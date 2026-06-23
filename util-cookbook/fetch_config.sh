#!/usr/bin/env bash
# fetch_config.sh — Download and decrypt proxy configs from GitHub nightly releases.
#
# Required env vars:
#   PASSWORD    — GPG passphrase (same as MASTER_PASSWORD in CI)
#
# Optional env vars:
#   CONF_DIR    — Output directory (default: /var/www/bwh-jp-01.rundong.me/html/conf)
#   CONF_URL    — Public base URL for the conf directory, used to rewrite sing-box
#                 remote rule-set URLs (default: https://bwh-jp-01.rundong.me/conf)
#   CONFIGS     — Space-separated list of release tags to fetch (default: all 7 configs)
#
# Prerequisites: gh (GitHub CLI, authenticated), gpg, jq
#
# Usage:
#   PASSWORD=xxx ./fetch_config.sh
#   PASSWORD=xxx CONFIGS="quantumult-x sing-box-clients" ./fetch_config.sh

set -euo pipefail

REPO="lirundong/homelab-infra"
GITHUB_URL="https://github.com/${REPO}/releases/download"
CONF_DIR="${CONF_DIR:-/var/www/bwh-jp-01.rundong.me/html/conf}"
CONF_URL="${CONF_URL:-https://bwh-jp-01.rundong.me/conf}"
CONFIGS="${CONFIGS:-clash clash-daemon clash-android quantumult-x sing-box-daemon sing-box-clients sing-box-apple}"
WORK_DIR="$(mktemp -d)"

cleanup() { rm -rf "${WORK_DIR}"; }
trap cleanup EXIT

die() { echo "ERROR: $*" >&2; exit 1; }

[[ -z "${PASSWORD:-}" ]] && die "PASSWORD env var is required"
command -v gh >/dev/null || die "gh CLI is required"
command -v gpg >/dev/null || die "gpg is required"
command -v jq >/dev/null || die "jq is required"

echo "=== fetch_config.sh ==="
echo "Configs: ${CONFIGS}"
echo "Output:  ${CONF_DIR}"
echo ""

for tag in ${CONFIGS}; do
    echo "[${tag}] Downloading ..."
    tag_dir="${WORK_DIR}/${tag}"
    mkdir -p "${tag_dir}"

    if ! gh release download "${tag}" -R "${REPO}" -D "${tag_dir}" --clobber; then
        echo "  WARNING: Failed to download release '${tag}', skipping."
        echo ""
        continue
    fi

    # Remove README files uploaded by the release action.
    find "${tag_dir}" -maxdepth 1 -iname 'README*' -delete

    # Decrypt all .gpg files.
    while IFS= read -r -d '' gpg_file; do
        echo "  Decrypting $(basename "${gpg_file}") ..."
        gpg --quiet --batch --yes \
            --passphrase="${PASSWORD}" \
            --pinentry-mode loopback \
            -d -o "${gpg_file%.gpg}" "${gpg_file}" \
        && rm -f "${gpg_file}"
    done < <(find "${tag_dir}" -name '*.gpg' -print0)

    # Rewrite sing-box remote rulesets to bootstrap without proxy dependencies.
    if [[ -f "${tag_dir}/config.json" ]]; then
        echo "  Rewriting .srs URLs -> ${CONF_URL}/${tag}/ and download_detour -> DIRECT ..."
        config_file="${tag_dir}/config.json"
        rewritten_config="${tag_dir}/config.json.rewritten"
        jq \
            --arg github_prefix "${GITHUB_URL}/${tag}/" \
            --arg self_hosted_prefix "${CONF_URL}/${tag}/" \
            '
            def rewrite_rule_set:
                if type == "object" then
                    (
                        if ((.url? | type == "string") and (.url | startswith($github_prefix))) then
                            .url = ($self_hosted_prefix + (.url | ltrimstr($github_prefix)))
                        else
                            .
                        end
                    )
                    | if .type == "remote" then .download_detour = "DIRECT" else . end
                else
                    .
                end;

            if (.route.rule_set? | type) == "array" then
                .route.rule_set |= map(rewrite_rule_set)
            else
                .
            end
            ' "${config_file}" > "${rewritten_config}"
        mv "${rewritten_config}" "${config_file}"
    fi

    # Count remaining files to decide layout.
    files=()
    while IFS= read -r -d '' f; do
        files+=("${f}")
    done < <(find "${tag_dir}" -maxdepth 1 -type f -print0)

    if [[ ${#files[@]} -eq 1 ]]; then
        # Single-file config (clash.yaml, quantumult-x.conf) -> top level.
        mkdir -p "${CONF_DIR}"
        cp -f "${files[0]}" "${CONF_DIR}/"
        echo "  -> ${CONF_DIR}/$(basename "${files[0]}")"
    else
        # Directory config (sing-box: config.json + *.srs) -> subdirectory.
        mkdir -p "${CONF_DIR}/${tag}"
        for f in "${files[@]}"; do
            cp -f "${f}" "${CONF_DIR}/${tag}/"
        done
        echo "  -> ${CONF_DIR}/${tag}/ (${#files[@]} files)"
    fi

    echo ""
done

echo "Done."
