# Workflow-artifact encryption + `verify-master-password.yaml`

> **Read [../SKILL.md](../SKILL.md) first** — the hard rule on never surfacing plaintext
> applies. This file covers the CI plumbing that turns the master password into encrypted
> artifacts, and the companion workflow used during rotation to verify the GitHub-side
> bytes.

## Why we encrypt before `upload-artifact`

`actions/upload-artifact` does not encrypt. On a public repo, anyone with read access can
download workflow artifacts via the REST API for the retention window (default 90 days,
configurable via `retention-days`). For a repo whose only confidential material lives
post-secret-expansion, that's a leak channel.

As of commit `dcee14b`:

1. **`build_configuration`** GPG-encrypts every non-`.srs` file in `artifacts-conf/` before
   `upload-artifact`. `.srs` rule sets are public-domain lists, intentionally plaintext.
2. **`build_openwrt`** decrypts the configs from `build_configuration`'s artifact, runs
   `build.sh`, then GPG-encrypts every `.gz` build output before `upload-artifact`.
3. **`release_proxy_configurations`** and **`release_openwrt_builds`** download the
   already-encrypted artifacts and `cp` them into the release directory — no second
   encryption pass.

**Invariant for any future job:** encrypt before upload, decrypt at consumer. Never
`upload-artifact` a file containing decrypted material on a public repo. Use
`retention-days: 7` on encrypted uploads as belt-and-suspenders.

## `verify-master-password.yaml`

`.github/workflows/verify-master-password.yaml` is a `workflow_dispatch`-only workflow that
emits the first 16 hex chars of `sha256(MASTER_PASSWORD)`. Used in step **B3** of the
rotation procedure ([rotation.md](rotation.md)) to confirm the GitHub-side secret matches
the local file.

Hardenings:

- `permissions: {}` — no `GITHUB_TOKEN` scopes available to the run
- `if: github.actor == 'lirundong'` — only the repo owner can invoke it

The truncated hash is fingerprint-safe **only** for high-entropy inputs. If a future
rotation uses anything other than `uuidgen -r` output, raise the truncation length or
switch to HMAC with a separate verification key — otherwise a short/low-entropy master
becomes brute-forceable from the public 16-hex prefix.

## Cross-references

- `.github/workflows/artifacts-release-nightly.yaml` — the encrypted-artifact pipeline
- `.github/workflows/verify-master-password.yaml` — fingerprint comparison workflow
- [rotation.md](rotation.md) — full master-password rotation procedure (B3 consumes this
  workflow)
- [../SKILL.md](../SKILL.md) — hard rule on plaintext surfaces (applies to every CI log line)
