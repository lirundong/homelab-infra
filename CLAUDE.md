# CLAUDE.md — Homelab Infrastructure Monorepo

## Project Structure
uv workspace monorepo. `uv sync` installs `common`, `conf-gen`, `tencent-cloud` editably into
`.venv` (via `__editable__.<pkg>.pth`); `uv.lock` pinned. Dev tools in root `dev` extra.

- **conf-gen**: Proxy config generator (Clash, Quantumult-X, sing-box)
- **openwrt-builder**: Custom OpenWRT firmware with integrated proxy
- **conf-cookbook**: Reference configs (Docker, Nginx, SS-Rust, V2Ray)
- **util-cookbook**: Utility scripts. Workspace pkg `tencent-cloud` → `register-dns` CLI
  (DDNS via Tencent DNSPod, invoked by OpenWRT on-device cron)

## Commands
```bash
uv sync                                                # runtime setup
uv sync --extra dev                                    # + mypy/black/isort
uv run conf-gen -s conf-gen/source.yaml -o output/     # gen configs
uv run black <file>                                    # format (99 cols)
uv run mypy common/src/common conf-gen/src/conf_gen \
    util-cookbook/tencent-cloud/src/tencent_cloud      # typecheck
# OpenWRT (PASSWORD env required; read secret-handling skill before invoking):
VERSION=25.12.2 GCC_VERSION=14.3.0_musl openwrt-builder/build.sh
```

## conf-gen (`conf-gen/src/conf_gen/`, note underscore)
Pipeline: `source.yaml -> Parser -> IR Objects -> Generator -> Config`. CLI:
`conf-gen -s/--src <source.yaml> -o/--dst <output-dir>`.
- **proxy/**: `ProxyBase` (SS, SS2022, Trojan, VMess, SOCKS5) implements
  `{clash,quantumult,sing_box}_proxy()`. Parsers: `parse_clash_proxies`, `parse_subscriptions`.
- **proxy_group/**: `SelectProxyGroup`, `FallbackProxyGroup`, `merge_proxy_by_region()`.
- **rule/**: `IRBase` + `@_IR_REGISTRY.register`, impls `{clash,quantumult,sing_box}_rule()`;
  types domain/IP CIDR/process/port. Utils: `group_sing_box_filters`,
  `split_sing_box_dst_ip_filters`, `parse_dnsmasq_conf`.
- **generator/**: `GeneratorBase` -> Clash YAML, Quantumult `.conf` + rewrites, SingBox
  (.srs via `RuleSetCompiler` ctx mgr; auto-downloads sing-box; DNS/route split).
- **rewrite/**: `QuantumultRewrite` for Quantumult-X URL rewriting.

## common — Secrets Management (`common/src/common/`)
Singleton `_SecretsManager`: Fernet (AEAD) + PBKDF2HMAC (SHA256, 100k iter). Env: `PASSWORD`
(master), `SALT` (default `"19260817"`). secrets.yaml lookup: `SECRETS_FILE` -> package dir
-> package root -> `/root/common/secrets.yaml`. Expansion (in any file processed by
`common-secret-decoder` or `expand_secret`): `@secret:KEY[!TYPE]` decrypts (optional cast);
`@include:FILE[:!JOIN][:>INDENT]` includes with comment stripping (project root: `PROJECT_
ROOT` -> git root -> cwd).

```python
from common import secrets
secrets.update("KEY", "value"); secrets.commit(); secrets.status()
secrets.rotate_password(new_password)  # crash-safe atomic write (fsync + dir-fsync)
```
CLIs: `common-secret-decoder -r <src> <dst> [-e <regex>]` expands markers; `common-rotate-
password < <pw-file>` re-encrypts all entries (stdin-only, rejects TTY, strips one `\n`).

**CRITICAL — never surface plaintext secrets in any recorded interaction.** Full surface list,
recording mechanisms, and rotation procedure: `.claude/skills/secret-handling/SKILL.md`.

## OpenWRT Builder (`openwrt-builder/build.sh`)
Steps: SDK download -> decrypt files (`common-secret-decoder -r`) -> cross-compile sing-box
(CGO) + vlmcsd -> fetch Yacd-meta -> `uv pip install --target` `common` + `tencent-cloud`
into rootfs `usr/lib/python$TARGET_PY/site-packages` (rewrite shebangs to `#!/usr/bin/env
python3`, expose via relative `usr/bin` symlinks) -> imagebuilder. Custom files:
`files/etc/{init.d,uci-defaults,nftables.d,dropbear,crontabs,apk}/`. Packages:
`packages/{25.12.2,snapshots}.txt` (25.12+ uses apk). Required apks: `coreutils-env`,
`python3-cryptography`. Env: `PASSWORD`, `VERSION` (default stale), `TARGET_ARCH` (`x86/64`),
`GCC_VERSION`, `PROFILE`, `PACKAGE_ARCH`, `REPOSITORY` (default Tsinghua mirror), `WORK_DIR`,
`SING_BOX_*`, `TOOLCHAIN_ARCH`, `HOST_ARCH`, `TAR_EXT`. `TARGET_PY` auto-detected from apk
feed (3.13 stable / 3.14 snapshots). **`uci-defaults/*` runs before networking** (during
`/etc/init.d/boot`, before WAN); network-dependent first-boot work fails closed — bake state
into the image, or use `hotplug.d/iface` with a default-route guard.

## CI (`.github/workflows/artifacts-release-nightly.yaml`)
Jobs: type_check -> build_configuration -> build_openwrt (matrix {x86/64, rockchip/armv8} x
{25.12.2, snapshots}) -> release_{proxy_configurations,openwrt_builds}. GCC `14.3.0_musl`;
rockchip profile `friendlyarm_nanopi-r6s`; snapshots `allow_failure`. **Workflow-artifact
encryption (commit `dcee14b`):** public-repo artifacts are world-downloadable for the
retention window; `build_configuration` and `build_openwrt` GPG-encrypt outputs with
`MASTER_PASSWORD` *before* `actions/upload-artifact`; release jobs `cp` the `.gpg` files (no
second pass). `.srs` stays plaintext (public). `retention-days: 7`. **`[no release]` in
commit message** skips `release_*` while still running `build_*` as integration tests — use
during rotation or when the deployed router can't yet decrypt new artifacts.
`verify-master-password.yaml` (workflow_dispatch only, repo-owner gated, `permissions: {}`)
emits a 16-hex sha256 prefix of `MASTER_PASSWORD` for rotation fingerprint comparison.

## Code Quality & Conventions
Python >=3.12 (PEP 604 unions, PEP 695 generics). Strict mypy + PEP 561 `py.typed` (flags in
root `pyproject.toml`). Black `line-length=99`, isort `profile=black`. **Fail fast on
invariants:** no `|| true` / `2>/dev/null` / try-except-pass to mask cases that "should never
happen". Prefer in-place edits (`sed -i`, `Edit`) over reconstruction; prefer symlinks over
moves when relocating tool-produced files.

**Adding types:** new proxy → subclass `ProxyBase` (3 platform methods) + register in
`parser.py`; new rule → subclass `IRBase` (`@_IR_REGISTRY.register`, 3 `*_rule()` methods);
new generator → subclass `GeneratorBase` + wire into `generate_conf()`.

## Key Files
- `conf-gen/source.yaml` — single source of truth for all configs
- `common/src/common/secrets.yaml` — encrypted secrets (in git)
- `openwrt-builder/build.sh` — build orchestration
- `.skip` suffix files in `openwrt-builder/` — excluded, templates only
- `.claude/skills/secret-handling/SKILL.md` — canonical secret rules + rotation procedure
