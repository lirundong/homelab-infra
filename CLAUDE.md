# CLAUDE.md — Homelab Infrastructure Monorepo

## Project Structure
uv workspace monorepo (`pyproject.toml` at root). `uv sync` installs
both `common` and `conf-gen` into a shared `.venv`. `uv.lock` pinned.

- **conf-gen**: Proxy config generator (Clash, Quantumult-X, sing-box)
- **openwrt-builder**: Custom OpenWRT firmware with integrated proxy
- **conf-cookbook**: Reference configs (Docker, Nginx, SS-Rust, V2Ray)
- **util-cookbook**: Utility scripts (DDNS, router management)

## Commands
```bash
uv sync                                                # setup
uv run conf-gen -s conf-gen/source.yaml -o output/     # gen configs
uv run black <file>                                    # format (99 cols)
uv run mypy common/src/common conf-gen/src/conf_gen    # typecheck
# OpenWRT (PASSWORD env var required):
VERSION=24.10.5 GCC_VERSION=13.3.0_musl openwrt-builder/build.sh
```

## conf-gen (`conf-gen/src/conf_gen/`, note underscore)
Pipeline: `source.yaml -> Parser -> IR Objects -> Generator -> Config`
- **proxy/**: `ProxyBase` subclasses (SS, SS2022, Trojan, VMess, SOCKS5)
  each implement `clash_proxy()`, `quantumult_proxy()`, `sing_box_proxy()`
  Parser: `parse_clash_proxies()`, `parse_subscriptions()`
- **proxy_group/**: `SelectProxyGroup`, `FallbackProxyGroup`,
  `merge_proxy_by_region()` (groups by country via emoji + pycountry)
- **rule/**: `IRBase` + `@_IR_REGISTRY.register` decorator. Types:
  domain, IP CIDR, process/package, port. Parsers:
  `parse_clash_classical_filter()`, `parse_domain_list()`,
  `parse_dnsmasq_conf()`. Utils: `group_sing_box_filters()`,
  `split_sing_box_dst_ip_filters()`, `SplittedSingBoxFilters`
- **generator/**: `GeneratorBase` -> Clash (YAML, dedup rules),
  Quantumult (.conf, rewrites), SingBox (.srs compilation via
  `RuleSetCompiler` ctx mgr, auto-downloads sing-box if not in PATH,
  DNS/route split, `from_base()`, `extract_ruleset_inplace()`)
- **rewrite/**: `QuantumultRewrite` for Quantumult-X URL rewriting
- CLI: `conf-gen -s/--src <source.yaml> -o/--dst <output-dir>`

## common — Secrets Management (`common/src/common/`)
Singleton `_SecretsManager`: Fernet (AEAD) + PBKDF2HMAC (SHA256, 100k).
Env: `PASSWORD` (master key), `SALT` (default "19260817").
secrets.yaml path: `SECRETS_FILE` env -> package dir -> package root
-> `/root/common/secrets.yaml` (OpenWRT compat).

Expansion syntax:
- `@secret:KEY` / `@secret:KEY!TYPE` — decrypt (optionally cast)
- `@include:FILE[:!JOIN][:>INDENT]` — include with comment stripping
  Project root: `PROJECT_ROOT` env -> git root -> cwd

```python
from common import secrets
secrets.update("KEY", "value"); secrets.commit(); secrets.status()
```
CLI: `common-secret-decoder -r <src> <dst> [-e <exclude_regex>]`
Exports: `secrets`, `CLASH_RULESET_FORMATS`, `COMMENT_BEGINS`

**CRITICAL:** Never write plaintext secrets to files. Use `@secret:`.

## OpenWRT Builder (`openwrt-builder/build.sh`)
Steps: download SDK -> decrypt files (`common-secret-decoder -r`) ->
cross-compile sing-box (CGO) + vlmcsd -> download Yacd-meta -> build.
Custom files: `files/etc/{init.d,uci-defaults,nftables.d,dropbear,
crontabs,opkg}/`. Packages: `packages/{24.10.5,snapshots}.txt`.

Env vars: `PASSWORD` (required), `VERSION` (required, default stale),
`TARGET_ARCH` (x86/64), `GCC_VERSION`, `PROFILE`, `REPOSITORY`
(default: Tsinghua mirror), `WORK_DIR` (/tmp/openwrt),
`SING_BOX_VERSION` (auto-fetches latest), `SING_BOX_ARCH`,
`SING_BOX_CONFIG`, `TOOLCHAIN_ARCH`, `HOST_ARCH`, `TAR_EXT`.

## CI (`.github/workflows/artifacts-release-nightly.yaml`)
Jobs: type_check (mypy) -> build_configuration -> build_openwrt
(matrix: {x86/64, rockchip/armv8} x {24.10.5, snapshots}) ->
release_{proxy_configurations,openwrt_builds} (GPG-encrypted).
GCC: 13.3.0_musl (stable), 14.3.0_musl (snapshots, allow_failure).
rockchip profile: friendlyarm_nanopi-r6s. Uses uv (astral-sh/setup-uv)
for Python/dependency management; uv auto-downloads Python as needed.

## Code Quality
Python >=3.12 (3.12+ syntax: PEP 604 unions, PEP 695 generics).
Strict mypy: `disallow_untyped_defs`, `disallow_incomplete_defs`,
`strict_optional`, `no_implicit_optional`, `warn_return_any`,
`warn_unused_ignores`. Both packages: PEP 561 `py.typed`.
Black (line-length=99), isort (profile=black). No tests yet.

## Adding Features
**New proxy:** subclass `ProxyBase` in `proxy/`, implement 3 platform
methods, add to `parser.py`, export from `__init__.py`.
**New rule:** subclass `IRBase` in `rule/ir.py`, `@_IR_REGISTRY.register`
decorator, implement `clash_rule()`, `quantumult_rule()`, `sing_box_rule()`
**New generator:** subclass `GeneratorBase` in `generator/`, implement
`generate()`, wire into `generate_conf()` in `generator/__init__.py`.

## Key Files
- `conf-gen/source.yaml`: single source of truth for all configs
- `common/src/common/secrets.yaml`: encrypted secrets (in git)
- `openwrt-builder/build.sh`: build orchestration
- `.skip` suffix files in openwrt-builder/: excluded, templates only
