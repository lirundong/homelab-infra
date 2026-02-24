# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a monorepo for homelab infrastructure management with four main components:
- **conf-gen**: Generates proxy configurations (Clash, Quantumult-X, sing-box) from a single source
- **openwrt-builder**: Builds custom OpenWRT firmware images with integrated proxy capabilities
- **conf-cookbook**: Reference configurations for Docker, Nginx, Shadowsocks-Rust, V2Ray
- **util-cookbook**: Utility scripts for DDNS, router management, etc.

## Common Development Commands

### Configuration Generation
```bash
# Install packages (first time only)
pip install -e ./common
pip install -e ./conf-gen

# Generate all proxy configurations (requires PASSWORD environment variable)
conf-gen -s conf-gen/source.yaml -o output/

# Or use the backwards-compatible wrapper
cd conf-gen
python3 generate.py -s source.yaml -o output/

# The command reads source.yaml and outputs platform-specific configs
# Ensure you have sing-box binary in PATH for rule set compilation
```

### OpenWRT Image Building
```bash
cd openwrt-builder

# Build stable x86/64 image
./build.sh

# Build with custom parameters (CI uses these values)
VERSION=24.10.5 GCC_VERSION=13.3.0_musl ./build.sh
TARGET_ARCH=rockchip/armv8 VERSION=snapshots GCC_VERSION=14.3.0_musl PROFILE=friendlyarm_nanopi-r6s ./build.sh

# Required environment variables:
# - PASSWORD: Master password for decrypting secrets
# - VERSION: "24.10.5" or "snapshots" (build.sh default is stale, always set explicitly)
# Optional:
# - SING_BOX_VERSION, SING_BOX_ARCH, SING_BOX_CONFIG
# - TARGET_ARCH (default: x86/64), TOOLCHAIN_ARCH, HOST_ARCH
# - GCC_VERSION (e.g. 13.3.0_musl for stable, 14.3.0_musl for snapshots)
# - REPOSITORY (default: mirrors.tuna.tsinghua.edu.cn/openwrt)
# - WORK_DIR (default: /tmp/openwrt)
# - PROFILE (e.g. friendlyarm_nanopi-r6s for rockchip/armv8)
```

### Python Environment
```bash
# Install packages (editable mode for development)
pip install -e ./common
pip install -e ./conf-gen

# Format code (Black configured in pyproject.toml, line-length=99)
black <file>

# Type checking (mypy configured in pyproject.toml)
mypy common/src/common conf-gen/src/conf_gen
```

## Architecture Overview

### conf-gen Package Structure

The `conf-gen` package is a standalone, pip-installable Python package for generating proxy configurations.

**Package Structure:**
```
conf-gen/
├── pyproject.toml          # Package configuration
├── README.md               # Package documentation
├── source.yaml             # Configuration source (not in package)
├── generate.py             # Backwards compatibility wrapper (deprecated)
└── src/
    └── conf_gen/           # Python package (note: underscore)
        ├── __init__.py     # Package exports
        ├── _cli.py         # CLI entry point (conf-gen command)
        ├── py.typed        # PEP 561 typed package marker
        ├── generator/      # Platform-specific generators
        ├── proxy/          # Proxy implementations
        ├── proxy_group/    # Proxy grouping logic
        ├── rewrite/        # URL rewriting rules
        └── rule/           # Rule IR system
```

**Installation:**
```bash
pip install -e ./common       # Install common package first
pip install -e ./conf-gen     # Install conf-gen package
```

The configuration generator uses an **Intermediate Representation (IR)** pattern to support multiple platforms:

```
source.yaml → Parser → IR Objects → Generator → Platform Config
```

**Key subsystems:**

1. **Proxy System** (`conf_gen.proxy`)
   - Base class: `ProxyBase`
   - Implementations: ShadowSocks, ShadowSocks2022, Trojan, VMess (WebSocket/GRPC variants), SOCKS5
   - Each proxy implements platform-specific output: `clash_proxy()`, `quantumult_proxy()`, `sing_box_proxy()`
   - Parser: `parse_clash_proxies()`, `parse_subscriptions()`

2. **Proxy Group System** (`conf_gen.proxy_group`)
   - `SelectProxyGroup`: Manual selection
   - `FallbackProxyGroup`: Auto-fallback with health checks
   - `merge_proxy_by_region()`: Groups proxies by country using emoji flags and `pycountry`

3. **Rule System** (`conf_gen.rule`)
   - **Registry Pattern**: `_IR_REGISTRY` for dynamic rule type registration
   - **Base Class**: `IRBase` - Abstract rule with platform translation methods
   - Rule types: Domain matchers, IP CIDR, Process/Package matchers, Port matchers
   - Parsers: `parse_clash_classical_filter()`, `parse_domain_list()`, `parse_dnsmasq_conf()`
   - Utilities: `group_sing_box_filters()`, `split_sing_box_dst_ip_filters()`

4. **Generator System** (`conf_gen.generator`)
   - Base class: `GeneratorBase`
   - **ClashGenerator**: Outputs YAML with deduplicated rules
   - **QuantumultGenerator**: Outputs .conf format with mandatory sections, integrates rewrites
   - **SingBoxGenerator**: Most complex generator (425 lines)
     - Compiles rule sets to binary `.srs` format using sing-box CLI
     - Separates DNS and route rules
     - Process-based filtering support
     - `from_base()`: Creates derived configs from base template
     - `extract_ruleset_inplace()`: Extracts rules into separate rule sets for performance

5. **Rewrite System** (`conf_gen.rewrite`)
   - `QuantumultRewrite`: URL rewriting rules for Quantumult-X

### OpenWRT Builder Architecture

The `build.sh` script orchestrates:
1. Downloads OpenWRT SDK for cross-compilation
2. Decrypts custom files using `common-secret-decoder -r files/`
3. Cross-compiles sing-box with CGO using OpenWRT toolchain
4. Cross-compiles vlmcsd (KMS emulator)
5. Downloads Yacd-meta web dashboard for sing-box UI
6. Builds firmware image with custom packages and overlay filesystem

**Custom file structure:**
- `files/etc/init.d/`: Service init scripts (sing-box, vlmcsd)
- `files/etc/uci-defaults/`: First-boot configuration (network, firewall, DHCP, SQM)
- `files/etc/nftables.d/`: nftables rules for transparent proxy
- `files/etc/dropbear/`: SSH authorized_keys
- `files/etc/crontabs/`: Scheduled tasks
- `files/etc/opkg/`: Package manager configuration

**Package lists:** `packages/24.10.5.txt`, `packages/snapshots.txt`

### Secrets Management System

The `common` package is a standalone, pip-installable Python package for secrets management.

**Package Structure:**
```
common/
├── pyproject.toml          # Package configuration
└── src/
    └── common/
        ├── __init__.py     # Exports: secrets, CLASH_RULESET_FORMATS, COMMENT_BEGINS
        ├── _manager.py     # SecretsManager implementation
        ├── secrets.py      # Module replacement for attribute access
        ├── secrets.yaml    # Encrypted secrets storage (checked into git)
        ├── _cli.py         # CLI entry point (common-secret-decoder)
        └── py.typed        # PEP 561 typed package marker
```

**Installation:**
```bash
cd common
pip install -e .  # Editable install for development
```

**Multi-layer encryption architecture:**

1. **Storage** (`common/src/common/secrets.yaml`): Fernet-encrypted key-value pairs
2. **Runtime** (`common/src/common/_manager.py`): Singleton `_SecretsManager` class
   - Encryption: Fernet (AEAD) with PBKDF2HMAC (SHA256, 100k iterations)
   - Master password from `PASSWORD` env var
   - Salt from `SALT` env var (default: "19260817")
   - **Path Resolution**: Finds secrets.yaml via fallback strategy:
     1. `SECRETS_FILE` environment variable
     2. Package directory: `common/secrets.yaml` (for regular install)
     3. Package root: `common/secrets.yaml` (for editable install, backward compat)
     4. `/root/common/secrets.yaml` (OpenWRT compatibility)

3. **Expansion Syntax:**
   - `@secret:<KEY>`: Decrypts and returns string
   - `@secret:<KEY>!<TYPE>`: Decrypts and casts to type (int, float, etc.)
   - `@include:<FILE>[:!<JOIN>][:><INDENT>]`: Includes file content with comment stripping
   - **Project Root Resolution** for `@include:` (priority order):
     1. `PROJECT_ROOT` environment variable
     2. Git repository root (`git rev-parse --show-toplevel`)
     3. Current working directory

4. **Secret Management:**
   ```python
   from common import secrets
   secrets.update("NEW_KEY", "plaintext_value")  # Stage
   secrets.commit()                               # Write to secrets.yaml
   secrets.status()                               # Show pending changes
   ```

5. **File Decryption (CLI):**
   ```bash
   # After installing the package, use the CLI command:
   common-secret-decoder -r <src_dir> <dst_dir> [-e <exclude_regex>]

   # Or via stdin:
   echo "@secret:MY_KEY" | common-secret-decoder
   ```

**CRITICAL:** Never write plaintext secrets or master password to files. Always use encrypted `@secret:` placeholders.

### GitHub Actions Workflow

**File:** `.github/workflows/artifacts-release-nightly.yaml`

**Jobs:**
1. `type_check`: Runs mypy type checking on both packages
2. `build_configuration`: Generates all proxy configs, extracts config names for matrix
3. `build_openwrt`: Matrix build (2 architectures × 2 versions)
4. `release_proxy_configurations`: GPG-encrypts and releases configs to GitHub
5. `release_openwrt_builds`: GPG-encrypts and releases firmware images

**Matrix dimensions:**
- Architectures: x86/64, rockchip/armv8 (with profile: friendlyarm_nanopi-r6s)
- Versions: 24.10.5 (stable, GCC 13.3.0_musl), snapshots (GCC 14.3.0_musl, allow_failure)

**Security:** All releases GPG-encrypted with `secrets.MASTER_PASSWORD`

## Code Quality

Both packages are fully typed (PEP 561 `py.typed` markers) with strict mypy configuration:
- `disallow_untyped_defs`, `disallow_incomplete_defs`, `strict_optional`, `no_implicit_optional`
- Python 3.12+ type syntax (PEP 604 unions, PEP 695 generics)
- CI runs mypy on every push via the `type_check` job

Formatting: Black (line-length=99) and isort (profile=black), configured in each `pyproject.toml`.

No test infrastructure exists yet (no pytest, no test directories).

## Design Patterns Used

- **Abstract Factory**: `GeneratorBase` with platform implementations
- **Registry Pattern**: `IRRegistry` for rule types
- **Template Method**: Base classes define structure, subclasses implement details
- **Singleton**: `_SecretsManager`
- **Strategy**: `SelectProxyGroup` vs `FallbackProxyGroup`
- **Intermediate Representation**: Rules → IR → Platform-specific output

## Important Files

- `conf-gen/source.yaml` (755 lines): Single source of truth for all configurations
- `conf-gen/pyproject.toml`: conf-gen package configuration
- `common/src/common/secrets.yaml`: Encrypted secrets storage
- `common/pyproject.toml`: common package configuration
- `openwrt-builder/build.sh`: Main build orchestration script
- `conf-gen/generate.py`: Backwards compatibility wrapper (deprecated, use `conf-gen` CLI)

## Adding New Features

### Adding a New Proxy Type
1. Create class in `conf-gen/src/conf_gen/proxy/` inheriting from `ProxyBase`
2. Implement `clash_proxy()`, `quantumult_proxy()`, `sing_box_proxy()` methods
3. Add parsing logic in `proxy/parser.py`
4. Export from `conf_gen.proxy.__init__.py`

### Adding a New Rule Type
1. Create class in `conf-gen/src/conf_gen/rule/ir.py` inheriting from `IRBase`
2. Register with `@_IR_REGISTRY.register` decorator
3. Implement translation methods: `clash_rule()`, `quantumult_rule()`, `sing_box_rule()`

### Adding a New Platform Generator
1. Create class in `conf-gen/src/conf_gen/generator/` inheriting from `GeneratorBase`
2. Implement `generate()` method
3. Handle proxy output, rule translation, and platform-specific formatting
4. Update `source.yaml` schema to include new platform section
5. Import and use in `generator/__init__.py`'s `generate_conf()` function

## Working with Encrypted Files

Files with `.skip` suffix in `openwrt-builder/files/` are excluded from builds but may contain template configurations for reference.

When modifying files in `openwrt-builder/files/`, you may encounter `@secret:` placeholders. These are expanded during build by the `common-secret-decoder` CLI tool. To add new secrets:

```bash
# Ensure common package is installed
pip install -e ./common

# Add a new secret
python3 -c "from common import secrets; secrets.update('KEY', 'value'); secrets.commit()"
```
