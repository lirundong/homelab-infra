# openwrt-builder

Build custom OpenWRT firmware with proxy, DDNS, and router configuration baked into the
image. Inherit the repository-root instructions.

## Build Pipeline

`build.sh` downloads the SDK and imagebuilder, expands `files/`, cross-compiles sing-box
(CGO) and vlmcsd, preinstalls the native sing-box dashboard with auto-updates enabled,
installs `common` and `tencent-cloud` into the target Python site-packages, and runs the
imagebuilder.

Stable package selection is `packages/25.12.5.txt`; snapshots use
`packages/snapshots.txt`. Target Python is detected from the apk feed. Required runtime
packages include `coreutils-env` and `python3-cryptography`. Files ending in `.skip` are
templates and are excluded.

`uci-defaults/*` runs before networking during first boot. Network-dependent initialization
must be baked into the image or deferred to `hotplug.d/iface` behind a default-route guard.

## Secret Discipline

Firmware contains expanded secrets. Read `.ai/skills/secret-handling/SKILL.md` before
running or changing the build, and never expose or upload an unencrypted image.

## Validation

PR and `master` push CI require stable `25.12.5` builds for both `x86/64` and
`rockchip/armv8`. Scheduled nightly runs additionally build snapshots for both architectures,
with snapshot failures allowed. There is no automated test or shell-lint suite, so changes
to `build.sh`, packages, or rootfs files require an affected end-to-end image build.

The local build reads `PASSWORD` from the gitignored `.env.local`; after reading the
secret-handling skill, use:

```bash
VERSION=25.12.5 GCC_VERSION=14.3.0_musl \
    uv run --env-file .env.local bash openwrt-builder/build.sh
```
