# openwrt-builder

Build custom OpenWRT firmware with proxy, DDNS, and router configuration baked into the
image. Inherit the repository-root instructions.

## Build Pipeline

`build.sh` downloads the SDK and imagebuilder, expands `files/`, cross-compiles sing-box
(CGO) and vlmcsd, fetches Yacd-meta, installs `common` and `tencent-cloud` into the target
Python site-packages, and runs the imagebuilder.

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

CI builds `{x86/64, rockchip/armv8} × {25.12.5, snapshots}`; stable builds are required and
snapshot builds are allowed failures. There is no unit-test or shell-lint suite, so changes
to `build.sh`, packages, or rootfs files require an affected end-to-end image build.

The local build requires a safely supplied `PASSWORD`; after reading the secret-handling
skill, use:

```bash
VERSION=25.12.5 GCC_VERSION=14.3.0_musl openwrt-builder/build.sh
```
