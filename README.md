# HomeLab Infra Monorepo

[![Artifacts Release Nightly](https://github.com/lirundong/homelab-infra/actions/workflows/artifacts-release-nightly.yaml/badge.svg)](https://github.com/lirundong/homelab-infra/actions/workflows/artifacts-release-nightly.yaml)

This is a [monorepo](https://en.wikipedia.org/wiki/Monorepo) containing all software infrastructures of Rundong's home-lab. Projects include:

* [conf-gen](./conf-gen): Generating [Clash](https://github.com/Dreamacro/clash) and [Quantumult-X](https://apps.apple.com/us/app/quantumult-x/id1443988620) configuration files for various deployment scenarios (PC clients, home routers, mobile apps, etc.) from one single unified source configuration file
* [conf-cookbook](./conf-cookbook): Boilerplate configurations for secured internet services (e.g., shadowsocks-rust, V2Ray + Nginx WebSocket)
* [openwrt-builder](./openwrt-builder): Build OpenWRT image with custom configurations and packages, include scripts to archive transparent proxy
* [util-cookbook](./util-cookbook): Handy utilities for daily home-lab maintaining, e.g., DDNS, router LED scheduling etc.

## How to handle confidential information

Confidential information such as API keys, subscription URLs, and user ids is mandatory for services such as Clash config generation. To safely include such information in this monorepo, we symmetrically encrypt them via the [Fernet](https://cryptography.io/en/latest/fernet/) construction (a time-tested AEAD cipher) and write the corresponding ciphertext to boilerplate code and configurations. Specifically, the encryption process comprises:

0. Inputs:
   * `master_password`: Any unicode string
   * `salt`: Any unicode string
   * `plain_text` or `cypher_text`: Any unsigned byte string to be encrypted or decrypted
1. Encode strings to bytes:
   * `master_password_byes` <- Encode `master_password` in UTF-8
   * `salt_bytes` <- Encode `salt` in UTF-8
2. Derive `key_bytes` <- PBKDF2HMAC algorithm from `master_password_bytes` and `salt_bytes` using the following parameters:
   * algorithm: SHA256
   * length: 32
   * iterations: 100000
3. Construct `fernet` <- [Fernet](https://cryptography.io/en/latest/fernet/) cypher from `key_bytes`
4. Encrypt `plain_text` or decrypt `cypher_text` by `fernet`

If you are intending to fork/reuse this monorepo and incorporate your own confidential information, please remember: It's safe to use `cypher_text` anywhere, however, **NEVER EVER WRITE `plain_text` OR `master_password` TO ANY CODE/CONFIG/FILES**!

## License

This work is distributed under the MIT License, see [LICENSE](./LICENSE) for details.
