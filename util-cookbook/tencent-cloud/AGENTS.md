# tencent-cloud

DNSPod DDNS updater distributed as the `tencent-cloud` workspace package and
`register-dns` CLI. Inherit both repository-root and `util-cookbook` instructions.

## Functionality

- `dnspod.py`: TC3-HMAC-SHA256 request signing, record lookup, and record modification
- `public_ip.py`: IPv4/IPv6 discovery through ipify, Taobao, ifconfig.me, fallback web
  requests, `ifaddr`, or optional `netifaces`
- `register_dns.py`: compare A/AAAA records, update only changed values, and support dry-run

The package is baked into OpenWRT images with pure-Python dependencies supplied by apk.
`netifaces` remains optional because OpenWRT lacks a suitable package/wheel.

DNSPod credentials come through `common`; read `.ai/skills/secret-handling/SKILL.md` before
running authenticated or OpenWRT-integrated paths. Never expose credentials or signed
request material.

## Validation

```bash
uv run --extra dev mypy util-cookbook/tencent-cloud/src/tencent_cloud
```

There is currently no pytest suite or coverage threshold. Do not use a live DNS update as
routine validation; add isolated tests with mocked network and secret dependencies for
behavior changes.
