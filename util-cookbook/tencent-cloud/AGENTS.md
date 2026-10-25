# tencent-cloud

DNSPod DDNS updater and SSL certificate fetcher distributed as the `tencent-cloud`
workspace package with `register-dns` and `fetch-cert` CLIs. Inherit both repository-root and `util-cookbook` instructions.

## Functionality

- `qcloud_api.py`: TC3-HMAC-SHA256 request signing shared by every Tencent Cloud service
- `dnspod.py`: DNSPod record lookup and record modification
- `public_ip.py`: IPv4/IPv6 discovery through ipify, Taobao, ifconfig.me, fallback web
  requests, `ifaddr`, or optional `netifaces`
- `register_dns.py`: compare A/AAAA records, update only changed values, and support dry-run
- `ssl_cert.py`: list, apply for, poll, download, and delete free DV certificates
- `fetch_cert.py`: stateless apply/check/download/delete CLI; converts nginx bundles to Plex
  PKCS#12

The package is baked into OpenWRT images with pure-Python dependencies supplied by apk.
`netifaces` remains optional because OpenWRT lacks a suitable package/wheel.

DNSPod credentials come through `common`; read `.ai/skills/secret-handling/SKILL.md` before
running authenticated or OpenWRT-integrated paths. Never expose credentials or signed
request material.

## Validation

```bash
uv run --extra dev mypy util-cookbook/tencent-cloud/src/tencent_cloud
```

There is no automated test suite. CI requires stable OpenWRT builds for code changes in
this package; successful packaging does not verify live DNS or certificate behavior.
Do not use a live DNS update or certificate application as routine validation: applications
consume the account's free quota.
`fetch-cert --check-only` is the safe live read.
