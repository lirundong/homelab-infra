# tencent-cloud - Tencent Cloud DNSPod DDNS Updater

Update Tencent Cloud DNSPod A/AAAA records from the host's current public IP
addresses. Intended for home routers (OpenWRT) or any system with Python 3.12+.

## Installation

```bash
# From repo root, installs all workspace packages (including common):
uv sync

# Standalone (e.g. on OpenWRT, inside a Docker image, etc.):
pip install -e ./common && pip install -e ./util-cookbook/tencent-cloud
```

Either path exposes `register-dns` on `PATH`.

Required secrets in `common/src/common/secrets.yaml` (see `common` README):
`MASTER_PASSWORD`, `QCLOUD_API_SECRET_ID`, `QCLOUD_API_SECRET_KEY`.

## Usage

```bash
# From repo root, via uv:
PASSWORD=<master-password> uv run register-dns \
    -d example.com -s home \
    -i pppoe-wan \
    --get-ipv4-method ipify \
    --get-ipv6-method ifaddr \
    --dry-run

# On OpenWRT after first-boot install, directly on PATH:
PASSWORD=<master-password> /usr/bin/register-dns \
    -d example.com -s home \
    -i pppoe-wan \
    --get-ipv4-method ipify \
    --get-ipv6-method ifaddr

# Equivalent module invocation (no shim on PATH needed):
PASSWORD=<master-password> python3 -m tencent_cloud.register_dns -h
```

`--dry-run` prints the records that would be modified without writing to
DNSPod. Omit it for a live update.

## Options

| Flag | Description |
| --- | --- |
| `-d`, `--domain` | Apex domain registered in DNSPod (e.g. `example.com`) |
| `-s`, `--sub-domain` | Subdomain to update (e.g. `home`) |
| `-i`, `--interface` | Interface name for `netifaces` / `ifaddr` lookups |
| `--get-ipv4-method` | `ipify` (default), `taobao`, `ifconfig`, `requests`, `netifaces`, `ifaddr` |
| `--get-ipv6-method` | Same set, default `netifaces`. `ifaddr` is the OpenWRT-friendly choice |
| `-n`, `--dry-run` | Print intended changes; no API writes |

## OpenWRT deployment

The `openwrt-builder` rsyncs this package to `/root/util-cookbook/tencent-cloud`
and a first-boot uci-defaults script runs
`python3 -m pip install -e /root/util-cookbook/tencent-cloud`, putting
`register-dns` at `/usr/bin/register-dns`. Cron then invokes it every 15 minutes
with credentials expanded from `secrets.yaml` at build time.
