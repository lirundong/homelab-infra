# tencent-cloud - Tencent Cloud DNSPod DDNS Updater and SSL Certificate Fetcher

- `register-dns`: update Tencent Cloud DNSPod A/AAAA records from the host's
  current public IP addresses. Intended for home routers (OpenWRT) or any system
  with Python 3.12+.
- `fetch-cert`: apply for, check, and download free TrustAsia DV certificates
  through the Tencent Cloud SSL API, validated automatically via DNSPod.

## Installation

```bash
# From repo root, installs all workspace packages (including common):
uv sync

# Standalone (e.g. on OpenWRT, inside a Docker image, etc.):
pip install -e ./common && pip install -e ./util-cookbook/tencent-cloud

# Optional: add netifaces (C extension; not available on OpenWRT) only if
# you need --get-ipv*-method=netifaces. Default is ifaddr (pure Python).
pip install -e './util-cookbook/tencent-cloud[netifaces]'
```

Either path exposes `register-dns` and `fetch-cert` on `PATH`.

Required secrets in `common/src/common/secrets.yaml` (see `common` README):
`MASTER_PASSWORD`, `QCLOUD_API_SECRET_ID`, `QCLOUD_API_SECRET_KEY`;
`fetch-cert -t plex` also needs `PLEX_CERT_PASSWORD` (or the secret named by
`--plex-password-secret`).

## `register-dns` usage

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

## `register-dns` options

| Flag | Description |
| --- | --- |
| `-d`, `--domain` | Apex domain registered in DNSPod (e.g. `example.com`) |
| `-s`, `--sub-domain` | Subdomain to update (e.g. `home`) |
| `-i`, `--interface` | Interface name for `netifaces` / `ifaddr` lookups |
| `--get-ipv4-method` | `ipify` (default), `taobao`, `ifconfig`, `requests`, `netifaces`, `ifaddr` |
| `--get-ipv6-method` | Same set, default `ifaddr`. Pass `netifaces` only if you installed the `[netifaces]` extra |
| `-n`, `--dry-run` | Print intended changes; no API writes |

## OpenWRT deployment

The `openwrt-builder` rsyncs this package to `/root/util-cookbook/tencent-cloud`
and a first-boot uci-defaults script runs
`python3 -m pip install -e /root/util-cookbook/tencent-cloud`, putting
`register-dns` at `/usr/bin/register-dns`. Cron then invokes it every 15 minutes
with credentials expanded from `secrets.yaml` at build time.

## `fetch-cert` usage

Every run is stateless and safe to repeat: it inspects the newest certificate of
the FQDN on Tencent Cloud and only applies for a new one when needed.

```bash
# Check every certificate under a domain; never applies or downloads.
PASSWORD=<master-password> uv run fetch-cert -d example.com --check-only

# Download (or apply for) nas.example.com in nginx format into ./certs/nas.example.com/.
PASSWORD=<master-password> uv run fetch-cert -d example.com -s nas -t nginx -o ./certs

# Plex: PKCS#12 encrypted with AES-256-CBC/SHA-256, protected by the PLEX_CERT_PASSWORD secret.
PASSWORD=<master-password> uv run fetch-cert -d example.com -s plex -t plex -o ./certs

# Delete every expired or failed certificate under the domain, after confirmation.
PASSWORD=<master-password> uv run fetch-cert -d example.com --delete
```

| Newest certificate | Action | Exit code |
| --- | --- | --- |
| Issued, expires beyond the renewal window | Download | 0 |
| Under review / adding DNS record | Report; never re-apply | 2 |
| Missing, expired, or inside the renewal window | Apply for a new one | 2 |
| Validation failed | Error; rerun with `--force` | 1 |

Issuance usually takes a few minutes. Rerun the same command after Tencent Cloud
notifies you, or pass `--wait MINUTES` to poll in the foreground.

| Flag | Description |
| --- | --- |
| `-d`, `--domain` | Apex domain registered in DNSPod |
| `-s`, `--sub-domain` | Certificate sub-domain, `@` for the apex; optional with `--check-only` |
| `-t`, `--type` | `nginx` (default), `apache`, `tomcat`, `iis`, `jks`, `plex` |
| `-o`, `--output-dir` | Files land in `<output-dir>/<fqdn>/` with mode `0600`, overwriting |
| `--renew-if-expiring-within-days` | Renewal window, default `30` |
| `-n`, `--check-only` | Report status only; exit `2` if anything needs attention |
| `--delete` | Delete expired/failed certificates after a `y/N` prompt; pending ones are skipped |
| `--force` | Fetch: apply even if a valid, pending, or failed certificate exists. Delete: also delete valid ones |
| `--wait MINUTES` | Poll for issuance and download once issued |
| `--plex-password-secret NAME` | `common` secret holding the Plex PKCS#12 password, default `PLEX_CERT_PASSWORD` |

Free certificates last three months, cover a single FQDN, and count against the
account's free quota, so `fetch-cert` reuses valid or pending certificates. Deleting a certificate does
not return quota.

For Plex, set Settings → Server → Network → Show Advanced → custom certificate
location to the `.p12`, the encryption key to that secret's value, and the
domain to the certificate FQDN. The Plex user must be able to read the file.
