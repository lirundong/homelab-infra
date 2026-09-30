# conf-gen - Proxy Configuration Generator

Generate Clash, Quantumult-X, and sing-box configurations from unified YAML source.

## Installation

```bash
uv sync            # from repo root, installs all workspace packages
# or standalone:
pip install -e ./common && pip install -e ./conf-gen
```

## Usage

```bash
# Command line
uv run conf-gen -s source.yaml -o output-dir/

# Python API
from conf_gen import generate_conf, parse_clash_proxies

proxies = parse_clash_proxies(config["proxies"])
generate_conf(generate_info=config["generates"], src="source.yaml", dst="output/",
              proxies=proxies, proxy_groups=proxy_groups)
```

## Features

- Single source of truth in source.yaml
- Multi-platform: Clash, Quantumult-X, sing-box
- Intermediate Representation for platform-agnostic rules
- Subscription parsing and region-based grouping
- Binary rule set compilation for sing-box
- Integrated secrets management

## Configuration

See source.yaml for full schema. Basic example:

```yaml
proxies:
  - name: "My Proxy"
    type: ss
    server: example.com
    password: "@secret:PROXY_PASSWORD"
  - name: "My Group"  # A selector over inline proxies; the first one is the default.
    type: select
    proxies:
      - name: "HTTP Proxy"
        type: http
        server: 192.0.2.1
        port: 8080
```

For sing-box targets, `outbounds` replaces the default `DIRECT` outbound, and
`ruleset_download_detour` names an outbound or gives a `type: regex` pattern that picks a
random matching proxy.
