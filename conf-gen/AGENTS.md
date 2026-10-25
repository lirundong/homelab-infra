# conf-gen

Generate Clash, Quantumult-X, and sing-box configurations from `source.yaml`. Inherit the
repository-root instructions.

## Architecture

Pipeline: `source.yaml → parsers → IR objects → generators → configurations`.

- `proxy/`: Shadowsocks/2022, Trojan, VMess (plain/WebSocket/gRPC), SOCKS5, HTTP, and SSH
  (sing-box only) adapters;
  top-level `proxies` may also hold one-level `type: select` groups of inline proxies
- `proxy_group/`: select/fallback groups and regional merging
- `rule/`: registered IR for user agent, process/package, domain variants, GeoIP/IP CIDR,
  source/destination ports, and match rules
- `generator/`: Clash YAML, Quantumult-X config, and sing-box JSON plus compiled `.srs` rule
  sets; Quantumult-X `rewrites` are inlined with their MITM hostnames merged into `[mitm]`

The CLI is `conf-gen -s/--src <source.yaml> -o/--dst <directory>`. `source.yaml` is the
single source of truth.

Production generation expands secrets into its output. Read
`.ai/skills/secret-handling/SKILL.md` before generating or inspecting those artifacts, and
never surface their plaintext values.

## Extension Conventions

- New proxies subclass `ProxyBase`, implement all three platform methods, and are parsed in
  `proxy/parser.py`.
- New rules subclass `IRBase`, register with `_IR_REGISTRY`, and implement all three backend
  methods.
- New generators subclass `GeneratorBase` and are wired into `generate_conf()`.
- Published `.srs` rule sets are plaintext. Sing-box rules that carry `@secret:` values must set
  `inline: true` to stay in the encrypted `config.json`.
  A space-separated filter list secret expands via `'@secret:KEY!str.split'`.

## Validation

```bash
uv run --extra dev mypy conf-gen/src/conf_gen
uv run conf-gen -s conf-gen/source.yaml -o output/
```

CI requires the CLI to generate all configurations and compiled rule sets successfully.
There is no automated test suite, schema validation, client configuration check, runtime
probe, or secret-leak scan. Keep generated configurations encrypted before uploading them;
do not print or directly inspect their secret values.
