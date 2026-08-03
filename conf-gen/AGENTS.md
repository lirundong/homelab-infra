# conf-gen

Generate Clash, Quantumult-X, and sing-box configurations from `source.yaml`. Inherit the
repository-root instructions.

## Architecture

Pipeline: `source.yaml → parsers → IR objects → generators → configurations`.

- `proxy/`: Shadowsocks/2022, Trojan, VMess (plain/WebSocket/gRPC), and SOCKS5 adapters
- `proxy_group/`: select/fallback groups and regional merging
- `rule/`: registered IR for user agent, process/package, domain variants, GeoIP/IP CIDR,
  source/destination ports, and match rules
- `generator/`: Clash YAML, Quantumult-X config/rewrites, and sing-box JSON plus compiled
  `.srs` rule sets
- `rewrite/`: Quantumult-X URL rewrites

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
- Keep pytest-only helpers under `tests/_support`, not `src/`.

## Validation

```bash
uv run --extra dev pytest conf-gen/tests
uv run --extra dev mypy conf-gen/src/conf_gen
uv run conf-gen -s conf-gen/source.yaml -o output/
```

The tracked test suite covers domain-rule translation, IR deduplication, route/DNS probe
selection, Dreamacro Clash checking, sing-box structure/schema/check behavior, local rule
sets, and source-derived no-TUN runtime behavior. Tests replace the production secret store
with safe fixtures.

Production artifact validation additionally runs:

```bash
uv run --extra dev pytest conf-gen/tests/test_generated_sing_box_artifacts.py \
    --artifact-dir artifacts-conf \
    --check-config sing-box-daemon \
    --check-config sing-box-apple \
    --check-config-android sing-box-clients
```

Android configs may fail only on `override_android_vpn` and must pass after those fields are
removed. The validator handles secret redaction; do not print or directly inspect generated
values. There is no configured line-coverage threshold; behavior and backend coverage are
asserted by focused and runtime tests.
