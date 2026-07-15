from pathlib import Path

import pytest
import yaml
from _support.clash import ClashConfigChecker


def test_generated_domain_list_rules_pass_dreamacro_clash_check(tmp_path: Path) -> None:
    from conf_gen.generator.clash_generator import ClashGenerator
    from conf_gen.proxy_group.selective_proxy_group import SelectProxyGroup
    from conf_gen.rule.ir import DomainListItem

    group = SelectProxyGroup(name="policy", filters=None, proxies=["DIRECT"])
    group._filters = [
        DomainListItem("example.test"),
        DomainListItem("+.example.test"),
        DomainListItem(".example.test"),
        DomainListItem("*.example.test"),
        DomainListItem("api.*.example.test"),
        DomainListItem("+.stun.*.*"),
        DomainListItem("+.*"),
    ]
    config_path = tmp_path / "clash.yaml"
    generator = ClashGenerator(
        src_file="domain-list-runtime-test",
        proxies=[],
        per_region_proxies=[group],
        proxy_groups=[group],
        **{"mixed-port": 7890, "mode": "rule", "log-level": "silent"},
    )

    with pytest.warns(UserWarning, match="Dreamacro Clash"):
        generator.generate(str(config_path))

    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert all("DOMAIN-REGEX" not in rule for rule in config["rules"])
    with ClashConfigChecker() as checker:
        checker.check(config_path)
