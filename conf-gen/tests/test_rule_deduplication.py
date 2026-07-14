from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from conf_gen.proxy_group.selective_proxy_group import SelectProxyGroup


def _proxy_groups() -> list[SelectProxyGroup]:
    from conf_gen.proxy_group.selective_proxy_group import SelectProxyGroup

    return [
        SelectProxyGroup(
            name="first",
            filters=[
                {"type": "domain", "args": ["example.test"]},
                {"type": "ip-cidr", "args": ["192.0.2.0/24", "no-resolve"]},
            ],
            proxies=["DIRECT"],
        ),
        SelectProxyGroup(
            name="later",
            filters=[
                {"type": "domain", "args": ["example.test"]},
                {"type": "ip-cidr", "args": ["192.0.2.0/24", "resolve"]},
            ],
            proxies=["DIRECT"],
        ),
    ]


def test_generators_deduplicate_irs_and_keep_distinct_resolve_states(tmp_path: Path) -> None:
    from conf_gen.generator.clash_generator import ClashGenerator
    from conf_gen.generator.quantumult_generator import QuantumultGenerator

    clash_path = tmp_path / "clash.yaml"
    clash = ClashGenerator(
        src_file="source.yaml",
        proxies=[],
        per_region_proxies=[],
        proxy_groups=_proxy_groups(),
    )
    clash.generate(str(clash_path))

    clash_config = yaml.safe_load(clash_path.read_text(encoding="utf-8"))
    assert clash_config["rules"] == [
        "DOMAIN,example.test,first",
        "IP-CIDR,192.0.2.0/24,first,no-resolve",
        "IP-CIDR,192.0.2.0/24,later",
    ]

    quantumult_path = tmp_path / "quantumult.conf"
    quantumult = QuantumultGenerator(
        src_file="source.yaml",
        proxies=[],
        per_region_proxies=[],
        proxy_groups=_proxy_groups(),
        rewrites=[],
    )
    quantumult.generate(str(quantumult_path))

    quantumult_config = quantumult_path.read_text(encoding="utf-8")
    assert "host,example.test,first\n" in quantumult_config
    assert "host,example.test,later\n" not in quantumult_config
    assert "ip-cidr,192.0.2.0/24,first,no-resolve\n" in quantumult_config
    assert "ip-cidr,192.0.2.0/24,later\n" in quantumult_config


def test_sing_box_expansion_deduplicates_rule_irs() -> None:
    from conf_gen.generator.sing_box_generator import expand_filters_inplace

    rule = {
        "filters": [
            {"type": "domain", "args": ["example.test"]},
            {"type": "domain", "args": ["example.test"]},
        ]
    }

    expand_filters_inplace(rule)

    assert rule == {"domain": ["example.test"]}


def test_deduplication_keeps_distinct_ir_classes_and_resolve_states() -> None:
    from conf_gen.rule.ir import Domain
    from conf_gen.rule.ir import DomainListItem
    from conf_gen.rule.ir import IPCIDR
    from conf_gen.rule.utils import deduplicate_rule_irs

    no_resolve = IPCIDR("192.0.2.0/24", resolve=False)
    resolve = IPCIDR("192.0.2.0/24", resolve=True)
    deduplicated = deduplicate_rule_irs(
        [
            [Domain("example.test"), no_resolve],
            [DomainListItem("example.test"), resolve],
        ]
    )

    assert deduplicated == [
        [Domain("example.test"), no_resolve],
        [DomainListItem("example.test"), resolve],
    ]


def test_deduplication_keeps_only_the_first_equivalent_ir() -> None:
    from conf_gen.rule.ir import Domain
    from conf_gen.rule.utils import deduplicate_rule_irs

    rule = Domain("example.test")

    assert deduplicate_rule_irs([[rule, rule], [Domain("example.test")]]) == [[rule], []]
