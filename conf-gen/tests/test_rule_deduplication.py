from __future__ import annotations

from pathlib import Path
from typing import Any
from typing import TYPE_CHECKING
from typing import Sequence

import yaml

if TYPE_CHECKING:
    from _support.sing_box import SourceContext
    from conf_gen.proxy_group.selective_proxy_group import SelectProxyGroup


def _proxy_groups() -> list[SelectProxyGroup]:
    from conf_gen.proxy_group.selective_proxy_group import SelectProxyGroup

    return [
        SelectProxyGroup(
            name="first",
            filters=[
                {"type": "domain", "args": ["example.test"]},
                {"type": "ip-cidr", "args": ["192.0.2.0/24", "resolve"]},
            ],
            proxies=["DIRECT"],
        ),
        SelectProxyGroup(
            name="later",
            filters=[
                {"type": "domain", "args": ["example.test"]},
                {"type": "ip-cidr", "args": ["192.0.2.0/24", "no-resolve"]},
            ],
            proxies=["DIRECT"],
        ),
    ]


def _legacy_deduplicate_rules(rules: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    deduplicated: list[str] = []
    for rule in rules:
        matcher = ",".join(rule.split(",")[:2])
        if matcher in seen:
            continue
        seen.add(matcher)
        deduplicated.append(rule)
    return deduplicated


def _legacy_clash_rules(proxy_groups: Sequence[Any]) -> list[str]:
    no_resolve_rules: list[str] = []
    resolve_rules: list[str] = []
    for proxy_group in proxy_groups:
        no_resolve, resolve = proxy_group.clash_rules
        no_resolve_rules += no_resolve
        resolve_rules += resolve
    return _legacy_deduplicate_rules(no_resolve_rules + resolve_rules)


def _legacy_quantumult_rules(proxy_groups: Sequence[Any]) -> list[str]:
    seen: set[str] = set()
    retained_by_phase: tuple[list[str], list[str]] = ([], [])
    for proxy_group in proxy_groups:
        for retained, rules in zip(retained_by_phase, proxy_group.quantumult_filters):
            for rule in rules:
                matcher = ",".join(rule.split(",")[:2])
                if matcher not in seen:
                    seen.add(matcher)
                    retained.append(rule)
    no_resolve_rules, resolve_rules = retained_by_phase
    return no_resolve_rules + resolve_rules


def _quantumult_filter_lines(config: str) -> list[str]:
    section = config.split("[filter_local]\n", 1)[1].split("\n[", 1)[0]
    return [line for line in section.splitlines() if line]


def test_generators_deduplicate_irs_using_backend_rule_precedence(tmp_path: Path) -> None:
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
        "IP-CIDR,192.0.2.0/24,later,no-resolve",
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

    quantumult_rules = _quantumult_filter_lines(quantumult_path.read_text(encoding="utf-8"))
    assert quantumult_rules == [
        "host,example.test,first",
        "ip-cidr,192.0.2.0/24,first",
    ]


def test_source_generated_routing_matches_legacy_post_codegen_deduplication(
    source_context: SourceContext,
    tmp_path: Path,
) -> None:
    from conf_gen.generator.clash_generator import ClashGenerator
    from conf_gen.generator.quantumult_generator import QuantumultGenerator

    clash_path = tmp_path / "source-clash.yaml"
    ClashGenerator(
        src_file="source.yaml",
        proxies=source_context.proxies,
        per_region_proxies=source_context.per_region_proxies,
        proxy_groups=source_context.proxy_groups,
    ).generate(str(clash_path))
    clash_config = yaml.safe_load(clash_path.read_text(encoding="utf-8"))
    legacy_clash_rules = _legacy_clash_rules(source_context.proxy_groups)
    assert _legacy_deduplicate_rules(clash_config["rules"]) == legacy_clash_rules

    quantumult_path = tmp_path / "source-quantumult.conf"
    QuantumultGenerator(
        src_file="source.yaml",
        proxies=source_context.proxies,
        per_region_proxies=source_context.per_region_proxies,
        proxy_groups=source_context.proxy_groups,
        rewrites=[],
    ).generate(str(quantumult_path))
    quantumult_rules = _quantumult_filter_lines(quantumult_path.read_text(encoding="utf-8"))
    legacy_quantumult_rules = _legacy_quantumult_rules(source_context.proxy_groups)
    assert quantumult_rules == legacy_quantumult_rules


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


def test_ir_equality_uses_concrete_matcher_identity() -> None:
    from conf_gen.rule.ir import Domain
    from conf_gen.rule.ir import DomainListItem
    from conf_gen.rule.ir import DomainSuffix
    from conf_gen.rule.ir import IPCIDR
    from conf_gen.rule.utils import deduplicate_rule_irs

    no_resolve = IPCIDR("192.0.2.0/24", resolve=False)
    resolve = IPCIDR("192.0.2.0/24", resolve=True)
    assert Domain("example.test") == DomainListItem("example.test")
    assert DomainListItem("+.example.test") == DomainSuffix("example.test")
    assert DomainListItem("*.example.test") != DomainSuffix("example.test")
    assert DomainListItem("..example.test") != Domain("example.test")
    assert DomainListItem("+..example.test") != DomainSuffix("example.test")
    assert no_resolve == resolve
    assert hash(no_resolve) == hash(resolve)


def test_deduplication_keeps_distinct_classes_and_honors_priority() -> None:
    from conf_gen.rule.ir import Domain
    from conf_gen.rule.ir import DomainListItem
    from conf_gen.rule.ir import IPCIDR
    from conf_gen.rule.utils import deduplicate_rule_irs

    resolve = IPCIDR("192.0.2.0/24", resolve=True)
    no_resolve = IPCIDR("192.0.2.0/24", resolve=False)
    deduplicated = deduplicate_rule_irs(
        [
            [Domain("example.test"), resolve],
            [DomainListItem("example.test"), no_resolve],
        ],
        priority=lambda group_index, rule_ir: (int(bool(rule_ir._resolve)),),
    )

    assert deduplicated == [
        [Domain("example.test")],
        [no_resolve],
    ]


def test_deduplication_keeps_only_the_first_equivalent_ir() -> None:
    from conf_gen.rule.ir import Domain
    from conf_gen.rule.utils import deduplicate_rule_irs

    rule = Domain("example.test")

    assert deduplicate_rule_irs([[rule, rule], [Domain("example.test")]]) == [[rule], []]
