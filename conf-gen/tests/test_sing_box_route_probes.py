from __future__ import annotations

import ipaddress

import pytest
from _support.sing_box import _route_probe


def test_route_probe_skips_a_host_shadowed_by_an_earlier_rule() -> None:
    route_rules = [
        {"action": "route", "outbound": "Bilibili", "domain_suffix": ["acg.tv"]},
        {"action": "route", "outbound": "Mainland", "domain": ["acg.tv", "baidu.com"]},
    ]

    probe = _route_probe(route_rules[1], route_rules[:1], 1, None)

    assert probe is not None
    assert probe.host == "baidu.com"


def test_route_probe_selection_is_deterministic() -> None:
    route_rules = [
        {
            "action": "route",
            "outbound": "Mainland",
            "domain": ["baidu.com", "qq.com", "taobao.com"],
        }
    ]

    first_probe = _route_probe(route_rules[0], [], 0, None)
    second_probe = _route_probe(route_rules[0], [], 0, None)

    assert first_probe == second_probe


def test_route_probe_combines_domain_and_port_matchers() -> None:
    route_rules = [
        {"action": "route", "outbound": "Mainland", "domain": ["baidu.com"], "port": [443]}
    ]

    probe = _route_probe(route_rules[0], [], 0, None)

    assert probe is not None
    assert probe.host == "baidu.com"
    assert probe.port == 443


def test_route_probe_uses_an_unshadowed_cidr_representative() -> None:
    route_rules = [
        {"action": "route", "outbound": "Earlier", "ip_cidr": ["10.0.0.0/31"]},
        {"action": "route", "outbound": "Mainland", "ip_cidr": ["10.0.0.0/24"]},
    ]

    probe = _route_probe(route_rules[1], route_rules[:1], 1, None)

    assert probe is not None
    assert ipaddress.ip_address(probe.host) in ipaddress.ip_network("10.0.0.0/24")
    assert ipaddress.ip_address(probe.host) not in ipaddress.ip_network("10.0.0.0/31")


def test_route_probe_combines_logical_matchers() -> None:
    route_rules = [
        {
            "action": "route",
            "outbound": "Mainland",
            "mode": "and",
            "rules": [
                {"clash_mode": "Rule"},
                {"domain_suffix": ["baidu.com"]},
            ],
            "type": "logical",
        }
    ]

    probe = _route_probe(route_rules[0], [], 0, "Rule")

    assert probe is not None
    assert probe.host.endswith(".baidu.com")
    assert probe.clash_mode == "Rule"


def test_route_probe_satisfies_an_inverted_matcher() -> None:
    route_rules = [
        {
            "action": "route",
            "outbound": "Mainland",
            "domain_suffix": ["blocked.example"],
            "invert": True,
        }
    ]

    probe = _route_probe(route_rules[0], [], 0, None)

    assert probe is not None
    assert not probe.host.endswith(".blocked.example")


def test_route_probe_fails_when_all_candidates_are_shadowed() -> None:
    route_rules = [
        {"action": "route", "outbound": "Bilibili", "domain_suffix": ["acg.tv"]},
        {"action": "route", "outbound": "Mainland", "domain": ["acg.tv"]},
    ]

    with pytest.raises(AssertionError, match=r"route rule 1.*\[0\]"):
        _route_probe(route_rules[1], route_rules[:1], 1, None)
