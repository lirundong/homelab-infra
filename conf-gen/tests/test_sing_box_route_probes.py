from __future__ import annotations

import ipaddress
from typing import Any

import pytest
from _support.sing_box import _dns_branch_probe
from _support.sing_box import _dns_rule_log_pattern
from _support.sing_box import _route_branch_probe
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


def test_route_probe_treats_hijack_dns_as_terminal() -> None:
    route_rules = [
        {
            "action": "hijack-dns",
            "mode": "or",
            "rules": [{"protocol": "dns"}, {"port": 53}],
            "type": "logical",
        },
        {"action": "route", "outbound": "Mainland", "port": [53, 8443]},
    ]

    probe = _route_probe(route_rules[1], route_rules[:1], 1, None)

    assert probe is not None
    assert probe.port == 8443


def test_route_branch_probe_builds_protocol_payloads() -> None:
    rule = {
        "action": "route",
        "outbound": "DIRECT",
        "mode": "or",
        "rules": [
            {"protocol": "bittorrent"},
            {"network": "tcp", "port": 22},
        ],
        "type": "logical",
    }

    bittorrent_probe = _route_branch_probe(rule, 0, [], 0, None)
    ssh_port_probe = _route_branch_probe(rule, 1, [], 0, None)

    assert bittorrent_probe.payload == "bittorrent"
    assert bittorrent_probe.network == "tcp"
    assert ssh_port_probe.port == 22
    assert ssh_port_probe.payload != "bittorrent"


def test_route_branch_probe_builds_udp_payloads() -> None:
    rule = {
        "action": "reject",
        "method": "drop",
        "mode": "or",
        "rules": [
            {"port": 853},
            {"network": "udp", "port": 443},
            {"protocol": "stun"},
        ],
        "type": "logical",
    }

    quic_probe = _route_branch_probe(rule, 1, [], 0, None)
    stun_probe = _route_branch_probe(rule, 2, [], 0, None)

    assert (quic_probe.network, quic_probe.port) == ("udp", 443)
    assert quic_probe.protocol is None
    assert stun_probe.payload == "stun"
    assert stun_probe.port != 853


def test_route_branch_probe_avoids_sibling_matching_candidates() -> None:
    rule = {
        "action": "route",
        "outbound": "Mainland",
        "mode": "or",
        "rules": [
            {"domain_suffix": ["example.com"]},
            {"domain": ["www.example.com", "other.test"]},
        ],
        "type": "logical",
    }

    probe = _route_branch_probe(rule, 1, [], 0, None)

    assert probe.host == "other.test"


def test_dns_branch_probe_isolates_clash_mode_branch() -> None:
    dns_rules = [
        {
            "action": "route",
            "server": "DIRECT",
            "mode": "or",
            "rules": [
                {"clash_mode": "Direct"},
                {"domain_suffix": ["rundong.local"]},
            ],
            "type": "logical",
        }
    ]

    qname, _ = _dns_branch_probe(dns_rules, 0, 0, "Direct")

    assert not qname.endswith(".rundong.local")


def test_dns_branch_probe_avoids_earlier_rule_shadowing() -> None:
    dns_rules: list[dict[str, Any]] = [
        {"action": "route", "server": "FakeIP", "query_type": ["A", "AAAA"]},
        {
            "action": "route",
            "server": "DIRECT",
            "mode": "or",
            "rules": [{"domain_suffix": ["probe.example"]}],
            "type": "logical",
        },
    ]

    _, qtype = _dns_branch_probe(dns_rules, 1, 0, None)

    assert qtype == 16  # TXT dodges the earlier A/AAAA rule.


def test_dns_rule_log_pattern_pins_sing_box_display_index() -> None:
    pattern = _dns_rule_log_pattern(3, {"action": "predefined", "rcode": "NOERROR"})

    assert r"match\[7\]" in pattern
