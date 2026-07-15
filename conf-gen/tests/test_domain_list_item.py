import re

import pytest


def _clash_domain_item_matches(item: str, host: str) -> bool:
    pattern = item.lower().split(".")
    labels = host.lower().split(".")
    first, *remaining = pattern
    if first == "+":
        expected = remaining
        if len(labels) < len(expected):
            return False
    elif first == "":
        expected = remaining
        if len(labels) <= len(expected):
            return False
    else:
        expected = pattern
        if len(labels) != len(expected):
            return False
    return all(
        pattern_label == "*" or pattern_label == label
        for pattern_label, label in zip(expected[::-1], labels[::-1])
    )


def _sing_box_domain_item_matches(item: str, host: str) -> bool:
    from conf_gen.rule.ir import DomainListItem

    matcher, value = DomainListItem(item).sing_box_rule
    if matcher == "domain":
        return host.lower() == value
    if matcher == "domain_suffix":
        return host.lower() == value or host.lower().endswith(f".{value}")
    assert matcher == "domain_regex"
    return re.fullmatch(value, host.lower()) is not None


@pytest.mark.parametrize(
    ("item", "clash_rule", "quantumult_rules", "sing_box_rule"),
    [
        (
            "example.test",
            "DOMAIN,example.test",
            ("host,example.test",),
            ("domain", "example.test"),
        ),
        (
            "EXAMPLE.TEST",
            "DOMAIN,example.test",
            ("host,example.test",),
            ("domain", "example.test"),
        ),
        (
            "+.example.test",
            "DOMAIN-SUFFIX,example.test",
            ("host-suffix,example.test",),
            ("domain_suffix", "example.test"),
        ),
        (
            ".example.test",
            r"DOMAIN-REGEX,^(?:[^.]+\.)+example\.test$",
            ("host-wildcard,*.example.test",),
            ("domain_regex", r"^(?:[^.]+\.)+example\.test$"),
        ),
        (
            "*.example.test",
            r"DOMAIN-REGEX,^[^.]+\.example\.test$",
            ("host-wildcard,*.example.test",),
            ("domain_regex", r"^[^.]+\.example\.test$"),
        ),
        (
            "api.*.example.test",
            r"DOMAIN-REGEX,^api\.[^.]+\.example\.test$",
            ("host-wildcard,api.*.example.test",),
            ("domain_regex", r"^api\.[^.]+\.example\.test$"),
        ),
        (
            "+.stun.*.*",
            r"DOMAIN-REGEX,^(?:[^.]+\.)*stun\.[^.]+\.[^.]+$",
            ("host-wildcard,stun.*.*", "host-wildcard,*.stun.*.*"),
            ("domain_regex", r"^(?:[^.]+\.)*stun\.[^.]+\.[^.]+$"),
        ),
        (
            "+",
            r"DOMAIN-REGEX,^[^.]+(?:\.[^.]+)*$",
            ("host-wildcard,*",),
            ("domain_regex", r"^[^.]+(?:\.[^.]+)*$"),
        ),
        (
            "+.*",
            r"DOMAIN-REGEX,^(?:[^.]+\.)*[^.]+$",
            ("host-wildcard,*",),
            ("domain_regex", r"^(?:[^.]+\.)*[^.]+$"),
        ),
        (
            "foo*bar.example.test",
            "DOMAIN,foo*bar.example.test",
            ("host,foo*bar.example.test",),
            ("domain", "foo*bar.example.test"),
        ),
        (
            "foo+bar.example.test",
            "DOMAIN,foo+bar.example.test",
            ("host,foo+bar.example.test",),
            ("domain", "foo+bar.example.test"),
        ),
        (
            "foo.+.example.test",
            "DOMAIN,foo.+.example.test",
            ("host,foo.+.example.test",),
            ("domain", "foo.+.example.test"),
        ),
    ],
)
def test_domain_list_item_codegen(
    item: str,
    clash_rule: str,
    quantumult_rules: tuple[str, ...],
    sing_box_rule: tuple[str, str],
) -> None:
    from conf_gen.rule.ir import DomainListItem

    rule = DomainListItem(item)

    assert rule.clash_rule == clash_rule
    assert rule.quantumult_rules == quantumult_rules
    assert rule.sing_box_rule == sing_box_rule


@pytest.mark.parametrize(
    ("item", "matches", "does_not_match"),
    [
        (".example.test", "a.b.example.test", "example.test"),
        ("*.example.test", "a.example.test", "a.b.example.test"),
        ("api.*.example.test", "api.v1.example.test", "api.example.test"),
        ("+.stun.*.*", "global.stun.example.com", "stun.example"),
        ("+.*", "example.test", ""),
        ("+", "one.two.example", ""),
    ],
)
def test_domain_list_item_regex_preserves_clash_trie_semantics(
    item: str,
    matches: str,
    does_not_match: str,
) -> None:
    from conf_gen.rule.ir import DomainListItem

    matcher, pattern = DomainListItem(item).sing_box_rule

    assert matcher == "domain_regex"
    assert re.fullmatch(pattern, matches)
    assert not re.fullmatch(pattern, does_not_match)


@pytest.mark.parametrize(
    "item",
    [
        "example.test",
        ".example.test",
        "+.example.test",
        "*.example.test",
        "api.*.example.test",
        ".apple.*",
        "+.stun.*.*",
        "+",
        "+.*",
        "foo*bar.example.test",
        "foo.+.example.test",
    ],
)
def test_sing_box_codegen_matches_clash_trie_reference(item: str) -> None:
    hosts = [
        "example.test",
        "a.example.test",
        "a.b.example.test",
        "api.v1.example.test",
        "api.v1.beta.example.test",
        "apple.com",
        "a.apple.com",
        "global.stun.example.com",
        "stun.example.com",
        "localhost",
        "foo+bar.example.test",
    ]

    for host in hosts:
        assert _sing_box_domain_item_matches(item, host) == _clash_domain_item_matches(item, host)


@pytest.mark.parametrize(
    "item",
    [
        "",
        ".",
        " example.test",
        "example.test ",
        "example.test.",
        "..example.test",
        "+..example.test",
    ],
)
def test_domain_list_item_rejects_invalid_clash_domains(item: str) -> None:
    from conf_gen.rule.ir import DomainListItem

    with pytest.raises(ValueError, match="Invalid Clash domain-list item"):
        DomainListItem(item)


def test_quantumult_codegen_expands_complex_domain_list_items() -> None:
    from conf_gen.proxy_group.selective_proxy_group import SelectProxyGroup
    from conf_gen.rule.ir import DomainListItem

    group = SelectProxyGroup(name="policy", filters=None, proxies=["DIRECT"])
    group._filters = [DomainListItem("+.stun.*.*")]

    assert group.quantumult_filters == (
        ["host-wildcard,stun.*.*,policy", "host-wildcard,*.stun.*.*,policy"],
        [],
    )
