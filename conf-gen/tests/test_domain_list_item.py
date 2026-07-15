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

    ((matcher, value),) = DomainListItem(item).sing_box_rules
    if matcher == "domain":
        return host.lower() == value
    if matcher == "domain_suffix":
        return host.lower() == value or host.lower().endswith(f".{value}")
    assert matcher == "domain_regex"
    return re.fullmatch(value, host.lower()) is not None


@pytest.mark.parametrize(
    ("item", "clash_rules", "quantumult_rules", "sing_box_rules", "lossy"),
    [
        (
            "example.test",
            ("DOMAIN,example.test",),
            ("host,example.test",),
            (("domain", "example.test"),),
            False,
        ),
        (
            "EXAMPLE.TEST",
            ("DOMAIN,example.test",),
            ("host,example.test",),
            (("domain", "example.test"),),
            False,
        ),
        (
            "+.example.test",
            ("DOMAIN-SUFFIX,example.test",),
            ("host-suffix,example.test",),
            (("domain_suffix", "example.test"),),
            False,
        ),
        (
            ".example.test",
            ("DOMAIN-SUFFIX,example.test",),
            ("host-wildcard,*.example.test",),
            (("domain_regex", r"^(?:[^.]+\.)+example\.test$"),),
            True,
        ),
        (
            "*.example.test",
            ("DOMAIN-SUFFIX,example.test",),
            ("host-wildcard,*.example.test",),
            (("domain_regex", r"^[^.]+\.example\.test$"),),
            True,
        ),
        (
            "api.*.example.test",
            ("DOMAIN-SUFFIX,example.test",),
            ("host-wildcard,api.*.example.test",),
            (("domain_regex", r"^api\.[^.]+\.example\.test$"),),
            True,
        ),
        (
            "+.stun.*.*",
            ("DOMAIN-KEYWORD,stun",),
            ("host-wildcard,stun.*.*", "host-wildcard,*.stun.*.*"),
            (("domain_regex", r"^(?:[^.]+\.)*stun\.[^.]+\.[^.]+$"),),
            True,
        ),
        (
            ".apple.*",
            ("DOMAIN-KEYWORD,apple",),
            ("host-wildcard,*.apple.*",),
            (("domain_regex", r"^(?:[^.]+\.)+apple\.[^.]+$"),),
            True,
        ),
        (
            "+",
            ("MATCH",),
            ("host-wildcard,*",),
            (("domain_regex", r"^[^.]+(?:\.[^.]+)*$"),),
            True,
        ),
        (
            "+.*",
            ("MATCH",),
            ("host-wildcard,*",),
            (("domain_regex", r"^(?:[^.]+\.)*[^.]+$"),),
            True,
        ),
        (
            "foo*bar.example.test",
            ("DOMAIN,foo*bar.example.test",),
            ("host,foo*bar.example.test",),
            (("domain", "foo*bar.example.test"),),
            False,
        ),
        (
            "foo+bar.example.test",
            ("DOMAIN,foo+bar.example.test",),
            ("host,foo+bar.example.test",),
            (("domain", "foo+bar.example.test"),),
            False,
        ),
        (
            "foo.+.example.test",
            ("DOMAIN,foo.+.example.test",),
            ("host,foo.+.example.test",),
            (("domain", "foo.+.example.test"),),
            False,
        ),
    ],
)
def test_domain_list_item_codegen(
    item: str,
    clash_rules: tuple[str, ...],
    quantumult_rules: tuple[str, ...],
    sing_box_rules: tuple[tuple[str, str], ...],
    lossy: bool,
) -> None:
    from conf_gen.rule.ir import DomainListItem

    rule = DomainListItem(item)

    if lossy:
        with pytest.warns(UserWarning, match="Dreamacro Clash"):
            assert rule.clash_rules == clash_rules
        with pytest.warns(UserWarning, match="Quantumult-X"):
            assert rule.quantumult_rules == quantumult_rules
    else:
        assert rule.clash_rules == clash_rules
        assert rule.quantumult_rules == quantumult_rules
    assert rule.sing_box_rules == sing_box_rules


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

    ((matcher, pattern),) = DomainListItem(item).sing_box_rules

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

    with pytest.warns(UserWarning, match="Quantumult-X"):
        assert group.quantumult_filters == (
            ["host-wildcard,stun.*.*,policy", "host-wildcard,*.stun.*.*,policy"],
            [],
        )


def test_clash_codegen_accepts_multiple_rules_from_one_ir() -> None:
    from conf_gen.proxy_group.selective_proxy_group import SelectProxyGroup
    from conf_gen.rule._base_ir import IRBase

    class MultiRule(IRBase):
        @property
        def clash_rules(self) -> tuple[str, ...]:
            return "DOMAIN,one.example", "DOMAIN,two.example"

    group = SelectProxyGroup(name="policy", filters=None, proxies=["DIRECT"])
    group._filters = [MultiRule("unused")]

    assert group.clash_rules == (
        ["DOMAIN,one.example,policy", "DOMAIN,two.example,policy"],
        [],
    )


def test_lossy_codegen_warns_with_input_backend_and_approximation() -> None:
    from conf_gen.rule.ir import DomainListItem

    rule = DomainListItem("api.*.example.test")

    with pytest.warns(
        UserWarning,
        match=(r"'api\.\*\.example\.test'.*Dreamacro Clash.*" r"DOMAIN-SUFFIX,example\.test"),
    ):
        assert rule.clash_rules == ("DOMAIN-SUFFIX,example.test",)


def test_dreamacro_clash_codegen_uses_only_supported_domain_rules() -> None:
    from conf_gen.rule.ir import DomainListItem

    items = (".example.test", "*.example.test", "api.*.example.test", "+.stun.*.*")

    with pytest.warns(UserWarning):
        rules = tuple(rule for item in items for rule in DomainListItem(item).clash_rules)

    assert all(not rule.startswith(("DOMAIN-REGEX,", "DOMAIN-WILDCARD,")) for rule in rules)
