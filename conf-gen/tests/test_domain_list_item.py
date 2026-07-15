import pytest


@pytest.mark.parametrize(
    ("item", "clash_rule", "quantumult_rule", "sing_box_rule"),
    [
        (
            "example.test",
            "DOMAIN,example.test",
            "host,example.test",
            ("domain", "example.test"),
        ),
        (
            "+.example.test",
            "DOMAIN-SUFFIX,example.test",
            "host-suffix,example.test",
            ("domain_suffix", "example.test"),
        ),
    ],
)
def test_domain_list_item_codegen(
    item: str,
    clash_rule: str,
    quantumult_rule: str,
    sing_box_rule: tuple[str, str],
) -> None:
    from conf_gen.rule.ir import DomainListItem

    rule = DomainListItem(item)

    assert rule.clash_rule == clash_rule
    assert rule.quantumult_rule == quantumult_rule
    assert rule.sing_box_rule == sing_box_rule


@pytest.mark.parametrize(
    "item",
    [
        "",
        ".example.test",
        "*.example.test",
        "sub.*.example.test",
        "+example.test",
        "+..example.test",
        "sub+example.test",
    ],
)
def test_domain_list_item_rejects_lossy_cross_backend_patterns(item: str) -> None:
    from conf_gen.rule.ir import DomainListItem

    with pytest.raises(ValueError, match="is not an exact domain or \\+\\. domain suffix"):
        DomainListItem(item)
