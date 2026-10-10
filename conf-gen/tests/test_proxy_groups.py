from __future__ import annotations

from typing import TYPE_CHECKING
from typing import Any

import pytest

if TYPE_CHECKING:
    from conf_gen.generator.sing_box_generator import SingBoxGenerator


def _http_info(name: str, **extra: Any) -> dict[str, Any]:
    return {"name": name, "type": "http", "server": "192.0.2.1", "port": 8080, **extra}


def _ss_info(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "type": "ss",
        "server": "192.0.2.2",
        "port": 8388,
        "cipher": "aes-128-gcm",
        "password": "synthetic-password",
    }


def _sing_box_generator(
    proxies_info: list[dict[str, Any]],
    rules_info: list[dict[str, Any]],
    final: str,
    **kwargs: Any,
) -> SingBoxGenerator:
    from conf_gen.generator.sing_box_generator import SingBoxGenerator
    from conf_gen.proxy import flatten_proxies
    from conf_gen.proxy import parse_clash_proxies
    from conf_gen.proxy_group import merge_proxy_by_region
    from conf_gen.proxy_group import parse_proxy_groups

    custom_proxies = parse_clash_proxies(proxies_info)
    proxies_without_region, per_region_proxies = merge_proxy_by_region(
        proxies=custom_proxies, proxy_check_url="http://example.test/", region_proxy_type="select"
    )
    return SingBoxGenerator(
        src_file="source.yaml",
        proxies=flatten_proxies(custom_proxies),
        per_region_proxies=per_region_proxies,
        proxy_groups=parse_proxy_groups(
            rules_info, available_proxies=[*proxies_without_region, *per_region_proxies]
        ),
        dns={"servers": [], "rules": []},
        route={"rules": [], "final": final},
        proxies_without_region=proxies_without_region,
        **kwargs,
    )


def _merged(proxies_info: list[dict[str, Any]]) -> tuple[Any, Any, Any]:
    from conf_gen.proxy import flatten_proxies
    from conf_gen.proxy import parse_clash_proxies
    from conf_gen.proxy_group import merge_proxy_by_region
    from conf_gen.proxy_group import parse_proxy_groups

    custom_proxies = parse_clash_proxies(proxies_info)
    proxies_without_region, per_region_proxies = merge_proxy_by_region(
        proxies=custom_proxies, proxy_check_url="http://example.test/", region_proxy_type="select"
    )
    return flatten_proxies(custom_proxies), proxies_without_region, per_region_proxies


_STATIC_OUTBOUNDS = [
    {"tag": "VPN", "type": "direct"},
    {"tag": "Direct", "type": "direct", "bind_interface": "eth0"},
]


def test_select_proxy_group_keeps_members_in_order() -> None:
    from conf_gen.proxy import HttpProxy
    from conf_gen.proxy import flatten_proxies
    from conf_gen.proxy import parse_clash_proxies
    from conf_gen.proxy_group.selective_proxy_group import SelectProxyGroup

    parsed = parse_clash_proxies(
        [
            {"name": "Pool", "type": "select", "proxies": [_http_info("b"), _http_info("a")]},
            _ss_info("standalone"),
        ]
    )
    group = parsed[0]
    assert isinstance(group, SelectProxyGroup)
    assert group._proxies == ["b", "a"]
    assert group.sing_box_outbound["outbounds"] == ["b", "a"]
    leaves = flatten_proxies(parsed)
    assert [p.name for p in leaves] == ["b", "a", "standalone"]
    assert isinstance(leaves[0], HttpProxy)


@pytest.mark.parametrize(
    "proxies_info",
    [
        [{"name": "Outer", "type": "select", "proxies": [{"name": "Inner", "type": "select"}]}],
        [{"name": "Empty", "type": "select", "proxies": []}],
        [_http_info("udp", udp=True)],
        [_http_info("half-auth", username="user")],
    ],
)
def test_invalid_proxy_specs_are_rejected(proxies_info: list[dict[str, Any]]) -> None:
    from conf_gen.proxy import parse_clash_proxies

    with pytest.raises((ValueError, KeyError)):
        parse_clash_proxies(proxies_info)


def test_http_proxy_backends() -> None:
    from conf_gen.proxy import parse_clash_proxies

    plain, secured = parse_clash_proxies(
        [
            _http_info("plain"),
            _http_info(
                "secured",
                username="user",
                password="pass",
                tls=True,
                sni="proxy.example.test",
                **{"skip-cert-verify": True},
            ),
        ]
    )
    assert plain.sing_box_proxy == {
        "type": "http",
        "tag": "plain",
        "server": "192.0.2.1",
        "server_port": 8080,
    }
    assert plain.clash_proxy == {
        "name": "plain",
        "type": "http",
        "server": "192.0.2.1",
        "port": 8080,
    }
    assert plain.quantumult_proxy == "http=192.0.2.1:8080,tag=plain"
    assert secured.sing_box_proxy == {
        "type": "http",
        "tag": "secured",
        "server": "192.0.2.1",
        "server_port": 8080,
        "username": "user",
        "password": "pass",
        "tls": {"enabled": True, "insecure": True, "server_name": "proxy.example.test"},
    }
    assert secured.clash_proxy == {
        "name": "secured",
        "type": "http",
        "server": "192.0.2.1",
        "port": 8080,
        "username": "user",
        "password": "pass",
        "tls": True,
        "skip-cert-verify": True,
        "sni": "proxy.example.test",
    }
    assert secured.quantumult_proxy == (
        "http=192.0.2.1:8080,tag=secured,username=user,password=pass,"
        "over-tls=true,tls-verification=false,tls-host=proxy.example.test"
    )


def test_http_proxy_path_and_headers() -> None:
    from conf_gen.proxy import parse_clash_proxies

    headers = {"X-Token": "synthetic"}
    with_headers, with_path = parse_clash_proxies(
        [
            _http_info("with-headers", headers=headers),
            _http_info("with-path", path="/connect", headers=headers),
        ]
    )
    assert with_headers.sing_box_proxy["headers"] == headers
    assert "path" not in with_headers.sing_box_proxy
    assert with_headers.clash_proxy["headers"] == headers
    assert with_path.sing_box_proxy["path"] == "/connect"
    assert with_path.sing_box_proxy["headers"] == headers
    # Clash has no HTTP proxy path, and Quantumult X has neither option.
    with pytest.raises(ValueError, match="not supported by clash"):
        with_path.clash_proxy
    for proxy in (with_headers, with_path):
        with pytest.raises(ValueError, match="not supported by quantumult x"):
            proxy.quantumult_proxy


def test_static_outbounds_replace_default_direct() -> None:
    generator = _sing_box_generator(
        proxies_info=[{"name": "Pool", "type": "select", "proxies": [_http_info("p1")]}],
        rules_info=[
            {"name": "Relay", "type": "select", "filters": [], "proxies": ["Direct", "Pool"]},
            {
                "name": "Final",
                "type": "select",
                "filters": [{"type": "match"}],
                "proxies": ["VPN", "Direct"],
            },
        ],
        final="Final",
        outbounds=_STATIC_OUTBOUNDS,
        dial_fields={"proxy": {"detour": "Relay"}},
    )
    outbounds = {o["tag"]: o for o in generator.outbounds}
    # A single per-region entry needs no PROXY selector, and DIRECT is not implied.
    assert "PROXY" not in outbounds
    assert "DIRECT" not in outbounds
    assert outbounds["Relay"]["outbounds"] == ["Direct", "Pool"]
    assert outbounds["Final"]["outbounds"] == ["VPN", "Direct"]
    assert outbounds["Pool"]["outbounds"] == ["p1"]
    assert outbounds["p1"]["detour"] == "Relay"
    assert outbounds["Direct"] == _STATIC_OUTBOUNDS[1]
    assert [o["tag"] for o in generator.outbounds][-2:] == ["VPN", "Direct"]


def test_default_direct_and_proxy_group_with_multiple_regions() -> None:
    generator = _sing_box_generator(
        proxies_info=[_ss_info("🇯🇵 Tokyo"), _ss_info("🇸🇬 Singapore")],
        rules_info=[],
        final="PROXY",
        dial_fields={"direct": {"bind_interface": "eth0"}, "proxy": {}},
    )
    outbounds = {o["tag"]: o for o in generator.outbounds}
    assert outbounds["DIRECT"] == {"tag": "DIRECT", "type": "direct", "bind_interface": "eth0"}
    assert outbounds["PROXY"]["outbounds"] == ["🇯🇵 Tokyo", "🇸🇬 Singapore"]


def test_direct_dial_fields_conflict_with_static_outbounds() -> None:
    with pytest.raises(ValueError, match="dial_fields.direct"):
        _sing_box_generator(
            proxies_info=[{"name": "Pool", "type": "select", "proxies": [_http_info("p1")]}],
            rules_info=[],
            final="Direct",
            outbounds=_STATIC_OUTBOUNDS,
            dial_fields={"direct": {"bind_interface": "eth0"}, "proxy": {}},
        )


@pytest.mark.parametrize(
    ("proxies", "final"),
    [(["DIRECT"], "Direct"), (["Direct", "PROXY"], "Direct"), (["Direct"], "PROXY")],
)
def test_undefined_outbound_references_are_rejected(proxies: list[str], final: str) -> None:
    with pytest.raises(ValueError, match="no available members|undefined|final"):
        _sing_box_generator(
            proxies_info=[{"name": "Pool", "type": "select", "proxies": [_http_info("p1")]}],
            rules_info=[{"name": "Group", "type": "select", "filters": [], "proxies": proxies}],
            final=final,
            outbounds=_STATIC_OUTBOUNDS,
        )


def test_ruleset_download_detour_resolution() -> None:
    generator = _sing_box_generator(
        proxies_info=[_ss_info("🇭🇰 HK-01"), _ss_info("🇭🇰 HK-02"), _ss_info("🇯🇵 JP-01")],
        rules_info=[],
        final="PROXY",
    )
    generator.ruleset_download_detour = {"type": "regex", "pattern": "HK"}
    assert {generator._resolve_ruleset_download_detour() for _ in range(64)} == {
        "🇭🇰 HK-01",
        "🇭🇰 HK-02",
    }
    generator.ruleset_download_detour = "PROXY"
    assert generator._resolve_ruleset_download_detour() == "PROXY"
    for invalid in ("Missing", {"type": "regex", "pattern": "US"}, None):
        generator.ruleset_download_detour = invalid
        with pytest.raises(ValueError):
            generator._resolve_ruleset_download_detour()


_POOL_A = {"name": "Pool A", "type": "select", "proxies": [_http_info("a1")]}
_POOL_B = {"name": "Pool B", "type": "select", "proxies": [_http_info("b1")]}


def test_merge_proxy_by_region_separates_pre_grouped_proxies() -> None:
    _, without_region, per_region = _merged([_POOL_A, _ss_info("🇯🇵 Tokyo"), _ss_info("🇸🇬 SG")])
    assert [g.name for g in without_region] == ["Pool A"]
    assert [p.name for p in per_region] == ["🇯🇵 Tokyo", "🇸🇬 SG"]
    _, without_region, per_region = _merged([_POOL_A, _POOL_B])
    assert [g.name for g in without_region] == ["Pool A", "Pool B"]
    assert per_region == []


def test_sing_box_has_no_proxy_group_without_region_entries() -> None:
    generator = _sing_box_generator(
        proxies_info=[_POOL_A, _POOL_B],
        rules_info=[
            {"name": "Final", "type": "select", "filters": [], "proxies": ["Pool A", "Pool B"]}
        ],
        final="Final",
        outbounds=_STATIC_OUTBOUNDS,
    )
    outbounds = {o["tag"]: o for o in generator.outbounds}
    assert "PROXY" not in outbounds
    assert outbounds["Pool A"]["outbounds"] == ["a1"]
    assert outbounds["Pool B"]["outbounds"] == ["b1"]
    assert outbounds["Final"]["outbounds"] == ["Pool A", "Pool B"]


def test_sing_box_proxy_group_selects_pre_grouped_and_region_entries() -> None:
    generator = _sing_box_generator(
        proxies_info=[_POOL_A, _ss_info("🇯🇵 Tokyo"), _ss_info("🇸🇬 Singapore")],
        rules_info=[],
        final="PROXY",
    )
    outbounds = {o["tag"]: o for o in generator.outbounds}
    assert outbounds["PROXY"]["outbounds"] == ["Pool A", "🇯🇵 Tokyo", "🇸🇬 Singapore"]


def test_sing_box_proxy_group_needs_more_than_one_choice() -> None:
    generator = _sing_box_generator(
        proxies_info=[_ss_info("🇯🇵 Tokyo")],
        rules_info=[],
        final="🇯🇵 Tokyo",
    )
    assert "PROXY" not in {o["tag"] for o in generator.outbounds}


def _clash_group_names(
    proxies: Any, without_region: Any, per_region: Any, rules_info: list[dict[str, Any]]
) -> dict[str, list[str]]:
    from conf_gen.generator.clash_generator import ClashGenerator
    from conf_gen.proxy_group import parse_proxy_groups

    generator = ClashGenerator(
        src_file="source.yaml",
        proxies=proxies,
        per_region_proxies=per_region,
        proxy_groups=parse_proxy_groups(
            rules_info, available_proxies=[*without_region, *per_region]
        ),
        proxies_without_region=without_region,
    )
    return {g.name: g._proxies for g in generator._proxy_groups}


def test_clash_proxy_group_requires_region_entries() -> None:
    groups = _clash_group_names(*_merged([_POOL_A, _POOL_B]), rules_info=[])
    assert sorted(groups) == ["Pool A", "Pool B"]
    groups = _clash_group_names(
        *_merged([_POOL_A, _ss_info("🇯🇵 Tokyo"), _ss_info("🇸🇬 SG")]), rules_info=[]
    )
    assert groups["PROXY"] == sorted(["Pool A", "🇯🇵 Tokyo", "🇸🇬 SG"])


def _quantumult_group_proxies(
    proxies: Any, without_region: Any, per_region: Any
) -> dict[str, list[str]]:
    from conf_gen.generator.quantumult_generator import QuantumultGenerator
    from conf_gen.proxy_group import parse_proxy_groups

    rules_info = [{"name": "Rule", "type": "select", "filters": [], "proxies": ["PROXY"]}]
    generator = QuantumultGenerator(
        src_file="source.yaml",
        proxies=proxies,
        per_region_proxies=per_region,
        proxy_groups=parse_proxy_groups(
            rules_info, available_proxies=[*without_region, *per_region]
        ),
        proxies_without_region=without_region,
    )
    return {g.name: g._proxies for g in generator._proxy_groups}


def test_quantumult_keeps_builtin_proxy_group_without_region_entries() -> None:
    groups = _quantumult_group_proxies(*_merged([_POOL_A, _POOL_B]))
    assert "PROXY-PER-REGION" not in groups
    assert groups["Rule"] == ["PROXY"]
    groups = _quantumult_group_proxies(
        *_merged([_POOL_A, _ss_info("🇯🇵 Tokyo"), _ss_info("🇸🇬 SG")])
    )
    assert groups["PROXY-PER-REGION"] == sorted(["Pool A", "🇯🇵 Tokyo", "🇸🇬 SG"])
    assert groups["Rule"] == ["PROXY-PER-REGION"]
