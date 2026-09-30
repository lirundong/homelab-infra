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
    per_region_proxies = merge_proxy_by_region(
        proxies=custom_proxies, proxy_check_url="http://example.test/", region_proxy_type="select"
    )
    return SingBoxGenerator(
        src_file="source.yaml",
        proxies=flatten_proxies(custom_proxies),
        per_region_proxies=per_region_proxies,
        proxy_groups=parse_proxy_groups(rules_info, available_proxies=per_region_proxies),
        dns={"servers": [], "rules": []},
        route={"rules": [], "final": final},
        **kwargs,
    )


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
