from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from _support.sing_box import load_config
from _support.sing_box import rule_set_compiler
from _support.sing_box import run_sing_box_check


def _ssh_info(name: str, **extra: Any) -> dict[str, Any]:
    return {
        "name": name,
        "type": "ssh",
        "server": "192.0.2.3",
        "port": 22,
        "username": "user",
        **extra,
    }


def _synthetic_private_key() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return (
        Ed25519PrivateKey.generate()
        .private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        .decode()
    )


def _synthetic_host_key() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        .decode()
    )


_HOST_KEY = _synthetic_host_key()


def test_ssh_proxy_sing_box_fields() -> None:
    from conf_gen.proxy import SshProxy
    from conf_gen.proxy import parse_clash_proxies

    private_key = _synthetic_private_key()
    by_password, by_inline_key, by_key_path = parse_clash_proxies(
        [
            _ssh_info("by-password", password="pass"),
            _ssh_info(
                "by-inline-key",
                **{
                    "private-key": private_key,
                    "private-key-passphrase": "phrase",
                    "host-key": [_HOST_KEY],
                    "host-key-algorithms": ["ssh-ed25519"],
                },
            ),
            _ssh_info("by-key-path", **{"private-key": "keys/id_ed25519"}),
        ]
    )
    assert isinstance(by_password, SshProxy)
    assert by_password.sing_box_proxy == {
        "type": "ssh",
        "tag": "by-password",
        "server": "192.0.2.3",
        "server_port": 22,
        "user": "user",
        "password": "pass",
    }
    assert by_inline_key.sing_box_proxy == {
        "type": "ssh",
        "tag": "by-inline-key",
        "server": "192.0.2.3",
        "server_port": 22,
        "user": "user",
        "private_key": private_key,
        "private_key_passphrase": "phrase",
        "host_key": [_HOST_KEY],
        "host_key_algorithms": ["ssh-ed25519"],
    }
    # Detection follows mihomo: any text naming a private key is inline, even with
    # malformed boundary lines; sing-box then reports the parse error.
    (sloppy_boundary,) = parse_clash_proxies(
        [_ssh_info("sloppy", **{"private-key": private_key.replace("-----", "----")})]
    )
    assert "private_key" in sloppy_boundary.sing_box_proxy
    assert "private_key_path" not in sloppy_boundary.sing_box_proxy
    assert by_key_path.sing_box_proxy == {
        "type": "ssh",
        "tag": "by-key-path",
        "server": "192.0.2.3",
        "server_port": 22,
        "user": "user",
        "private_key_path": "keys/id_ed25519",
    }


@pytest.mark.parametrize(
    "proxy_info",
    [
        _ssh_info("no-auth"),
        _ssh_info("udp", password="pass", udp=True),
        _ssh_info("passphrase-only", password="pass", **{"private-key-passphrase": "phrase"}),
        {"name": "no-user", "type": "ssh", "server": "192.0.2.3", "port": 22, "password": "pass"},
    ],
)
def test_invalid_ssh_proxy_specs_are_rejected(proxy_info: dict[str, Any]) -> None:
    from conf_gen.proxy import parse_clash_proxies

    with pytest.raises((ValueError, KeyError)):
        parse_clash_proxies([proxy_info])


def test_ssh_proxy_is_sing_box_only() -> None:
    from conf_gen.proxy import parse_clash_proxies

    (proxy,) = parse_clash_proxies([_ssh_info("ssh", password="pass")])
    with pytest.raises(ValueError, match="not supported by clash"):
        proxy.clash_proxy
    with pytest.raises(ValueError, match="not supported by quantumult x"):
        proxy.quantumult_proxy


def test_generated_ssh_outbounds_pass_sing_box_check(tmp_path: Path) -> None:
    from conf_gen.generator.sing_box_generator import SingBoxGenerator
    from conf_gen.proxy import flatten_proxies
    from conf_gen.proxy import parse_clash_proxies
    from conf_gen.proxy_group import merge_proxy_by_region
    from conf_gen.proxy_group import parse_proxy_groups

    key_file = tmp_path / "id_ed25519"
    key_file.write_text(_synthetic_private_key(), encoding="utf-8")
    custom_proxies = parse_clash_proxies(
        [
            {
                "name": "SSH",
                "type": "select",
                "proxies": [
                    _ssh_info("by-password", password="pass"),
                    _ssh_info(
                        "by-inline-key",
                        **{"private-key": _synthetic_private_key(), "host-key": [_HOST_KEY]},
                    ),
                    _ssh_info("by-key-path", **{"private-key": str(key_file)}),
                ],
            }
        ]
    )
    proxies_without_region, per_region_proxies = merge_proxy_by_region(
        proxies=custom_proxies, proxy_check_url="http://example.test/", region_proxy_type="select"
    )
    generator = SingBoxGenerator(
        src_file="source.yaml",
        proxies=flatten_proxies(custom_proxies),
        per_region_proxies=per_region_proxies,
        proxy_groups=parse_proxy_groups(
            [{"name": "Final", "type": "select", "filters": [], "proxies": ["SSH", "Direct"]}],
            available_proxies=[*proxies_without_region, *per_region_proxies],
        ),
        dns={"servers": [], "rules": []},
        route={"rules": [], "final": "Final"},
        proxies_without_region=proxies_without_region,
        outbounds=[{"tag": "Direct", "type": "direct"}],
        dial_fields={"proxy": {"detour": "Direct"}},
    )
    config_dir = tmp_path / "config"
    generator.generate(config_dir)
    outbounds = {o["tag"]: o for o in load_config(config_dir)["outbounds"]}
    assert outbounds["SSH"]["outbounds"] == ["by-password", "by-inline-key", "by-key-path"]
    for tag in ("by-password", "by-inline-key", "by-key-path"):
        assert outbounds[tag]["type"] == "ssh"
        assert outbounds[tag]["detour"] == "Direct"
    # sing-box check reads and parses every private key, inline or by path.
    with rule_set_compiler() as compiler:
        run_sing_box_check(compiler._sing_box, config_dir)
