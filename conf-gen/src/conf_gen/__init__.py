"""Configuration generator for Clash, Quantumult-X, and sing-box proxy clients.

This package generates platform-specific proxy configurations from a unified YAML source file.
"""

from conf_gen.generator import generate_conf
from conf_gen.proxy import (
    ProxyBase,
    parse_clash_proxies,
    parse_subscriptions,
    ShadowSocksProxy,
    ShadowSocks2022Proxy,
    Socks5Proxy,
    TrojanProxy,
    VMessProxy,
    VMessGRPCProxy,
    VMessWebSocketProxy,
)
from conf_gen.proxy_group import (
    ProxyGroupBase,
    parse_proxy_groups,
    merge_proxy_by_region,
)
from conf_gen.rewrite import parse_rewrites
from conf_gen.rule import parse_filter

__version__ = "0.1.0"
__all__ = [
    "generate_conf",
    "ProxyBase",
    "parse_clash_proxies",
    "parse_subscriptions",
    "ShadowSocksProxy",
    "ShadowSocks2022Proxy",
    "Socks5Proxy",
    "TrojanProxy",
    "VMessProxy",
    "VMessGRPCProxy",
    "VMessWebSocketProxy",
    "ProxyGroupBase",
    "parse_proxy_groups",
    "merge_proxy_by_region",
    "parse_rewrites",
    "parse_filter",
]
