from typing import Dict, Union

from proxy._base_proxy import ProxyBase
ProxyT = Union[ProxyBase, str, Dict[str, str]]  # To prevent circular import.
from proxy.parser import (
    parse_clash_proxies,
    parse_clash_subscription,
    parse_subscriptions,
)
from proxy.shadowsocks_proxy import ShadowSocksProxy
from proxy.trojan_proxy import TrojanProxy
from proxy.v2ray_proxy import VMessProxy, VMessGRPCProxy, VMessWebSocketProxy


__all__ = (
    "ProxyBase",
    "ProxyT",
    "ShadowSocksProxy",
    "TrojanProxy",
    "VMessGRPCProxy",
    "VMessProxy",
    "VMessWebSocketProxy",
    "parse_clash_proxies",
    "parse_clash_subscription",
    "parse_subscriptions",
)
