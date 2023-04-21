from typing import Dict, Union

from ._base_proxy import ProxyBase
from .parser import (
    parse_clash_proxies,
    parse_clash_subscription,
    parse_subscriptions,
)
from .shadowsocks_proxy import ShadowSocksProxy
from .trojan_proxy import TrojanProxy
from .v2ray_proxy import VMessProxy, VMessGRPCProxy, VMessWebSocketProxy


ProxyT = Union[ProxyBase, str, Dict[str, str]]

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
