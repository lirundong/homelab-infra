from copy import copy
import json
import os
from typing import Dict, List, Optional, Union
from warnings import warn

from generator._base_generator import GeneratorBase
from proxy import (
    ProxyBase,
    ShadowSocksProxy,
    TrojanProxy,
)
from proxy_group import group_sing_box_filters, ProxyGroupBase
from proxy_group.fallback_proxy_group import FallbackProxyGroup
from proxy_group.selective_proxy_group import SelectProxyGroup
from rule.parser import parse_filter


class SingBoxGenerator(GeneratorBase):
    _SUPPORTED_PROXY_TYPE = (
        ShadowSocksProxy,
        TrojanProxy,
    )
    _DEFAULT_PROXY_NAMES = {"PROXY", "DIRECT", "REJECT", "DNS"}

    def __init__(
        self,
        src_file: str,
        proxies: List[Union[ProxyBase, ProxyGroupBase]],
        per_region_proxies: List[Union[FallbackProxyGroup, ProxyBase]],
        proxy_groups: List[ProxyGroupBase],
        dns: Dict,
        route: Dict,
        inbounds: Optional[List] = None,
        log: Optional[Dict] = None,
        ntp: Optional[Dict] = None,
        experimental: Optional[Dict] = None,
        skip_process_names: bool = False,
    ):
        # Construct the special group `PROXY` for sing-box.
        proxy_groups = copy(proxy_groups)
        the_per_region_proxy_group = SelectProxyGroup(
            name="PROXY", filters=None, proxies=per_region_proxies
        )
        the_per_region_proxy_group._proxies = sorted(the_per_region_proxy_group._proxies)
        proxy_groups.insert(0, the_per_region_proxy_group)

        super().__init__(src_file, proxies, proxy_groups)

        # Parse DNS rules using the same infra as in parsing route rules.
        if "rules" not in dns:
            raise ValueError("The dns argument didn't include a `rules` field")
        for rule in dns["rules"]:
            if "filters" in rule:
                filters = []
                for f in rule.pop("filters"):
                    filters += parse_filter(f, for_dns=True)
                filters = group_sing_box_filters(filters, skip_process_names=skip_process_names)
                rule.update(filters)

        # Sane default options for sing-box.
        if log is None:
            log = {"level": "info"}
        if ntp is None:
            ntp = {"enabled": False}
        if inbounds is None:
            inbounds = [
                {
                    "tag": "tun",
                    "type": "tun",
                    "interface_name": "tun0",
                    "inet4_address": "172.19.0.1/24",
                    "inet6_address": "fdfe:dcba:9876::1/126",
                    "sniff": True,
                }
            ]
        if route is None:
            route = {"rules": []}
        if "geoip" not in route or "geosite" not in route:
            route.update(
                {"geoip": {"path": "/tmp/geoip.db"}, "geosite": {"path": "/tmp/geosite.db"}}
            )
        if experimental is None:
            experimental = {}
        self.log = log
        self.dns = dns
        self.ntp = ntp
        self.inbounds = inbounds
        self.outbounds = []
        self.route = route
        self.experimental = experimental
        self.skip_process_names = skip_process_names

        self._build_outbounds()
        self._build_route()

    def _build_outbounds(self):
        # 1. Build the mandatory DIRECT, REJECT, and DNS outbounds.
        mandatory_outbounds = [
            {"tag": "DIRECT", "type": "direct", "domain_strategy": "prefer_ipv6"},
            {"tag": "REJECT", "type": "block"},
            {"tag": "DNS", "type": "dns"},
        ]
        # 2. Build outbounds for each of the proxy servers.
        proxy_server_outbounds = []
        for p in self._proxies:
            proxy_server_outbounds.append(p.sing_box_proxy)
        # 3. Build outbounds for each of the proxy groups.
        proxy_group_outbounds = []
        for g in self._proxy_groups:
            proxy_group_outbounds.append(g.sing_box_outbound)
        # ...and finally we merge them together!
        self.outbounds += proxy_group_outbounds + proxy_server_outbounds + mandatory_outbounds
        self._valid_outbound_tags = set(o["tag"] for o in self.outbounds)

    def _build_route(self):
        for i, r in enumerate(self.route["rules"]):
            if not r["outbound"] in self._valid_outbound_tags:
                raise ValueError(f"#{i} rule's outbound {r['outbound']} is invalid")
        for g in self._proxy_groups:
            g.skip_process_names = self.skip_process_names
            filters = g.sing_box_filers
            if filters:
                # Not every proxy group contains matching filters, e.g., the PROXY group.
                self.route["rules"].append(filters)
        if self.route.get("final") and self.route["final"] not in self._valid_outbound_tags:
            raise ValueError(f"Given final outbound {self.route['final']} is invalid")
        if "final" not in self.route:
            warn(f"The final outbound was not set in route, fallback to the default `PROXY`")
            self.route.setdefault("final", "PROXY")

    def generate(self, file):
        conf = {
            "log": self.log,
            "dns": self.dns,
            "ntp": self.ntp,
            "inbounds": self.inbounds,
            "outbounds": self.outbounds,
            "route": self.route,
            "experimental": self.experimental,
        }
        base, _ = os.path.split(file)
        os.makedirs(base, exist_ok=True)
        with open(file, "w", encoding="utf-8") as f:
            json.dump(conf, f, ensure_ascii=False, indent=4)
