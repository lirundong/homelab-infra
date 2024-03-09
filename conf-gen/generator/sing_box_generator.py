from copy import copy
import json
import os
from typing import Dict, List, Optional, Self, Union
from warnings import warn

from generator._base_generator import GeneratorBase
from proxy import (
    DomainStrategyT,
    ProxyBase,
    ShadowSocksProxy,
    ShadowSocks2022Proxy,
    TrojanProxy,
)
from proxy_group import group_sing_box_filters, ProxyGroupBase
from proxy_group.fallback_proxy_group import FallbackProxyGroup
from proxy_group.selective_proxy_group import SelectProxyGroup
from rule.parser import parse_filter



class SingBoxGenerator(GeneratorBase):
    _SUPPORTED_PROXY_TYPE = (
        ShadowSocksProxy,
        ShadowSocks2022Proxy,
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
        included_process_irs: Optional[List[str]] = None,
        proxy_domain_strategy: Optional[DomainStrategyT] = None,
    ):
        # Construct the special group `PROXY` for sing-box.
        proxy_groups = copy(proxy_groups)
        the_per_region_proxy_group = SelectProxyGroup(
            name="PROXY", filters=None, proxies=per_region_proxies
        )
        the_per_region_proxy_group._proxies = sorted(the_per_region_proxy_group._proxies)
        proxy_groups.insert(0, the_per_region_proxy_group)

        super().__init__(src_file, proxies, proxy_groups)
        self.included_process_irs = included_process_irs
        self.proxy_domain_strategy = proxy_domain_strategy

        # Parse DNS rules using the same infra as in parsing route rules.
        if "rules" not in dns:
            raise ValueError("The dns argument didn't include a `rules` field")
        for rule in dns["rules"]:
            self._expand_filters_in_rule(rule, filters_key="filters")

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
        if experimental is None:
            experimental = {}
        self.log = log
        self.dns = dns
        self.ntp = ntp
        self.inbounds = inbounds
        self.outbounds = []
        self.route = route
        self.experimental = experimental
        self._initial_route_rules = copy(self.route["rules"])

        self._build_outbounds()
        self._build_route()

    def _expand_filters_in_rule(self, rule_obj, filters_key="filters"):
        if isinstance(rule_obj, dict) and filters_key in rule_obj:
            # We assume that match_with_dns might live in the same level as filters.
            filters = []
            for f in rule_obj.pop(filters_key):
                filters += parse_filter(f, match_with_dns=rule_obj.get("match_with_dns"))
            filters = group_sing_box_filters(filters, included_process_irs=self.included_process_irs)
            rule_obj.update(filters)
            if "match_with_dns" in rule_obj: rule_obj.pop("match_with_dns")
            return
        elif isinstance(rule_obj, dict):
            for v in rule_obj.values():
                self._expand_filters_in_rule(v, filters_key)
        elif isinstance(rule_obj, (list, tuple)):
            for v in rule_obj:
                self._expand_filters_in_rule(v, filters_key)

    def _build_outbounds(self):
        # 1. Build the mandatory DIRECT, REJECT, and DNS outbounds.
        mandatory_outbounds = [
            {"tag": "DIRECT", "type": "direct", "domain_strategy": "prefer_ipv4"},
            {"tag": "REJECT", "type": "block"},
            {"tag": "DNS", "type": "dns"},
        ]
        # 2. Build outbounds for each of the proxy servers.
        proxy_server_outbounds = []
        for p in self._proxies:
            if self.proxy_domain_strategy is not None:
                p.domain_strategy = self.proxy_domain_strategy
            proxy_server_outbounds.append(p.sing_box_proxy)
        # 3. Build outbounds for each of the proxy groups.
        proxy_group_outbounds = []
        for g in self._proxy_groups:
            proxy_group_outbounds.append(g.sing_box_outbound)
        # ...and finally we merge them together!
        self.outbounds = proxy_group_outbounds + proxy_server_outbounds + mandatory_outbounds
        self._valid_outbound_tags = set(o["tag"] for o in self.outbounds)

    def _build_route(self):
        for i, r in enumerate(self.route["rules"]):
            if not r["outbound"] in self._valid_outbound_tags:
                raise ValueError(f"#{i} rule's outbound {r['outbound']} is invalid")
        for g in self._proxy_groups:
            g.included_process_irs = self.included_process_irs
            filters = g.sing_box_filers
            if filters:
                # Not every proxy group contains matching filters, e.g., the PROXY group.
                self.route["rules"].append(filters)
        if self.route.get("final") and self.route["final"] not in self._valid_outbound_tags:
            raise ValueError(f"Given final outbound {self.route['final']} is invalid")
        if "final" not in self.route:
            warn(f"The final outbound was not set in route, fallback to the default `PROXY`")
            self.route.setdefault("final", "PROXY")

    # TODO: 
    # - Make this method more general and robust.
    # - Define a former behavior of replacements and overwrites.
    @classmethod
    def from_base(cls, base_object: Self, dns, inbounds, route, experimental, included_process_irs):
        new_object = copy(base_object)
        # `dns` only overwrites or appends DNS servers.
        if dns is not None and dns.get("servers"):
            old_servers = {s["tag"]: s for s in base_object.dns["servers"]}
            for new_server in dns["servers"]:
                tag = new_server["tag"]
                old_servers.setdefault(tag, {}).clear()
                old_servers[tag].update(new_server)
            new_object.dns["servers"] = list(old_servers.values())
        if inbounds is not None:
            new_object.inbounds = inbounds
        if route is not None:
            new_object.route.update(route)
        if experimental is not None:
            new_object.experimental.update(experimental)
        # Always overwrite included_process_irs. Default fallback was handed by upper-level logic.
        new_object.included_process_irs = included_process_irs

        # Rebuild route rules.
        new_object.route["rules"].clear()
        new_object.route["rules"] += new_object._initial_route_rules
        new_object._build_route()

        return new_object

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
            json.dump(conf, f, ensure_ascii=False, indent=4, sort_keys=True)
