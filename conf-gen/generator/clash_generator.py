import os
from copy import copy

import yaml

from generator._base_generator import GeneratorBase
from proxy import (
    Socks5Proxy,
    ShadowSocksProxy,
    TrojanProxy,
    VMessProxy,
    VMessGRPCProxy,
    VMessWebSocketProxy,
)
from proxy_group.selective_proxy_group import SelectProxyGroup


class ClashGenerator(GeneratorBase):

    _SUPPORTED_PROXY_TYPE = (
        Socks5Proxy,
        ShadowSocksProxy,
        TrojanProxy,
        VMessProxy,
        VMessGRPCProxy,
        VMessWebSocketProxy,
    )

    def __init__(self, src_file, proxies, per_region_proxies, proxy_groups, **general_options):
        # Construct special group `PROXY` for clash.
        proxy_groups = copy(proxy_groups)
        the_per_region_proxy_group = SelectProxyGroup(
            name="PROXY", filters=None, proxies=per_region_proxies
        )
        the_per_region_proxy_group._proxies = sorted(the_per_region_proxy_group._proxies)
        proxy_groups.insert(0, the_per_region_proxy_group)
        super().__init__(src_file, proxies, proxy_groups)
        self._general_options = general_options

    def generate(self, file):
        conf = {}
        conf.update(self._general_options)
        conf["proxies"] = [p.clash_proxy for p in self._proxies]
        conf["proxy-groups"] = [g.clash_proxy_group for g in self._proxy_groups]

        # Ensure rules that require hostname resolving go to the ending of Clash rules.
        no_resolve_rules = []
        resolve_rules = []
        for g in self._proxy_groups:
            no_resolve_r, resolve_r = g.clash_rules
            no_resolve_rules += no_resolve_r
            resolve_rules += resolve_r
        conf["rules"] = no_resolve_rules + resolve_rules

        # Deduplicate rules. Clash performs rule traversal in O(N) thus this could improve perf.
        num_duplicates = 0
        existing_matchers = set()
        deduplicated_rules = []
        for rule in conf["rules"]:
            matcher = ",".join(rule.split(",")[:2])
            if matcher not in existing_matchers:
                existing_matchers.add(matcher)
                deduplicated_rules.append(rule)
            else:
                num_duplicates += 1
        if 0 < num_duplicates:
            print(f"Filtered out {num_duplicates} duplications in Clash rules.")
            conf["rules"] = deduplicated_rules

        base, _ = os.path.split(file)
        os.makedirs(base, exist_ok=True)
        with open(file, "w", encoding="utf-8") as f:
            f.write(f"{self.header}\n")
            yaml.dump(
                conf,
                f,
                Dumper=yaml.SafeDumper,
                allow_unicode=True,
                line_break="\n",
            )
