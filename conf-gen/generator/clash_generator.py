import os
from copy import copy

import yaml

from generator._base_generator import GeneratorBase
from proxy import (
    ShadowSocksProxy,
    VMessProxy,
    VMessGRPCProxy,
    VMessWebSocketProxy,
)
from proxy_group.selective_proxy_group import SelectProxyGroup


class ClashGenerator(GeneratorBase):

    _SUPPORTED_PROXY_TYPE = (
        ShadowSocksProxy,
        VMessProxy,
        VMessGRPCProxy,
        VMessWebSocketProxy,
    )

    def __init__(self, src_file, proxies, proxy_groups, **general_options):
        # Construct special group `PROXY` for clash.
        proxy_groups = copy(proxy_groups)
        the_proxy_proxy_group = SelectProxyGroup(
            name="PROXY", filters=None, proxies=proxies
        )
        proxy_groups.insert(0, the_proxy_proxy_group)
        super().__init__(src_file, proxies, proxy_groups)
        self._general_options = general_options

    def generate(self, file):
        conf = {}
        conf.update(self._general_options)
        conf["proxies"] = [p.clash_proxy for p in self._proxies]
        conf["proxy-groups"] = [g.clash_proxy_group for g in self._proxy_groups]
        conf["rules"] = []
        for g in self._proxy_groups:
            conf["rules"] += g.clash_rules

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
                conf, f, Dumper=yaml.SafeDumper, allow_unicode=True, line_break="\n",
            )
