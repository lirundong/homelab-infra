from copy import copy
import os

from generator._base_generator import GeneratorBase
from proxy import (
    ShadowSocksProxy,
    TrojanProxy,
    VMessProxy,
    VMessWebSocketProxy,
)
from proxy_group.selective_proxy_group import SelectProxyGroup


class QuantumultGenerator(GeneratorBase):

    _MANDATORY_SECTIONS = (
        "dns",
        "general",
        "filter_local",
        "filter_remote",
        "policy",
        "server_local",
        "server_remote",
        "rewrite_local",
        "rewrite_remote",
        "task_local",
        "mitm",
    )

    _SUPPORTED_PROXY_TYPE = (
        ShadowSocksProxy,
        TrojanProxy,
        VMessProxy,
        VMessWebSocketProxy,
    )

    def __init__(
        self, src_file, proxies, per_region_proxies, proxy_groups, rewrites, **additional_sections
    ):
        # Quantumult-X has a built-in "PROXY" selective group that contains all servers, thus we
        # have to create another selective proxy group to contain per-region auto-fallback servers,
        # then rewrite "PROXY" in rules with this group's name.
        proxy_groups = copy(proxy_groups)
        the_per_region_proxy_group = SelectProxyGroup(
            name="PROXY-PER-REGION", filters=None, proxies=per_region_proxies
        )
        proxy_groups.insert(0, the_per_region_proxy_group)

        super().__init__(src_file, proxies, proxy_groups)
        self._rewrites = rewrites
        self._additional_sections = additional_sections
        for group in self._proxy_groups:
            # Replace the default "PROXY" name. The `group` has been copied in __init__.
            for i, p in enumerate(group._proxies):
                if isinstance(p, str) and p == "PROXY":
                    group._proxies[i] = the_per_region_proxy_group.name

    @staticmethod
    def parse_tasks(tasks_info):
        ret = []
        for t in tasks_info:
            if t["type"] == "event-interaction":
                task = [
                    f"event-interaction {t['url']}",
                    f"tag={t['name']}",
                    f"img-url={t['img-url']}",
                    "enabled=true",
                ]
                task = ",".join(task)
                ret.append(task)
            else:
                raise ValueError(f"Unsupported task type: {t['type']}.")

        return ret

    def generate(self, file):
        base, _ = os.path.split(file)
        os.makedirs(base, exist_ok=True)
        missing_sections = set(self._MANDATORY_SECTIONS)
        with open(file, "w", encoding="utf-8") as f:
            # Header.
            f.write(f"{self.header}\n")
            # Additional key-value items.
            for section, content in self._additional_sections.items():
                f.write(f"[{section}]\n")
                missing_sections.remove(section)
                if content is None:
                    continue
                elif section == "task_local":
                    for task in self.parse_tasks(content):
                        f.write(f"{task}\n")
                else:
                    for k, v in content.items():
                        if isinstance(v, (list, tuple)):
                            v = ",".join(v)
                        f.write(f"{k}={v}\n")
            # Server.
            f.write("[server_local]\n")
            missing_sections.remove("server_local")
            for p in self._proxies:
                f.write(f"{p.quantumult_proxy}\n")
            # Policy.
            f.write("[policy]\n")
            missing_sections.remove("policy")
            for g in self._proxy_groups:
                f.write(f"{g.quantumult_policy}\n")
            # Filter.
            f.write("[filter_local]\n")
            missing_sections.remove("filter_local")
            filters = []
            existing_matchers = set()
            num_duplications = 0
            for g in self._proxy_groups:
                for filter in g.quantumult_filters:
                    matcher = ",".join(filter.split(",")[:2])
                    if matcher not in existing_matchers:
                        existing_matchers.add(matcher)
                        filters.append(filter)
                    else:
                        num_duplications += 1
            if 0 < num_duplications:
                print(f"Filtered out {num_duplications} duplications in " "Quantumult-x filters.")
            f.write("\n".join(filters) + "\n")
            # Rewrite.
            f.write("[rewrite_local]\n")
            missing_sections.remove("rewrite_local")
            for r in self._rewrites:
                f.write("\n".join(r.quantumult_rewrite) + "\n")
            # Other missing sections.
            for section in missing_sections:
                f.write(f"[{section}]\n")
