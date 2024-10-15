from collections import defaultdict
from random import shuffle
import re
from typing import List, Union

import emoji
import pycountry

from proxy_group import ProxyGroupBase
from proxy_group._base_proxy_group import ProxyBase
from proxy_group.fallback_proxy_group import FallbackProxyGroup
from proxy_group.selective_proxy_group import SelectProxyGroup


def merge_proxy_by_region(
    proxies: List[Union[ProxyBase, ProxyGroupBase]],
    proxy_check_url: str,
    proxy_check_interval: int = 300,
    stat_proxy_name_pattern: str = r"traffic|expire",
) -> List[Union[FallbackProxyGroup, ProxyBase]]:
    proxies_by_region = defaultdict(list)
    ret = []
    for proxy in proxies:
        if isinstance(proxy, ProxyGroupBase):
            # Custom proxies are pre-grouped.
            ret.append(proxy)
        elif re.search(stat_proxy_name_pattern, proxy.name, re.IGNORECASE):
            proxies_by_region["📈 Statistics"].append(proxy)
        else:
            if region_flags := emoji.emoji_list(proxy.name):
                search_key = region_flags[0]["emoji"]
            else:
                search_key = proxy.name.split("-")[0]
                # Hardcode fix for FlyingBird proxies.
                if search_key.lower() == "turkey":
                    search_key = "Turkiye"
                elif search_key.lower() == "uk":
                    search_key = "United Kingdom"
            region_info = pycountry.countries.search_fuzzy(search_key)[0]
            # Hardcode fix for Taiwan proxies with China flag in their names.
            if region_info.name == "China" and re.search(r"Taiwan", proxy.name, re.IGNORECASE):
                region_info = pycountry.countries.get(common_name="Taiwan")
            if hasattr(region_info, "common_name"):
                region_name = region_info.common_name
            else:
                region_name = region_info.name
            proxies_by_region[f"{region_info.flag} {region_name}"].append(proxy)

    for region_name, region_proxies in proxies_by_region.items():
        if len(region_proxies) == 1:
            ret.append(region_proxies[0])
        else:
            region_proxy = FallbackProxyGroup(
                name=region_name,
                filters=None,
                proxies=region_proxies,
                proxy_check_url=proxy_check_url,
                proxy_check_interval=proxy_check_interval,
            )
            # Shuffle proxies within each region to achieve certain degree of "load balancing".
            shuffle(region_proxy._proxies)
            ret.append(region_proxy)

    return ret


def parse_proxy_groups(proxy_groups_info, available_proxies=None):
    proxy_groups = []
    for g_info in proxy_groups_info:
        if g_info["type"] == "select":
            g = SelectProxyGroup(
                name=g_info["name"],
                filters=g_info["filters"],
                proxies=g_info["proxies"],
                img_url=g_info["img-url"],
                available_proxies=available_proxies,
            )
        else:
            raise ValueError(f"Unsupported proxy group type: {g_info['type']}.")
        proxy_groups.append(g)

    for proxy in available_proxies:
        if isinstance(proxy, ProxyGroupBase):
            proxy_groups.append(proxy)

    return proxy_groups
