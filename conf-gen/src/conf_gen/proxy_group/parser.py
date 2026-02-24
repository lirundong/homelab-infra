from collections import defaultdict
from random import shuffle
import re
from typing import Any, Literal, Sequence

import emoji
import pycountry

from conf_gen.proxy_group import ProxyGroupBase
from conf_gen.proxy_group._base_proxy_group import ProxyBase
from conf_gen.proxy_group.fallback_proxy_group import FallbackProxyGroup
from conf_gen.proxy_group.selective_proxy_group import SelectProxyGroup


def merge_proxy_by_region(
    proxies: Sequence[ProxyBase | ProxyGroupBase],
    proxy_check_url: str,
    proxy_check_interval: int = 300,
    stat_proxy_name_pattern: str = r"traffic|expire",
    region_proxy_type: Literal["url_fallback", "select"] = "url_fallback",
) -> list[FallbackProxyGroup | SelectProxyGroup | ProxyBase]:
    proxies_by_region: defaultdict[str, list[ProxyBase]] = defaultdict(list)
    ret: list[FallbackProxyGroup | SelectProxyGroup | ProxyBase] = []
    for proxy in proxies:
        if isinstance(proxy, ProxyGroupBase):
            # Custom proxies are pre-grouped.
            ret.append(proxy)  # type: ignore[arg-type]
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
            region_info: Any = pycountry.countries.search_fuzzy(search_key)[0]
            # Hardcode fix for Taiwan proxies with China flag in their names.
            if region_info.name == "China" and re.search(r"Taiwan", proxy.name, re.IGNORECASE):
                region_info = pycountry.countries.get(common_name="Taiwan")
            if hasattr(region_info, "common_name"):
                region_name = region_info.common_name
            else:
                region_name = region_info.name
            proxies_by_region[f"{region_info.flag} {region_name}"].append(proxy)

    for region_name, region_proxies in proxies_by_region.items():
        region_proxy: FallbackProxyGroup | SelectProxyGroup | ProxyBase
        if len(region_proxies) == 1:
            region_proxy = region_proxies[0]
        elif region_proxy_type == "url_fallback":
            fallback_group = FallbackProxyGroup(
                name=region_name,
                filters=None,
                proxies=region_proxies,
                proxy_check_url=proxy_check_url,
                proxy_check_interval=proxy_check_interval,
            )
            # Shuffle proxies within each region to achieve certain degree of "load balancing".
            shuffle(fallback_group._proxies)
            region_proxy = fallback_group
        elif region_proxy_type == "select":
            select_group = SelectProxyGroup(
                name=region_name,
                filters=None,
                proxies=region_proxies,
            )
            # Different from the url_fallback, we sort the proxies here to ease selection.
            select_group._proxies = sorted(select_group._proxies)
            region_proxy = select_group
        else:
            raise ValueError(f"invalid {region_proxy_type=}, expect url_fallback or select")
        ret.append(region_proxy)

    return ret


def parse_proxy_groups(
    proxy_groups_info: list[dict[str, Any]],
    available_proxies: Sequence[ProxyBase | ProxyGroupBase] | None = None,
) -> list[ProxyGroupBase]:
    proxy_groups: list[ProxyGroupBase] = []
    for g_info in proxy_groups_info:
        if g_info["type"] == "select":
            g: ProxyGroupBase = SelectProxyGroup(
                name=g_info["name"],
                filters=g_info["filters"],
                proxies=g_info["proxies"],
                img_url=g_info["img-url"],
                available_proxies=available_proxies,
            )
        else:
            raise ValueError(f"Unsupported proxy group type: {g_info['type']}.")
        proxy_groups.append(g)

    if available_proxies is not None:
        for proxy in available_proxies:
            if isinstance(proxy, ProxyGroupBase):
                proxy_groups.append(proxy)

    return proxy_groups
