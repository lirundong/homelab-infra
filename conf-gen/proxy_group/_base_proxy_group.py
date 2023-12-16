import re
from typing import Dict, Optional, List, Union

from proxy import ProxyBase, ProxyT
from rule import FilterT, parse_filter


class ProxyGroupBase:
    def __init__(
        self,
        name: str,
        filters: Optional[List[FilterT]],
        proxies: List[Union[ProxyT, "ProxyGroupBase"]],
        img_url: Optional[str] = None,
        available_proxies: Optional[List[ProxyT]] = None,
    ):
        self.name = name
        self.img_url = img_url
        self._filters = []
        self._proxies = []

        if filters:  # `filters` could be None, e.g., clash's special PROXY group.
            for filter in filters:
                filter = parse_filter(filter)
                self._filters += filter

        for proxy in proxies:
            if isinstance(proxy, str):
                self._proxies.append(proxy)
            elif isinstance(proxy, (ProxyBase, ProxyGroupBase)):
                self._proxies.append(proxy.name)
            elif isinstance(proxy, dict) and proxy["type"] == "regex":
                if available_proxies is None:
                    raise ValueError("Must provide non-empty proxy list to use proxy regex.")
                pattern = proxy["pattern"]
                for available_proxy in available_proxies:
                    if isinstance(available_proxy, (ProxyBase, ProxyGroupBase)) and re.search(
                        pattern, available_proxy.name
                    ):
                        self._proxies.append(available_proxy.name)
                    elif isinstance(available_proxy, str) and re.search(pattern, available_proxy):
                        self._proxies.append(available_proxy)

    @property
    def quantumult_policy(self) -> str:
        raise NotImplementedError()

    @property
    def quantumult_filters(self) -> List[str]:
        filters = []
        for filter in self._filters:
            try:
                filter = f"{filter.quantumult_rule},{self.name}"
            except ValueError as e:
                if str(e).endswith("is not supported by quantumult x."):
                    continue
                else:
                    raise e
            filters.append(filter)
        return filters

    @property
    def clash_proxy_group(self) -> Dict[str, Union[str, List[str], int]]:
        raise NotImplementedError()

    @property
    def clash_rules(self) -> List[str]:
        ret = []
        for filter in self._filters:
            try:
                clash_rule = filter.clash_rule.split(",")
            except ValueError as e:
                if str(e).endswith("is not supported by clash."):
                    continue
                else:
                    raise e
            if clash_rule[-1] == "no-resolve":
                clash_rule.insert(-1, self.name)
            else:
                clash_rule.append(self.name)
            ret.append(",".join(clash_rule))
        return ret
