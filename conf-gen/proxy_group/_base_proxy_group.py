import re

from proxy import ProxyBase
from rule import parse_filter


class ProxyGroupBase:
    def __init__(self, name, filters, proxies, img_url=None, available_proxies=None):
        self.name = name
        self.img_url = img_url
        self._filters = []
        self._proxies = []

        if filters:  # `filters` could be None, e.g., clash's special PROXY group.
            for filter in filters:
                filter = parse_filter(**filter)
                self._filters += filter

        for proxy in proxies:
            if isinstance(proxy, str):
                self._proxies.append(proxy)
            elif isinstance(proxy, ProxyBase):
                self._proxies.append(proxy.name)
            elif isinstance(proxy, dict) and proxy["type"] == "regex":
                if available_proxies is None:
                    raise ValueError("Must provide non-empty proxy list to use proxy regex.")
                pattern = proxy["pattern"]
                for available_proxy in available_proxies:
                    if re.search(pattern, available_proxy.name):
                        self._proxies.append(available_proxy.name)

    @property
    def quantumult_policy(self):
        raise NotImplementedError()

    @property
    def quantumult_filters(self):
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
    def clash_proxy_group(self):
        raise NotImplementedError()

    @property
    def clash_rules(self):
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
