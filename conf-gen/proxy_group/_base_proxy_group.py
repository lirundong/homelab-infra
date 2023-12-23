from collections import defaultdict
import re
from typing import Dict, Optional, List, Union

from proxy import ProxyBase, ProxyT
from rule import FilterT, parse_filter
from rule._base_ir import IRBase
from rule.ir import ProcessName


def group_sing_box_filters(
    filters: List[IRBase],
    skip_process_names: bool = False,
) -> Dict[str, List[str]]:
    ret = defaultdict(list)
    for f in filters:
        if skip_process_names and isinstance(f, ProcessName):
            continue
        try:
            k, v = f.sing_box_rule
        except ValueError as e:
            if str(e).endswith("is not supported by sing-box."):
                continue
            else:
                raise e
        ret[k].append(v)
    return ret


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
        self.skip_process_names = False  # TODO: Consider expose this in interface?
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
                filter = filter.quantumult_rule.split(",")
            except ValueError as e:
                if str(e).endswith("is not supported by quantumult x."):
                    continue
                else:
                    raise e
            if filter[-1] == "no-resolve":
                filter.insert(-1, self.name)
            else:
                filter.append(self.name)
            filters.append(",".join(filter))
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

    @property
    def sing_box_outbound(self) -> Dict:
        raise NotImplementedError()

    @property
    def sing_box_filers(self) -> Dict:
        matchers = group_sing_box_filters(self._filters, skip_process_names=self.skip_process_names)
        if matchers:
            return {"outbound": self.name, **matchers}
        else:
            return {}
