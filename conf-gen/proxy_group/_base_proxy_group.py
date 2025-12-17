from collections import defaultdict
from functools import lru_cache
import re
from typing import Dict, Optional, List, Literal, Tuple, Union

from proxy import ProxyBase
from rule import FilterT, parse_filter
from rule._base_ir import _IR_REGISTRY, IRBase
from rule.ir import PackageName, ProcessName


ProxyT = Union[ProxyBase, str, Dict[str, str]]
ProxyLeafT = Union[ProxyBase, str]


_PROCESS_IRS = frozenset({PackageName, ProcessName})


def group_sing_box_filters(
    filters: List[IRBase],
    included_process_irs: Optional[List[str]] = None,
    process_irs_combination_mode: Literal["and", "or"] = "or",
) -> Dict[str, List[str]]:
    normal_filters = defaultdict(list)
    process_filters = defaultdict(list)
    if included_process_irs is not None:
        included_process_irs = tuple(_IR_REGISTRY[t] for t in included_process_irs)
        excluded_process_irs = tuple(_PROCESS_IRS - set(included_process_irs))
    else:
        included_process_irs = None
        excluded_process_irs = tuple(_PROCESS_IRS)
    for f in filters:
        try:
            k, v = f.sing_box_rule
        except ValueError as e:
            if str(e).endswith("is not supported by sing-box."):
                continue
            else:
                raise e
        if excluded_process_irs and isinstance(f, excluded_process_irs):
            continue
        elif included_process_irs and isinstance(f, included_process_irs):
            process_filters[k].append(v)
        else:
            normal_filters[k].append(v)
    # NOTE: We enforce process-related IRs to take precedence over others if applicable.
    if process_filters:
        filters = {
            "type": "logical",
            "mode": process_irs_combination_mode,
            "rules": [
                process_filters,
                normal_filters,
            ]
        }
    else:
        filters = normal_filters
    return filters


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
        self.included_process_irs = False  # TODO: Consider expose this in interface?
        self._filters = []
        self._proxies: list[str] = []

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
    def prefer_reject(self) -> bool:
        return 0 < len(self._proxies) and self._proxies[0] == "REJECT"

    @property
    @lru_cache(maxsize=1)
    def require_resolve(self) -> bool:
        for filter in self._filters:
            if filter._might_resolvable and filter._resolve:
                return True
        return False

    @property
    def quantumult_policy(self) -> str:
        raise NotImplementedError()

    @property
    def quantumult_filters(self) -> Tuple[List[str], List[str]]:
        no_resolve_filters = []
        resolve_filters = []
        for filter in self._filters:
            if filter._might_resolvable and filter._resolve:
                filters = resolve_filters
            else:
                filters = no_resolve_filters
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
        return no_resolve_filters, resolve_filters

    @property
    def clash_proxy_group(self) -> Dict[str, Union[str, List[str], int]]:
        raise NotImplementedError()

    @property
    def clash_rules(self) -> Tuple[List[str], List[str]]:
        no_resolve_rules = []
        resolve_rules = []
        for filter in self._filters:
            if filter._might_resolvable and filter._resolve:
                rules = resolve_rules
            else:
                rules = no_resolve_rules
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
            rules.append(",".join(clash_rule))
        return no_resolve_rules, resolve_rules

    @property
    def sing_box_outbound(self) -> Dict:
        raise NotImplementedError()

    @property
    def sing_box_filers(self) -> Dict:
        filters = group_sing_box_filters(
            filters=self._filters,
            included_process_irs=self.included_process_irs,
        )
        if filters:
            if self.prefer_reject:
                action = {"action": "reject"}
            else:
                action = {"action": "route", "outbound": self.name}
            return {**action, **filters}
        else:
            return {}
