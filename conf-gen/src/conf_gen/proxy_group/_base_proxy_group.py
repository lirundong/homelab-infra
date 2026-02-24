from __future__ import annotations

from collections import defaultdict
from functools import lru_cache
import re
from typing import Any, Sequence, TypeAlias

from conf_gen.proxy import ProxyBase
from conf_gen.rule import FilterT, parse_filter
from conf_gen.rule import group_sing_box_filters
from conf_gen.rule._base_ir import IRBase
from conf_gen.rule.ir import Match


ProxyT: TypeAlias = ProxyBase | str | dict[str, str]
ProxyLeafT: TypeAlias = ProxyBase | str


class ProxyGroupBase:
    def __init__(
        self,
        name: str,
        filters: Sequence[FilterT] | None,
        proxies: Sequence[ProxyT | "ProxyGroupBase"],
        img_url: str | None = None,
        available_proxies: Sequence[ProxyT | "ProxyGroupBase"] | None = None,
    ) -> None:
        self.name = name
        self.img_url = img_url
        self.included_process_irs: list[str] | None = None
        self._filters: list[IRBase] = []
        self._proxies: list[str] = []

        if filters:  # `filters` could be None, e.g., clash's special PROXY group.
            for f in filters:
                parsed = parse_filter(f)
                self._filters += parsed

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
    def quantumult_filters(self) -> tuple[list[str], list[str]]:
        no_resolve_filters: list[str] = []
        resolve_filters: list[str] = []
        for ir_filter in self._filters:
            if ir_filter._might_resolvable and ir_filter._resolve:
                target_filters = resolve_filters
            else:
                target_filters = no_resolve_filters
            try:
                filter_parts = ir_filter.quantumult_rule.split(",")
            except ValueError as e:
                if str(e).endswith("is not supported by quantumult x."):
                    continue
                else:
                    raise e
            if filter_parts[-1] == "no-resolve":
                filter_parts.insert(-1, self.name)
            else:
                filter_parts.append(self.name)
            target_filters.append(",".join(filter_parts))
        return no_resolve_filters, resolve_filters

    @property
    def clash_proxy_group(self) -> dict[str, str | list[str] | int]:
        raise NotImplementedError()

    @property
    def clash_rules(self) -> tuple[list[str], list[str]]:
        no_resolve_rules: list[str] = []
        resolve_rules: list[str] = []
        for ir_filter in self._filters:
            if ir_filter._might_resolvable and ir_filter._resolve:
                rules = resolve_rules
            else:
                rules = no_resolve_rules
            try:
                clash_rule = ir_filter.clash_rule.split(",")
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
    def sing_box_outbound(self) -> dict[str, Any]:
        raise NotImplementedError()

    @property
    def sing_box_filers(self) -> dict[str, Any]:
        if not self._filters or 1 == len(self._filters) and isinstance(self._filters[0], Match):
            return {}
        if self.prefer_reject:
            action = {"action": "reject"}
        else:
            action = {"action": "route", "outbound": self.name}
        filters = group_sing_box_filters(
            filters=self._filters,
            included_process_irs=self.included_process_irs,
        )
        filters.update(action)
        return filters
