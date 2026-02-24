from copy import copy
from datetime import datetime
from typing import Any, ClassVar, Sequence

from pytz import timezone

from conf_gen.proxy._base_proxy import ProxyBase
from conf_gen.proxy_group._base_proxy_group import ProxyGroupBase


class GeneratorBase:

    _SUPPORTED_PROXY_TYPE: ClassVar[tuple[type[ProxyBase], ...] | None] = None
    _DEFAULT_PROXY_NAMES: ClassVar[set[str]] = {"PROXY", "DIRECT", "REJECT"}

    def __init__(
        self,
        src_file: str,
        proxies: Sequence[ProxyBase],
        proxy_groups: Sequence[ProxyGroupBase],
    ) -> None:
        self.src_file = src_file
        self._proxies: list[ProxyBase] = []
        self._proxy_groups: list[ProxyGroupBase] = []
        proxy_names = set(pg.name for pg in proxy_groups).union(self._DEFAULT_PROXY_NAMES)
        for proxy in proxies:
            if self._SUPPORTED_PROXY_TYPE is not None and type(proxy) in self._SUPPORTED_PROXY_TYPE:
                self._proxies.append(proxy)
                proxy_names.add(proxy.name)
        for proxy_group in proxy_groups:
            proxy_group = copy(proxy_group)
            proxy_group._proxies = [p for p in proxy_group._proxies if p in proxy_names]
            self._proxy_groups.append(proxy_group)

    @property
    def header(self) -> str:
        info = "# " + "=" * 78 + "\n"
        info += f"# THIS FILE IS AUTO-GENERATED FROM: {self.src_file}\n"
        info += f"# AT {datetime.now(timezone('Asia/Shanghai')).strftime('%Y/%m/%d %H:%M')}.\n"
        info += "# " + "=" * 78
        return info

    def generate(self, file: str) -> None:
        raise NotImplementedError()

    @classmethod
    def from_base(cls, base_object: "GeneratorBase", *args: Any, **kwargs: Any) -> "GeneratorBase":
        raise NotImplementedError()
