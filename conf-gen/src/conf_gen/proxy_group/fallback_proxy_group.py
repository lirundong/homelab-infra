from __future__ import annotations

from typing import Any, Sequence

from conf_gen.proxy import ProxyBase
from conf_gen.proxy_group._base_proxy_group import ProxyGroupBase, ProxyT
from conf_gen.rule import FilterT


class FallbackProxyGroup(ProxyGroupBase):
    def __init__(
        self,
        name: str,
        filters: Sequence[FilterT] | None,
        proxies: Sequence[ProxyT | ProxyGroupBase],
        proxy_check_url: str,
        proxy_check_interval: int = 300,
        img_url: str | None = None,
        available_proxies: Sequence[ProxyT | ProxyGroupBase] | None = None,
    ) -> None:
        if filters is not None:
            raise ValueError(f"{self.__class__.__name__} doesn't accept filters/rules.")
        for proxy in proxies:
            if not isinstance(proxy, (ProxyBase, str)):
                raise ValueError(f"{self.__class__.__name__} only accept leaf proxy specs.")
        if proxy_check_interval <= 0:
            raise ValueError(f"Invalid proxy check interval {proxy_check_interval}")
        super().__init__(
            name, filters, proxies, img_url=img_url, available_proxies=available_proxies
        )
        self._proxy_check_url = proxy_check_url
        self._proxy_check_interval = proxy_check_interval

    @property
    def quantumult_policy(self) -> str:
        info = [f"available={self.name}"]
        info += self._proxies
        if self.img_url:
            info.append(f"img-url={self.img_url}")
        return ",".join(info)

    @property
    def clash_proxy_group(self) -> dict[str, str | list[str] | int]:
        return {
            "name": self.name,
            "type": "fallback",
            "proxies": self._proxies,
            "url": self._proxy_check_url,
            "interval": self._proxy_check_interval,
        }

    @property
    def sing_box_outbound(self) -> dict[str, Any]:
        return {
            "tag": self.name,
            "type": "urltest",
            "outbounds": self._proxies,
            "url": self._proxy_check_url,
            "interval": f"{self._proxy_check_interval}s",
            "idle_timeout": f"{self._proxy_check_interval * 2}s",
            "interrupt_exist_connections": False,
        }
