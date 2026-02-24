from __future__ import annotations

from typing import Any, Sequence

from conf_gen.proxy_group._base_proxy_group import ProxyGroupBase, ProxyT
from conf_gen.rule import FilterT


class SelectProxyGroup(ProxyGroupBase):
    def __init__(
        self,
        name: str,
        filters: Sequence[FilterT] | None,
        proxies: Sequence[ProxyT | ProxyGroupBase],
        img_url: str | None = None,
        available_proxies: Sequence[ProxyT | ProxyGroupBase] | None = None,
    ) -> None:
        super().__init__(
            name, filters, proxies, img_url=img_url, available_proxies=available_proxies
        )

    @property
    def quantumult_policy(self) -> str:
        info = [f"static={self.name}"]
        info += self._proxies
        if self.img_url:
            info.append(f"img-url={self.img_url}")
        return ",".join(info)

    @property
    def clash_proxy_group(self) -> dict[str, str | list[str] | int]:
        return {
            "name": self.name,
            "type": "select",
            "proxies": self._proxies,
        }

    @property
    def sing_box_outbound(self) -> dict[str, Any]:
        if self.prefer_reject:
            return {}
        else:
            return {
                "tag": self.name,
                "type": "selector",
                "outbounds": self._proxies,
            }
