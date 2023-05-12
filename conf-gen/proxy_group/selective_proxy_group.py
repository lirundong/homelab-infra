from typing import Dict, Optional, List, Union

from proxy import ProxyT
from proxy_group import ProxyGroupBase
from rule import FilterT


class SelectProxyGroup(ProxyGroupBase):
    def __init__(
        self,
        name: str,
        filters: Optional[List[FilterT]],
        proxies: List[ProxyT],
        img_url: Optional[str] = None,
        available_proxies: Optional[List[ProxyT]] = None,
    ):
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
    def clash_proxy_group(self) -> Dict[str, Union[str, List[str], int]]:
        return {
            "name": self.name,
            "type": "select",
            "proxies": self._proxies,
        }
