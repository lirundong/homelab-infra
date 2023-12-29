from typing import Dict, get_args, Optional, List, Union

from proxy_group._base_proxy_group import ProxyGroupBase, ProxyT, ProxyLeafT
from rule import FilterT


class FallbackProxyGroup(ProxyGroupBase):
    def __init__(
        self,
        name: str,
        filters: Optional[List[FilterT]],
        proxies: List[ProxyT],
        proxy_check_url: str,
        proxy_check_interval: int = 300,
        img_url: Optional[str] = None,
        available_proxies: Optional[List[ProxyT]] = None,
    ):
        if filters is not None:
            raise ValueError(f"{self.__class.__name__} doesn't accept filters/rules.")
        for proxy in proxies:
            if not isinstance(proxy, get_args(ProxyLeafT)):
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
    def clash_proxy_group(self) -> Dict[str, Union[str, List[str], int]]:
        return {
            "name": self.name,
            "type": "fallback",
            "proxies": self._proxies,
            "url": self._proxy_check_url,
            "interval": self._proxy_check_interval,
        }

    @property
    def sing_box_outbound(self) -> Dict:
        return {
            "tag": self.name,
            "type": "urltest",
            "outbounds": self._proxies,
            "url": self._proxy_check_url,
            "interval": f"{self._proxy_check_interval}s",
        }
