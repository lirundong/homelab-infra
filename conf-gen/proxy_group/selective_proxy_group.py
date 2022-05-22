from proxy_group._base_proxy_group import ProxyGroupBase


class SelectProxyGroup(ProxyGroupBase):
    def __init__(self, name, filters, proxies, img_url=None, available_proxies=None):
        super().__init__(
            name, filters, proxies, img_url=img_url, available_proxies=available_proxies
        )

    @property
    def quantumult_policy(self):
        info = [f"static={self.name}"]
        info += self._proxies
        if self.img_url:
            info.append(f"img-url={self.img_url}")
        return ",".join(info)

    @property
    def clash_proxy_group(self):
        return {
            "name": self.name,
            "type": "select",
            "proxies": self._proxies,
        }
