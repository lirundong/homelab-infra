from proxy._base_proxy import ProxyBase


class ShadowSocksProxy(ProxyBase):
    def __init__(self, name, server, port, password, cipher, udp=False):
        super().__init__(name, server, port)
        self.password = password
        self.cipher = cipher
        self.udp = udp

    @property
    def clash_proxy(self):
        return {
            "cipher": self.cipher,
            "name": self.name,
            "password": self.password,
            "port": self.port,
            "server": self.server,
            "type": "ss",
            "udp": self.udp,
        }

    @property
    def quantumult_proxy(self):
        info = [
            (
                "shadowsocks",
                f"{self.server}:{self.port}",
            ),
            (
                "method",
                f"{self.cipher}",
            ),
            (
                "password",
                f"{self.password}",
            ),
            (
                "udp-relay",
                f"{self.udp}".lower(),
            ),
            (
                "tag",
                f"{self.name}",
            ),
        ]
        return ",".join(f"{k}={v}" for k, v in info)

    @property
    def sing_box_proxy(self):
        cfg = super().sing_box_proxy
        cfg.update({
            "type": "shadowsocks",
            "tag": self.name,
            "server": self.server,
            "server_port": self.port,
            "method": self.cipher,
            "password": self.password,
        })
        if not self.udp:
            cfg["network"] = "tcp"
        return cfg
