from proxy._base_proxy import ProxyBase


class TrojanProxy(ProxyBase):
    def __init__(
        self, name, server, port, password, udp=False, sni=None, alpn=None, skip_cert_verify=False
    ):
        super().__init__(name, server, port)
        self.password = password
        self.udp = udp
        self.sni = sni
        self.skip_cert_verify = skip_cert_verify
        if alpn is not None:
            assert isinstance(alpn, (list, tuple))
            self.alpn = list(alpn)
        else:
            self.alpn = None

    @property
    def clash_proxy(self):
        info = {
            "name": self.name,
            "password": self.password,
            "port": self.port,
            "server": self.server,
            "skip-cert-verify": self.skip_cert_verify,
            "type": "trojan",
            "udp": self.udp,
        }
        if self.sni is not None:
            info["sni"] = self.sni
        if self.alpn is not None:
            info["alpn"] = self.alpn
        return info

    @property
    def quantumult_proxy(self):
        info = [
            ("trojan", f"{self.server}:{self.port}"),
            ("password", self.password),
            ("over-tls", "true"),
            ("tls-verification", f"{not self.skip_cert_verify}".lower()),
            ("udp-relay", f"{self.udp}".lower()),
            ("tag", self.name),
        ]
        if self.sni is not None:
            info.append(("tls-host", self.sni))
        return ",".join(f"{k}={v}" for k, v in info)
