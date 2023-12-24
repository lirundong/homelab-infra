from typing import Literal, NotRequired, Optional, Sequence, TypedDict

from proxy._base_proxy import ClashProxyT, ProxyBase, SingBoxProxyT, SingBoxTlsT


_ClashTrojanMixinT = TypedDict(
    "_ClashTrojanMixinT",
    {
        "type": Literal["trojan"],
        "password": str,
        "skip-cert-verify": bool,
        "udp": bool,
        "sni": NotRequired[str],
        "alpn": NotRequired[Sequence[str]],
    },
)


class ClashTrojanProxyT(ClashProxyT, _ClashTrojanMixinT):
    pass


class SingBoxTrojanProxyT(SingBoxProxyT):
    type: Literal["trojan"]
    password: str
    tls: SingBoxTlsT
    network: NotRequired[Literal["tcp", "udp"]]


class TrojanProxy(ProxyBase):
    def __init__(
        self,
        name: str,
        server: str,
        port: int,
        password: str,
        udp: bool = False,
        sni: Optional[str] = None,
        alpn: Optional[Sequence[str]] = None,
        skip_cert_verify: bool = False,
    ):
        super().__init__(name, server, port)
        self.password = password
        self.udp = udp
        self.sni = sni
        self.skip_cert_verify = skip_cert_verify
        self.alpn: Optional[Sequence[str]]
        if alpn is not None:
            assert isinstance(alpn, (list, tuple))
            self.alpn = list(alpn)
        else:
            self.alpn = None

    @property
    def clash_proxy(self) -> ClashTrojanProxyT:
        info = ClashTrojanProxyT({
            "name": self.name,
            "password": self.password,
            "port": self.port,
            "server": self.server,
            "skip-cert-verify": self.skip_cert_verify,
            "type": "trojan",
            "udp": self.udp,
        })
        if self.sni is not None:
            info["sni"] = self.sni
        if self.alpn is not None:
            info["alpn"] = self.alpn
        return info

    @property
    def quantumult_proxy(self) -> str:
        proxy = super().quantumult_proxy.format(type="trojan")
        info = [
            ("over-tls", "true"),
            ("password", self.password),
            ("tls-verification", f"{not self.skip_cert_verify}".lower()),
            ("udp-relay", f"{self.udp}".lower()),
        ]
        if self.sni is not None:
            info.append(("tls-host", self.sni))
        return proxy + "," + ",".join(f"{k}={v}" for k, v in info)

    @property
    def sing_box_proxy(self) -> SingBoxTrojanProxyT:
        base_cfg = super().sing_box_proxy
        tls_cfg = SingBoxTlsT({
            "enabled": True,
            "insecure": self.skip_cert_verify,
        })
        if self.sni:
            tls_cfg["server_name"] = self.sni
        if self.alpn:
            tls_cfg["alpn"] = self.alpn
        cfg = SingBoxTrojanProxyT(
            type="trojan",
            tag=base_cfg["tag"],
            server=base_cfg["server"],
            server_port=base_cfg["server_port"],
            domain_strategy=base_cfg["domain_strategy"],
            password=self.password,
            tls=tls_cfg,
        )
        if not self.udp:
            cfg["network"] = "tcp"
        return cfg
