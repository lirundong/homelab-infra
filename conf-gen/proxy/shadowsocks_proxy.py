from typing import get_args, Literal, NotRequired

from proxy._base_proxy import ClashProxyT, ProxyBase, SingBoxProxyT


ShadowSocksAEADCiphersT = Literal[
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
]


ShadowSocks2022CiphersT = Literal[
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
]


ShadowSocksCiphersT = Literal[ShadowSocksAEADCiphersT, ShadowSocks2022CiphersT]


class ClashShadowSocksProxyT(ClashProxyT):
    type: Literal["ss"]
    cipher: ShadowSocksCiphersT
    password: str
    udp: bool


class SingBoxShadowSocksProxyT(SingBoxProxyT):
    type: Literal["shadowsocks"]
    method: ShadowSocksCiphersT
    password: str
    network: NotRequired[Literal["tcp", "udp"]]


class ShadowSocksProxy(ProxyBase):
    def __init__(
        self,
        name: str,
        server: str,
        port: int,
        password: str,
        cipher: ShadowSocksCiphersT,
        udp: bool = False,
    ) -> None:
        if cipher in get_args(ShadowSocks2022CiphersT):
            raise ValueError(
                f"{self.__class__.__name__} doesn't support {cipher}; use ShadowSocks2022Proxy "
                f"instead."
            )
        super().__init__(name, server, port)
        self.password = password
        self.cipher = cipher
        self.udp = udp

    @property
    def clash_proxy(self) -> ClashShadowSocksProxyT:
        return {
            "type": "ss",
            "cipher": self.cipher,
            "password": self.password,
            "udp": self.udp,
            **super().clash_proxy,
        }

    @property
    def quantumult_proxy(self) -> str:
        proxy = super().quantumult_proxy.format(type="shadowsocks")
        cipher = "chacha20-poly1305" if self.cipher == "chacha20-ietf-poly1305" else self.cipher
        info = [
            (
                "method",
                f"{cipher}",
            ),
            (
                "password",
                f"{self.password}",
            ),
            (
                "udp-relay",
                f"{self.udp}".lower(),
            ),
        ]
        return proxy + "," + ",".join(f"{k}={v}" for k, v in info)

    @property
    def sing_box_proxy(self) -> SingBoxShadowSocksProxyT:
        base_cfg = super().sing_box_proxy
        cfg = SingBoxShadowSocksProxyT(
            type = "shadowsocks",
            method = self.cipher,
            password = self.password,
            tag = base_cfg["tag"],
            server = base_cfg["server"],
            server_port = base_cfg["server_port"],
        )
        if not self.udp:
            cfg["network"] = "tcp"
        return cfg


# Distinct from other normal Shadowsocks proxies merely in cipher choices. Build such a subclass so
# services without Shadowsocks-2022 ciphers can safely exclude this proxy.
class ShadowSocks2022Proxy(ShadowSocksProxy):
    def __init__(
        self,
        name: str,
        server: str,
        port: int,
        password: str,
        cipher: ShadowSocksCiphersT,
        udp: bool = False,
    ):
        if cipher not in get_args(ShadowSocks2022CiphersT):
            raise ValueError(
                f"{self.__class__.__name__} doesn't support {cipher}; use ShadowSocksProxy instead."
            )
        ProxyBase.__init__(self, name, server, port)
        self.password = password
        self.cipher = cipher
        self.udp = udp
