from typing import Literal, NotRequired, TypedDict

from conf_gen.proxy._base_proxy import ClashProxyT, ProxyBase


_Socks5MixinT = TypedDict(
    "_Socks5MixinT",
    {
        "type": Literal["socks5"],
        "udp": bool,
        "username": NotRequired[str],
        "password": NotRequired[str],
        "tls": NotRequired[bool],
        "skip_cert_verify": NotRequired[bool],
    },
)


class Socks5ClashProxyT(ClashProxyT, _Socks5MixinT):
    pass


class Socks5Proxy(ProxyBase):
    def __init__(
        self,
        name: str,
        server: str,
        port: int,
        username: str | None = None,
        password: str | None = None,
        tls: bool | None = None,
        skip_cert_verify: bool = False,
        udp: bool = False,
    ) -> None:
        super().__init__(name, server, port)
        self.username = username
        self.password = password
        self.tls = tls
        self.skip_cert_verify = skip_cert_verify
        self.udp = udp

    @property
    def clash_proxy(self) -> Socks5ClashProxyT:
        ret = Socks5ClashProxyT(
            type="socks5",
            name=self.name,
            server=self.server,
            port=self.port,
            udp=self.udp,
        )
        if self.username is not None and self.password is not None:
            ret["username"] = self.username
            ret["password"] = self.password
        if self.tls is not None:
            ret["tls"] = self.tls
            ret["skip_cert_verify"] = self.skip_cert_verify
        return ret
