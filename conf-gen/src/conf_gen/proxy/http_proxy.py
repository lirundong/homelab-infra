from typing import Literal
from typing import NotRequired
from typing import TypedDict

from conf_gen.proxy._base_proxy import ClashProxyT
from conf_gen.proxy._base_proxy import ProxyBase
from conf_gen.proxy._base_proxy import SingBoxProxyT
from conf_gen.proxy._base_proxy import SingBoxTlsT

_ClashHttpMixinT = TypedDict(
    "_ClashHttpMixinT",
    {
        "type": Literal["http"],
        "username": NotRequired[str],
        "password": NotRequired[str],
        "tls": NotRequired[bool],
        "skip-cert-verify": NotRequired[bool],
        "sni": NotRequired[str],
    },
)


class ClashHttpProxyT(ClashProxyT, _ClashHttpMixinT):
    pass


class SingBoxHttpProxyT(SingBoxProxyT):
    type: Literal["http"]
    username: NotRequired[str]
    password: NotRequired[str]
    tls: NotRequired[SingBoxTlsT]


class HttpProxy(ProxyBase):
    # HTTP CONNECT carries TCP only, so there is no UDP option.
    def __init__(
        self,
        name: str,
        server: str,
        port: int,
        username: str | None = None,
        password: str | None = None,
        tls: bool = False,
        skip_cert_verify: bool = False,
        sni: str | None = None,
    ) -> None:
        super().__init__(name, server, port)
        if (username is None) != (password is None):
            raise ValueError(f"HTTP proxy {name} needs both username and password, or neither")
        self.username = username
        self.password = password
        self.tls = tls
        self.skip_cert_verify = skip_cert_verify
        self.sni = sni

    @property
    def clash_proxy(self) -> ClashHttpProxyT:
        info = ClashHttpProxyT(
            name=self.name,
            type="http",
            server=self.server,
            port=self.port,
        )
        if self.username is not None and self.password is not None:
            info["username"] = self.username
            info["password"] = self.password
        if self.tls:
            info["tls"] = True
            info["skip-cert-verify"] = self.skip_cert_verify
            if self.sni is not None:
                info["sni"] = self.sni
        return info

    @property
    def quantumult_proxy(self) -> str:
        proxy = super().quantumult_proxy.format(type="http")
        info: list[tuple[str, str]] = []
        if self.username is not None and self.password is not None:
            info += [("username", self.username), ("password", self.password)]
        if self.tls:
            info += [
                ("over-tls", "true"),
                ("tls-verification", f"{not self.skip_cert_verify}".lower()),
            ]
            if self.sni is not None:
                info.append(("tls-host", self.sni))
        if not info:
            return proxy
        return proxy + "," + ",".join(f"{k}={v}" for k, v in info)

    @property
    def sing_box_proxy(self) -> SingBoxHttpProxyT:
        base_cfg = super().sing_box_proxy
        cfg = SingBoxHttpProxyT(
            type="http",
            tag=base_cfg["tag"],
            server=base_cfg["server"],
            server_port=base_cfg["server_port"],
        )
        if self.username is not None and self.password is not None:
            cfg["username"] = self.username
            cfg["password"] = self.password
        if self.tls:
            tls_cfg = SingBoxTlsT(enabled=True, insecure=self.skip_cert_verify)
            if self.sni is not None:
                tls_cfg["server_name"] = self.sni
            cfg["tls"] = tls_cfg
        return cfg
