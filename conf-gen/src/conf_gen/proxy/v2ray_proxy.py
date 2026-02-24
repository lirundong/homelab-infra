from copy import copy
from typing import Any, Literal, NotRequired, TypedDict

from conf_gen.proxy._base_proxy import ClashProxyT, ProxyBase


class VMessClashProxyT(ClashProxyT):
    alterId: int
    cipher: str
    servername: str | None
    type: Literal["vmess"]
    udp: bool
    uuid: str


# TypedDict for VMessWebSocket - includes ws-opts and tls settings
_VMessWSMixinT = TypedDict(
    "_VMessWSMixinT",
    {
        "tls": bool,
        "skip-cert-verify": bool,
        "network": Literal["ws"],
        "ws-opts": NotRequired[dict[str, Any]],
    },
)


class VMessWSClashProxyT(VMessClashProxyT, _VMessWSMixinT):
    pass


# TypedDict for VMessGRPC - includes grpc-opts and tls settings
_VMessGRPCMixinT = TypedDict(
    "_VMessGRPCMixinT",
    {
        "tls": bool,
        "skip-cert-verify": bool,
        "network": Literal["grpc"],
        "grpc-opts": NotRequired[dict[str, Any]],
    },
)


class VMessGRPCClashProxyT(VMessClashProxyT, _VMessGRPCMixinT):
    pass


class VMessProxy(ProxyBase):
    def __init__(
        self,
        name: str,
        server: str,
        port: int,
        servername: str | None,
        uuid: str,
        alter_id: int,
        cipher: str,
        udp: bool = False,
    ) -> None:
        super().__init__(name, server, port)
        self.servername = servername
        self.uuid = uuid
        self.alter_id = alter_id
        self.cipher = cipher
        self.udp = udp

    @property
    def clash_proxy(self) -> VMessClashProxyT:
        return {
            "alterId": self.alter_id,
            "cipher": self.cipher,
            "name": self.name,
            "port": self.port,
            "server": self.server,
            "servername": self.servername,
            "type": "vmess",
            "udp": self.udp,
            "uuid": self.uuid,
        }

    @property
    def quantumult_proxy(self) -> str:
        method = "chacha20-ietf-poly1305" if self.cipher == "auto" else self.cipher
        info: list[tuple[str, str]] = [
            (
                "vmess",
                f"{self.server}:{self.port}",
            ),
            (
                "method",
                method,
            ),
            (
                "password",
                f"{self.uuid}",
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


class VMessWebSocketProxy(VMessProxy):
    def __init__(
        self,
        name: str,
        server: str,
        port: int,
        servername: str | None,
        uuid: str,
        alter_id: int,
        cipher: str,
        udp: bool = False,
        tls: bool = True,
        skip_cert_verify: bool = False,
        tls_version: float = 1.2,
        **ws_options: Any,
    ) -> None:
        super().__init__(name, server, port, servername, uuid, alter_id, cipher, udp=udp)
        self.tls = tls
        self.skip_cert_verify = skip_cert_verify
        self.tls_version = tls_version
        self.ws_options = ws_options

    @property
    def clash_proxy(self) -> VMessWSClashProxyT:
        info: VMessWSClashProxyT = {
            "alterId": self.alter_id,
            "cipher": self.cipher,
            "name": self.name,
            "port": self.port,
            "server": self.server,
            "servername": self.servername,
            "type": "vmess",
            "udp": self.udp,
            "uuid": self.uuid,
            "tls": self.tls,
            "network": "ws",
            "skip-cert-verify": self.skip_cert_verify,
        }
        if self.ws_options:
            info["ws-opts"] = copy(self.ws_options)
        return info

    @property
    def quantumult_proxy(self) -> str:
        info: list[tuple[str, str]] = [
            (
                "vmess",
                f"{self.server}:{self.port}",
            ),
            (
                "method",
                f"{self.cipher}",
            ),
            (
                "password",
                f"{self.uuid}",
            ),
            (
                "udp-relay",
                f"{self.udp}".lower(),
            ),
            ("obfs", "wss"),
            ("obfs-host", f"{self.servername}"),
            ("obfs-uri", f"{self.ws_options['path']}"),
            ("tls-verification", f"{not self.skip_cert_verify}".lower()),
            ("tls13", f"{self.tls_version >= 1.3}".lower()),
            (
                "tag",
                f"{self.name}",
            ),
        ]
        return ",".join(f"{k}={v}" for k, v in info)


class VMessGRPCProxy(VMessProxy):
    def __init__(
        self,
        name: str,
        server: str,
        port: int,
        servername: str | None,
        uuid: str,
        alter_id: int,
        cipher: str,
        udp: bool = False,
        tls: bool = True,
        skip_cert_verify: bool = False,
        tls_version: float = 1.2,
        server_name: str | None = None,
        **grpc_options: Any,
    ) -> None:
        super().__init__(name, server, port, servername, uuid, alter_id, cipher, udp=udp)
        self.tls = tls
        self.skip_cert_verify = skip_cert_verify
        self.tls_version = tls_version
        self.server_name = server_name
        self.grpc_options = grpc_options

    @property
    def clash_proxy(self) -> VMessGRPCClashProxyT:
        info: VMessGRPCClashProxyT = {
            "alterId": self.alter_id,
            "cipher": self.cipher,
            "name": self.name,
            "port": self.port,
            "server": self.server,
            "servername": self.servername if self.server_name is None else self.server_name,
            "type": "vmess",
            "udp": self.udp,
            "uuid": self.uuid,
            "tls": self.tls,
            "network": "grpc",
            "skip-cert-verify": self.skip_cert_verify,
        }
        if self.grpc_options:
            info["grpc-opts"] = copy(self.grpc_options)
        return info

    @property
    def quantumult_proxy(self) -> str:
        raise NotImplementedError("QuantumultX doesn't support VMess + gRPC yet.")
