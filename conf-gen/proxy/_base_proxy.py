from typing import NotRequired, Sequence, TypedDict


class ClashProxyT(TypedDict):
    name: str
    server: str
    port: int


class SingBoxProxyT(TypedDict):
    tag: str
    server: str
    server_port: int


class SingBoxTlsT(TypedDict):
    enabled: bool
    insecure: bool
    server_name: NotRequired[str]
    alpn: NotRequired[Sequence[str]]


class ProxyBase:
    def __init__(self, name: str, server: str, port: int) -> None:
        self.name = name
        self.server = server
        self.port = port

    @property
    def clash_proxy(self) -> ClashProxyT:
        return {
            "name": self.name,
            "server": self.server,
            "port": self.port,
        }

    @property
    def quantumult_proxy(self) -> str:
        return "{type}" + f"={self.server}:{self.port},tag={self.name}"

    @property
    def sing_box_proxy(self) -> SingBoxProxyT:
        return {
            "tag": self.name,
            "server": self.server,
            "server_port": self.port,
        }
