from typing import Literal, get_args, NotRequired, Optional, Sequence, TypedDict


class ClashProxyT(TypedDict):
    name: str
    server: str
    port: int


DomainStrategyT = Literal["prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"]


class SingBoxProxyT(TypedDict):
    tag: str
    server: str
    server_port: int
    domain_strategy: DomainStrategyT


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
        self._domain_strategy: Optional[DomainStrategyT] = None

    @property
    def domain_strategy(self) -> DomainStrategyT:
        if self._domain_strategy is None:
            return "prefer_ipv6"
        else:
            return self._domain_strategy

    @domain_strategy.setter
    def domain_strategy(self, strategy: str) -> None:
        if strategy not in get_args(DomainStrategyT):
            raise ValueError(f"Unsupported domain_strategy {strategy}")
        self._domain_strategy = strategy

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
            "domain_strategy": self.domain_strategy,
        }
