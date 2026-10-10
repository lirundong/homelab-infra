from typing import Literal
from typing import NoReturn
from typing import NotRequired
from typing import Sequence

from conf_gen.proxy._base_proxy import ProxyBase
from conf_gen.proxy._base_proxy import SingBoxProxyT


class SingBoxSshProxyT(SingBoxProxyT):
    type: Literal["ssh"]
    user: str
    password: NotRequired[str]
    private_key: NotRequired[str]
    private_key_path: NotRequired[str]
    private_key_passphrase: NotRequired[str]
    host_key: NotRequired[list[str]]
    host_key_algorithms: NotRequired[list[str]]


class SshProxy(ProxyBase):
    # Source fields follow mihomo's SSH proxy. SSH forwards TCP only, so there is no UDP
    # option, and neither Dreamacro Clash nor Quantumult X has an SSH proxy.
    def __init__(
        self,
        name: str,
        server: str,
        port: int,
        username: str,
        password: str | None = None,
        private_key: str | None = None,
        private_key_passphrase: str | None = None,
        host_key: Sequence[str] | None = None,
        host_key_algorithms: Sequence[str] | None = None,
    ) -> None:
        super().__init__(name, server, port)
        if password is None and private_key is None:
            raise ValueError(f"SSH proxy {name} needs a password or a private key")
        if private_key_passphrase is not None and private_key is None:
            raise ValueError(f"SSH proxy {name} has a private key passphrase but no private key")
        self.username = username
        self.password = password
        self.private_key = private_key
        self.private_key_passphrase = private_key_passphrase
        self.host_key = list(host_key) if host_key else None
        self.host_key_algorithms = list(host_key_algorithms) if host_key_algorithms else None

    @property
    def clash_proxy(self) -> NoReturn:
        raise ValueError(f"SSH proxy {self.name}: SSH is not supported by clash.")

    @property
    def quantumult_proxy(self) -> NoReturn:
        raise ValueError(f"SSH proxy {self.name}: SSH is not supported by quantumult x.")

    @property
    def sing_box_proxy(self) -> SingBoxSshProxyT:
        base_cfg = super().sing_box_proxy
        cfg = SingBoxSshProxyT(
            type="ssh",
            tag=base_cfg["tag"],
            server=base_cfg["server"],
            server_port=base_cfg["server_port"],
            user=self.username,
        )
        if self.password is not None:
            cfg["password"] = self.password
        if self.private_key is not None:
            # Like mihomo, `private-key` holds either the PEM text or a path to it, and text
            # that names a private key is the key itself, whatever its boundary lines look like.
            if "PRIVATE KEY" in self.private_key:
                cfg["private_key"] = self.private_key
            else:
                cfg["private_key_path"] = self.private_key
        if self.private_key_passphrase is not None:
            cfg["private_key_passphrase"] = self.private_key_passphrase
        if self.host_key:
            cfg["host_key"] = self.host_key
        if self.host_key_algorithms:
            cfg["host_key_algorithms"] = self.host_key_algorithms
        return cfg
