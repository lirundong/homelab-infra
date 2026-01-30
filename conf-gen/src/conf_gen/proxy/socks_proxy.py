from conf_gen.proxy._base_proxy import ProxyBase


class Socks5Proxy(ProxyBase):
    def __init__(
        self, name, server, port, username=None, password=None, tls=None, skip_cert_verify=False, udp=False
    ):
        super().__init__(name, server, port)
        self.username = username
        self.password = password
        self.tls = tls
        self.skip_cert_verify = skip_cert_verify
        self.udp = udp

    @property
    def clash_proxy(self):
        ret = {
            "type": "socks5",
            "name": self.name,
            "server": self.server,
            "port": self.port,
            "udp": self.udp,
        }
        if self.username is not None and self.password is not None:
            ret["username"] = self.username
            ret["password"] = self.password
        if self.tls is not None:
            ret["tls"] = self.tls
            ret["skip_cert_verify"] = self.skip_cert_verify
        return ret
