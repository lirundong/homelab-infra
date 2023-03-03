from copy import copy

from proxy._base_proxy import ProxyBase


class VMessProxy(ProxyBase):
    def __init__(self, name, server, port, servername, uuid, alter_id, cipher, udp=False):
        super().__init__(name, server, port)
        self.servername = servername
        self.uuid = uuid
        self.alter_id = alter_id
        self.cipher = cipher
        self.udp = udp

    @property
    def clash_proxy(self):
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
    def quantumult_proxy(self):
        method = "chacha20-ietf-poly1305" if self.cipher == "auto" else self.cipher
        info = [
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
        name,
        server,
        port,
        servername,
        uuid,
        alter_id,
        cipher,
        udp=False,
        tls=True,
        skip_cert_verify=False,
        tls_version=1.2,
        **ws_options,
    ):
        super().__init__(name, server, port, servername, uuid, alter_id, cipher, udp=udp)
        self.tls = tls
        self.skip_cert_verify = skip_cert_verify
        self.tls_version = tls_version
        self.ws_options = ws_options

    @property
    def clash_proxy(self):
        info = super().clash_proxy
        info.update(
            {
                "tls": self.tls,
                "skip-cert-verify": self.skip_cert_verify,
                "network": "ws",
            }
        )
        if self.ws_options:
            info["ws-opts"] = copy(self.ws_options)
        return info

    @property
    def quantumult_proxy(self):
        info = [
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
        name,
        server,
        port,
        servername,
        uuid,
        alter_id,
        cipher,
        udp=False,
        tls=True,
        skip_cert_verify=False,
        tls_version=1.2,
        server_name=None,
        **grpc_options,
    ):
        super().__init__(name, server, port, servername, uuid, alter_id, cipher, udp=udp)
        self.tls = tls
        self.skip_cert_verify = skip_cert_verify
        self.tls_version = tls_version
        self.server_name = server_name
        self.grpc_options = grpc_options

    @property
    def clash_proxy(self):
        info = super().clash_proxy
        info.update(
            {
                "tls": self.tls,
                "skip-cert-verify": self.skip_cert_verify,
                "network": "grpc",
            }
        )
        if self.server_name is not None:
            info["servername"] = self.server_name
        if self.grpc_options:
            info["grpc-opts"] = copy(self.grpc_options)
        return info

    @property
    def quantumult_proxy(self):
        raise NotImplementedError("QuantumultX doesn't support VMess + gRPC yet.")
