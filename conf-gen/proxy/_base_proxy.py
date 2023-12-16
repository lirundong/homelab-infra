class ProxyBase:
    def __init__(self, name, server, port):
        self.name = name
        self.server = server
        self.port = port

    @property
    def clash_proxy(self):
        raise NotImplementedError()

    @property
    def quantumult_proxy(self):
        raise NotImplementedError()

    @property
    def sing_box_proxy(self):
        # Return dial fields.
        cfg = {
            "domain_strategy": "prefer_ipv6",
        }
        return cfg
