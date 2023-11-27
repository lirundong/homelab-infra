from rule._base_ir import _IR_REGISTRY, IRBase


@_IR_REGISTRY.register()
class UserAgent(IRBase):

    _clash_prefix = None
    _quantumult_prefix = "user-agent"


@_IR_REGISTRY.register()
class ProcessName(IRBase):

    _clash_prefix = "PROCESS-NAME"
    _quantumult_prefix = None


@_IR_REGISTRY.register()
class Domain(IRBase):

    _clash_prefix = "DOMAIN"
    _quantumult_prefix = "host"


@_IR_REGISTRY.register()
class DomainSuffix(IRBase):

    _clash_prefix = "DOMAIN-SUFFIX"
    _quantumult_prefix = "host-suffix"


@_IR_REGISTRY.register()
class DomainKeyword(IRBase):

    _clash_prefix = "DOMAIN-KEYWORD"
    _quantumult_prefix = "host-keyword"


@_IR_REGISTRY.register()
class DomainWildcard(IRBase):

    _clash_prefix = "DOMAIN-KEYWORD"
    _quantumult_prefix = "host-wildcard"

    @property
    def clash_rule(self):
        keyword = self._val.split("*")[0]
        return f"{self._clash_prefix},{keyword}"


@_IR_REGISTRY.register()
class GeoIP(IRBase):

    _clash_prefix = "GEOIP"
    _quantumult_prefix = "geoip"

    @property
    def clash_rule(self):
        return f"{super().clash_rule},no-resolve"


@_IR_REGISTRY.register()
class IPCIDR(IRBase):

    _clash_prefix = "IP-CIDR"
    _quantumult_prefix = "ip-cidr"

    @property
    def clash_rule(self):
        return f"{super().clash_rule},no-resolve"


@_IR_REGISTRY.register()
class IPCIDR6(IRBase):

    _clash_prefix = "IP-CIDR6"
    _quantumult_prefix = "ip6-cidr"

    @property
    def clash_rule(self):
        return f"{super().clash_rule},no-resolve"


@_IR_REGISTRY.register()
class SrcIPCIDR(IRBase):

    _clash_prefix = "SRC-IP-CIDR"
    _quantumult_prefix = None


@_IR_REGISTRY.register()
class SrcPort(IRBase):

    _clash_prefix = "SRC-PORT"
    _quantumult_prefix = None


@_IR_REGISTRY.register()
class DstPort(IRBase):

    _clash_prefix = "DST-PORT"
    _quantumult_prefix = None


@_IR_REGISTRY.register()
class Match(IRBase):

    _clash_prefix = "MATCH"
    _quantumult_prefix = "final"

    def __init__(self):
        super().__init__(val=None)

    @property
    def clash_rule(self):
        return self._clash_prefix

    @property
    def quantumult_rule(self):
        return self._quantumult_prefix
