from rule._base_ir import _IR_REGISTRY, IRBase


@_IR_REGISTRY.register()
class UserAgent(IRBase):

    _quantumult_prefix = "user-agent"


@_IR_REGISTRY.register()
class ProcessName(IRBase):

    _clash_prefix = "PROCESS-NAME"
    _sing_box_prefix = "process_name"


@_IR_REGISTRY.register()
class Domain(IRBase):

    _clash_prefix = "DOMAIN"
    _quantumult_prefix = "host"
    _sing_box_prefix = "domain"


@_IR_REGISTRY.register()
class DomainSuffix(IRBase):

    _clash_prefix = "DOMAIN-SUFFIX"
    _quantumult_prefix = "host-suffix"
    _sing_box_prefix = "domain_suffix"


@_IR_REGISTRY.register()
class DomainKeyword(IRBase):

    _clash_prefix = "DOMAIN-KEYWORD"
    _quantumult_prefix = "host-keyword"
    _sing_box_prefix = "domain_keyword"


@_IR_REGISTRY.register()
class DomainWildcard(IRBase):

    _quantumult_prefix = "host-wildcard"

    @property
    def clash_rule(self):
        keyword = self._val.split("*")[0]
        return f"DOMAIN-KEYWORD,{keyword}"

    @property
    def sing_box_rule(self):
        key = "domain_regex"
        val = self._val.replace("*", r"(\w*)")
        return key, val


@_IR_REGISTRY.register()
class DomainListItem(IRBase):
    """A special IR class that only be used in domain-list parsing."""
    _clash_prefix = None
    _quantumult_prefix = None
    _sing_box_prefix = None

    @property
    def clash_rule(self):
        domain = self._val
        is_domain_suffix = False
        if "+" in domain:
            domain = domain.split("+")[-1]
            is_domain_suffix = True
        if "*" in domain:
            domain = domain.split("*")[-1]
            is_domain_suffix = True
        if domain.startswith("."):
            domain = domain[1:]
        if not domain:
            raise ValueError(f"Domain-list item {self._val} cannot be parsed to a Clash rule")
        if is_domain_suffix:
            return f"DOMAIN-SUFFIX,{domain}"
        else:
            return f"DOMAIN,{domain}"
    
    @property
    def quantumult_rule(self):
        domain = self._val
        if "+" in domain:
            domain = domain.split("+")[-1]
            if domain.startswith("."):
                domain = domain[1:]
            return f"host-suffix,{domain}"
        elif "*" in domain:
            if domain.startswith("."):
                domain = domain[1:]
            return f"host-wildcard,{domain}"
        else:
            if domain.startswith("."):
                domain = domain[1:]
            return f"host,{domain}"
    
    @property
    def sing_box_rule(self):
        domain = self._val
        if "+" in domain:
            if domain.startswith("+") and domain.count("+") == 1:
                domain = domain.split("+")[-1]
                if domain.startswith("."):
                    domain = domain[1:]
                return "domain_suffix", domain
            else:
                domain = domain.replace("+", r"([\w\.]*)")
                return "domain_regex", domain
        elif "*" in domain:
            if domain.startswith("*") and domain.count("*") == 1:
                domain = domain.split("*")[-1]
                if domain.startswith("."):
                    domain = domain[1:]
                return "domain_suffix", domain
            else:
                domain = domain.replace("*", r"(\w*)")
                return "domain_regex", domain
        else:
            if domain.startswith("."):
                domain = domain[1:]
            return "domain", domain


@_IR_REGISTRY.register()
class GeoIP(IRBase):

    _clash_prefix = "GEOIP"
    _quantumult_prefix = "geoip"
    _sing_box_prefix = "geoip"


@_IR_REGISTRY.register()
class IPCIDR(IRBase):

    _clash_prefix = "IP-CIDR"
    _quantumult_prefix = "ip-cidr"
    _sing_box_prefix = "ip_cidr"

    @property
    def clash_rule(self):
        return f"{super().clash_rule},no-resolve"

    @property
    def quantumult_rule(self):
        return f"{super().quantumult_rule},no-resolve"


@_IR_REGISTRY.register()
class IPCIDR6(IRBase):

    _clash_prefix = "IP-CIDR6"
    _quantumult_prefix = "ip6-cidr"

    @property
    def clash_rule(self):
        return f"{super().clash_rule},no-resolve"

    @property
    def quantumult_rule(self):
        return f"{super().quantumult_rule},no-resolve"
    
    @property
    def sing_box_rule(self):
        return "ip_cidr", self._val


@_IR_REGISTRY.register()
class SrcIPCIDR(IRBase):

    _clash_prefix = "SRC-IP-CIDR"
    _quantumult_prefix = None
    _sing_box_prefix = "source_ip_cidr"


@_IR_REGISTRY.register()
class SrcPort(IRBase):

    _clash_prefix = "SRC-PORT"
    _sing_box_prefix = "source_port"


@_IR_REGISTRY.register()
class DstPort(IRBase):

    _clash_prefix = "DST-PORT"
    _sing_box_prefix = "port"


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
