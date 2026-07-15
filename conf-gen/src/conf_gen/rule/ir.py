from conf_gen.rule._base_ir import _IR_REGISTRY
from conf_gen.rule._base_ir import IRBase as _IRBase


@_IR_REGISTRY.register()
class UserAgent(_IRBase):

    _quantumult_prefix = "user-agent"


@_IR_REGISTRY.register()
class ProcessName(_IRBase):

    _clash_prefix = "PROCESS-NAME"
    _sing_box_prefix = "process_name"


@_IR_REGISTRY.register()
class PackageName(_IRBase):

    _sing_box_prefix = "package_name"


@_IR_REGISTRY.register()
class Domain(_IRBase):

    _clash_prefix = "DOMAIN"
    _quantumult_prefix = "host"
    _sing_box_prefix = "domain"
    _val_is_domain = True

    def _comparison_key(self) -> tuple[str, str]:
        return "domain", self._val


@_IR_REGISTRY.register()
class DomainSuffix(_IRBase):

    _clash_prefix = "DOMAIN-SUFFIX"
    _quantumult_prefix = "host-suffix"
    _sing_box_prefix = "domain_suffix"
    _val_is_domain = True

    def _comparison_key(self) -> tuple[str, str]:
        return "domain_suffix", self._val


@_IR_REGISTRY.register()
class DomainKeyword(_IRBase):

    _clash_prefix = "DOMAIN-KEYWORD"
    _quantumult_prefix = "host-keyword"
    _sing_box_prefix = "domain_keyword"
    _val_is_domain = True


@_IR_REGISTRY.register()
class DomainWildcard(_IRBase):

    _clash_prefix = "DOMAIN-WILDCARD"
    _quantumult_prefix = "host-wildcard"
    _val_is_domain = True

    @property
    def sing_box_rule(self) -> tuple[str, str]:
        key = "domain_regex"
        val = self._val.replace("*", r"([\w\-]*)")
        return key, val


@_IR_REGISTRY.register()
class DomainListItem(_IRBase):
    """A domain-provider item supported losslessly by every output backend."""

    _clash_prefix = None
    _quantumult_prefix = None
    _sing_box_prefix = None
    _val_is_domain = True

    def __init__(self, val: str, resolve: bool | None = None) -> None:
        super().__init__(val=val, resolve=resolve)
        if self._val.startswith("+."):
            self._domain = self._val[2:]
            self._is_suffix = True
        else:
            self._domain = self._val
            self._is_suffix = False
        if (
            not self._domain
            or self._domain.startswith(".")
            or "+" in self._domain
            or "*" in self._domain
        ):
            raise ValueError(
                f"Domain-list item {self._val} is not an exact domain or +. domain suffix"
            )

    def _comparison_key(self) -> tuple[object, str]:
        if self._is_suffix:
            return "domain_suffix", self._domain
        return "domain", self._domain

    @property
    def clash_rule(self) -> str:
        if self._is_suffix:
            return f"DOMAIN-SUFFIX,{self._domain}"
        return f"DOMAIN,{self._domain}"

    @property
    def quantumult_rule(self) -> str:
        if self._is_suffix:
            return f"host-suffix,{self._domain}"
        return f"host,{self._domain}"

    @property
    def sing_box_rule(self) -> tuple[str, str]:
        if self._is_suffix:
            return "domain_suffix", self._domain
        return "domain", self._domain


@_IR_REGISTRY.register()
class DomainRegex(_IRBase):

    _sing_box_prefix = "domain_regex"
    _val_is_domain = True


@_IR_REGISTRY.register()
class GeoIP(_IRBase):

    _clash_prefix = "GEOIP"
    _quantumult_prefix = "geoip"
    _sing_box_prefix = "geoip"
    _might_resolvable = True


@_IR_REGISTRY.register()
class IPCIDR(_IRBase):

    _clash_prefix = "IP-CIDR"
    _quantumult_prefix = "ip-cidr"
    _sing_box_prefix = "ip_cidr"
    _might_resolvable = True


@_IR_REGISTRY.register()
class IPCIDR6(_IRBase):

    _clash_prefix = "IP-CIDR6"
    _quantumult_prefix = "ip6-cidr"
    _might_resolvable = True

    @property
    def sing_box_rule(self) -> tuple[str, str]:
        return "ip_cidr", self._val


@_IR_REGISTRY.register()
class SrcIPCIDR(_IRBase):

    _clash_prefix = "SRC-IP-CIDR"
    _sing_box_prefix = "source_ip_cidr"


@_IR_REGISTRY.register()
class SrcPort(_IRBase):

    _clash_prefix = "SRC-PORT"
    _sing_box_prefix = "source_port"


@_IR_REGISTRY.register()
class DstPort(_IRBase):

    _clash_prefix = "DST-PORT"
    _sing_box_prefix = "port"


@_IR_REGISTRY.register()
class Match(_IRBase):

    _clash_prefix = "MATCH"
    _quantumult_prefix = "final"
    _might_resolvable = True  # Ensure this is the last rule for Clash and Quantumult-X.

    def __init__(self, val: str | None = None, resolve: bool | None = None) -> None:
        if val is None:
            val = "match"
        super().__init__(val=val, resolve=resolve)

    @property
    def clash_rule(self) -> str:
        return self._clash_prefix

    @property
    def quantumult_rule(self) -> str:
        return self._quantumult_prefix
