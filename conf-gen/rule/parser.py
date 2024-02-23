import re
from typing import Literal, NotRequired, Optional, Sequence, TypedDict, Union

import requests
import yaml

from rule._base_ir import _IR_REGISTRY, IRBase
from rule.ir import (
    Domain,
    DomainKeyword,
    DomainListItem,
    DomainSuffix,
    DomainWildcard,
    PackageName,
    ProcessName,
)
from common import CLASH_RULESET_FORMATS, COMMENT_BEGINS


DNS_COMPATIBLE_IRS = (
    Domain,
    DomainKeyword,
    DomainListItem,
    DomainSuffix,
    DomainWildcard,
    PackageName,
    ProcessName,
)


def _fetch_rule_set_payload(url: str, format: Literal["yaml", "text"]) -> Sequence[str]:
    if format not in CLASH_RULESET_FORMATS:
        raise ValueError(f"Unsupported format {format}, expect any of {CLASH_RULESET_FORMATS}")

    r = requests.get(url, headers={"user-agent": "clash"})
    if r.status_code != 200:
        raise requests.HTTPError(r.reason)

    filters = []
    if format == "yaml":
        filters = [l.strip() for l in yaml.load(r.text, Loader=yaml.SafeLoader)["payload"]]
    elif format == "text":
        filters = [
            l.strip()
            for l in r.text.splitlines()
            if l and not l.lstrip().startswith(COMMENT_BEGINS)
        ]

    return filters


def parse_clash_classical_filter(
    url: str,
    format: Literal["yaml", "text"],
    resolve: Union[bool, Literal["literal"]],
) -> Sequence[IRBase]:
    if not resolve in ("literal", True, False):
        raise ValueError(f"Unsupported resolve argument {resolve}, expect boolean or 'literal'")
    filters = _fetch_rule_set_payload(url, format)
    ret = []
    for l in filters:
        type, *args = l.split(",")
        rule_requires_resolve: Optional[bool]
        if len(args) < 1:
            raise ValueError(f"Got unparsable rule {l}")
        elif len(args) == 1:
            val = args[0]
            if resolve == "literal":
                raise ValueError(f"Given resolve='literal' but rule {l} didn't have resolve info")
            rule_requires_resolve = resolve
        else:
            val = args[0]
            # Resolve condition in the rule literal only takes effect when resolve set to "literal".
            if resolve == "literal":
                if (
                    args[-1].lower() not in ("no-resolve", "resolve")
                    and _IR_REGISTRY[type]._might_resolvable
                ):
                    raise ValueError(
                        f"Specified resolve=literal but the rule {l} did not indicate whether to "
                        f"resolve hostname or not"
                    )
                elif args[-1].lower() == "no-resolve":
                    rule_requires_resolve = False
                elif args[-1].lower() == "resolve":
                    rule_requires_resolve = True
                else:
                    rule_requires_resolve = None
            else:
                rule_requires_resolve = resolve
        ir = _IR_REGISTRY[type](val, rule_requires_resolve)
        ret.append(ir)
    return ret


def parse_clash_ipcidr_filter(
    url: str,
    format: Literal["yaml", "text"],
    resolve: Optional[bool],
) -> Sequence[IRBase]:
    if resolve is None:
        raise ValueError("Must explicitly specify IP rules resolve, but got None instead.")
    filters = _fetch_rule_set_payload(url, format)
    ret = []
    for l in filters:
        if re.search(r"[0-9]+(?:\.[0-9]+){3}", l):  # Is it IPv4?
            type = "IP-CIDR"
        else:
            type = "IP-CIDR6"
        ir = _IR_REGISTRY[type](l, resolve)
        ret.append(ir)
    return ret


def parse_domain_list(url: str, format: Literal["yaml", "text"]) -> Sequence[IRBase]:
    filters = _fetch_rule_set_payload(url, format)
    ret = []
    for l in filters:
        ir = DomainListItem(l)
        ret.append(ir)
    return ret


def parse_dnsmasq_conf(url: str) -> Sequence[IRBase]:
    dnsmasq_template = r"server=/([^/]+)/.*"
    filters = _fetch_rule_set_payload(url, format="text")
    ret = []
    for l in filters:
        m = re.search(dnsmasq_template, l)
        if m:
            d = m.group(1)
            ir = DomainSuffix(d)
            ret.append(ir)
    return ret


class RuleItemKwargsT(TypedDict):
    val: NotRequired[str]
    resolve: NotRequired[bool]


class RuleItemT(RuleItemKwargsT):
    # TODO: Generate type literal automatically at compilation time.
    type: Literal[
        "user-agent",
        "process-name",
        "process_name",
        "domain",
        "host",
        "domain-suffix",
        "host-suffix",
        "domain_suffix",
        "domain-keyword",
        "host-keyword",
        "domain_keyword",
        "host-wildcard",
        "domain_regex",
        "geoip",
        "ip-cidr",
        "ip_cidr",
        "ip-cidr6",
        "ip6-cidr",
        "src-ip-cidr",
        "source_ip_cidr",
        "src-port",
        "source_port",
        "dst-port",
        "port",
        "match",
        "final",
    ]
    args: NotRequired[Union[str, Sequence[str], RuleItemKwargsT]]


class QuantumultXRuleSetT(TypedDict):
    type: Literal["quantumult"]
    url: str
    resolve: bool


class DomainListT(TypedDict):
    type: Literal["domain-list"]
    url: str
    format: Literal["text", "yaml"]


class DNSMasqT(TypedDict):
    type: Literal["dnsmasq"]
    url: str


class ClashRuleSetT(TypedDict):
    type: Literal["clash-classical", "clash-ipcidr"]
    url: str
    format: Literal["text", "yaml"]
    resolve: bool


FilterT = Union[str, RuleItemT, QuantumultXRuleSetT, DomainListT, ClashRuleSetT, DNSMasqT]


def parse_filter(
    filter: FilterT,
    for_dns: bool = False,
) -> Sequence[IRBase]:
    ret: Sequence[IRBase]

    if isinstance(filter, dict):
        if "type" not in filter:
            raise ValueError(f"filter_info must contain a `type` kwarg if it is a dict")
        if filter["type"] == "quantumult":
            ret = parse_clash_classical_filter(
                url=filter["url"], format="text", resolve=filter["resolve"]
            )
        elif filter["type"] == "clash-classical":
            ret = parse_clash_classical_filter(
                url=filter["url"], format=filter["format"], resolve=filter["resolve"]
            )
        elif filter["type"] == "clash-ipcidr":
            ret = parse_clash_ipcidr_filter(
                url=filter["url"], format=filter["format"], resolve=filter["resolve"]
            )
        elif filter["type"] == "domain-list":
            ret = parse_domain_list(url=filter["url"], format=filter["format"])
        elif filter["type"] == "dnsmasq":
            ret = parse_dnsmasq_conf(url=filter["url"])
        elif filter["type"] in _IR_REGISTRY:
            if "args" in filter:
                if isinstance(filter["args"], Sequence):
                    val = filter["args"][0]
                    if len(filter["args"]) <= 1 or filter["args"][1].lower() not in (
                        "no-resolve",
                        "resolve",
                    ):
                        resolve = None
                    elif filter["args"][1].lower() == "no-resolve":
                        resolve = False
                    else:
                        resolve = True
                    ir = _IR_REGISTRY[filter["type"]](val=val, resolve=resolve)
                elif isinstance(filter["args"], dict):
                    ir = _IR_REGISTRY[filter["type"]](
                        val=filter["args"]["val"], resolve=filter["args"]["resolve"]
                    )
                else:
                    ir = _IR_REGISTRY[filter["type"]](val=filter["args"])
            else:
                if filter["type"] not in ("final", "match"):
                    raise RuntimeError(f"Got incomplete rule {filter}")
                # Set the final match resolvable to ensure it goes to the last of rule-list.
                ir = _IR_REGISTRY[filter["type"]](val="match", resolve=True)
            ret = [
                ir,
            ]
    elif isinstance(filter, str):
        type, *args = filter.split(",")
        if 1 < len(args):  # The last flag should specify resolve or not.
            if args[-1].lower() == "no-resolve":
                resolve = False
            elif args[-1].lower() == "resolve":
                resolve = True
            else:
                raise ValueError(
                    f"Cannot parse the last part ({args[-1]}) of rule {filter}. That part "
                    f"should be either `no-resolve` or `resolve` to specify this rule requires "
                    f"hostname resolving or not."
                )
        else:
            resolve = None
        if type in _IR_REGISTRY:
            if args:
                ir = _IR_REGISTRY[type](val=args[0], resolve=resolve)
            else:
                if type not in ("final", "match"):
                    raise RuntimeError(f"Got incomplete rule {filter}")
                ir = _IR_REGISTRY[type](val="match", resolve=True)
            ret = [
                ir,
            ]

    if not ret:
        raise ValueError(f"Got empty parsing result from: {filter}")
    if for_dns:
        ret = [r for r in ret if isinstance(r, DNS_COMPATIBLE_IRS)]

    return ret
