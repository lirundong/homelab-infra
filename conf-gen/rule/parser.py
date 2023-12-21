import copy
import re

import requests
import yaml

from rule.ir import (
    _IR_REGISTRY,
    Domain,
    DomainKeyword,
    DomainListItem,
    DomainSuffix,
    DomainWildcard,
    ProcessName,
)
from common import CLASH_RULESET_FORMATS, COMMENT_BEGINS


DNS_COMPATIBLE_IRS = (
    Domain,
    DomainKeyword,
    DomainListItem,
    DomainSuffix,
    DomainWildcard,
    ProcessName,
)


def _fetch_rule_set_payload(url, format):
    if format not in CLASH_RULESET_FORMATS:
        raise ValueError(f"Unsupported format {format}, expect any of {CLASH_RULESET_FORMATS}")

    r = requests.get(url, headers={"user-agent": "clash"})
    if r.status_code != 200:
        raise requests.HTTPError(r.reason)
    
    filters = []
    if format == "yaml":
        filters = [l.strip() for l in yaml.load(r.text, Loader=yaml.SafeLoader)["payload"]]
    elif format == "text":
        filters = [l.strip() for l in r.text.splitlines() if l and not l.lstrip().startswith(COMMENT_BEGINS)]

    return filters


def parse_clash_classical_filter(url, format, resolve):
    filters = _fetch_rule_set_payload(url, format)
    ret = []
    for l in filters:
        type, *args = l.split(",")
        if len(args) < 1:
            raise ValueError(f"Got unparsable rule {l}")
        elif len(args) == 1:
            val = args[0]
            rule_requires_resolve = resolve
        else:
            val = args[0]
            # resolve argument take precedences over the rule tail literals.
            if args[-1].lower() in ("no-resolve", "resolve"):
                rule_literal_requires_resolve = False if args[-1].lower() == "no-resolve" else True
                if rule_literal_requires_resolve == resolve:
                    rule_requires_resolve = rule_literal_requires_resolve
                else:
                    rule_requires_resolve = resolve
            else:
                rule_requires_resolve = resolve
        ir = _IR_REGISTRY[type](val, rule_requires_resolve)
        ret.append(ir)
    return ret


def parse_clash_ipcidr_filter(url, format, resolve):
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


def parse_domain_list(url, format):
    filters = _fetch_rule_set_payload(url, format)
    ret = []
    for l in filters:
        ir = DomainListItem(l)
        ret.append(ir)
    return ret


def parse_dnsmasq_conf(url):
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


def parse_filter(filter_info, for_dns=False):
    ret = []

    if isinstance(filter_info, dict):
        if not "type" in filter_info:
            raise ValueError(f"filter_info must contain a `type` kwarg if the info is a dict")
        kwargs = copy.copy(filter_info)
        type = kwargs.pop("type")
        if type == "quantumult":
            ret = parse_clash_classical_filter(format="text", **kwargs)
        elif type == "clash-classical":
            ret = parse_clash_classical_filter(**kwargs)
        elif type == "clash-ipcidr":
            ret = parse_clash_ipcidr_filter(**kwargs)
        elif type == "domain-list":
            ret = parse_domain_list(**kwargs)
        elif type == "dnsmasq":
            ret = parse_dnsmasq_conf(**kwargs)
        elif type in _IR_REGISTRY:
            if "arg" in kwargs:
                if isinstance(kwargs["arg"], (list, tuple)):
                    ir = _IR_REGISTRY[type](*kwargs["arg"])
                elif isinstance(kwargs["arg"], dict):
                    ir = _IR_REGISTRY[type](**kwargs["arg"])
                else:
                    ir = _IR_REGISTRY[type](kwargs["arg"])
            else:
                ir = _IR_REGISTRY[type]()
            ret = [ir, ]
    elif isinstance(filter_info, str):
        type, *args = filter_info.split(",")
        if 1 < len(args):  # The last flag should specify resolve or not.
            if args[-1].lower() == "no-resolve":
                args[-1] = False
            elif args[-1].lower() == "resolve":
                args[-1] = True
            else:
                raise ValueError(
                    f"Cannot parse the last part ({args[-1]}) of rule {filter_info}. That part "
                    f"should be either `no-resolve` or `resolve` to specify this rule requires "
                    f"hostname resolving or not."
                )
        if type in _IR_REGISTRY:
            if args:
                ir = _IR_REGISTRY[type](*args)
            else:
                ir = _IR_REGISTRY[type]()
            ret = [ir, ]

    if not ret:
        raise ValueError(f"Got empty parsing result from: {filter_info}")
    if for_dns:
        ret = [r for r in ret if isinstance(r, DNS_COMPATIBLE_IRS)]

    return ret
