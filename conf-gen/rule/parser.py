import copy
import re

import requests
import yaml

from rule.ir import _IR_REGISTRY, DomainListItem
from common import CLASH_RULESET_FORMATS, COMMENT_BEGINS


def parse_quantumult_filter(url):
    r = requests.get(url)
    if r.status_code != 200:
        raise requests.HTTPError(r.reason)

    ret = []
    for l in r.text.splitlines():
        l = l.strip()
        if not l or any(l.startswith(prefix) for prefix in COMMENT_BEGINS):
            continue
        type, val = l.split(",")[:2]
        rule_ir = _IR_REGISTRY[type](val)
        ret.append(rule_ir)
    return ret


def _fetch_clash_rule_set_payload(url, format):
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


def parse_clash_classical_filter(url, format):
    filters = _fetch_clash_rule_set_payload(url, format)
    ret = []
    for l in filters:
        type, val = l.split(",")[:2]
        ir = _IR_REGISTRY[type](val)
        ret.append(ir)
    return ret


def parse_clash_ipcidr_filter(url, format):
    filters = _fetch_clash_rule_set_payload(url, format)
    ret = []
    for l in filters:
        if re.search(r"[0-9]+(?:\.[0-9]+){3}", l):  # Is it IPv4?
            type = "IP-CIDR"
        else:
            type = "IP-CIDR6"
        ir = _IR_REGISTRY[type](l)
        ret.append(ir)
    return ret


def parse_domain_list(url, format):
    filters = _fetch_clash_rule_set_payload(url, format)
    ret = []
    for l in filters:
        ir = DomainListItem(l)
        ret.append(ir)
    return ret


def parse_filter(filter_info):
    ret = []

    if isinstance(filter_info, dict):
        if not "type" in filter_info:
            raise ValueError(f"filter_info must contain a `type` kwarg if the info is a dict")
        kwargs = copy.copy(filter_info)
        type = kwargs.pop("type")
        if type == "quantumult":
            ret = parse_quantumult_filter(**kwargs)
        elif type == "clash-classical":
            ret = parse_clash_classical_filter(**kwargs)
        elif type == "clash-ipcidr":
            ret = parse_clash_ipcidr_filter(**kwargs)
        elif type == "domain-list":
            ret = parse_domain_list(**kwargs)
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
        if type in _IR_REGISTRY:
            if args:
                ir = _IR_REGISTRY[type](*args)
            else:
                ir = _IR_REGISTRY[type]()
            ret = [ir, ]

    if not ret:
        raise ValueError(f"Unsupported filter: {type}")
    return ret
