import re

import requests
import yaml

from rule.ir import _IR_REGISTRY, DomainSuffix
from common import QUANTUMULT_COMMENT_BEGINS


def parse_quantumult_filter(url):
    r = requests.get(url)
    if r.status_code != 200:
        raise requests.HTTPError(r.reason)

    ret = []
    for l in r.text.splitlines():
        l = l.strip()
        if not l or any(l.startswith(prefix) for prefix in QUANTUMULT_COMMENT_BEGINS):
            continue
        type, val = l.split(",")[:2]
        rule_ir = _IR_REGISTRY[type](val)
        ret.append(rule_ir)
    return ret


def parse_clash_classic_filter(url):
    r = requests.get(url, headers={"user-agent": "clash"})
    if r.status_code != 200:
        raise requests.HTTPError(r.reason)

    ret = []
    for l in yaml.load(r.text, Loader=yaml.SafeLoader)["payload"]:
        type, val = l.strip().split(",")[:2]
        rule_ir = _IR_REGISTRY[type](val)
        ret.append(rule_ir)
    return ret


def parse_clash_ipcidr_filter(url):
    r = requests.get(url, headers={"user-agent": "clash"})
    if r.status_code != 200:
        raise requests.HTTPError(r.reason)

    ret = []
    for l in yaml.load(r.text, Loader=yaml.SafeLoader)["payload"]:
        val = l.strip()
        if re.search(r"[0-9]+(?:\.[0-9]+){3}", val):  # Is it IPv4?
            type = "IP-CIDR"
        else:
            type = "IP-CIDR6"
        rule_ir = _IR_REGISTRY[type](val)
        ret.append(rule_ir)
    return ret


def parse_domain_list(url):
    r = requests.get(url)
    if r.status_code != 200:
        raise requests.HTTPError(r.reason)

    ret = []
    for l in r.text.splitlines():
        l = l.strip()
        if not l or any(l.startswith(prefix) for prefix in QUANTUMULT_COMMENT_BEGINS):
            continue
        rule_ir = DomainSuffix(l)
        ret.append(rule_ir)
    return ret


def parse_filter(type, **kwargs):
    if type == "quantumult":
        return parse_quantumult_filter(**kwargs)
    elif type == "clash-classic":
        return parse_clash_classic_filter(**kwargs)
    elif type == "clash-ipcidr":
        return parse_clash_ipcidr_filter(**kwargs)
    elif type == "domain-list":
        return parse_domain_list(**kwargs)
    elif type in _IR_REGISTRY:
        if "arg" in kwargs:
            return [_IR_REGISTRY[type](kwargs["arg"])]
        else:
            return [_IR_REGISTRY[type]()]
    else:
        raise ValueError(f"Unsupported filter type: {type}")
