from copy import copy, deepcopy
import io
import itertools
import json
import os
import re
import subprocess
import tempfile
from typing import Dict, List, Optional, Self, Union
from urllib.parse import urlparse, urljoin
from warnings import warn

from generator._base_generator import GeneratorBase
from packaging.version import Version, parse
from proxy import (
    DomainStrategyT,
    ProxyBase,
    ShadowSocksProxy,
    ShadowSocks2022Proxy,
    TrojanProxy,
)
from proxy_group import group_sing_box_filters, ProxyGroupBase
from proxy_group.fallback_proxy_group import FallbackProxyGroup
from proxy_group.selective_proxy_group import SelectProxyGroup
from rule.parser import parse_filter


# TODO: Make this an attribute of rule IR.
# https://sing-box.sagernet.org/configuration/rule-set/headless-rule/
RULE_SET_COMPLIANT_IRS = frozenset([
    "query_type",
    "network",
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "source_ip_cidr",
    "ip_cidr",
    "source_port",
    "source_port_range",
    "port",
    "port_range",
    "process_name",
    "process_path",
    "process_path_regex",
    "package_name",
    "wifi_ssid",
    "wifi_bssid",
    "invert",
])


def expand_filters_inplace(rule, filters_key="filters", included_process_irs=None):
    if isinstance(rule, dict) and filters_key in rule:
        # We assume that match_with_dns might live in the same level as filters.
        filters = []
        for f in rule.pop(filters_key):
            filters += parse_filter(f, match_with_dns=rule.get("match_with_dns"))
        filters = group_sing_box_filters(
            filters, included_process_irs=included_process_irs
        )
        rule.update(filters)
        if "match_with_dns" in rule:
            rule.pop("match_with_dns")
        return
    elif isinstance(rule, dict):
        for v in rule.values():
            expand_filters_inplace(v, filters_key, included_process_irs)
    elif isinstance(rule, (list, tuple)):
        for v in rule:
            expand_filters_inplace(v, filters_key, included_process_irs)


def extract_ruleset_inplace(rule, tag_prefix, ruleset_literals) -> str | None:
    # Return ruleset tag only if one valid ruleset is created.
    if rule.get("type") == "logical":
        mergeable_subrulesets = []
        for i, subrule in enumerate(rule["rules"]):
            sub_prefix = f"{tag_prefix}.{i}"
            sub_tag = extract_ruleset_inplace(subrule, sub_prefix, ruleset_literals)
            if sub_tag and len(subrule) == 1:
                assert "rule_set" in subrule
                mergeable_subrulesets.append(sub_tag)
        if len(mergeable_subrulesets) == len(rule["rules"]):
            # All subrules are purely ruleset compliant, merge to a mega ruleset.
            assert (mega_ruleset_tag := tag_prefix) not in ruleset_literals
            mega_ruleset_content = {
                "type": "logical",
                "mode": rule["mode"],
                "invert": rule.get("invert", False),
                "rules": [ruleset_literals.pop(tag) for tag in mergeable_subrulesets]
            }
            ruleset_literals[mega_ruleset_tag] = mega_ruleset_content
            for k in mega_ruleset_content.keys():
                rule.pop(k, None)
            rule["rule_set"] = mega_ruleset_tag
            return mega_ruleset_content
        else:
            return None
    else:
        assert (ruleset_tag := tag_prefix) not in ruleset_literals
        extracted_content = dict()
        for k, v in rule.items():
            if k in RULE_SET_COMPLIANT_IRS:
                extracted_content[k] = v
        if extracted_content:
            ruleset_literals[ruleset_tag] = extracted_content
            for k in extracted_content.keys():
                del rule[k]
            rule["rule_set"] = ruleset_tag
            return ruleset_tag
        else:
            return None


def compile_ruleset(ruleset_literals):
    # Since sing-box 1.10, use rule set version 2.
    ret = subprocess.run(
        ["sing-box", "version"],
        check=True,
        capture_output=True,
        encoding="utf-8",
    )
    sing_box_version = parse(re.search(r'sing-box version (.*)', ret.stdout).group(1))
    ruleset_version = 2 if Version("1.10") <= sing_box_version else 1
    ruleset_binaries = dict()
    for tag, rule in ruleset_literals.items():
        normalized_tag = tag.replace(" ", "_")
        ruleset = {
            "version": ruleset_version,
            "rules": rule if isinstance(rule, list) else [rule, ],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            json_file = os.path.join(tmpdir, f"{normalized_tag}.json")
            srs_file = os.path.join(tmpdir, f"{normalized_tag}.srs")
            json.dump(ruleset, open(json_file, "w", encoding="utf-8"), ensure_ascii=False)
            subprocess.run(
                ["sing-box", "rule-set", "compile", json_file, "-o", srs_file],
                check=True,
            )
            ruleset_binaries[tag] = io.BytesIO(open(srs_file, "rb").read())
    return ruleset_binaries


def build_rule_set(rules, ruleset_prefix, ruleset_url, download_detour):
    ruleset_literals = dict()
    for i, rule in enumerate(rules):
        if "server" in rule:
            tag_prefix = rule["server"]
        elif "outbound" in rule:
            tag_prefix = rule["outbound"]
        else:
            raise ValueError(
                f"Expect rule to have `server` or `outbound` filed but got {rule.keys()}"
            )
        # Normalize ruleset tag to be compliant with URLs.
        tag_prefix = re.sub(r"(\s+\&\s+)|(\s+)", "_", tag_prefix)
        extract_ruleset_inplace(
            rule,
            tag_prefix=f"{ruleset_prefix}.{i}.{tag_prefix}",
            ruleset_literals=ruleset_literals,
        )
    ruleset_binaries = compile_ruleset(ruleset_literals)
    ruleset = list()
    for tag in ruleset_literals.keys():
        ruleset.append({
            "tag": tag,
            "type": "remote",
            "format": "binary",
            "url": urljoin(ruleset_url, f"{tag}.srs"),
            "download_detour": download_detour,
        })
    return ruleset, ruleset_binaries


class SingBoxGenerator(GeneratorBase):
    _SUPPORTED_PROXY_TYPE = (
        ShadowSocksProxy,
        ShadowSocks2022Proxy,
        TrojanProxy,
    )
    _DEFAULT_PROXY_NAMES = {"PROXY", "DIRECT", "REJECT", "DNS"}

    def __init__(
        self,
        src_file: str,
        proxies: List[Union[ProxyBase, ProxyGroupBase]],
        per_region_proxies: List[Union[FallbackProxyGroup, ProxyBase]],
        proxy_groups: List[ProxyGroupBase],
        dns: Dict,
        route: Dict,
        direct_domain_strategy: DomainStrategyT,
        inbounds: Optional[List] = None,
        log: Optional[Dict] = None,
        ntp: Optional[Dict] = None,
        experimental: Optional[Dict] = None,
        included_process_irs: Optional[List[str]] = None,
        proxy_domain_strategy: Optional[DomainStrategyT] = None,
        ruleset_url: Optional[str] = None,
    ):
        # Construct the special group `PROXY` for sing-box.
        proxy_groups = copy(proxy_groups)
        the_per_region_proxy_group = SelectProxyGroup(
            name="PROXY", filters=None, proxies=per_region_proxies
        )
        the_per_region_proxy_group._proxies = sorted(the_per_region_proxy_group._proxies)
        proxy_groups.insert(0, the_per_region_proxy_group)

        super().__init__(src_file, proxies, proxy_groups)
        self.included_process_irs = included_process_irs
        self.direct_domain_strategy = direct_domain_strategy
        self.proxy_domain_strategy = proxy_domain_strategy
        if ruleset_url:
            if not urlparse(ruleset_url).path.endswith("/"):
                raise ValueError(f"ruleset_url must point to a directory, but got {ruleset_url=}")
            self.ruleset_url = ruleset_url
        else:
            self.ruleset_url = None

        # Parse DNS rules using the same infra as in parsing route rules.
        if "rules" not in dns:
            raise ValueError("The dns argument didn't include a `rules` field")
        for rule in dns["rules"]:
            expand_filters_inplace(
                rule, filters_key="filters", included_process_irs=self.included_process_irs
            )

        # Sane default options for sing-box.
        if log is None:
            log = {"level": "info"}
        if ntp is None:
            ntp = {"enabled": False}
        if inbounds is None:
            inbounds = [
                {
                    "tag": "tun",
                    "type": "tun",
                    "address": ["172.19.0.1/24", "fdfe:dcba:9876::1/126"],
                    "sniff": True,
                    "sniff_override_destination": True,
                }
            ]
        if route is None:
            route = {"rules": []}
        if experimental is None:
            experimental = {}
        self.log = log
        self.dns = dns
        self.ntp = ntp
        self.inbounds = inbounds
        self.outbounds = []
        self.route = route
        self.experimental = experimental
        self._initial_route_rules = copy(self.route["rules"])

        self._build_outbounds()
        self._build_route()

    # TODO:
    # - Make this method more general and robust.
    # - Define a former behavior of replacements and overwrites.
    # - Make '!clear' behavior more general.
    @classmethod
    def from_base(
        cls,
        base_object: Self,
        dns,
        inbounds,
        route,
        experimental,
        included_process_irs,
        direct_domain_strategy,
        ruleset_url,
    ):
        new_object = copy(base_object)
        # `dns` only overwrites or appends DNS servers.
        if dns is not None:
            if dns.get("servers"):
                old_servers = {s["tag"]: s for s in base_object.dns["servers"]}
                for new_server in dns["servers"]:
                    tag = new_server["tag"]
                    old_servers.setdefault(tag, {}).clear()
                    old_servers[tag].update(new_server)
                new_object.dns["servers"] = list(old_servers.values())
            if dns.get("rules"):
                new_dns_rules = copy(dns["rules"])
                for rule in new_dns_rules:
                    expand_filters_inplace(
                        rule, filters_key="filters", included_process_irs=included_process_irs,
                    )
                new_object.dns["rules"] = new_dns_rules
        if inbounds is not None:
            new_object.inbounds = inbounds
        if route is not None:
            if "rules" in route:
                new_object._initial_route_rules = copy(route["rules"])
            for k, v in route.items():
                if v == "!clear":
                    del new_object.route[k]
                else:
                    new_object.route[k] = v
        if experimental is not None:
            new_object.experimental.update(experimental)
        # Always overwrite included_process_irs. Default fallback was handed by upper-level logic.
        new_object.included_process_irs = included_process_irs
        if direct_domain_strategy is not None:
            new_object.direct_domain_strategy = direct_domain_strategy
        # Update ruleset download URL if specified.
        if ruleset_url is not None:
            new_object.ruleset_url = ruleset_url

        # Rebuild outbounds and route rules.
        new_object._build_outbounds()
        new_object.route["rules"].clear()
        new_object.route["rules"] += new_object._initial_route_rules
        new_object._build_route()

        return new_object

    def _build_outbounds(self):
        # 1. Build the mandatory DIRECT, REJECT, and DNS outbounds.
        mandatory_outbounds = [
            {"tag": "DIRECT", "type": "direct", "domain_strategy": self.direct_domain_strategy},
            {"tag": "REJECT", "type": "block"},
            {"tag": "DNS", "type": "dns"},
        ]
        # 2. Build outbounds for each of the proxy servers.
        proxy_server_outbounds = []
        for p in self._proxies:
            if self.proxy_domain_strategy is not None:
                p.domain_strategy = self.proxy_domain_strategy
            proxy_server_outbounds.append(p.sing_box_proxy)
        # 3. Build outbounds for each of the proxy groups.
        proxy_group_outbounds = []
        for g in self._proxy_groups:
            proxy_group_outbounds.append(g.sing_box_outbound)
        # ...and finally we merge them together!
        self.outbounds = proxy_group_outbounds + proxy_server_outbounds + mandatory_outbounds
        self._valid_outbound_tags = set(o["tag"] for o in self.outbounds)

    def _build_route(self):
        for i, r in enumerate(self.route["rules"]):
            if r["outbound"] not in self._valid_outbound_tags:
                raise ValueError(f"#{i} rule's outbound {r['outbound']} is invalid")
        for g in self._proxy_groups:
            g.included_process_irs = self.included_process_irs
            filters = g.sing_box_filers
            if filters:
                # Not every proxy group contains matching filters, e.g., the PROXY group.
                self.route["rules"].append(filters)
        if self.route.get("final") and self.route["final"] not in self._valid_outbound_tags:
            raise ValueError(f"Given final outbound {self.route['final']} is invalid")
        if "final" not in self.route:
            warn(f"The final outbound was not set in route, fallback to the default `PROXY`")
            self.route.setdefault("final", "PROXY")

    def generate(self, dst_dir):
        os.makedirs(dst_dir, exist_ok=True)
        # This method should not modify any of the internal data structures, so we deepcopy.
        conf = {
            "log": deepcopy(self.log),
            "dns": deepcopy(self.dns),
            "ntp": deepcopy(self.ntp),
            "inbounds": deepcopy(self.inbounds),
            "outbounds": deepcopy(self.outbounds),
            "route": deepcopy(self.route),
            "experimental": deepcopy(self.experimental),
        }
        if self.ruleset_url:
            # Use the first instance in GitHub group to download ruleset binaries.
            download_detour = "GitHub"
            dns_ruleset, dns_ruleset_binaries = build_rule_set(
                rules=conf["dns"]["rules"],
                ruleset_prefix="dns",
                ruleset_url=self.ruleset_url,
                download_detour=download_detour,
            )
            route_ruleset, route_ruleset_binaries = build_rule_set(
                rules=conf["route"]["rules"],
                ruleset_prefix="route",
                ruleset_url=self.ruleset_url,
                download_detour=download_detour,
            )
            for tag, binary in itertools.chain(
                dns_ruleset_binaries.items(), route_ruleset_binaries.items()
            ):
                srs_file = os.path.join(dst_dir, f"{tag}.srs")
                with open(srs_file, "wb") as f:
                    f.write(binary.getbuffer())
            conf["route"]["rule_set"] = dns_ruleset + route_ruleset
        config_file = os.path.join(dst_dir, "config.json")
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(conf, f, ensure_ascii=False, indent=4, sort_keys=True)
