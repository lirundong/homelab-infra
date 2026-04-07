from copy import copy, deepcopy
import io
import itertools
import json
import os
from pathlib import Path
import platform
import random
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import types
from typing import Any, Literal, Self, Sequence
from urllib.parse import urlparse, urljoin
from warnings import warn

import requests

from conf_gen.generator._base_generator import GeneratorBase
from packaging.version import Version, parse
from conf_gen.proxy import (
    ProxyBase,
    ShadowSocksProxy,
    ShadowSocks2022Proxy,
    TrojanProxy,
)
from conf_gen.proxy_group import ProxyGroupBase
from conf_gen.proxy_group.fallback_proxy_group import FallbackProxyGroup
from conf_gen.proxy_group.selective_proxy_group import SelectProxyGroup
from conf_gen.rule.parser import parse_filter
from conf_gen.rule.utils import group_sing_box_filters
from conf_gen.rule.utils import split_sing_box_dst_ip_filters


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


def expand_filters_inplace(
    rule: Any,
    filters_key: str = "filters",
    included_process_irs: list[str] | None = None,
) -> None:
    if isinstance(rule, dict) and filters_key in rule:
        # We assume that match_with_dns might live in the same level as filters.
        filter_irs: list[Any] = []
        for f in rule.pop(filters_key):
            filter_irs += parse_filter(f, match_with_dns=rule.get("match_with_dns"))
        grouped_filters = group_sing_box_filters(
            filter_irs, included_process_irs=included_process_irs
        )
        rule.update(grouped_filters)
        if "match_with_dns" in rule:
            rule.pop("match_with_dns")
        return
    elif isinstance(rule, dict):
        for v in rule.values():
            expand_filters_inplace(v, filters_key, included_process_irs)
    elif isinstance(rule, (list, tuple)):
        for v in rule:
            expand_filters_inplace(v, filters_key, included_process_irs)


def extract_ruleset_inplace(
    rule: dict[str, Any],
    tag_prefix: str,
    ruleset_literals: dict[str, Any],
    rules_per_set_minimum: int = 10,
) -> str | None:
    # Return ruleset tag only if one valid ruleset is created.
    if rule.get("type") == "logical":
        mergeable_subrulesets: list[str] = []
        for i, subrule in enumerate(rule["rules"]):
            sub_prefix = f"{tag_prefix}.{i}"
            sub_tag = extract_ruleset_inplace(subrule, sub_prefix, ruleset_literals)
            if sub_tag and len(subrule) == 1:
                assert "rule_set" in subrule
                mergeable_subrulesets.append(sub_tag)
        if len(mergeable_subrulesets) == len(rule["rules"]):
            # All subrules are purely ruleset compliant, merge to a mega ruleset.
            mega_ruleset_tag = tag_prefix
            assert mega_ruleset_tag not in ruleset_literals
            mega_ruleset_content: dict[str, Any] = {
                "type": "logical",
                "mode": rule["mode"],
                "invert": rule.get("invert", False),
                "rules": [ruleset_literals.pop(tag) for tag in mergeable_subrulesets]
            }
            ruleset_literals[mega_ruleset_tag] = mega_ruleset_content
            for k in mega_ruleset_content.keys():
                rule.pop(k, None)
            rule["rule_set"] = mega_ruleset_tag
            return mega_ruleset_tag
        else:
            return None
    else:
        assert (ruleset_tag := tag_prefix) not in ruleset_literals
        extracted_content = dict()
        num_rules = 0
        for k, v in rule.items():
            if k in RULE_SET_COMPLIANT_IRS:
                extracted_content[k] = v
                num_rules += len(v) if isinstance(v, (list, tuple)) else 1
        if extracted_content and rules_per_set_minimum <= num_rules:
            ruleset_literals[ruleset_tag] = extracted_content
            for k in extracted_content.keys():
                del rule[k]
            rule["rule_set"] = ruleset_tag
            return ruleset_tag
        else:
            return None


class RuleSetCompiler:
    """Manages a sing-box binary and working directory for rule-set compilation.

    Use as a context manager — the working directory (and extracted binary) are cleaned
    up on exit.  Downloaded tarballs are cached at the class level so that multiple
    compiler instances within the same process only fetch once.
    """

    _github_release = "https://github.com/SagerNet/sing-box/releases"
    _arch_map = {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "armv7"}
    _download_cache: dict[str, bytes] = {}

    def __init__(self) -> None:
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self._workdir: Path | None = None
        self._sing_box: Path | None = None
        self._ruleset_version: int = 0

    def __enter__(self) -> Self:
        self._tmpdir = tempfile.TemporaryDirectory()
        self._workdir = Path(self._tmpdir.__enter__())
        self._sing_box = self._resolve_sing_box()
        self._ruleset_version = self._detect_ruleset_version()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        if self._tmpdir is not None:
            self._tmpdir.__exit__(exc_type, exc_val, exc_tb)
            self._tmpdir = None

    @classmethod
    def _fetch_tarball(cls, url: str) -> bytes:
        """Download a tarball, or return cached bytes if already fetched."""
        if url not in cls._download_cache:
            print(f"Downloading {url} ...")
            resp = requests.get(url, stream=True, timeout=60)
            resp.raise_for_status()
            cls._download_cache[url] = resp.content
            print(f"Cached {len(cls._download_cache[url])} bytes for {url}")
        else:
            print(f"Using cached download for {url}")
        return cls._download_cache[url]

    def _resolve_sing_box(self) -> Path:
        assert self._workdir is not None
        path = shutil.which("sing-box")
        if path is not None:
            return Path(path)

        system = platform.system().lower()
        machine = platform.machine()
        arch = self._arch_map.get(machine)
        if system != "linux" or arch is None:
            raise RuntimeError(
                f"sing-box not found in PATH and auto-download is not supported for "
                f"{system}/{machine}. Please install sing-box manually."
            )

        # Resolve latest version via GitHub redirect.
        resp = requests.head(
            f"{self._github_release}/latest", allow_redirects=True, timeout=15
        )
        resp.raise_for_status()
        match = re.search(r"/v(\d+\.\d+\.\d+)$", resp.url)
        if not match:
            raise RuntimeError(
                f"Could not determine latest sing-box version from {resp.url}"
            )
        version = match.group(1)

        tarball_name = f"sing-box-{version}-{system}-{arch}"
        url = f"{self._github_release}/download/v{version}/{tarball_name}.tar.gz"
        tarball_bytes = self._fetch_tarball(url)

        with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tar:
            tar.extractall(self._workdir, filter="data")

        binary = self._workdir / tarball_name / "sing-box"
        if not binary.is_file():
            raise RuntimeError(
                f"Expected sing-box binary at {binary} but not found after extraction"
            )
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
        print(f"sing-box {version} extracted to {binary}")
        return binary

    def _detect_ruleset_version(self) -> int:
        assert self._sing_box is not None
        ret = subprocess.run(
            [self._sing_box, "version"],
            check=True,
            capture_output=True,
            encoding="utf-8",
        )
        sing_box_version = parse(
            re.search(r"sing-box version (.*)", ret.stdout).group(1)  # type: ignore[union-attr]
        )
        if Version("1.13") <= sing_box_version:
            return 4
        elif Version("1.11") <= sing_box_version:
            return 3
        elif Version("1.10") <= sing_box_version:
            return 2
        else:
            return 1

    def compile(self, ruleset_literals: dict[str, Any]) -> dict[str, io.BytesIO]:
        assert self._workdir is not None and self._sing_box is not None
        ruleset_binaries: dict[str, io.BytesIO] = dict()
        for tag, rule in ruleset_literals.items():
            normalized_tag = tag.replace(" ", "_")
            ruleset = {
                "version": self._ruleset_version,
                "rules": rule if isinstance(rule, list) else [rule],
            }
            json_file = self._workdir / f"{normalized_tag}.json"
            srs_file = self._workdir / f"{normalized_tag}.srs"
            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(ruleset, f, ensure_ascii=False)
            subprocess.run(
                [self._sing_box, "rule-set", "compile", json_file, "-o", srs_file],
                check=True,
            )
            with open(srs_file, "rb") as f:
                ruleset_binaries[tag] = io.BytesIO(f.read())
        return ruleset_binaries

    def build_rule_set(
        self,
        rules: list[dict[str, Any]],
        ruleset_prefix: str,
        ruleset_url: str,
        download_detour: str,
    ) -> tuple[list[dict[str, Any]], dict[str, io.BytesIO]]:
        ruleset_literals: dict[str, Any] = dict()
        for i, rule in enumerate(rules):
            if rule["action"] == "route" and "server" in rule:
                tag_prefix = rule["server"]
            elif rule["action"] == "route" and "outbound" in rule:
                tag_prefix = rule["outbound"]
            elif rule["action"] == "reject":
                tag_prefix = "Reject"
            else:
                print(f"Skip extracting ruleset from #{ruleset_prefix}.{i}: {rule}")
                continue
            # Normalize ruleset tag to be compliant with URLs.
            tag_prefix = re.sub(r"(\s+\&\s+)|(\s+)", "_", tag_prefix)
            extract_ruleset_inplace(
                rule,
                tag_prefix=f"{ruleset_prefix}.{i}.{tag_prefix}",
                ruleset_literals=ruleset_literals,
            )
        ruleset_binaries = self.compile(ruleset_literals)
        ruleset: list[dict[str, Any]] = list()
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

    def __init__(
        self,
        src_file: str,
        proxies: Sequence[ProxyBase | ProxyGroupBase],
        per_region_proxies: Sequence[ProxyGroupBase | ProxyBase],
        proxy_groups: list[ProxyGroupBase],
        dns: dict[str, Any],
        route: dict[str, Any],
        inbounds: list[dict[str, Any]] | None = None,
        log: dict[str, Any] | None = None,
        ntp: dict[str, Any] | None = None,
        experimental: dict[str, Any] | None = None,
        included_process_irs: list[str] | None = None,
        ruleset_url: str | None = None,
        dial_fields: dict[Literal["direct", "proxy"], dict[str, str]] | None = None,
        add_resolve_action: dict[str, Any] | None = None,
    ) -> None:
        # Construct the special group `PROXY` for sing-box.
        proxy_groups = copy(proxy_groups)
        the_per_region_proxy_group = SelectProxyGroup(
            name="PROXY", filters=None, proxies=list(per_region_proxies)
        )
        the_per_region_proxy_group._proxies = sorted(the_per_region_proxy_group._proxies)
        proxy_groups.insert(0, the_per_region_proxy_group)

        # Filter proxies to only ProxyBase for parent class
        base_proxies = [p for p in proxies if isinstance(p, ProxyBase)]
        super().__init__(src_file, base_proxies, proxy_groups)
        self.included_process_irs = included_process_irs
        self.ruleset_url: str | None
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
                    "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                    "mtu": 1492,
                }
            ]
        if route is None:
            route = {"rules": []}
        if experimental is None:
            experimental = {}
        if dial_fields is None:
            dial_fields = {"direct": dict(), "proxy": dict()}

        self.log = log
        self.dns = dns
        self.ntp = ntp
        self.inbounds = inbounds
        self.outbounds: list[dict[str, Any]] = []
        self.route = route
        self.experimental = experimental
        self.add_resolve_action = add_resolve_action
        self._initial_route_rules = copy(self.route["rules"])
        self._direct_dial_fields = dial_fields["direct"]
        self._proxy_dial_fields = dial_fields["proxy"]

        self._build_outbounds()
        self._build_route()

    # TODO:
    # - Make this method more general and robust.
    # - Define a former behavior of replacements and overwrites.
    # - Make '!clear' behavior more general.
    @classmethod
    def from_base(  # type: ignore[override]
        cls,
        base_object: Self,
        dns: dict[str, list[dict[str, str]]] | None = None,
        inbounds: list[dict[str, str]] | None = None,
        route: dict[str, list[dict[str, str]] | str] | None = None,
        experimental: dict[str, str] | None = None,
        included_process_irs: list[str] | None = None,
        ruleset_url: str | None = None,
    ) -> Self:
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
        # 1. Build the mandatory DIRECT outbound.
        mandatory_outbounds = [
            {"tag": "DIRECT", "type": "direct", **self._direct_dial_fields},
        ]
        # 2. Build outbounds for each of the proxy servers.
        proxy_server_outbounds = []
        for p in self._proxies:
            proxy_outbound = p.sing_box_proxy
            proxy_outbound.update(self._proxy_dial_fields)
            proxy_server_outbounds.append(proxy_outbound)
        # 3. Build outbounds for each of the proxy groups.
        proxy_group_outbounds = []
        for g in self._proxy_groups:
            if outbound := g.sing_box_outbound:
                proxy_group_outbounds.append(outbound)
        # ...and finally we merge them together!
        self.outbounds = proxy_group_outbounds + proxy_server_outbounds + mandatory_outbounds
        self._valid_outbound_tags = set(o["tag"] for o in self.outbounds)

    def _build_route(self):
        for i, r in enumerate(self.route["rules"]):
            if r["action"] == "route" and r["outbound"] not in self._valid_outbound_tags:
                raise ValueError(f"#{i} rule's outbound {r['outbound']} is invalid")
        no_resolve_filters, dst_ip_filters = [], []
        for g in self._proxy_groups:
            g.included_process_irs = self.included_process_irs
            if filters := g.sing_box_filers:
                # Not every proxy group contains matching filters, e.g., the PROXY group.
                filters = split_sing_box_dst_ip_filters(filters, must_have_action=True)
                no_resolve_filters.append(filters.no_resolve_filters)
                if filters.dst_ip_filters:
                    dst_ip_filters.append(filters.dst_ip_filters)
        self.route["rules"] += no_resolve_filters
        # If specified to add resolve action, also append dst_ip based rules.
        if self.add_resolve_action and dst_ip_filters:
            self.route["rules"].append({"action": "resolve", **self.add_resolve_action})
            self.route["rules"] += dst_ip_filters
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
            # Randomly pick a HK proxy to download rulesets.
            # TODO: Enable specify the download detour from config file.
            assert (hk_group := next(g for g in self._proxy_groups if "🇭🇰" in g.name))
            download_detour = random.choice(hk_group._proxies)
            with RuleSetCompiler() as compiler:
                dns_ruleset, dns_ruleset_binaries = compiler.build_rule_set(
                    rules=conf["dns"]["rules"],
                    ruleset_prefix="dns",
                    ruleset_url=self.ruleset_url,
                    download_detour=download_detour,
                )
                route_ruleset, route_ruleset_binaries = compiler.build_rule_set(
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
