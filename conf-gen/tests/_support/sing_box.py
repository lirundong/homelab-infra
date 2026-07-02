from __future__ import annotations

import hashlib
import ipaddress
import json
import random
import re
import shutil
import socket
import struct
import subprocess
import threading
import time
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from functools import partial
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING
from typing import Any
from typing import Callable
from typing import Iterator
from typing import Sequence
from typing import TypeVar

import jsonschema
import requests
import yaml

if TYPE_CHECKING:
    from conf_gen.generator.sing_box_generator import RuleSetCompiler
    from conf_gen.proxy import ProxyBase
    from conf_gen.proxy_group import ProxyGroupBase

REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_FILE = REPO_ROOT / "conf-gen" / "source.yaml"
CUSTOM_GROUP_NAME = "\U0001f30f Custom"
SCHEMA_URL = (
    "https://gist.githubusercontent.com/artiga033/fea992d95ad44dc8d024b229223b1002"
    "/raw/sing-box.schema.json"
)
_T = TypeVar("_T")

_SECRET_MARKER_RE = re.compile(r"@secret:(?P<key>\w+)(?:!(?P<cast>\w+))?")
_DNS_QUERY_TYPES = {
    "A": 1,
    "AAAA": 28,
    "PTR": 12,
    "HTTPS": 65,
    "TXT": 16,
    "MX": 15,
}
_SS2022_AES_128_PASSWORD = "MDEyMzQ1Njc4OWFiY2RlZg=="
_SS2022_AES_256_PASSWORD = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
_DNS_ENDPOINT_TYPES = {"https", "tls", "quic", "tcp", "udp"}
_SENSITIVE_LEAF_KEYS = {
    "password",
    "secret",
    "server_name",
    "servername",
    "server_port",
    "sni",
    "username",
    "uuid",
}
_SAFE_SECRET_VALUES: dict[str, str | int] = {
    "CLASH_PROXY_PASSWORD": "proxy-password",
    "CLASH_PROXY_USERNAME": "proxy-user",
    "CLASH_SECRET": "clash-secret",
    "DOMAIN": "example.test",
    "DOT_PUB": "1.12.12.12",
    "JP_NODE_AES_128_PASSWORD": "jp-aes-128-password",
    "JP_NODE_AES_128_PORT": 12003,
    "JP_NODE_CHACHA_PASSWORD": "jp-chacha-password",
    "JP_NODE_CHACHA_PORT": 12004,
    "JP_NODE_HOSTNAME": "jp-node.example.test",
    "JP_NODE_IPV4": "8.8.4.4",
    "JP_NODE_IPV6": "2606:4700:4700::1001",
    "JP_NODE_SS2022_AES_256_PASSWORD": "jp-2022-aes-password",
    "JP_NODE_SS2022_AES_256_PORT": 12001,
    "JP_NODE_SS2022_CHACHA_PASSWORD": "jp-2022-chacha-password",
    "JP_NODE_SS2022_CHACHA_PORT": 12002,
    "SUBSCRIPTION_BACKUP_URL": "https://example.test/subscription-backup.yaml",
    "SUBSCRIPTION_URL": "https://example.test/subscription.yaml",
}


@dataclass(frozen=True)
class SourceContext:
    source: dict[str, Any]
    proxies: Sequence[ProxyBase]
    per_region_proxies: Sequence[ProxyBase | ProxyGroupBase]
    proxy_groups: Sequence[ProxyGroupBase]


@dataclass(frozen=True)
class RouteProbe:
    host: str
    port: int
    user_agent: str
    clash_mode: str | None

    @property
    def url(self) -> str:
        host = self.host
        try:
            if ipaddress.ip_address(host).version == 6:
                host = f"[{host}]"
        except ValueError:
            pass
        return f"http://{host}:{self.port}/"


def load_sanitized_source() -> dict[str, Any]:
    source = yaml.safe_load(SOURCE_FILE.read_text(encoding="utf-8"))
    if not isinstance(source, dict):
        raise TypeError(f"Expected {SOURCE_FILE} to contain a mapping")
    sanitized = _sanitize_secret_markers(source)
    assert_no_secret_markers(sanitized)
    return sanitized


def build_source_context() -> SourceContext:
    from conf_gen.proxy import parse_clash_proxies
    from conf_gen.proxy_group import merge_proxy_by_region
    from conf_gen.proxy_group import parse_proxy_groups
    from conf_gen.proxy_group.selective_proxy_group import SelectProxyGroup

    source = load_sanitized_source()
    source["subscriptions"] = []
    source["proxies"] = _synthetic_custom_proxy_infos()

    custom_proxies = parse_clash_proxies(source["proxies"])
    subscription_proxies = parse_clash_proxies(_synthetic_subscription_proxy_infos())
    proxies = custom_proxies + subscription_proxies
    grouped_proxy: list[ProxyBase | ProxyGroupBase] = [
        SelectProxyGroup(name=CUSTOM_GROUP_NAME, filters=None, proxies=custom_proxies)
    ]
    per_region_proxies = merge_proxy_by_region(
        proxies=grouped_proxy + list(subscription_proxies),
        proxy_check_url=source["global"]["proxy_check_url"],
        proxy_check_interval=source["global"]["proxy_check_interval"],
        region_proxy_type=source["global"]["region_proxy_type"],
    )
    proxy_groups = parse_proxy_groups(source["rules"], available_proxies=per_region_proxies)
    return SourceContext(
        source=source,
        proxies=proxies,
        per_region_proxies=per_region_proxies,
        proxy_groups=proxy_groups,
    )


def generate_daemon_artifacts(context: SourceContext, output_root: Path) -> Path:
    from conf_gen.generator.sing_box_generator import SingBoxGenerator

    daemon_info = get_generate_info(context.source, "sing-box-daemon")
    generator = SingBoxGenerator(
        src_file=SOURCE_FILE.name,
        proxies=context.proxies,
        per_region_proxies=context.per_region_proxies,
        proxy_groups=list(context.proxy_groups),
        dns=deepcopy(daemon_info["dns"]),
        route=deepcopy(daemon_info["route"]),
        inbounds=deepcopy(daemon_info.get("inbounds")),
        log=deepcopy(daemon_info.get("log")),
        ntp=deepcopy(daemon_info.get("ntp")),
        experimental=deepcopy(daemon_info.get("experimental")),
        included_process_irs=deepcopy(daemon_info.get("included_process_irs")),
        ruleset_url=daemon_info["ruleset_url"],
        dial_fields=deepcopy(daemon_info.get("dial_fields")),
        add_resolve_action=deepcopy(daemon_info.get("add_resolve_action")),
    )
    output_dir = output_root / "sing-box-daemon"
    generator.generate(output_dir)
    return output_dir


def generate_selected_artifacts(
    context: SourceContext,
    output_root: Path,
    names: Sequence[str],
) -> None:
    from conf_gen.generator import generate_conf

    generate_conf(
        generate_info=[get_generate_info(context.source, name) for name in names],
        src=SOURCE_FILE.name,
        dst=str(output_root),
        proxies=context.proxies,
        per_region_proxies=context.per_region_proxies,
        proxy_groups=context.proxy_groups,
    )


def generate_runtime_config(
    context: SourceContext,
    output_root: Path,
    mixed_port: int,
    dns_port: int,
    clash_mode: str | None = None,
) -> Path:
    from conf_gen.generator.sing_box_generator import SingBoxGenerator

    daemon_info = get_generate_info(context.source, "sing-box-daemon")
    output_dir = output_root / "sing-box-runtime"
    inbounds = [
        {
            "tag": "mixed",
            "type": "mixed",
            "listen": "127.0.0.1",
            "listen_port": mixed_port,
        },
        {
            "tag": "dns-direct",
            "type": "direct",
            "listen": "127.0.0.1",
            "listen_port": dns_port,
            "network": "udp",
            "override_address": "8.8.8.8",
            "override_port": 53,
        },
    ]
    experimental: dict[str, Any] = {}
    if clash_mode is not None:
        experimental["clash_api"] = {"default_mode": clash_mode}

    generator = SingBoxGenerator(
        src_file=SOURCE_FILE.name,
        proxies=context.proxies,
        per_region_proxies=context.per_region_proxies,
        proxy_groups=list(context.proxy_groups),
        dns=deepcopy(daemon_info["dns"]),
        route=deepcopy(daemon_info["route"]),
        inbounds=inbounds,
        log={"level": "debug", "output": str(output_dir / "sing-box.log")},
        ntp={"enabled": False, "server": "time.apple.com"},
        experimental=experimental,
        included_process_irs=deepcopy(daemon_info.get("included_process_irs")),
        ruleset_url=None,
        dial_fields=deepcopy(daemon_info.get("dial_fields")),
        add_resolve_action=deepcopy(daemon_info.get("add_resolve_action")),
    )
    generator.generate(output_dir)
    return output_dir


def get_generate_info(source: dict[str, Any], name: str) -> dict[str, Any]:
    for generate_info in source["generates"]:
        if generate_info["name"] == name:
            return deepcopy(generate_info)
    raise KeyError(f"No generate entry named {name!r}")


def load_config(config_dir: Path) -> dict[str, Any]:
    with open(config_dir / "config.json", encoding="utf-8") as f:
        config = json.load(f)
    assert_no_secret_markers(config)
    return config


def fetch_live_schema() -> dict[str, Any]:
    response = requests.get(SCHEMA_URL, timeout=60)
    response.raise_for_status()
    schema = response.json()
    if not isinstance(schema, dict):
        raise TypeError("Expected sing-box schema to be a JSON object")
    _patch_live_schema_compatibility(schema)
    return schema


def validate_config_schema(config: dict[str, Any], schema: dict[str, Any]) -> None:
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(config), key=lambda error: list(error.absolute_path))
    if errors:
        error = errors[0]
        path = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise AssertionError(f"schema validation failed at {path}: {error.validator}")


def run_sing_box_check(sing_box: Path | None, config_dir: Path) -> None:
    sing_box = _require_sing_box(sing_box)
    result = subprocess.run(
        [sing_box, "check", "-c", config_dir / "config.json", "-D", config_dir],
        check=False,
        capture_output=True,
        encoding="utf-8",
        timeout=120,
    )
    if result.returncode != 0:
        raise AssertionError(f"sing-box check failed for {config_dir.name}")


def run_redacted_sing_box_check(
    sing_box: Path | None,
    config_dir: Path,
    config: dict[str, Any],
) -> None:
    with TemporaryDirectory() as tmp_dir:
        check_dir = Path(tmp_dir)
        for rule_set in config_dir.glob("*.srs"):
            shutil.copy2(rule_set, check_dir / rule_set.name)
        (check_dir / "config.json").write_text(
            json.dumps(redact_sing_box_config(config), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        run_sing_box_check(sing_box, check_dir)


def redact_sing_box_config(config: dict[str, Any]) -> dict[str, Any]:
    return _redact_sensitive_leaves(config)


@contextmanager
def rule_set_compiler() -> Iterator[RuleSetCompiler]:
    from conf_gen.generator.sing_box_generator import RuleSetCompiler

    with RuleSetCompiler() as compiler:
        yield compiler


@contextmanager
def running_sing_box(sing_box: Path | None, config_dir: Path) -> Iterator[subprocess.Popen[bytes]]:
    sing_box = _require_sing_box(sing_box)
    run_sing_box_check(sing_box, config_dir)
    with open(config_dir / "config.json", encoding="utf-8") as f:
        inbounds = json.load(f).get("inbounds") or []
    process = subprocess.Popen(
        [sing_box, "run", "-c", config_dir / "config.json", "-D", config_dir],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_inbounds_ready(process, inbounds)
        yield process
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def _wait_for_inbounds_ready(
    process: subprocess.Popen[bytes],
    inbounds: list[dict[str, Any]],
) -> None:
    pending = [inbound for inbound in inbounds if inbound.get("listen_port") is not None]
    deadline = time.monotonic() + 10
    while pending and time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"sing-box exited early with status {process.returncode}")
        pending = [inbound for inbound in pending if not _inbound_listening(inbound)]
        if pending:
            time.sleep(0.05)
    if pending:
        tags = [inbound.get("tag", "?") for inbound in pending]
        raise AssertionError(f"timed out waiting for sing-box inbounds: {tags}")


def _inbound_listening(inbound: dict[str, Any]) -> bool:
    port = inbound["listen_port"]
    if inbound.get("network") == "udp":
        return _udp_port_in_use(port)
    return _tcp_port_in_use(port)


def _tcp_port_in_use(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def _udp_port_in_use(port: int) -> bool:
    # If our test bind succeeds, sing-box hasn't claimed the port yet; we close immediately.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", port))
    except OSError:
        return True
    return False


def _require_sing_box(sing_box: Path | None) -> Path:
    if sing_box is None:
        raise AssertionError("RuleSetCompiler did not resolve a sing-box binary")
    return sing_box


def _redact_sensitive_leaves(
    value: Any,
    key: str | None = None,
    parent: dict[str, Any] | None = None,
) -> Any:
    if isinstance(value, dict):
        return {
            child_key: _redact_sensitive_leaves(child_value, child_key, value)
            for child_key, child_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_sensitive_leaves(item, key, parent) for item in value]
    if key in _SENSITIVE_LEAF_KEYS:
        return _redacted_leaf_value(key, parent)
    if key == "server" and parent is not None:
        if "server_port" in parent:
            return "127.0.0.1"
        if parent.get("type") in _DNS_ENDPOINT_TYPES:
            return "1.1.1.1"
    return value


def _redacted_leaf_value(key: str, parent: dict[str, Any] | None) -> str | int:
    if key == "password":
        return _redacted_password(parent)
    if key == "server_port":
        return 443
    if key == "uuid":
        return "00000000-0000-4000-8000-000000000000"
    if key in {"server_name", "servername", "sni"}:
        return "example.test"
    if key == "username":
        return "redacted-user"
    return "redacted-secret"


def _redacted_password(parent: dict[str, Any] | None) -> str:
    method = parent.get("method") if parent is not None else None
    if method == "2022-blake3-aes-128-gcm":
        return _SS2022_AES_128_PASSWORD
    if method in {"2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"}:
        return _SS2022_AES_256_PASSWORD
    return "redacted-password"


def collect_rule_set_references(value: Any) -> set[str]:
    references: set[str] = set()
    if isinstance(value, dict):
        if "rule_set" in value:
            rule_set = value["rule_set"]
            if isinstance(rule_set, str):
                references.add(rule_set)
            else:
                references.update(rule_set)
        for nested_value in value.values():
            references.update(collect_rule_set_references(nested_value))
    elif isinstance(value, list):
        for nested_value in value:
            references.update(collect_rule_set_references(nested_value))
    return references


@contextmanager
def http_server() -> Iterator[int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _DirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class _DirectHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"direct-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        return


def unused_port(socket_type: int) -> int:
    with socket.socket(socket.AF_INET, socket_type) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def exercise_generated_route_rules(
    config: dict[str, Any],
    mixed_port: int,
    dns_port: int,
    log_path: Path,
    clash_mode: str | None,
) -> set[int]:
    route_rules = config["route"]["rules"]
    covered_rules: set[int] = set()
    for index, rule in enumerate(route_rules):
        rule_clash_modes = _clash_modes(rule)
        if clash_mode is None and rule_clash_modes:
            continue
        if clash_mode is not None and clash_mode not in rule_clash_modes:
            continue
        if _exercise_route_rule(
            index,
            rule,
            route_rules[:index],
            mixed_port,
            dns_port,
            log_path,
            clash_mode,
        ):
            covered_rules.add(index)
    return covered_rules


def route_clash_modes(route_rules: list[dict[str, Any]]) -> list[str]:
    return sorted({mode for rule in route_rules for mode in _clash_modes(rule)})


def sanitize_host_label(value: str) -> str:
    label = re.sub(r"[^a-zA-Z0-9-]+", "-", value).strip("-").lower()
    return label[:40] or "keyword"


def assert_dns_rule_match(
    log_path: Path,
    index: int,
    rule: dict[str, Any],
    probe: Callable[[], _T],
) -> _T:
    return _assert_log_pattern_after_probe(
        log_path,
        _dns_rule_log_pattern(index, rule),
        f"DNS rule {index}",
        probe,
    )


def exercise_generated_dns_rules(
    dns_rules: list[dict[str, Any]],
    dns_port: int,
    log_path: Path,
) -> set[int]:
    covered_rules: set[int] = set()
    for index, rule in enumerate(dns_rules):
        qname, qtype = _dns_rule_probe(dns_rules, index, rule)
        assert_dns_rule_match(
            log_path,
            index,
            rule,
            partial(dns_exchange, dns_port, qname, qtype),
        )
        covered_rules.add(index)
    return covered_rules


def fakeip_dns_answers(
    dns_rules: list[dict[str, Any]],
    dns_port: int,
    log_path: Path,
) -> tuple[str, str]:
    for index, rule in enumerate(dns_rules):
        query_types = set(rule.get("query_type", []))
        if (
            rule.get("action") == "route"
            and rule.get("server") == "FakeIP"
            and {"A", "AAAA"} <= query_types
        ):
            qname = f"fakeip-probe-{random.getrandbits(64):016x}.invalid"
            a_answer = assert_dns_rule_match(
                log_path,
                index,
                rule,
                lambda: dns_query(dns_port, qname, _DNS_QUERY_TYPES["A"]),
            )
            aaaa_answer = assert_dns_rule_match(
                log_path,
                index,
                rule,
                lambda: dns_query(dns_port, qname, _DNS_QUERY_TYPES["AAAA"]),
            )
            return a_answer, aaaa_answer
    raise AssertionError("No FakeIP A/AAAA DNS rule found")


def file_contains(path: Path, needle: str) -> bool:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if path.exists() and needle in path.read_text(encoding="utf-8"):
            return True
        time.sleep(0.1)
    return False


def http_get_via_mixed(
    mixed_port: int,
    url: str,
    timeout: float | tuple[float, float] = 5,
    headers: dict[str, str] | None = None,
) -> requests.Response:
    session = requests.Session()
    session.trust_env = False
    return session.get(
        url,
        proxies={
            "http": f"http://127.0.0.1:{mixed_port}",
            "https": f"http://127.0.0.1:{mixed_port}",
        },
        timeout=timeout,
        headers=headers,
    )


def dns_query(port: int, qname: str, qtype: int) -> str:
    response, transaction_id = dns_exchange(port, qname, qtype)
    return _parse_dns_answer(response, transaction_id, qtype)


def dns_exchange(port: int, qname: str, qtype: int) -> tuple[bytes, int]:
    transaction_id = random.randrange(0, 65536)
    query = _build_dns_query(transaction_id, qname, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(query, ("127.0.0.1", port))
        response, _ = sock.recvfrom(4096)
    return response, transaction_id


def _exercise_route_rule(
    index: int,
    rule: dict[str, Any],
    previous_rules: list[dict[str, Any]],
    mixed_port: int,
    dns_port: int,
    log_path: Path,
    clash_mode: str | None,
) -> bool:
    if rule["action"] == "hijack-dns":
        _assert_route_probe_match(
            log_path,
            index,
            rule,
            lambda: dns_exchange(dns_port, "route-hijack-runtime.example", 1),
        )
        return True
    if probe := _route_probe(rule, previous_rules, index, clash_mode):
        _assert_route_probe_match(
            log_path,
            index,
            rule,
            lambda: _probe_http_via_mixed(mixed_port, probe),
        )
        return True
    if _clash_modes(rule):
        return False
    raise AssertionError(f"No runtime probe can be derived for route rule {index}: {rule}")


def _route_probe(
    rule: dict[str, Any],
    previous_rules: list[dict[str, Any]],
    index: int,
    clash_mode: str | None,
) -> RouteProbe | None:
    if rule["action"] == "sniff":
        return RouteProbe("route-sniff-runtime.example", 80, "pytest-runtime-probe", clash_mode)
    _assert_supported_route_matchers(rule, f"route rule {index}")
    for previous_index, previous_rule in enumerate(previous_rules):
        if _is_terminal_route_rule(previous_rule):
            _assert_supported_route_matchers(
                previous_rule, f"previous route rule {previous_index}"
            )

    candidates = _route_probe_candidates(rule, index, clash_mode)
    if not candidates:
        raise AssertionError(f"No runtime probe candidates can be derived for route rule {index}")

    randomizer = random.Random(_route_probe_seed(index, rule, clash_mode))
    randomizer.shuffle(candidates)
    blockers: dict[int, int] = {}
    matching_candidates = 0
    for candidate in candidates:
        if not _route_rule_matches(rule, candidate):
            continue
        matching_candidates += 1
        matching_previous_rules = [
            previous_index
            for previous_index, previous_rule in enumerate(previous_rules)
            if _is_terminal_route_rule(previous_rule)
            and _route_rule_matches(previous_rule, candidate)
        ]
        if not matching_previous_rules:
            return candidate
        for previous_index in matching_previous_rules:
            blockers[previous_index] = blockers.get(previous_index, 0) + 1

    if not matching_candidates:
        raise AssertionError(f"No runtime probe candidate satisfies route rule {index}")
    raise AssertionError(
        f"No precedence-safe runtime probe for route rule {index}; "
        f"all {len(candidates)} candidates were shadowed by earlier route rules "
        f"{sorted(blockers)}"
    )


def _route_probe_seed(index: int, rule: dict[str, Any], clash_mode: str | None) -> int:
    serialized = json.dumps(
        {"index": index, "rule": rule, "clash_mode": clash_mode},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return int.from_bytes(hashlib.sha256(serialized.encode()).digest()[:8], "big")


def _route_probe_candidates(
    rule: dict[str, Any], index: int, clash_mode: str | None
) -> list[RouteProbe]:
    hosts = _route_probe_hosts(rule, index)
    ports = _route_probe_ports(rule)
    user_agents = _route_probe_user_agents(rule)
    return sorted(
        {
            RouteProbe(host=host, port=port, user_agent=user_agent, clash_mode=clash_mode)
            for host in hosts
            for port in ports
            for user_agent in user_agents
        },
        key=lambda probe: (probe.host, probe.port, probe.user_agent, probe.clash_mode or ""),
    )


def _route_probe_hosts(rule: dict[str, Any], index: int) -> set[str]:
    hosts: set[str] = set()
    for value in _rule_values(rule, "domain"):
        if _is_http_host(value):
            hosts.add(value)
    for value in _rule_values(rule, "domain_suffix"):
        for label in _probe_labels(index):
            host = f"{label}.{value.lstrip('.')}"
            if _is_http_host(host):
                hosts.add(host)
    for value in _rule_values(rule, "domain_keyword"):
        for label in _probe_labels(index):
            host = f"{label}-{sanitize_host_label(value)}.invalid"
            if _is_http_host(host):
                hosts.add(host)
    for value in _rule_values(rule, "domain_regex"):
        hosts.update(_hosts_from_domain_regex(value, index))
    for value in _rule_values(rule, "ip_cidr"):
        hosts.update(_hosts_from_cidr(value))
    if _rule_truthy(rule, "ip_is_private"):
        hosts.add("127.0.0.1")
    if not hosts or _has_invert(rule) or not _has_destination_matcher(rule):
        hosts.add(f"route-runtime-{index}.invalid")
    return hosts


def _probe_labels(index: int) -> tuple[str, ...]:
    return tuple(f"runtime-{index}-{suffix}" for suffix in ("a", "b", "c"))


def _route_probe_ports(rule: dict[str, Any]) -> set[int]:
    ports = {80}
    for value in _rule_values(rule, "port"):
        if isinstance(value, int):
            ports.add(value)
    for value in _rule_values(rule, "port_range"):
        ports.add(_port_from_range(value))
    return ports


def _route_probe_user_agents(rule: dict[str, Any]) -> set[str]:
    user_agents = {"pytest-runtime-probe"}
    user_agents.update(_rule_values(rule, "user_agent"))
    return user_agents


def _rule_values(rule: dict[str, Any], key: str) -> list[Any]:
    values: list[Any] = []
    value = rule.get(key)
    if isinstance(value, list):
        values.extend(value)
    elif value is not None:
        values.append(value)
    for subrule in rule.get("rules", []):
        values.extend(_rule_values(subrule, key))
    return values


def _rule_truthy(rule: dict[str, Any], key: str) -> bool:
    if rule.get(key):
        return True
    return any(_rule_truthy(subrule, key) for subrule in rule.get("rules", []))


def _has_destination_matcher(rule: dict[str, Any]) -> bool:
    keys = {
        "domain",
        "domain_suffix",
        "domain_keyword",
        "domain_regex",
        "ip_cidr",
        "ip_is_private",
    }
    return any(key in rule for key in keys) or any(
        _has_destination_matcher(subrule) for subrule in rule.get("rules", [])
    )


def _has_invert(rule: dict[str, Any]) -> bool:
    return bool(rule.get("invert")) or any(
        _has_invert(subrule) for subrule in rule.get("rules", [])
    )


def _hosts_from_domain_regex(pattern: str, index: int) -> set[str]:
    candidate = pattern.strip("^").strip("$")
    candidate = re.sub(r"\(\?[:=!<][^)]*\)", "", candidate)
    candidate = re.sub(r"\([^)]*\)", f"runtime{index}", candidate)
    candidate = re.sub(r"\[[^]]+\][*+]", f"runtime{index}", candidate)
    candidate = candidate.replace(r"\.", ".")
    candidate = candidate.replace(".*", f"runtime{index}")
    candidate = candidate.replace(".+", f"runtime{index}")
    candidate = candidate.replace("?", "")
    candidate = candidate.replace("\\", "")
    if _is_http_host(candidate) and _matches_domain_regex(pattern, candidate):
        return {candidate}
    return set()


def _hosts_from_cidr(cidr: str) -> set[str]:
    network = ipaddress.ip_network(cidr, strict=False)
    offsets = {0, max(0, network.num_addresses // 2), network.num_addresses - 1}
    return {str(network.network_address + offset) for offset in offsets}


def _port_from_range(value: str | int) -> int:
    if isinstance(value, int):
        return value
    start, _, _ = value.partition(":")
    if not start.isdecimal():
        raise AssertionError(f"Cannot derive a port from range {value!r}")
    return int(start)


def _is_http_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    labels = host.rstrip(".").split(".")
    return all(
        label and len(label) <= 63 and re.fullmatch(r"[A-Za-z0-9-]+", label) for label in labels
    )


def _is_terminal_route_rule(rule: dict[str, Any]) -> bool:
    return rule.get("action") in {"reject", "route"}


def _assert_supported_route_matchers(rule: dict[str, Any], description: str) -> None:
    supported = {
        "action",
        "clash_mode",
        "domain",
        "domain_keyword",
        "domain_regex",
        "domain_suffix",
        "inbound",
        "invert",
        "ip_cidr",
        "ip_is_private",
        "ip_version",
        "method",
        "mode",
        "network",
        "outbound",
        "port",
        "port_range",
        "protocol",
        "rules",
        "server",
        "strategy",
        "client_subnet",
        "source_ip_cidr",
        "source_ip_is_private",
        "type",
        "user_agent",
    }
    unsupported = sorted(set(rule) - supported)
    if unsupported:
        raise AssertionError(f"Cannot derive a runtime probe for {description}: {unsupported}")
    for subrule in rule.get("rules", []):
        _assert_supported_route_matchers(subrule, description)


def _route_rule_matches(rule: dict[str, Any], probe: RouteProbe) -> bool:
    if rule.get("type") == "logical":
        submatches = [_route_rule_matches(subrule, probe) for subrule in rule["rules"]]
        match = all(submatches) if rule["mode"] == "and" else any(submatches)
    else:
        match = _default_route_rule_matches(rule, probe)
    return not match if rule.get("invert") else match


def _default_route_rule_matches(rule: dict[str, Any], probe: RouteProbe) -> bool:
    if not _matches_destination(rule, probe):
        return False
    if not _matches_ports(rule, probe):
        return False
    if not _matches_source_ip(rule):
        return False
    if not _matches_value(rule, "inbound", "mixed"):
        return False
    if not _matches_value(rule, "network", "tcp"):
        return False
    if not _matches_value(rule, "protocol", "http"):
        return False
    if not _matches_value(rule, "user_agent", probe.user_agent):
        return False
    if clash_mode := rule.get("clash_mode"):
        if clash_mode != probe.clash_mode:
            return False
    if ip_version := rule.get("ip_version"):
        if _probe_ip_version(probe) != ip_version:
            return False
    return True


def _matches_destination(rule: dict[str, Any], probe: RouteProbe) -> bool:
    matchers = (
        _rule_values(rule, "domain"),
        _rule_values(rule, "domain_suffix"),
        _rule_values(rule, "domain_keyword"),
        _rule_values(rule, "domain_regex"),
        _rule_values(rule, "ip_cidr"),
        [True] if _rule_truthy(rule, "ip_is_private") else [],
    )
    if not any(matchers):
        return True
    host = probe.host.rstrip(".").lower()
    return (
        any(host == value.lower() for value in matchers[0] if isinstance(value, str))
        or any(
            _matches_domain_suffix(host, value) for value in matchers[1] if isinstance(value, str)
        )
        or any(value.lower() in host for value in matchers[2] if isinstance(value, str))
        or any(
            _matches_domain_regex(value, host) for value in matchers[3] if isinstance(value, str)
        )
        or any(_matches_cidr(host, value) for value in matchers[4] if isinstance(value, str))
        or (bool(matchers[5]) and _is_private_ip(host))
    )


def _matches_ports(rule: dict[str, Any], probe: RouteProbe) -> bool:
    ports = _rule_values(rule, "port")
    ranges = _rule_values(rule, "port_range")
    if not ports and not ranges:
        return True
    return probe.port in ports or any(_port_in_range(probe.port, value) for value in ranges)


def _matches_source_ip(rule: dict[str, Any]) -> bool:
    cidrs = _rule_values(rule, "source_ip_cidr")
    if cidrs and not any(_matches_cidr("127.0.0.1", cidr) for cidr in cidrs):
        return False
    return not _rule_truthy(rule, "source_ip_is_private") or _is_private_ip("127.0.0.1")


def _matches_value(rule: dict[str, Any], key: str, value: str) -> bool:
    values = _rule_values(rule, key)
    return not values or value in values


def _matches_domain_suffix(host: str, suffix: str) -> bool:
    normalized = suffix.lstrip(".").lower()
    return host == normalized or host.endswith(f".{normalized}")


def _matches_domain_regex(pattern: str, host: str) -> bool:
    try:
        return re.search(pattern, host) is not None
    except re.error as error:
        raise AssertionError(f"Cannot evaluate domain regex {pattern!r}: {error}") from error


def _matches_cidr(host: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _is_private_ip(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def _probe_ip_version(probe: RouteProbe) -> int | None:
    try:
        return ipaddress.ip_address(probe.host).version
    except ValueError:
        return None


def _port_in_range(port: int, value: str | int) -> bool:
    if isinstance(value, int):
        return port == value
    start, separator, end = value.partition(":")
    if not separator or not start.isdecimal() or not end.isdecimal():
        raise AssertionError(f"Cannot evaluate port range {value!r}")
    return int(start) <= port <= int(end)


def _clash_modes(rule: dict[str, Any]) -> set[str]:
    modes: set[str] = set()
    if clash_mode := rule.get("clash_mode"):
        modes.add(clash_mode)
    for subrule in rule.get("rules", []):
        modes.update(_clash_modes(subrule))
    return modes


def _probe_http_via_mixed(mixed_port: int, probe: RouteProbe) -> None:
    try:
        http_get_via_mixed(
            mixed_port,
            probe.url,
            timeout=(0.25, 1),
            headers={"User-Agent": probe.user_agent},
        )
    except requests.RequestException:
        pass


def _assert_route_probe_match(
    log_path: Path,
    index: int,
    rule: dict[str, Any],
    probe: Callable[[], object],
) -> None:
    _assert_log_pattern_after_probe(
        log_path,
        _route_rule_log_pattern(index, rule),
        f"route rule {index}",
        probe,
    )


def _assert_log_pattern_after_probe(
    log_path: Path,
    pattern: str,
    description: str,
    probe: Callable[[], _T],
) -> _T:
    start_offset = _log_size(log_path)
    result = probe()
    deadline = time.monotonic() + 5
    log_segment = ""
    while time.monotonic() < deadline:
        log_segment = _read_log_from(log_path, start_offset)
        if re.search(pattern, log_segment):
            return result
        time.sleep(0.1)
    raise AssertionError(
        f"probe for {description} did not produce expected log pattern {pattern!r}; "
        f"new log segment was:\n{log_segment[-2000:]}"
    )


def _log_size(path: Path) -> int:
    if not path.exists():
        return 0
    return path.stat().st_size


def _read_log_from(path: Path, start_offset: int) -> str:
    if not path.exists():
        return ""
    with path.open("rb") as f:
        f.seek(start_offset)
        return f.read().decode("utf-8", errors="replace")


def _route_rule_log_pattern(index: int, rule: dict[str, Any]) -> str:
    match_prefix = rf"router: match\[{index}\].*=> "
    action = rule["action"]
    if action == "route":
        return match_prefix + rf"route\({re.escape(rule['outbound'])}\)"
    if action == "reject":
        method = rule.get("method")
        return match_prefix + (rf"reject\({re.escape(method)}\)" if method else "reject")
    if action == "resolve":
        return match_prefix + rf"resolve\({re.escape(rule['server'])}"
    if action in {"sniff", "hijack-dns"}:
        return match_prefix + re.escape(action)
    raise AssertionError(f"No runtime coverage pattern for route rule {index}: {rule}")


def _dns_rule_probe(
    dns_rules: list[dict[str, Any]],
    index: int,
    rule: dict[str, Any],
) -> tuple[str, int]:
    if rule["action"] == "predefined":
        return "predefined-runtime.example", _unmatched_dns_qtype(dns_rules[:index])
    if rule["action"] == "route":
        if query_types := rule.get("query_type"):
            return f"dns-rule-{index}.example", _dns_qtype_number(query_types[0])
        if qname := _dns_qname_from_rule(rule):
            return qname, _DNS_QUERY_TYPES["A"]
    raise AssertionError(f"No runtime DNS probe can be derived for rule {index}: {rule}")


def _dns_qname_from_rule(rule: dict[str, Any]) -> str | None:
    for value in rule.get("domain", []):
        if _is_http_host(value):
            return value
    for value in rule.get("domain_suffix", []):
        host = f"probe.{value.lstrip('.')}"
        if _is_http_host(host):
            return host
    for keyword in rule.get("domain_keyword", []):
        host = f"probe-{sanitize_host_label(keyword)}.example"
        if _is_http_host(host):
            return host
    for subrule in rule.get("rules", []):
        if qname := _dns_qname_from_rule(subrule):
            return qname
    return None


def _dns_qtype_number(query_type: str | int) -> int:
    if isinstance(query_type, int):
        return query_type
    if query_type not in _DNS_QUERY_TYPES:
        raise AssertionError(f"No DNS qtype number configured for {query_type}")
    return _DNS_QUERY_TYPES[query_type]


def _unmatched_dns_qtype(previous_rules: list[dict[str, Any]]) -> int:
    previous_query_types = {
        _dns_qtype_number(query_type)
        for rule in previous_rules
        for query_type in rule.get("query_type", [])
    }
    for query_type in ("HTTPS", "TXT", "MX"):
        qtype = _DNS_QUERY_TYPES[query_type]
        if qtype not in previous_query_types:
            return qtype
    raise AssertionError("No unused DNS qtype available for predefined-rule probe")


def _dns_rule_log_pattern(index: int, rule: dict[str, Any]) -> str:
    if rule["action"] == "predefined":
        return rf"dns: match\[\d+\] => predefined\({re.escape(rule['rcode'])}\)"
    if rule["action"] != "route":
        raise AssertionError(f"No runtime coverage pattern for DNS rule {index}: {rule}")

    server = re.escape(rule["server"])
    if query_types := rule.get("query_type"):
        if len(query_types) == 1:
            query_pattern = re.escape(query_types[0])
        else:
            query_pattern = (
                r"\[" + " ".join(re.escape(query_type) for query_type in query_types) + r"\]"
            )
        return rf"dns: match\[\d+\].*query_type={query_pattern}.*=> route\({server}\)"
    if rule.get("type") == "logical":
        return rf"dns: match\[\d+\].*domain_suffix=.*=> route\({server}\)"
    raise AssertionError(f"No runtime coverage pattern for DNS rule {index}: {rule}")


def _build_dns_query(transaction_id: int, qname: str, qtype: int) -> bytes:
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    encoded_name = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in qname.rstrip(".").split(".")
    )
    return header + encoded_name + b"\x00" + struct.pack("!HH", qtype, 1)


def _parse_dns_answer(response: bytes, transaction_id: int, qtype: int) -> str:
    header_id, _, _, answer_count, _, _ = struct.unpack("!HHHHHH", response[:12])
    if header_id != transaction_id:
        raise AssertionError("DNS response transaction ID mismatch")
    offset = _skip_dns_name(response, 12) + 4
    for _ in range(answer_count):
        offset = _skip_dns_name(response, offset)
        answer_type, answer_class, _, data_length = struct.unpack(
            "!HHIH", response[offset : offset + 10]
        )
        offset += 10
        data = response[offset : offset + data_length]
        offset += data_length
        if answer_type == qtype and answer_class == 1:
            if qtype == 1 and data_length == 4:
                return str(ipaddress.IPv4Address(data))
            if qtype == 28 and data_length == 16:
                return str(ipaddress.IPv6Address(data))
    raise AssertionError(f"DNS response did not contain qtype {qtype}")


def _skip_dns_name(message: bytes, offset: int) -> int:
    while True:
        length = message[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length


def assert_no_secret_markers(value: Any) -> None:
    if isinstance(value, dict):
        for nested_value in value.values():
            assert_no_secret_markers(nested_value)
    elif isinstance(value, list):
        for nested_value in value:
            assert_no_secret_markers(nested_value)
    elif isinstance(value, str) and "@secret:" in value:
        raise AssertionError("unsanitized secret marker remains")


def _sanitize_secret_markers(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _sanitize_secret_markers(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [_sanitize_secret_markers(nested) for nested in value]
    if isinstance(value, str):
        full_match = _SECRET_MARKER_RE.fullmatch(value)
        if full_match:
            return _safe_secret_value(full_match)
        return _SECRET_MARKER_RE.sub(lambda match: str(_safe_secret_value(match)), value)
    return value


def _safe_secret_value(match: re.Match[str]) -> str | int:
    key = match.group("key")
    cast = match.group("cast")
    if key not in _SAFE_SECRET_VALUES:
        raise KeyError(f"No safe placeholder configured for {key}")
    value = _SAFE_SECRET_VALUES[key]
    if cast == "int":
        if not isinstance(value, int):
            raise TypeError(f"Safe placeholder for {key} must be int")
        return value
    if cast is not None:
        raise ValueError(f"Unsupported secret cast {cast!r} for {key}")
    return value


def _synthetic_custom_proxy_infos() -> list[dict[str, Any]]:
    return [
        _ss_proxy_info("Custom-Japan-01", "127.0.0.1", 20010),
    ]


def _synthetic_subscription_proxy_infos() -> list[dict[str, Any]]:
    proxies: list[dict[str, Any]] = []
    for region, base_port in (
        ("Hong Kong", 21000),
        ("Singapore", 22000),
        ("Taiwan", 23000),
        ("United States", 24000),
        ("Japan", 25000),
    ):
        proxies.append(_ss_proxy_info(f"{region}-01", "127.0.0.1", base_port + 1))
        proxies.append(_ss_proxy_info(f"{region}-02", "127.0.0.1", base_port + 2))
    return proxies


def _ss_proxy_info(name: str, server: str, port: int) -> dict[str, Any]:
    return {
        "name": name,
        "type": "ss",
        "server": server,
        "port": port,
        "cipher": "aes-128-gcm",
        "password": "synthetic-password",
        "udp": True,
    }


def _patch_live_schema_compatibility(schema: dict[str, Any]) -> None:
    _allow_documented_domain_resolver_object(schema)
    _allow_disabled_ntp_without_server(schema)


def _allow_documented_domain_resolver_object(schema: dict[str, Any]) -> None:
    # The schema gist lags sing-box's documented object form for dial domain_resolver.
    dial_schema = schema["$defs"]["shared/dial.schema.json"]
    domain_resolver = dial_schema["properties"]["domain_resolver"]
    if domain_resolver.get("type") == "string":
        description = domain_resolver.get("description")
        domain_resolver.clear()
        if description is not None:
            domain_resolver["description"] = description
        domain_resolver["oneOf"] = [
            {"type": "string"},
            _domain_resolver_object_schema(schema),
        ]


def _domain_resolver_object_schema(schema: dict[str, Any]) -> dict[str, Any]:
    route_action = schema["$defs"]["dns/rule_action.schema.json"]["oneOf"][0]
    return {
        "type": "object",
        "required": ["server"],
        "additionalProperties": False,
        "properties": {
            key: deepcopy(value)
            for key, value in route_action["properties"].items()
            if key != "action"
        },
    }


def _allow_disabled_ntp_without_server(schema: dict[str, Any]) -> None:
    # sing-box accepts disabled NTP without a server; `sing-box check` is authoritative.
    ntp_schema = schema["$defs"]["ntp.schema.json"]
    for subschema in [ntp_schema, *ntp_schema.get("allOf", [])]:
        required = subschema.get("required")
        if isinstance(required, list) and "server" in required:
            required.remove("server")
