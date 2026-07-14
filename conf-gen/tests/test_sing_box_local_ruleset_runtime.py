from __future__ import annotations

import ipaddress
import re
import socket
import time
from pathlib import Path
from typing import Any
from typing import Sequence

import pytest
from _support.sing_box import SourceContext
from _support.sing_box import RouteProbe
from _support.sing_box import _execute_route_probe
from _support.sing_box import _route_rule_matches
from _support.sing_box import assert_local_ruleset_rule_alignment
from _support.sing_box import exercise_generated_dns_rule_branches
from _support.sing_box import exercise_generated_dns_rules
from _support.sing_box import exercise_generated_route_rules
from _support.sing_box import expected_dns_branches
from _support.sing_box import expected_route_branches
from _support.sing_box import generate_local_ruleset_runtime_config
from _support.sing_box import generate_runtime_config
from _support.sing_box import get_generate_info
from _support.sing_box import load_config
from _support.sing_box import route_clash_modes
from _support.sing_box import rule_set_compiler
from _support.sing_box import running_sing_box
from _support.sing_box import sanitize_host_label
from _support.sing_box import unused_port


def _identity_rule_ir_pass(
    rule_groups: Sequence[Sequence[Any]], priority: Any = None
) -> list[list[Any]]:
    return [list(rule_group) for rule_group in rule_groups]


def _test_rule_ir_key(rule_ir: Any) -> tuple[object, str]:
    class_name = type(rule_ir).__name__
    if class_name == "Domain":
        return "domain", rule_ir._val
    if class_name == "DomainSuffix":
        return "domain_suffix", rule_ir._val
    if class_name == "DomainListItem":
        if rule_ir._val.startswith("+") and rule_ir._val.count("+") == 1:
            if suffix := rule_ir._val[1:].removeprefix("."):
                return "domain_suffix", suffix
        if "+" not in rule_ir._val and "*" not in rule_ir._val:
            if domain := rule_ir._val.removeprefix("."):
                return "domain", domain
    return type(rule_ir), rule_ir._val


def _deduplicated_sing_box_matchers(
    context: SourceContext,
) -> tuple[list[tuple[int, str, str]], set[str]]:
    seen: dict[tuple[object, str], int] = {}
    duplicate_matchers: list[tuple[int, str, str]] = []
    unsupported_types: set[str] = set()
    for group_index, proxy_group in enumerate(context.proxy_groups):
        for filter_ir in proxy_group._filters:
            key = _test_rule_ir_key(filter_ir)
            if key not in seen:
                seen[key] = group_index
                continue
            retained_group_index = seen[key]
            try:
                matcher, value = filter_ir.sing_box_rule
                duplicate_matchers.append((retained_group_index, matcher, value))
            except ValueError as error:
                if not str(error).endswith("is not supported by sing-box."):
                    raise
                unsupported_types.add(type(filter_ir).__name__)
    return duplicate_matchers, unsupported_types


def _explicit_filter_duplicates(context: SourceContext) -> tuple[int, int]:
    from conf_gen.rule.parser import parse_filter

    daemon_info = get_generate_info(context.source, "sing-box-daemon")
    filter_lists = 0
    duplicates = 0

    def scan(value: Any) -> None:
        nonlocal filter_lists, duplicates
        if isinstance(value, dict):
            if filters := value.get("filters"):
                filter_lists += 1
                seen: set[tuple[object, str]] = set()
                for filter_info in filters:
                    for filter_ir in parse_filter(
                        filter_info, match_with_dns=value.get("match_with_dns")
                    ):
                        key = _test_rule_ir_key(filter_ir)
                        if key in seen:
                            duplicates += 1
                        seen.add(key)
            for nested in value.values():
                scan(nested)
        elif isinstance(value, (list, tuple)):
            for nested in value:
                scan(nested)

    scan(daemon_info["dns"])
    scan(daemon_info["route"])
    return filter_lists, duplicates


def _contains_matcher(rule: dict[str, Any], matcher: str, value: str) -> bool:
    values = rule.get(matcher, [])
    if not isinstance(values, list):
        values = [values]
    return value in values or any(
        _contains_matcher(subrule, matcher, value) for subrule in rule.get("rules", [])
    )


def _retained_route_rule(
    route_rules: list[dict[str, Any]],
    group_name: str,
    prefer_reject: bool,
    matcher: str,
    value: str,
) -> tuple[int, dict[str, Any]]:
    matches = []
    for index, rule in enumerate(route_rules):
        expected_action = (
            rule.get("action") == "reject"
            if prefer_reject
            else (rule.get("action") == "route" and rule.get("outbound") == group_name)
        )
        if expected_action and _contains_matcher(rule, matcher, value):
            matches.append((index, rule))
    assert len(matches) == 1
    return matches[0]


def _deduplicated_matcher_probe(
    matcher: str,
    value: str,
    occurrence: int,
) -> RouteProbe:
    if matcher == "domain":
        hosts = [value]
    elif matcher == "domain_suffix":
        hosts = [f"deduplicated-{occurrence}-{suffix}.{value.lstrip('.')}" for suffix in "abc"]
    elif matcher == "domain_keyword":
        hosts = [f"deduplicated-{occurrence}-{sanitize_host_label(value)}.invalid"]
    elif matcher == "ip_cidr":
        network = ipaddress.ip_network(value, strict=False)
        offsets = (0, network.num_addresses // 2, network.num_addresses - 1)
        hosts = [str(network.network_address + offset) for offset in offsets]
    else:
        raise AssertionError(f"No duplicate runtime probe builder for {matcher}")

    matcher_rule = {matcher: [value]}
    for host in hosts:
        probe = RouteProbe(
            host=host,
            port=80,
            user_agent="pytest-deduplication-probe",
            clash_mode=None,
            network="tcp",
            payload="raw",
        )
        if _route_rule_matches(matcher_rule, probe):
            return probe
    raise AssertionError(f"No runtime probe for deduplicated IR occurrence {occurrence}")


def _runtime_route_match(log_path: Path, mixed_port: int, probe: RouteProbe) -> tuple[int, str]:
    start_offset = log_path.stat().st_size if log_path.exists() else 0
    _execute_route_probe(mixed_port, probe)
    pattern = re.compile(
        r"router: match\[(?P<index>\d+)\].*=> "
        r"(?P<action>route\([^)]*\)|reject(?:\([^)]*\))?|hijack-dns)"
    )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if log_path.exists():
            with log_path.open("rb") as log:
                log.seek(start_offset)
                segment = log.read().decode("utf-8", errors="replace")
            if matches := list(pattern.finditer(segment)):
                matched = matches[-1]
                return int(matched.group("index")), matched.group("action")
        time.sleep(0.1)
    raise AssertionError("deduplicated IR probe did not produce a terminal route match")


def test_local_ruleset_runtime_matches_inline_probe_behavior(
    source_context: SourceContext,
    tmp_path: Path,
) -> None:
    """Exercises the shipped config shape: rules extracted into compiled rule sets.

    Production sing-box configs run `extract_ruleset_inplace`, which rewrites
    rule matchers into `rule_set` references backed by compiled `.srs` files;
    the inline runtime test never executes that shape, so an extraction or
    compilation bug could change shipped routing behavior while all inline
    probes stay green. This test closes that gap: it generates the extracted
    config with `rule_set` entries rewritten from remote to local `.srs` paths,
    then drives the full probe suite against it using probes derived from the
    inline config (extraction preserves rule order, so `match[N]` indices
    align — asserted up front). Identical coverage proves the compiled rule
    sets match the inline matchers rule by rule and branch by branch.
    """
    mixed_port = unused_port(socket.SOCK_STREAM)
    dns_port = unused_port(socket.SOCK_DGRAM)
    inline_dir = generate_runtime_config(
        context=source_context,
        output_root=tmp_path / "inline",
        mixed_port=mixed_port,
        dns_port=dns_port,
    )
    inline_config = load_config(inline_dir)
    local_dir = generate_local_ruleset_runtime_config(
        context=source_context,
        output_root=tmp_path,
        mixed_port=mixed_port,
        dns_port=dns_port,
    )
    local_config = load_config(local_dir)
    assert_local_ruleset_rule_alignment(inline_config, local_config)
    assert any("rule_set" in rule for rule in local_config["route"]["rules"])

    covered_route_rules: set[int] = set()
    covered_route_branches: set[tuple[int, int]] = set()
    covered_dns_branches: set[tuple[int, int]] = set()
    dns_rules = inline_config["dns"]["rules"]
    with (
        rule_set_compiler() as compiler,
        running_sing_box(compiler._sing_box, local_dir),
    ):
        covered_rules, covered_branches = exercise_generated_route_rules(
            inline_config,
            mixed_port,
            dns_port,
            local_dir / "sing-box.log",
            clash_mode=None,
        )
        covered_route_rules |= covered_rules
        covered_route_branches |= covered_branches
        covered_dns_rules = exercise_generated_dns_rules(
            dns_rules,
            dns_port,
            local_dir / "sing-box.log",
        )
        covered_dns_branches |= exercise_generated_dns_rule_branches(
            dns_rules,
            dns_port,
            local_dir / "sing-box.log",
            clash_mode=None,
        )
        assert covered_dns_rules == set(range(len(dns_rules)))

    for clash_mode in route_clash_modes(inline_config["route"]["rules"]):
        mode_mixed_port = unused_port(socket.SOCK_STREAM)
        mode_dns_port = unused_port(socket.SOCK_DGRAM)
        mode_local_dir = generate_local_ruleset_runtime_config(
            context=source_context,
            output_root=tmp_path / f"{sanitize_host_label(clash_mode)}-mode",
            mixed_port=mode_mixed_port,
            dns_port=mode_dns_port,
            clash_mode=clash_mode,
        )
        with (
            rule_set_compiler() as compiler,
            running_sing_box(compiler._sing_box, mode_local_dir),
        ):
            covered_rules, covered_branches = exercise_generated_route_rules(
                inline_config,
                mode_mixed_port,
                mode_dns_port,
                mode_local_dir / "sing-box.log",
                clash_mode=clash_mode,
            )
            covered_route_rules |= covered_rules
            covered_route_branches |= covered_branches
            covered_dns_branches |= exercise_generated_dns_rule_branches(
                dns_rules,
                mode_dns_port,
                mode_local_dir / "sing-box.log",
                clash_mode=clash_mode,
            )

    assert covered_route_rules == set(range(len(inline_config["route"]["rules"])))
    assert covered_route_branches == expected_route_branches(inline_config["route"]["rules"])
    assert covered_dns_branches == expected_dns_branches(dns_rules)


def test_deduplicated_rule_irs_preserve_origin_master_routing(
    source_context: SourceContext,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from conf_gen.generator import _base_generator
    from conf_gen.generator import sing_box_generator

    duplicate_matchers, unsupported_types = _deduplicated_sing_box_matchers(source_context)
    assert duplicate_matchers
    assert unsupported_types <= {"UserAgent"}
    explicit_filter_lists, explicit_duplicates = _explicit_filter_duplicates(source_context)
    assert explicit_filter_lists > 0
    assert explicit_duplicates == 0

    baseline_mixed_port = unused_port(socket.SOCK_STREAM)
    baseline_dns_port = unused_port(socket.SOCK_DGRAM)
    with monkeypatch.context() as patch:
        patch.setattr(_base_generator, "deduplicate_rule_irs", _identity_rule_ir_pass)
        patch.setattr(sing_box_generator, "deduplicate_rule_irs", _identity_rule_ir_pass)
        baseline_dir = generate_runtime_config(
            context=source_context,
            output_root=tmp_path / "origin-master",
            mixed_port=baseline_mixed_port,
            dns_port=baseline_dns_port,
        )
    baseline_config = load_config(baseline_dir)

    current_mixed_port = unused_port(socket.SOCK_STREAM)
    current_dns_port = unused_port(socket.SOCK_DGRAM)
    current_dir = generate_runtime_config(
        context=source_context,
        output_root=tmp_path / "ir-deduplicated",
        mixed_port=current_mixed_port,
        dns_port=current_dns_port,
    )
    current_config = load_config(current_dir)

    baseline_rules = baseline_config["route"]["rules"]
    current_rules = current_config["route"]["rules"]
    runtime_cases = []
    for occurrence, (group_index, matcher, value) in enumerate(duplicate_matchers):
        proxy_group = source_context.proxy_groups[group_index]
        baseline_index, baseline_rule = _retained_route_rule(
            baseline_rules,
            proxy_group.name,
            proxy_group.prefer_reject,
            matcher,
            value,
        )
        current_index, current_rule = _retained_route_rule(
            current_rules,
            proxy_group.name,
            proxy_group.prefer_reject,
            matcher,
            value,
        )
        assert {key: current_rule.get(key) for key in ("action", "method", "outbound")} == {
            key: baseline_rule.get(key) for key in ("action", "method", "outbound")
        }
        probe = _deduplicated_matcher_probe(
            matcher,
            value,
            occurrence,
        )
        assert _route_rule_matches(baseline_rule, probe)
        assert _route_rule_matches(current_rule, probe)
        runtime_cases.append(
            (
                occurrence,
                matcher,
                value,
                probe,
                baseline_index,
                current_index,
            )
        )

    with (
        rule_set_compiler() as compiler,
        running_sing_box(compiler._sing_box, baseline_dir),
        running_sing_box(compiler._sing_box, current_dir),
    ):
        for (
            occurrence,
            matcher,
            value,
            probe,
            retained_baseline_index,
            retained_current_index,
        ) in runtime_cases:
            baseline_index, baseline_action = _runtime_route_match(
                baseline_dir / "sing-box.log", baseline_mixed_port, probe
            )
            current_index, current_action = _runtime_route_match(
                current_dir / "sing-box.log", current_mixed_port, probe
            )
            assert baseline_index < len(baseline_rules)
            assert current_index < len(current_rules)
            assert current_action == baseline_action, (
                f"deduplicated IR occurrence {occurrence} ({matcher}, {value}) "
                "changed its runtime destination"
            )
            assert current_index == baseline_index, (
                f"deduplicated IR occurrence {occurrence} ({matcher}, {value}) "
                "matched a different terminal rule"
            )
            if baseline_index == retained_baseline_index:
                assert current_index == retained_current_index
            else:
                assert baseline_index < retained_baseline_index
                assert current_index < retained_current_index
