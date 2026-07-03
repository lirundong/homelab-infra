from __future__ import annotations

import socket
from pathlib import Path

from _support.sing_box import SourceContext
from _support.sing_box import assert_local_ruleset_rule_alignment
from _support.sing_box import exercise_generated_dns_rule_branches
from _support.sing_box import exercise_generated_dns_rules
from _support.sing_box import exercise_generated_route_rules
from _support.sing_box import expected_dns_branches
from _support.sing_box import expected_route_branches
from _support.sing_box import generate_local_ruleset_runtime_config
from _support.sing_box import generate_runtime_config
from _support.sing_box import load_config
from _support.sing_box import route_clash_modes
from _support.sing_box import rule_set_compiler
from _support.sing_box import running_sing_box
from _support.sing_box import sanitize_host_label
from _support.sing_box import unused_port


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
