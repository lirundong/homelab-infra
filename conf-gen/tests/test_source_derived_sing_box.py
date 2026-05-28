from __future__ import annotations

import ipaddress
import socket
from pathlib import Path

from _support.sing_box import SourceContext
from _support.sing_box import collect_rule_set_references
from _support.sing_box import exercise_generated_dns_rules
from _support.sing_box import exercise_generated_route_rules
from _support.sing_box import fakeip_dns_answers
from _support.sing_box import fetch_live_schema
from _support.sing_box import file_contains
from _support.sing_box import generate_runtime_config
from _support.sing_box import generate_selected_artifacts
from _support.sing_box import http_get_via_mixed
from _support.sing_box import http_server
from _support.sing_box import load_config
from _support.sing_box import route_clash_modes
from _support.sing_box import rule_set_compiler
from _support.sing_box import run_sing_box_check
from _support.sing_box import running_sing_box
from _support.sing_box import sanitize_host_label
from _support.sing_box import unused_port
from _support.sing_box import validate_config_schema


def test_source_derived_daemon_generates_valid_artifacts(
    daemon_artifacts: Path,
) -> None:
    """Validates the daemon generator's file-level contract.

    This is the cheap structural test for the source-derived daemon output. It
    proves generation emits a config plus compiled rule-set files, then checks
    that every DNS and route rule-set reference points at a generated rule-set
    tag. This catches missing `.srs` artifacts, stale rule-set references, and
    accidental divergence between `route.rule_set` declarations and rule usage.
    """
    config_path = daemon_artifacts / "config.json"
    assert config_path.is_file()
    srs_files = {path.name for path in daemon_artifacts.glob("*.srs")}
    assert srs_files

    config = load_config(daemon_artifacts)
    rule_sets = config["route"]["rule_set"]
    rule_set_tags = {rule_set["tag"] for rule_set in rule_sets}
    assert rule_set_tags
    assert {f"{tag}.srs" for tag in rule_set_tags} == srs_files

    referenced_tags = collect_rule_set_references(config["dns"]["rules"])
    referenced_tags |= collect_rule_set_references(config["route"]["rules"])
    assert referenced_tags
    assert referenced_tags <= rule_set_tags


def test_source_derived_daemon_schema_and_sing_box_check(
    daemon_artifacts: Path,
) -> None:
    """Checks the daemon output against external validators.

    This is the static correctness test for the generated daemon config. It
    validates `config.json` against the live sing-box JSON Schema and then runs
    `sing-box check` using the same `RuleSetCompiler` context that compiled the
    source-derived rule sets. Together these cover both schema-level shape and
    sing-box's own semantic config validation.
    """
    config = load_config(daemon_artifacts)
    validate_config_schema(config, fetch_live_schema())

    with rule_set_compiler() as compiler:
        run_sing_box_check(compiler._sing_box, daemon_artifacts)


def test_source_derived_client_omits_disabled_clash_api(
    source_context: SourceContext,
    tmp_path: Path,
) -> None:
    """Checks derived client config overrides for inherited experimental sections.

    The Android client derives from the daemon generator but disables the
    daemon-only Clash API with `clash_api: null` in `source.yaml`. The generated
    JSON should omit that inherited object instead of serializing a JSON null,
    while still preserving the client's own cache-file settings.
    """
    generate_selected_artifacts(
        context=source_context,
        output_root=tmp_path,
        names=["sing-box-daemon", "sing-box-clients"],
    )

    config = load_config(tmp_path / "sing-box-clients")
    assert "clash_api" not in config["experimental"]
    assert config["experimental"]["cache_file"]["path"] == "cache.db"


def test_source_derived_runtime_without_tun(
    source_context: SourceContext,
    tmp_path: Path,
) -> None:
    """Exercises real route and DNS behavior without requiring a TUN device.

    This is the end-to-end runtime test. It generates a localhost-only sing-box
    variant from the production daemon rules, starts sing-box with a mixed HTTP
    proxy and UDP DNS inbound, then drives requests through those inbounds. Each
    route and DNS probe checks only the log segment written after that specific
    probe, so the test proves the intended rule/action handled the matching
    request instead of only proving that every expected outbound appeared
    somewhere in the aggregate log. The test also verifies representative
    user-visible behavior: private HTTP traffic reaches `DIRECT`, secured DNS is
    rejected, and A/AAAA DNS answers are generated from FakeIP ranges.
    """
    mixed_port = unused_port(socket.SOCK_STREAM)
    dns_port = unused_port(socket.SOCK_DGRAM)
    runtime_dir = generate_runtime_config(
        context=source_context,
        output_root=tmp_path,
        mixed_port=mixed_port,
        dns_port=dns_port,
    )
    config = load_config(runtime_dir)

    covered_route_rules: set[int] = set()
    with (
        rule_set_compiler() as compiler,
        http_server() as http_port,
        running_sing_box(compiler._sing_box, runtime_dir),
    ):
        direct_response = http_get_via_mixed(
            mixed_port,
            f"http://127.0.0.1:{http_port}/private",
            timeout=5,
        )
        assert direct_response.status_code == 200
        assert direct_response.text == "direct-ok"
        assert file_contains(runtime_dir / "sing-box.log", "route(DIRECT)")

        reject_response = http_get_via_mixed(
            mixed_port,
            "http://example.com:853/",
            timeout=(1, 3),
        )
        assert reject_response.status_code == 502
        assert file_contains(runtime_dir / "sing-box.log", "reject(drop)")

        covered_route_rules |= exercise_generated_route_rules(
            config,
            mixed_port,
            dns_port,
            runtime_dir / "sing-box.log",
            clash_mode=None,
        )
        dns_rules = config["dns"]["rules"]
        dns_log_path = runtime_dir / "sing-box.log"
        covered_dns_rules = exercise_generated_dns_rules(
            dns_rules,
            dns_port,
            dns_log_path,
        )
        a_answer, aaaa_answer = fakeip_dns_answers(
            dns_rules,
            dns_port,
            dns_log_path,
        )
        assert ipaddress.ip_address(a_answer) in ipaddress.ip_network("198.18.0.0/15")
        assert ipaddress.ip_address(aaaa_answer) in ipaddress.ip_network("fc00::/18")
        assert covered_dns_rules == set(range(len(dns_rules)))

    for clash_mode in route_clash_modes(config["route"]["rules"]):
        mode_mixed_port = unused_port(socket.SOCK_STREAM)
        mode_dns_port = unused_port(socket.SOCK_DGRAM)
        mode_runtime_dir = generate_runtime_config(
            context=source_context,
            output_root=tmp_path / f"{sanitize_host_label(clash_mode)}-mode",
            mixed_port=mode_mixed_port,
            dns_port=mode_dns_port,
            clash_mode=clash_mode,
        )
        with (
            rule_set_compiler() as compiler,
            running_sing_box(
                compiler._sing_box,
                mode_runtime_dir,
            ),
        ):
            covered_route_rules |= exercise_generated_route_rules(
                config,
                mode_mixed_port,
                mode_dns_port,
                mode_runtime_dir / "sing-box.log",
                clash_mode=clash_mode,
            )

    assert covered_route_rules == set(range(len(config["route"]["rules"])))
