from __future__ import annotations

import json
import subprocess
import traceback
from pathlib import Path
from typing import Any
from typing import Iterator

import pytest
from _support.sing_box import _SAFE_SECRET_VALUES
from _support.sing_box import SourceContext
from _support.sing_box import generate_selected_artifacts
from _support.sing_box import load_config
from _support.sing_box import rule_set_compiler

# `DOMAIN` already ships in the public Guard rule set; accepted, do not extend this list.
_PUBLIC_SECRET_KEYS = frozenset({"DOMAIN"})
_SING_BOX_CONFIGS = ("sing-box-daemon", "sing-box-clients", "sing-box-apple")


def _secret_needles() -> dict[str, str]:
    needles: dict[str, str] = {}
    for key, value in _SAFE_SECRET_VALUES.items():
        if key in _PUBLIC_SECRET_KEYS or not isinstance(value, str):
            continue
        for item in value.split():
            # Filter-list secrets look like `DOMAIN-SUFFIX,host`; match the payload.
            needles[item.rsplit(",", 1)[-1]] = key
    return needles


def _string_leaves(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for nested in value.values():
            yield from _string_leaves(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _string_leaves(nested)
    elif isinstance(value, str):
        yield value


def test_published_rule_sets_exclude_secret_values(
    source_context: SourceContext,
    tmp_path: Path,
) -> None:
    """Published `.srs` rule sets are plaintext, so no secret may be compiled into them.

    Generates every sing-box variant from the sanitized source, decompiles each
    rule set, and asserts none of the safe secret placeholders appear. Secret-bearing
    rules must set `inline: true` to stay in the encrypted `config.json`.
    """
    generate_selected_artifacts(source_context, tmp_path, _SING_BOX_CONFIGS)
    needles = _secret_needles()
    leaks: list[str] = []
    with rule_set_compiler() as compiler:
        assert compiler._sing_box is not None
        for srs in sorted(tmp_path.glob("*/*.srs")):
            decompiled = srs.with_suffix(".json")
            subprocess.run(
                [compiler._sing_box, "rule-set", "decompile", srs, "-o", decompiled],
                check=True,
                capture_output=True,
            )
            for leaf in _string_leaves(json.loads(decompiled.read_text(encoding="utf-8"))):
                payload = leaf.lstrip(".").split("/", 1)[0]
                if payload in needles:
                    leaks.append(f"{srs.parent.name}/{srs.name}: {needles[payload]}")
    assert not leaks


def test_inline_rule_stays_in_config(daemon_artifacts: Path) -> None:
    config = load_config(daemon_artifacts)
    direct_rule = config["dns"]["rules"][0]
    assert direct_rule["server"] == "DIRECT"
    assert "rule_set" not in json.dumps(direct_rule)
    assert '"inline"' not in json.dumps(config)
    domain_rule = direct_rule["rules"][1]
    assert "real-ip-suffix-0.test" in domain_rule["domain_suffix"]
    assert domain_rule["domain"] == ["real-ip-host.test"]


def test_secret_cast_error_omits_plaintext(monkeypatch: pytest.MonkeyPatch) -> None:
    from common._manager import _SecretsManager

    sentinel = "plaintext-sentinel-value"
    # Unregistered keys fall back to the environment.
    monkeypatch.setenv("CAST_PROBE_SECRET", sentinel)
    manager = _SecretsManager()
    with pytest.warns(UserWarning), pytest.raises(ValueError) as excinfo:
        manager.expand_secret("@secret:CAST_PROBE_SECRET!int")
    rendered = "".join(traceback.format_exception(excinfo.value))
    assert "CAST_PROBE_SECRET" in rendered
    assert sentinel not in rendered
