from __future__ import annotations

from pathlib import Path

import pytest

from _support.sing_box import (
    fetch_live_schema,
    load_config,
    run_redacted_sing_box_check,
    rule_set_compiler,
    validate_config_schema,
)


def test_generated_artifacts_pass_schema_and_sing_box_check(
    artifact_dir: Path,
    check_config_names: frozenset[str],
) -> None:
    """Checks generated production sing-box artifacts from the CLI job.

    This is the CI artifact gate for the already-generated `conf-gen` output.
    It finds each sing-box `config.json` under the artifact root, validates the
    raw config against the live schema, and then runs `sing-box check` on a
    secret-redacted copy for config names selected by the CI runner.
    Platform-specific configs still get schema coverage even when the local
    runner cannot semantically check them. This test does not generate configs
    or start sing-box at runtime; those paths are covered by the source-derived
    pytest cases.
    """
    config_dirs = sorted(path.parent for path in artifact_dir.glob("*/config.json"))
    if not config_dirs:
        pytest.fail(f"No sing-box config directories found under {artifact_dir}")

    schema = fetch_live_schema()
    checked_config_dirs: list[Path] = []
    with rule_set_compiler() as compiler:
        for config_dir in config_dirs:
            config = load_config(config_dir)
            validate_config_schema(config, schema)
            if config_dir.name in check_config_names:
                run_redacted_sing_box_check(compiler._sing_box, config_dir, config)
                checked_config_dirs.append(config_dir)

    checked_config_names = {config_dir.name for config_dir in checked_config_dirs}
    if checked_config_names != check_config_names:
        missing_config_names = sorted(check_config_names - checked_config_names)
        pytest.fail(f"Missing local sing-box checks for {missing_config_names}")
