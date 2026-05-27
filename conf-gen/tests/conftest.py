from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

import pytest
from _support.sing_box import SourceContext
from _support.sing_box import build_source_context
from _support.sing_box import generate_daemon_artifacts


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--artifact-dir",
        action="store",
        help="Directory produced by conf-gen for generated artifact validation.",
    )
    parser.addoption(
        "--check-config",
        action="append",
        default=[],
        help="Generated sing-box config name to validate with local sing-box check.",
    )


@pytest.fixture(scope="session")
def artifact_dir(request: pytest.FixtureRequest) -> Path:
    value = request.config.getoption("--artifact-dir")
    if value is None:
        pytest.skip("--artifact-dir is required for generated artifact validation")
    return Path(value)


@pytest.fixture(scope="session")
def check_config_names(request: pytest.FixtureRequest) -> frozenset[str]:
    return frozenset(request.config.getoption("--check-config"))


@pytest.fixture(scope="session", autouse=True)
def safe_secret_environment(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    safe_secrets_file = tmp_path_factory.mktemp("safe-secrets") / "secrets.yaml"
    safe_secrets_file.write_text("{}\n", encoding="utf-8")
    previous_password = os.environ.get("PASSWORD")
    previous_secrets_file = os.environ.get("SECRETS_FILE")
    had_password = "PASSWORD" in os.environ
    had_secrets_file = "SECRETS_FILE" in os.environ
    os.environ["PASSWORD"] = "test-master-password"
    os.environ["SECRETS_FILE"] = str(safe_secrets_file)
    yield
    if had_password and previous_password is not None:
        os.environ["PASSWORD"] = previous_password
    else:
        os.environ.pop("PASSWORD", None)
    if had_secrets_file and previous_secrets_file is not None:
        os.environ["SECRETS_FILE"] = previous_secrets_file
    else:
        os.environ.pop("SECRETS_FILE", None)


@pytest.fixture(scope="session")
def source_context(safe_secret_environment: None) -> SourceContext:
    return build_source_context()


@pytest.fixture(scope="session")
def daemon_artifacts(
    source_context: SourceContext,
    tmp_path_factory: pytest.TempPathFactory,
) -> Path:
    return generate_daemon_artifacts(
        context=source_context,
        output_root=tmp_path_factory.mktemp("sing-box-daemon-artifacts"),
    )
