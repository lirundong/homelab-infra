"""Common utilities for homelab infrastructure management.

This package provides secrets management and configuration constants.
"""
from typing import Final

# Import secrets module (which replaces itself with _SecretsManager instance)
import common.secrets
from common._manager import _SecretsManager

CLASH_RULESET_FORMATS: Final[tuple[str, str]] = ("text", "yaml")
COMMENT_BEGINS: Final[tuple[str, str, str]] = ("#", ";", "//")

__version__: Final[str] = "0.1.0"
__all__: list[str] = ["secrets", "CLASH_RULESET_FORMATS", "COMMENT_BEGINS"]

# Make secrets available at package level
# Type annotation helps mypy understand this is a _SecretsManager instance
secrets: _SecretsManager = common.secrets  # type: ignore[assignment]
