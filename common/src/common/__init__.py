"""Common utilities for homelab infrastructure management.

This package provides secrets management and configuration constants.
"""
# Import secrets module (which replaces itself with _SecretsManager instance)
import common.secrets

CLASH_RULESET_FORMATS = ("text", "yaml")
COMMENT_BEGINS = ("#", ";", "//")

__version__ = "0.1.0"
__all__ = ['secrets', 'CLASH_RULESET_FORMATS', 'COMMENT_BEGINS']

# Make secrets available at package level
secrets = common.secrets
