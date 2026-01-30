"""Backwards-compatible secrets module with sys.modules replacement.

This module enables the pattern: `from common import secrets; secrets.SECRET_NAME`
by replacing itself in sys.modules with a _SecretsManager instance.
"""
from common._manager import _SecretsManager
import sys

# Allow accessing secrets as module-level attributes, see https://stackoverflow.com/a/880550.
sys.modules[__name__] = _SecretsManager()
