import sys

from common._manager import _SecretsManager

# Replace this module with a _SecretsManager instance so callers can do
# `from common import secrets; secrets.SECRET_NAME`. See https://stackoverflow.com/a/880550.
_manager_instance: _SecretsManager = _SecretsManager()
sys.modules[__name__] = _manager_instance  # type: ignore[assignment]
