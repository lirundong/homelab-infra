from typing import Final

import common.secrets
from common._manager import _SecretsManager

CLASH_RULESET_FORMATS: Final[tuple[str, str]] = ("text", "yaml")
COMMENT_BEGINS: Final[tuple[str, str, str]] = ("#", ";", "//")

__version__: Final[str] = "0.1.0"
__all__: list[str] = ["secrets", "CLASH_RULESET_FORMATS", "COMMENT_BEGINS"]

secrets: _SecretsManager = common.secrets  # type: ignore[assignment]
