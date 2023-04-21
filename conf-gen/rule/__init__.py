from typing import Dict

from .parser import parse_filter

FilterT = Dict[str, str]

__all__ = (
    "FilterT",
    "parse_filter",
)
