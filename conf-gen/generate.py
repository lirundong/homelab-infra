#!/usr/bin/env python3

"""Deprecated wrapper. Use the `conf-gen` console script instead."""

import sys
import warnings

warnings.warn(
    "generate.py is deprecated. Please use 'conf-gen' command instead. "
    "Install with: pip install -e .",
    DeprecationWarning,
    stacklevel=2
)

from conf_gen._cli import main

if __name__ == "__main__":
    main()
