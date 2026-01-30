#!/usr/bin/env python3

"""Backwards compatibility wrapper for conf-gen CLI.

This script is deprecated. Please use the `conf-gen` command instead:
    pip install -e .
    conf-gen -s source.yaml -o output/
"""

import sys
import warnings

# Show deprecation warning
warnings.warn(
    "generate.py is deprecated. Please use 'conf-gen' command instead. "
    "Install with: pip install -e .",
    DeprecationWarning,
    stacklevel=2
)

# Import and run the CLI
from conf_gen._cli import main

if __name__ == "__main__":
    main()
