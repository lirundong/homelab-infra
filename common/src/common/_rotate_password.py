#!/usr/bin/env python3

"""Rotate the master password used to encrypt secrets.yaml.

The new password must be supplied on stdin (file redirect or pipe). The current
password is read from the PASSWORD environment variable as usual.
"""

import sys
from argparse import ArgumentParser

from common import secrets


def main() -> int:
    parser = ArgumentParser(
        prog="common-rotate-password",
        description=(
            "Re-encrypt every entry in secrets.yaml with a new master password. "
            "The current password must be in the PASSWORD environment variable. "
            "The new password is read from stdin (one line, trailing newline "
            "stripped). To prevent terminal echo, stdin must be redirected from "
            "a file or pipe; an interactive TTY is rejected."
        ),
    )
    parser.add_argument(
        "--new-salt",
        default=None,
        help="Optional new salt (otherwise the existing SALT is reused).",
    )
    args = parser.parse_args()

    if sys.stdin.isatty():
        print(
            "Refusing to read new password from a TTY (would echo to terminal). "
            "Redirect stdin from a file or pipe.",
            file=sys.stderr,
        )
        return 2

    new_password = sys.stdin.read().rstrip("\n")
    if not new_password:
        print("New password is empty; aborting.", file=sys.stderr)
        return 1

    count = secrets.rotate_password(new_password, new_salt=args.new_salt)
    print(f"Re-encrypted {count} secret(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
