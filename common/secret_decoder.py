#!/usr/bin/env python3

from argparse import ArgumentParser
import os
import re
import sys

import secrets


def copy_single_file(src, dst, force=False):
    if os.path.exists(dst) and not force:
        raise RuntimeError(f"Destination file {dst} already exists.")

    os.makedirs(os.path.dirname(dst), exist_ok=True)

    with open(src, "r", encoding="utf-8") as f_in, open(dst, "w", encoding="utf-8") as f_out:
        decoded_lines = []
        for line in f_in.readlines():
            decoded_lines.append(secrets.expand_secret(line.rstrip("\n")))
        f_out.write("\n".join(decoded_lines) + "\n")

    os.chmod(dst, mode=os.stat(src).st_mode)


if __name__ == "__main__":
    parser = ArgumentParser("Copy files and expand secrets within.")
    parser.add_argument("src", nargs="?", default=None, help="Source file path.")
    parser.add_argument("dst", nargs="?", default=None, help="Destination path.")
    parser.add_argument("-e", "--exclude", nargs="*", help="Regex to excluded filenames.")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively copy.")
    parser.add_argument("-f", "--force", action="store_true", help="Overwire on existing dst.")
    args = parser.parse_args()

    if args.src is None and args.dst is None:  # Input from stdin.
        for line in sys.stdin:
            decoded = secrets.expand_secret(line.strip())
            print(decoded)
    else:
        if os.path.isdir(args.src):
            if not args.recursive:
                raise RuntimeError(f"Non-recursive copy on source directory: {args.src}")

            abs_src = os.path.abspath(args.src)
            abs_dst = os.path.abspath(args.dst)

            for dirpath, dirnames, filenames in os.walk(abs_src):
                if filenames:
                    for filename in filenames:
                        if args.exclude and any(
                            re.match(pattern, filename) for pattern in args.exclude
                        ):
                            continue
                        relpath = os.path.relpath(dirpath, abs_src)
                        src = os.path.join(dirpath, filename)
                        dst = os.path.join(abs_dst, relpath, filename)
                        copy_single_file(src, dst, force=args.force)
        else:
            abs_src = os.path.abspath(args.src)
            abs_dst = os.path.abspath(args.dst)
            copy_single_file(abs_src, abs_dst, force=args.force)
