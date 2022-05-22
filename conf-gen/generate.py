#!/usr/bin/env python3

"""Generate config files for various clients from a common source spec."""

from argparse import ArgumentParser
import os
from pathlib import Path
import sys

# TODO: Remove this path hack.
sys.path.insert(0, str(Path(os.path.realpath(__file__)).parents[1]))

import yaml

from common import secrets
from generator import generate_conf
from proxy import parse_clash_proxies, parse_subscriptions
from proxy_group import parse_proxy_groups
from rewrite import parse_rewrites


if __name__ == "__main__":
    parser = ArgumentParser("Generate Clash/QuantumultX config from specified source.")
    parser.add_argument("-s", "--src", required=True, help="Source spec in YAML format.")
    parser.add_argument("-o", "--dst", required=True, help="Directory of generated files.")
    args = parser.parse_args()

    src_conf = yaml.load(open(args.src, "r", encoding="utf-8"), Loader=yaml.SafeLoader)
    src_conf = secrets.expand_secret_object(src_conf)
    src_file = os.path.split(args.src)[-1]

    proxies = parse_clash_proxies(src_conf["proxies"])
    proxies += parse_subscriptions(src_conf["subscriptions"])
    proxy_groups = parse_proxy_groups(src_conf["rules"], available_proxies=proxies)
    rewrites = parse_rewrites(src_conf["rewrites"])

    generate_conf(src_conf["generates"], src_file, args.dst, proxies, proxy_groups, rewrites)
