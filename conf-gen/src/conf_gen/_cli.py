#!/usr/bin/env python3

"""Generate config files for various clients from a common source spec."""

from argparse import ArgumentParser
import os
from typing import Any

import yaml

from common import secrets
from conf_gen.generator import generate_conf
from conf_gen.proxy import ProxyBase, parse_clash_proxies, parse_subscriptions
from conf_gen.proxy_group import ProxyGroupBase, parse_proxy_groups, merge_proxy_by_region
from conf_gen.proxy_group.selective_proxy_group import SelectProxyGroup
from conf_gen.rewrite import parse_rewrites


def main() -> None:
    parser = ArgumentParser("Generate Clash/QuantumultX/sing-box config from specified source.")
    parser.add_argument("-s", "--src", required=True, help="Source spec in YAML format.")
    parser.add_argument("-o", "--dst", required=True, help="Directory of generated files.")
    args = parser.parse_args()

    src_conf: dict[str, Any] = yaml.safe_load(open(args.src, "r", encoding="utf-8"))
    src_conf = secrets.expand_secret_object(src_conf)
    src_file = os.path.split(args.src)[-1]

    custom_proxies = parse_clash_proxies(src_conf["proxies"])
    subscription_proxies = parse_subscriptions(src_conf["subscriptions"])
    proxies = custom_proxies + subscription_proxies
    grouped_proxy: list[ProxyBase | ProxyGroupBase] = [
        SelectProxyGroup(name="🌏 Custom", filters=None, proxies=custom_proxies)
    ]
    per_region_proxies = merge_proxy_by_region(
        proxies=grouped_proxy + list(subscription_proxies),
        proxy_check_url=src_conf["global"]["proxy_check_url"],
        proxy_check_interval=src_conf["global"]["proxy_check_interval"],
        region_proxy_type=src_conf["global"]["region_proxy_type"],
    )
    proxy_groups = parse_proxy_groups(src_conf["rules"], available_proxies=per_region_proxies)
    rewrites = parse_rewrites(src_conf["rewrites"])

    generate_conf(
        generate_info=src_conf["generates"],
        src=src_file,
        dst=args.dst,
        proxies=proxies,
        per_region_proxies=per_region_proxies,
        proxy_groups=proxy_groups,
        rewrites=rewrites,
    )


if __name__ == "__main__":
    main()
