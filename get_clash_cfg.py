"""Load custom rules and update Clash configuration from subscription URL.

Custom rule format:

..code:: YAML
    general_options:
      key1: val1
      key2: val2
      ...
    daemon_only_options:
      daemon_key_1: daemon_val_1
      daemon_key_2: daemon_val_2
      ...
    proxies:
      - [in clash proxy format]
    add-to-group: # add previous `proxies' to which proxy groups
      - proxy group names
    rules:
        - name: custom_rule_name_1
          proxies:
            - proxy_1
            - Proxy_2
            - ...
          rule:
            - rule_1
            - rule_2
            - ...
        - name: custom_rule_2
            ...
"""

from itertools import chain
from argparse import ArgumentParser
from json import loads
from copy import copy

import requests
import yaml

PG_T = "proxy-groups"
RULE_T = "rules"
PROXY_T = "proxies"
GENERAL_T = "general_options"
DAEMON_T = "daemon_only_options"


def get_subscription(url, **kwargs):
    r = requests.get(url, headers={"user-agent": "clash"}, **kwargs)
    if r.status_code != 200:
        raise requests.HTTPError(r.reason)
    sub_info = yaml.load(r.text, Loader=yaml.SafeLoader)
    return sub_info


def get_custom_rule(path):
    info = yaml.load(open(path, "r", encoding="utf-8"), Loader=yaml.SafeLoader)
    rules = info["rules"]
    info.pop("rules")
    proxies = info["proxies"]
    info.pop("proxies")
    add_to = info["add-to-group"]
    info.pop("add-to-group")
    return rules, proxies, add_to, info


def update_with_custom_rule(sub,
                            custom_rules,
                            custom_proxies,
                            add_to_pg,
                            strict=False,
                            **custom_kv):
    if strict:
        assert all(k in sub for k in chain(custom_kv[GENERAL_T].keys(),
                                           custom_kv[DAEMON_T].keys()))

    new_pg = []
    new_rules = []
    sub_pg_names = {s["name"] for s in sub[PG_T]}
    for rule in custom_rules:
        if rule["name"] not in sub_pg_names:
            pg = {
                "name": rule["name"],
                "type": "select",
                "proxies": rule["proxies"],
            }
            new_pg.append(pg)
        for r in rule["rule"]:
            if r.endswith(",no-resolve"):
                tokens = r.split(",")[:-1]  # eliminate tailing `,no-resolve`
                assert len(tokens) == 2, f"Invalid custom rule: {r}"
                r = f"{tokens[0]},{tokens[1]},{rule['name']},no-resolve"
            else:
                r += f",{rule['name']}"
            new_rules.append(r)

    # update proxy groups
    proxy_groups = []
    custom_proxy_names = [p["name"] for p in custom_proxies]
    for pg in chain(sub[PG_T], new_pg):
        if pg["name"] in add_to_pg:
            pg["proxies"] = pg["proxies"] + custom_proxy_names
        proxy_groups.append(pg)

    sub.update(custom_kv[GENERAL_T])
    sub[PG_T] = proxy_groups
    sub[RULE_T] = new_rules + sub[RULE_T]
    sub[PROXY_T] = custom_proxies + sub[PROXY_T]

    daemon_sub = copy(sub)
    daemon_sub.update(custom_kv[DAEMON_T])

    return sub, daemon_sub


if __name__ == "__main__":
    # V2fly, private
    parser = ArgumentParser(
        "CLI utility to merge Clash subscriptions with custom configurations.")
    parser.add_argument(
        "--url",
        default="https://sub.v2club.top/api/v1/client/subscribe",
        help="Clash subscription URL")
    parser.add_argument(
        "--params",
        type=loads,
        default='''
            {
                "token": "90cc293a40e07f4387655fdf6722225f"
            }
        ''',
        help="Subscription arguments (e.g. authorization token) in JSON format"
    )
    parser.add_argument("--proxies",
                        type=loads,
                        help="Proxy when fetching subscription in JSON format")
    parser.add_argument("--custom-rules",
                        "-i",
                        required=True,
                        help="Path to custom rule file, in YAML format")
    parser.add_argument("--output-rules",
                        "-o",
                        required=True,
                        help="Prefix of out rule file, in YAML format")
    parser.add_argument("--additional-config",
                        "-a",
                        type=loads,
                        default="{}",
                        help="Additional configurations to the final rules")
    args = parser.parse_args()

    sub = get_subscription(args.url, params=args.params, proxies=args.proxies)
    custom_rules, custom_proxies, proxy_add_to, custom_cfg = get_custom_rule(
        args.custom_rules)
    custom_cfg[GENERAL_T].update(args.additional_config)
    general_sub, daemon_sub = update_with_custom_rule(
        sub, custom_rules, custom_proxies, proxy_add_to, **custom_cfg)
    open(args.output_rules + "_general.yaml", "w", encoding="utf-8").write(
        yaml.dump(general_sub, Dumper=yaml.SafeDumper, allow_unicode=True))
    open(args.output_rules + "_daemon.yaml", "w", encoding="utf-8").write(
        yaml.dump(daemon_sub, Dumper=yaml.SafeDumper, allow_unicode=True))
