"""Load custom rules and update Clash configuration from subscription URL.

Custom rule format:

..code:: YAML
    key1: val1
    key2: val2
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

import requests
import yaml

PG_T = "proxy-groups"
RULE_T = "rules"
PROXY_T = "proxies"


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


def update_with_custom_rule(sub, custom_rules, custom_proxies, add_to_pg, **custom_kv):
    assert all(k in sub for k in custom_kv.keys())

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
            r += f",{rule['name']}"
            new_rules.append(r)
    
    # update proxy groups
    proxy_groups = []
    custom_proxy_names = [p["name"] for p in custom_proxies]
    for pg in chain(new_pg, sub[PG_T]):
        if pg["name"] in add_to_pg:
            pg["proxies"] = custom_proxy_names + pg["proxies"]
        proxy_groups.append(pg)
    
    sub.update(custom_kv)
    sub[PG_T] = proxy_groups
    sub[RULE_T] = new_rules + sub[RULE_T]
    sub[PROXY_T] = custom_proxies + sub[PROXY_T]

    return sub


if __name__ == "__main__":
    # V2fly, private
    url = "https://sub.v2club.top/api/v1/client/subscribe"
    sub_args = {
        "params": {
            "token":"90cc293a40e07f4387655fdf6722225f",
        },
        "proxies": {
            "https": "http://127.0.0.1:10081",
        },
    }
    custom_path = "my_rules.yaml"
    output_path = "V2Club.yaml"

    sub = get_subscription(url, **sub_args)
    custom_rules, custom_proxies, proxy_add_to, custom_cfg = get_custom_rule(custom_path)
    updated_sub = update_with_custom_rule(sub, custom_rules, custom_proxies, proxy_add_to, **custom_cfg)
    open(output_path, "w", encoding="utf-8").write(
        yaml.dump(updated_sub, Dumper=yaml.SafeDumper, allow_unicode=True)
    )
