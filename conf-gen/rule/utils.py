from collections import defaultdict
from dataclasses import dataclass
from typing import Literal

from rule._base_ir import _IR_REGISTRY
from rule._base_ir import IRBase
from rule.ir import IPCIDR
from rule.ir import IPCIDR6
from rule.ir import PackageName
from rule.ir import ProcessName


_DST_IP_IRS = (IPCIDR, IPCIDR6)
_PROCESS_IRS = (PackageName, ProcessName)


def group_sing_box_filters(
    filters: list[IRBase],
    included_process_irs: list[str] | None = None,
    process_irs_combination_mode: Literal["and", "or"] = "or",
) -> dict | defaultdict:
    normal_filters = defaultdict[str, list[str]](list)
    process_filters = defaultdict[str, list[str]](list)
    if included_process_irs is not None:
        included_process_ir_types = tuple[type[IRBase], ...](_IR_REGISTRY[t] for t in included_process_irs)
        excluded_process_ir_types = tuple[type[IRBase], ...](set(_PROCESS_IRS) - set(included_process_ir_types))
    else:
        included_process_ir_types = None
        excluded_process_ir_types = _PROCESS_IRS
    for f in filters:
        try:
            k, v = f.sing_box_rule
        except ValueError as e:
            if str(e).endswith("is not supported by sing-box."):
                continue
            else:
                raise e
        if excluded_process_ir_types and isinstance(f, excluded_process_ir_types):
            continue
        elif included_process_ir_types and isinstance(f, included_process_ir_types):
            process_filters[k].append(v)
        else:
            normal_filters[k].append(v)
    # NOTE: We enforce process-related IRs to take precedence over others if applicable.
    if process_filters:
        grouped_filters = {
            "type": "logical",
            "mode": process_irs_combination_mode,
            "rules": [
                process_filters,
                normal_filters,
            ]
        }
    else:
        grouped_filters = normal_filters
    return grouped_filters


@dataclass
class SplittedSingBoxFilters:
    no_resolve_filters: dict
    dst_ip_filters: dict


def split_sing_box_dst_ip_filters(
    grouped_filters: dict,
    must_have_action: bool = True,
) -> SplittedSingBoxFilters:
    if grouped_filters.get("type") == "logical":
        assert 2 == len(grouped_filters["rules"])
        process_rules, splitted_sub_rules = None, None
        for i, sub_rules in enumerate(grouped_filters["rules"]):
            if 0 == i:
                # The first sub rule group should only consists of process matchers.
                assert all(_IR_REGISTRY[t] in _PROCESS_IRS for t in sub_rules.keys())
                process_rules = sub_rules
                continue
            splitted_sub_rules = split_sing_box_dst_ip_filters(sub_rules, must_have_action=False)
        assert process_rules is not None
        assert splitted_sub_rules is not None
        no_resolve_filters = {
            "type": "logical",
            "mode": grouped_filters["mode"],
            "rules": [
                process_rules,
                splitted_sub_rules.no_resolve_filters,
            ],
        }
        if splitted_sub_rules.dst_ip_filters:
            dst_ip_filters = {
                "type": "logical",
                "mode": grouped_filters["mode"],
                "rules": [
                    process_rules,
                    splitted_sub_rules.dst_ip_filters,
                ],
            }
        else:
            dst_ip_filters = {}
    else:
        no_resolve_filters = defaultdict(list)
        dst_ip_filters = defaultdict(list)
        for k, v in grouped_filters.items():
            if k not in _IR_REGISTRY:
                # Could be rule actions or options.
                continue
            elif k == "ip_cidr":
                dst_ip_filters[k] += v
            else:
                no_resolve_filters[k] += v
    if (action := grouped_filters.get("action")) == "route":
        assert grouped_filters["outbound"]
        action = {"action": "route", "outbound": grouped_filters["outbound"]}
    elif action == "reject":
        action = {"action": "reject"}
    elif action is not None:
        raise ValueError(f"Currently we do not support split rule {action=}")
    elif must_have_action:
        raise ValueError("Input filter mapping did not contain an `action` field")
    else:
        action = {}
    no_resolve_filters.update(action)
    if dst_ip_filters:
        dst_ip_filters.update(action)
    return SplittedSingBoxFilters(no_resolve_filters, dst_ip_filters)
