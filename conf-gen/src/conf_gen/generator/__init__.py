from copy import copy
import os
from typing import Any, Sequence

from conf_gen.generator._base_generator import GeneratorBase
from conf_gen.generator.clash_generator import ClashGenerator
from conf_gen.generator.quantumult_generator import QuantumultGenerator
from conf_gen.generator.sing_box_generator import SingBoxGenerator
from conf_gen.proxy._base_proxy import ProxyBase
from conf_gen.proxy_group._base_proxy_group import ProxyGroupBase
from conf_gen.rewrite._base_rewrite import RewriteBase


def generate_conf(
    generate_info: list[dict[str, Any]],
    src: str,
    dst: str,
    proxies: Sequence[ProxyBase],
    per_region_proxies: Sequence[ProxyBase | ProxyGroupBase],
    proxy_groups: Sequence[ProxyGroupBase],
    rewrites: Sequence[RewriteBase] | None = None,
) -> None:
    generators: dict[str, GeneratorBase] = {}
    for gen_info in generate_info:
        gen: GeneratorBase
        if gen_info["type"] == "clash":
            general_options = copy(gen_info)
            general_options.pop("name")
            general_options.pop("type")
            gen = ClashGenerator(
                src_file=src,
                proxies=proxies,
                per_region_proxies=per_region_proxies,
                proxy_groups=proxy_groups,
                **general_options,
            )
            dst_dir = os.path.join(dst, f"{gen_info['name']}.yaml")
            gen.generate(dst_dir)
        elif gen_info["type"] == "quantumult":
            if rewrites is None:
                raise ValueError("`rewrites` arg is required for generating Quantumult configs.")
            additional_sections = copy(gen_info)
            additional_sections.pop("name")
            additional_sections.pop("type")
            gen = QuantumultGenerator(
                src_file=src,
                proxies=proxies,
                per_region_proxies=per_region_proxies,
                proxy_groups=proxy_groups,
                rewrites=rewrites,
                **additional_sections,
            )
            dst_dir = os.path.join(dst, f"{gen_info['name']}.conf")
            gen.generate(dst_dir)
        elif gen_info["type"] == "sing-box":
            if gen_info.get("base"):
                base_gen = generators[gen_info["base"]]
                if not isinstance(base_gen, SingBoxGenerator):
                    raise ValueError(f"Base generator {gen_info['base']} is not a SingBoxGenerator")
                if gen_info.get("included_process_irs"):
                    if gen_info["included_process_irs"] == "!clear":
                        included_process_irs = None
                    else:
                        included_process_irs = gen_info["included_process_irs"]
                else:
                    included_process_irs = base_gen.included_process_irs
                gen = SingBoxGenerator.from_base(
                    base_object=base_gen,
                    dns=gen_info.get("dns"),
                    inbounds=gen_info.get("inbounds"),
                    route=gen_info.get("route"),
                    experimental=gen_info.get("experimental"),
                    included_process_irs=included_process_irs,
                    ruleset_url=gen_info.get("ruleset_url"),
                )
            else:
                args = copy(gen_info)
                gen = SingBoxGenerator(
                    src_file=src,
                    proxies=list(proxies),
                    per_region_proxies=list(per_region_proxies),
                    proxy_groups=list(proxy_groups),
                    dns=args["dns"],
                    route=args["route"],
                    inbounds=args.get("inbounds"),
                    log=args.get("log"),
                    ntp=args.get("ntp"),
                    experimental=args.get("experimental"),
                    included_process_irs=args.get("included_process_irs"),
                    ruleset_url=args.get("ruleset_url"),
                    dial_fields=args.get("dial_fields"),
                    add_resolve_action=args.get("add_resolve_action"),
                )
            dst_dir = os.path.join(dst, gen_info["name"])
            gen.generate(dst_dir)
        else:
            raise ValueError(f"Unsupported generate type: {gen_info['type']}.")
        generators[gen_info["name"]] = gen


__all__ = (
    "ClashGenerator",
    "QuantumultGenerator",
    "SingBoxGenerator",
    "generate_conf",
)
