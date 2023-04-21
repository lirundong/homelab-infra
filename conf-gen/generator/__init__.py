from copy import copy
import os

from .clash_generator import ClashGenerator
from .quantumult_generator import QuantumultGenerator


def generate_conf(
    generate_info, src, dst, proxies, per_region_proxies, proxy_groups, rewrites=None
):
    for gen_info in generate_info:
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
            dst_filename = os.path.join(dst, f"{gen_info['name']}.yaml")
            gen.generate(dst_filename)
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
            dst_filename = os.path.join(dst, f"{gen_info['name']}.conf")
            gen.generate(dst_filename)
        else:
            raise ValueError(f"Unsupported generate type: {gen_info['type']}.")


__all__ = (
    "ClashGenerator",
    "QuantumultGenerator",
    "generate_conf",
)
