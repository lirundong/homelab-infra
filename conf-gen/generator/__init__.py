from copy import copy
import os

from generator.clash_generator import ClashGenerator
from generator.quantumult_generator import QuantumultGenerator
from generator.sing_box_generator import SingBoxGenerator


def generate_conf(
    generate_info, src, dst, proxies, per_region_proxies, proxy_groups, rewrites=None
):
    generators = {}
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
        elif gen_info["type"] == "sing-box":
            if gen_info.get("base"):
                gen = SingBoxGenerator.from_base(
                    base_object=generators[gen_info["base"]],
                    inbounds=gen_info["inbounds"],
                    route=gen_info["route"],
                    experimental=gen_info["experimental"],
                )
            else:
                args = copy(gen_info)
                gen = SingBoxGenerator(
                    src_file=src,
                    proxies=proxies,
                    per_region_proxies=per_region_proxies,
                    proxy_groups=proxy_groups,
                    dns=args["dns"],
                    route=args["route"],
                    inbounds=args.get("inbounds"),
                    log=args.get("log"),
                    ntp=args.get("ntp"),
                    experimental=args.get("experimental"),
                    skip_process_names=args.get("skip_process_names", False),
                    proxy_domain_strategy=args.get("proxy_domain_strategy"),
                )
            dst_filename = os.path.join(dst, f"{gen_info['name']}.json")
            gen.generate(dst_filename)
        else:
            raise ValueError(f"Unsupported generate type: {gen_info['type']}.")
        generators[gen_info["name"]] = gen


__all__ = (
    "ClashGenerator",
    "QuantumultGenerator",
    "generate_conf",
)
