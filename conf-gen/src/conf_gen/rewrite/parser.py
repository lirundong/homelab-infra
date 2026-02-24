from typing import Any

from conf_gen.rewrite._base_rewrite import RewriteBase
from conf_gen.rewrite.quantumult_rewrite import QuantumultRewrite


def parse_rewrites(rewrites_info: list[dict[str, Any]]) -> list[RewriteBase]:
    rewrites: list[RewriteBase] = []
    for r_info in rewrites_info:
        if r_info["type"] == "quantumult":
            rewrite: RewriteBase = QuantumultRewrite(
                name=r_info["name"],
                url=r_info["url"],
            )
        else:
            raise ValueError(f"Unsupported rewrite type: {r_info['type']}.")
        rewrites.append(rewrite)

    return rewrites
