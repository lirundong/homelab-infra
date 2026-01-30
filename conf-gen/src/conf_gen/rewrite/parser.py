from conf_gen.rewrite.quantumult_rewrite import QuantumultRewrite


def parse_rewrites(rewrites_info):
    rewrites = []
    for r_info in rewrites_info:
        if r_info["type"] == "quantumult":
            r = QuantumultRewrite(
                name=r_info["name"],
                url=r_info["url"],
            )
        else:
            raise ValueError(f"Unsupported rewrite type: {r_info['type']}.")
        rewrites.append(r)

    return rewrites
