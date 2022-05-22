from proxy_group.selective_proxy_group import SelectProxyGroup


def parse_proxy_groups(proxy_groups_info, available_proxies=None):
    proxy_groups = []
    for g_info in proxy_groups_info:
        if g_info["type"] == "select":
            g = SelectProxyGroup(
                name=g_info["name"],
                filters=g_info["filters"],
                proxies=g_info["proxies"],
                img_url=g_info["img-url"],
                available_proxies=available_proxies,
            )
        else:
            raise ValueError(f"Unsupported proxy group type: {g_info['type']}.")
        proxy_groups.append(g)

    return proxy_groups
