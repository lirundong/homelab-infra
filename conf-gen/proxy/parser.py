import requests
import yaml

from proxy.shadowsocks_proxy import ShadowSocksProxy
from proxy.trojan_proxy import TrojanProxy
from proxy.v2ray_proxy import VMessProxy, VMessGRPCProxy, VMessWebSocketProxy


def parse_clash_proxies(proxies_info):
    ret = []
    for proxy_info in proxies_info:
        if proxy_info["type"] == "ss":
            proxy = ShadowSocksProxy(
                name=proxy_info["name"],
                server=proxy_info["server"],
                port=proxy_info["port"],
                password=proxy_info["password"],
                cipher=proxy_info["cipher"],
                udp=proxy_info.get("udp", False),
            )
        elif proxy_info["type"] == "vmess":
            if proxy_info.get("network", None) == "ws":
                tls_version = proxy_info.get("tls-version", 1.3)
                proxy = VMessWebSocketProxy(
                    name=proxy_info["name"],
                    server=proxy_info["server"],
                    port=proxy_info["port"],
                    uuid=proxy_info["uuid"],
                    alter_id=proxy_info["alterId"],
                    cipher=proxy_info["cipher"],
                    udp=proxy_info.get("udp", False),
                    tls=proxy_info["tls"],
                    tls_version=tls_version,
                    skip_cert_verify=proxy_info["skip-cert-verify"],
                    **proxy_info.get("ws-opts", {}),
                )
            elif proxy_info.get("network", None) == "grpc":
                tls_version = proxy_info.get("tls-version", 1.3)
                proxy = VMessGRPCProxy(
                    name=proxy_info["name"],
                    server=proxy_info["server"],
                    port=proxy_info["port"],
                    uuid=proxy_info["uuid"],
                    alter_id=proxy_info["alterId"],
                    cipher=proxy_info["cipher"],
                    udp=proxy_info.get("udp", False),
                    tls=proxy_info["tls"],
                    tls_version=tls_version,
                    skip_cert_verify=proxy_info["skip-cert-verify"],
                    server_name=proxy_info.get("servername", None),
                    **proxy_info.get("grpc-opts", {}),
                )
            else:
                proxy = VMessProxy(
                    name=proxy_info["name"],
                    server=proxy_info["server"],
                    port=proxy_info["port"],
                    uuid=proxy_info["uuid"],
                    alter_id=proxy_info["alterId"],
                    cipher=proxy_info["cipher"],
                    udp=proxy_info.get("udp", False),
                )
        elif proxy_info["type"] == "trojan":
            if proxy_info.get("network", None) in ("ws", "grpc"):
                raise NotImplementedError(
                    "WebSocket or gRPC support for Trojan was not implemented yet."
                )
            else:
                proxy = TrojanProxy(
                    name=proxy_info["name"],
                    server=proxy_info["server"],
                    port=proxy_info["port"],
                    password=proxy_info["password"],
                    udp=proxy_info.get("udp", False),
                    sni=proxy_info.get("sni", None),
                    alpn=proxy_info.get("alpn", None),
                    skip_cert_verify=proxy_info["skip-cert-verify"],
                )
        else:
            raise RuntimeError(f"Get unsupported proxy type: {proxy_info['type']}")
        ret.append(proxy)

    return ret


def parse_clash_subscription(url):
    r = requests.get(url, headers={"user-agent": "clash"})
    if r.status_code != 200:
        raise requests.HTTPError(r.reason)
    return parse_clash_proxies(yaml.load(r.text, Loader=yaml.SafeLoader)["proxies"])


def parse_subscriptions(subscriptions_info):
    proxies = []
    for sub_info in subscriptions_info:
        type = sub_info["type"]
        url = sub_info["url"]
        if type == "clash":
            proxies += parse_clash_subscription(url)
        else:
            raise ValueError(f"Not supported subscription type: {type}")
    return proxies
