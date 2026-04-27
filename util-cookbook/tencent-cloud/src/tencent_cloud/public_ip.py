"""Public IP address discovery via web services and local interfaces."""

import ipaddress as ip
import re
import socket
from typing import Any, Literal, cast

import requests
import urllib3.util.connection as urllib3_cn

IPType = Literal["A", "AAAA"]


class PublicIPGetter:

    request_url: str | None = None

    def parse_ipv4_response(self, r: requests.Response) -> str:
        raise NotImplementedError()

    def parse_ipv6_response(self, r: requests.Response) -> str:
        raise NotImplementedError()

    def get_public_ip(self, type: IPType) -> str:
        if self.request_url is None:
            raise ValueError(f"request_url not provided for {self.__class__.__name__}")
        if type == "AAAA" and not urllib3_cn.HAS_IPV6:
            raise RuntimeError("Network stack doesn't support IPv6")
        # Force requests library to use either IPv4 or IPv6.
        # https://stackoverflow.com/a/46972341
        urllib3_cn.allowed_gai_family = lambda: (
            socket.AF_INET6 if type == "AAAA" else socket.AF_INET
        )
        r = requests.get(self.request_url)
        if r.status_code != 200:
            raise RuntimeError(r.reason)
        ip_str = self.parse_ipv6_response(r) if type == "AAAA" else self.parse_ipv4_response(r)
        ip_obj = ip.ip_address(ip_str)
        if not ip_obj.is_global:
            raise RuntimeError(f"{type} address {ip_str} was not global")
        return ip_str


class taobao(PublicIPGetter):

    request_url = "https://www.taobao.com/help/getip.php"

    def parse_ipv4_response(self, r: requests.Response) -> str:
        pattern = re.compile(r"ipCallback\({ip:\"(.*)\"}\)")
        if match := pattern.search(r.text):
            return match.group(1)
        else:
            raise ValueError(f"Did not find IPv4 address in response {r.text}")

    def parse_ipv6_response(self, r: requests.Response) -> str:
        pattern = re.compile(r"ipCallback\({ip:\"(.*)\"}\)")
        if match := pattern.search(r.text):
            return match.group(1)
        else:
            raise ValueError(f"Did not find IPv6 address in response {r.text}")


class RawTextGetter(PublicIPGetter):

    def parse_ipv4_response(self, r: requests.Response) -> str:
        return r.text.strip()

    def parse_ipv6_response(self, r: requests.Response) -> str:
        return r.text.strip()


class ipify(RawTextGetter):

    request_url = "https://api64.ipify.org"


class ifconfig(RawTextGetter):

    request_url = "https://ifconfig.me"


PUBLIC_IP_GETTERS: dict[str, type[PublicIPGetter]] = {
    "taobao": taobao,
    "ipify": ipify,
    "ifconfig": ifconfig,
}

VALID_METHODS = (*PUBLIC_IP_GETTERS.keys(), "requests", "netifaces", "ifaddr")


def _from_web_service(method: str, type: IPType) -> str:
    return PUBLIC_IP_GETTERS[method]().get_public_ip(type=type)


def _try_each_web_service(type: IPType) -> str:
    last_error: Exception | None = None
    for getter in PUBLIC_IP_GETTERS.values():
        try:
            return getter().get_public_ip(type=type)
        except Exception as e:
            last_error = e
    raise RuntimeError(
        f"Cannot get public IP by methods {list(PUBLIC_IP_GETTERS.keys())}"
    ) from last_error


def _from_netifaces(interface: str, type: IPType) -> str:
    import netifaces as ni

    itype = ni.AF_INET6 if type == "AAAA" else ni.AF_INET
    for entry in ni.ifaddresses(interface)[itype]:
        ip_obj = ip.ip_address(entry["addr"])
        if ip_obj.is_global:
            return str(ip_obj)
    raise RuntimeError(f"Cannot find {type} address on {interface} via netifaces")


def _from_ifaddr(interface: str, type: IPType) -> str:
    import ifaddr

    for adapter in ifaddr.get_adapters():
        if adapter.name != interface and adapter.nice_name != interface:
            continue
        for adapter_ip in adapter.ips:
            # ifaddr's `ip` field is `str` for IPv4 and `tuple[str, int, int]` for IPv6.
            if type == "AAAA" and adapter_ip.is_IPv6:
                assert isinstance(adapter_ip.ip, tuple)
                ip_obj = ip.ip_address(adapter_ip.ip[0])
            elif type == "A" and adapter_ip.is_IPv4:
                assert isinstance(adapter_ip.ip, str)
                ip_obj = ip.ip_address(adapter_ip.ip)
            else:
                continue
            if ip_obj.is_global:
                return str(ip_obj)
    raise RuntimeError(f"Cannot find {type} address on {interface} via ifaddr")


def get_public_ip_addresses(method: str = "ipify", type: str = "A", **kwargs: Any) -> str:
    if method not in VALID_METHODS:
        raise ValueError(f"Invalid IP acquisition method {method}")
    if type not in ("A", "AAAA"):
        raise ValueError(f"Invalid target IP type {type}")
    ip_type = cast(IPType, type)

    if method in PUBLIC_IP_GETTERS:
        return _from_web_service(method, ip_type)
    if method == "requests":
        return _try_each_web_service(ip_type)
    if method == "netifaces":
        return _from_netifaces(kwargs["interface"], ip_type)
    if method == "ifaddr":
        return _from_ifaddr(kwargs["interface"], ip_type)
    raise AssertionError(f"unreachable: method={method}")
