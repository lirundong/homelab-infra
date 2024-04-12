#!/usr/bin/env python3
#
# Copy to /usr/bin/update_qcloud_dns on OpenWRT.

from argparse import ArgumentParser
import copy
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress as ip
import json
import os
from pathlib import Path
from pprint import pprint
import socket
import sys
import re
from typing import Dict, List, Literal, Optional, Type

# TODO: Remove this path hack.
sys.path.insert(0, str(Path(os.path.realpath(__file__)).parents[2]))

import requests
import requests.packages.urllib3.util.connection as urllib3_cn

from common import secrets

QCLOUD_API_HOSTNAME = "dnspod.tencentcloudapi.com"
QCLOUD_PUBLIC_API = {
    "X-TC-Action": None,
    "X-TC-Region": None,
    "X-TC-Timestamp": None,
    "X-TC-Token": None,
    "X-TC-Language": None,
}
QCLOUD_DNS_API = {
    "DescribeRecordList": {
        "X-TC-Version": "2021-03-23",
        "Domain": None,
        "Subdomain": None,
    },
    "ModifyRecord": {
        "X-TC-Version": "2021-03-23",
        "Domain": None,
        "Subdomain": None,
        "RecordType": None,
        "RecordLine": None,
        "Value": None,
        "RecordId": None,
        "MX": None,
    },
}


class PublicIPGetter:

    request_url = None

    def __init__(self) -> None:
        super().__init__()

    def parse_ipv4_response(self, r: requests.Response) -> str:
        raise NotImplementedError()

    def parse_ipv6_response(self, r: requests.Response) -> str:
        raise NotImplementedError()

    def get_public_ip(self, type: Literal["A", "AAAA"]) -> str:
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


PUBLIC_IP_GETTERS: Dict[str, Type[PublicIPGetter]] = {
    "taobao": taobao,
    "ipify": ipify,
    "ifconfig": ifconfig,
}


def get_public_ip_addresses(method: str = "ipify", type: str = "A", **kwargs) -> str:
    if method not in ("ipify", "taobao", "ifconfig", "requests", "netifaces", "ifaddr"):
        raise ValueError(f"Invalid IP acquisition method {method}")
    if type not in ("A", "AAAA"):
        raise ValueError(f"Invalid target IP type {type}")

    if method in PUBLIC_IP_GETTERS:
        ip_addr = PUBLIC_IP_GETTERS[method]().get_public_ip(type=type)
    elif method == "requests":
        last_error, ip_addr = None, None
        for _, getter in PUBLIC_IP_GETTERS.items():
            try:
                ip_addr = getter().get_public_ip(type=type)
            except Exception as e:
                last_error = e
            if ip_addr is not None:
                break
        if ip_addr is None:
            raise RuntimeError(
                f"Cannot get public IP by methods {list(PUBLIC_IP_GETTERS.keys())}"
            ) from last_error
    elif method == "netifaces":
        import netifaces as ni

        itype = ni.AF_INET6 if type == "AAAA" else ni.AF_INET
        for ip_addr in ni.ifaddresses(kwargs["interface"])[itype]:
            ip_addr = ip.ip_address(ip_addr["addr"])
            if ip_addr.is_global:
                ip_addr = str(ip_addr)
                break
    elif method == "ifaddr":
        import ifaddr

        ip_addr = None
        for adapter in ifaddr.get_adapters():
            if adapter.name == kwargs["interface"] or adapter.nice_name == kwargs["interface"]:
                for adapter_ip in adapter.ips:
                    if type == "AAAA" and adapter_ip.is_IPv6:
                        ip_addr_obj = ip.ip_address(adapter_ip.ip[0])
                        if ip_addr_obj.is_global:
                            ip_addr = str(ip_addr_obj)
                            break
                    elif type == "A" and adapter_ip.is_IPv4:
                        ip_addr_obj = ip.ip_address(adapter_ip.ip)
                        if ip_addr_obj.is_global:
                            ip_addr = str(ip_addr_obj)
                            break
        if ip_addr is None:
            raise RuntimeError(f"Cannot find {type} address with ifaddr")

    return ip_addr


def normalize_dict(src: Dict) -> Dict:
    dst = dict()
    for k, v in src.items():
        if v is None:
            continue
        dst[k] = v
    return dst


def get_qcloud_auth(headers: Dict[str, str], payload: Dict[str, str]) -> str:
    # 0. Protect the inputs.
    headers = copy.copy(headers)
    payload = copy.copy(payload)
    # 1. Build the CanonicalRequest.
    canonical_request_template = (
        r"{http_request_method}"
        "\n"
        r"{canonical_uri}"
        "\n"
        r"{canonical_query_string}"
        "\n"
        r"{canonical_headers}"
        "\n"
        r"{signed_headers}"
        "\n"
        r"{hashed_request_payload}"
    )
    headers.setdefault("Host", QCLOUD_API_HOSTNAME)
    headers.setdefault("Content-Type", "application/json")
    sorted_headers = [
        (k.lower().strip(), headers[k].lower().strip()) for k in sorted(list(headers.keys()))
    ]
    hashed_request_payload = hashlib.sha256(json.dumps(payload).encode("utf-8")).hexdigest()
    canonical_request = canonical_request_template.format(
        http_request_method="POST",
        canonical_uri="/",
        canonical_query_string="",
        canonical_headers="\n".join(f"{h[0]}:{h[1]}" for h in sorted_headers) + "\n",
        signed_headers=";".join(h[0] for h in sorted_headers),
        hashed_request_payload=hashed_request_payload,
    )
    # 2. Build the StringToSign.
    string_to_sign_template = (
        r"{algorithm}"
        "\n"
        r"{request_timestamp}"
        "\n"
        r"{date}/{service}/tc3_request"  # CredentialScope
        "\n"
        r"{hashed_canonical_request}"
    )
    timestamp = int(headers["X-TC-Timestamp"])
    date = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d")
    service = "dnspod"
    hashed_canonical_request = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    string_to_sign = string_to_sign_template.format(
        algorithm="TC3-HMAC-SHA256",
        request_timestamp=timestamp,
        date=date,
        service=service,
        hashed_canonical_request=hashed_canonical_request,
    )
    # 3. Compute the Signature.
    secret_key = secrets.QCLOUD_API_SECRET_KEY
    secret_date = hmac.new(
        key=f"TC3{secret_key}".encode("utf-8"),
        msg=date.encode("utf-8"),
        digestmod="sha256",
    ).digest()
    secret_service = hmac.new(
        key=secret_date,
        msg=service.encode("utf-8"),
        digestmod="sha256",
    ).digest()
    secret_signing = hmac.new(
        key=secret_service,
        msg="tc3_request".encode("utf-8"),
        digestmod="sha256",
    ).digest()
    signature = hmac.new(
        key=secret_signing,
        msg=string_to_sign.encode("utf-8"),
        digestmod="sha256",
    ).hexdigest()
    # 4. Build the final Authorization.
    authorization_template = (
        r"{algorithm} "
        r"Credential={secret_id}/{date}/{service}/tc3_request, "
        r"SignedHeaders={signed_headers}, "
        r"Signature={signature}"
    )
    secret_id = secrets.QCLOUD_API_SECRET_ID
    authorization = authorization_template.format(
        algorithm="TC3-HMAC-SHA256",
        secret_id=secret_id,
        date=date,
        service=service,
        signed_headers=";".join(h[0] for h in sorted_headers),
        signature=signature,
    )
    return authorization


def get_qcloud_subdomain_record(domain: str, subdomain: str) -> List[Dict[str, str]]:
    """Get subdomain's record id and previous value, return None if it does not exist."""
    payload = copy.copy(QCLOUD_DNS_API["DescribeRecordList"])
    payload["Domain"] = domain
    payload["Subdomain"] = subdomain
    payload = normalize_dict(payload)

    headers = copy.copy(QCLOUD_PUBLIC_API)
    headers["X-TC-Action"] = "DescribeRecordList"
    headers["X-TC-Version"] = payload.pop("X-TC-Version")
    headers["X-TC-Timestamp"] = str(int(datetime.now(timezone.utc).timestamp()))
    headers = normalize_dict(headers)
    headers["Authorization"] = get_qcloud_auth(headers, payload)

    response = requests.post(
        f"https://{QCLOUD_API_HOSTNAME}", json=payload, headers=headers
    ).json()["Response"]

    if response.get("Error"):
        err_code = response["Error"]["Code"]
        err_msg = response["Error"]["Message"]
        raise RuntimeError(f"{err_code}: {err_msg}")
    ret = []
    for record in response["RecordList"]:
        assert record["Name"] == subdomain
        filtered_record = {
            "RecordId": record["RecordId"],
            "RecordType": record["Type"],
            "RecordLine": record["Line"],
            "Value": record["Value"],
        }
        if record["MX"]:
            filtered_record["MX"] = record["MX"]
        ret.append(filtered_record)

    return ret


def update_qcloud_subdomain_record(
    domain: str,
    subdomain: str,
    get_ipv4_method: str = "ipify",
    get_ipv6_method: str = "netifaces",
    interface: Optional[str] = None,
    dry_run: bool = False,
):
    current_records = get_qcloud_subdomain_record(domain, subdomain)
    ipv4 = get_public_ip_addresses(get_ipv4_method, type="A", interface=interface)
    ipv6 = get_public_ip_addresses(get_ipv6_method, type="AAAA", interface=interface)

    updating_records = []
    for record in current_records:
        if record["RecordType"] == "A" and record["Value"] == ipv4:
            continue
        if record["RecordType"] == "AAAA":
            if (ipv6 is None) or (ipv6 and record["Value"] == ipv6):
                continue
        update_record = copy.copy(QCLOUD_DNS_API["ModifyRecord"])
        update_record["Domain"] = domain
        update_record["SubDomain"] = subdomain
        update_record.update(record)
        update_record["Value"] = ipv4 if record["RecordType"] == "A" else ipv6
        update_record = normalize_dict(update_record)
        updating_records.append(update_record)

    if dry_run:
        print("These records are going to be updated:")
        pprint(updating_records)
    else:
        new_records = []
        for payload in updating_records:
            headers = copy.copy(QCLOUD_PUBLIC_API)
            headers["X-TC-Action"] = "ModifyRecord"
            headers["X-TC-Version"] = payload.pop("X-TC-Version")
            headers["X-TC-Timestamp"] = str(int(datetime.now(timezone.utc).timestamp()))
            headers = normalize_dict(headers)
            headers["Authorization"] = get_qcloud_auth(headers, payload)

            response = requests.post(
                f"https://{QCLOUD_API_HOSTNAME}", json=payload, headers=headers
            ).json()["Response"]

            if response.get("Error"):
                err_code = response["Error"]["Code"]
                err_msg = response["Error"]["Message"]
                raise RuntimeError(f"{err_code}: {err_msg}")
            else:
                new_records.append(payload)
        print("Updated records:")
        pprint(new_records)


if __name__ == "__main__":
    parser = ArgumentParser("Update QCloud DNS records by host IP addresses.")
    parser.add_argument("--domain", "-d", help="Domain to be updated.")
    parser.add_argument("--sub-domain", "-s", help="Sub-domain to be updated.")
    parser.add_argument(
        "--get-ipv4-method", default="ipify", help="Method to get host public IPv4 addresses."
    )
    parser.add_argument(
        "--get-ipv6-method", default="netifaces", help="Method to get host public IPv6 addresses."
    )
    parser.add_argument(
        "--dry-run",
        "-n",
        action="store_true",
        help="Print modifications and don't actually perform them.",
    )
    parser.add_argument("--interface", "-i", help="Network interface name to get IP addresses from")
    args = parser.parse_args()

    update_qcloud_subdomain_record(
        domain=args.domain,
        subdomain=args.sub_domain,
        get_ipv4_method=args.get_ipv4_method,
        get_ipv6_method=args.get_ipv6_method,
        interface=args.interface,
        dry_run=args.dry_run,
    )
