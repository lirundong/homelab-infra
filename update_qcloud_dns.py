from argparse import ArgumentParser
import base64
from collections import OrderedDict
import copy
import hashlib
import hmac
import json
import warnings
from pprint import pprint
import random
from typing import Dict, Tuple, List, Optional
import time

import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

QCLOUD_API_HOSTNAME = "cns.api.qcloud.com"
QCLOUD_API_PATH = "/v2/index.php"
QCLOUD_PUBLIC_API = {
    "Action": None,
    "Region": None,
    "Timestamp": None,
    "Nonce": None,
    "SecretId": None,
    "Signature": None,
    "SignatureMethod": None,
    "Token": None,
}
QCLOUD_DNS_API = {
    "RecordModify": {
        "domain": None,
        "recordId": None,
        "subDomain": None,
        "recordType": None,
        "recordLine": None,
        "value": None,
        "ttl": None,
        "mx": None,
    },
    "RecordList": {
        "domain": None,
        "offset": None,
        "length": None,
        "subDomain": None,
        "recordType": None,
        "qProjectId": None,
    },
}
# Carvet: QCloud secret ID and Key are encrypted with Fernet symmetric cipher.
# The cipher key is derived from *the MASTER PASSWORD you known* via PBKDF2HMAC,
# and its salt is the birthday of the elder in an 8-byte string.
QCLOUD_API_SECRET_ID = b"gAAAAABgL6nBl9uEi-ZLuioZxaYrDReSTTkrw14CiXPlipSyXlPUoGbpmOtzDq4p1QSBmzV4BvPCVGTljDOQf8k3SwYvu5lsuB3FIB4dHzdkfHO5I6lK7Uy_3ktZkhJpjhDSodRQbBYx"
QCLOUD_API_SECRET_KEY = b"gAAAAABgL6q53c_MImiiMqMsgxhnWxjFilGgxjIoAIXA3A5iFgcTLYi0Q51Tc5I9RWQ-HjnwqAsPgvSAIS96gwCMJETSLSy1OPK35677SoYEHOOJGolPpUAOptX8xhyDKvsbCphqMOfH"


def get_public_ip_addresses(method: str="ipify") -> Tuple[str, str]:
    if method == "ipify":
        ipv4 = requests.get("https://api.ipify.org").text
        try:
            ipv6 = requests.get("https://api6.ipify.org").text
        except requests.ConnectionError as e:
            warnings.warn(f"Seems that we don't have IPv6 addresses: {e}")
            ipv6 = None
    else:
        raise ValueError(f"Unsupported method: {method}")

    return ipv4, ipv6


def normalize_dict(src: Dict) -> Dict:
    dst = dict()
    for k, v in src.items():
        if v is None:
            continue
        dst[k] = v
    return dst


def get_qcloud_secret(
        master_password: str,
        salt: str,
    ) -> Tuple[str, str]:
    master_password = master_password.encode("utf-8")
    salt = salt.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password))
    f = Fernet(key)
    qcloud_secret_id = f.decrypt(QCLOUD_API_SECRET_ID).decode("utf-8")
    qcloud_secret_key = f.decrypt(QCLOUD_API_SECRET_KEY).decode("utf-8")

    return qcloud_secret_id, qcloud_secret_key


def get_qcloud_signature(
        plain_request: Dict[str, str],
        secret_key: str,
        request_method: str="GET",
        hmac_method: str="sha256",
    ) -> str:
    ordered_request = []
    for key in sorted(plain_request.keys()):
        val = plain_request[key]
        if val is None:
            raise ValueError(f"Get None value for request key {key}")
        key = key.replace("_", ".")
        ordered_request.append(f"{key}={val}")
    request_plain_str = f"{request_method}{QCLOUD_API_HOSTNAME}{QCLOUD_API_PATH}?" \
                        + "&".join(ordered_request) 
    signature = hmac.new(
        key=secret_key.encode("utf-8"),
        msg=request_plain_str.encode("utf-8"),
        digestmod=hmac_method,
    ).digest()
    encoded_signature = base64.b64encode(signature).decode("utf-8")

    return encoded_signature


def get_full_request(
        action: str,
        action_request: Dict[str, str],
        master_password: str,
        salt: str,
        request_method: str="GET",
        hmac_method: str="sha256",
    ) -> Dict[str, str]:
    assert request_method in ("GET", "PUT")
    assert hmac_method in ("sha256", "sha1")

    qcloud_secret_id, qcloud_secret_key = get_qcloud_secret(master_password, salt)
    request = copy.copy(QCLOUD_PUBLIC_API)
    request["Action"] = action
    request["Timestamp"] = int(time.time())
    request["Nonce"] = random.randint(0, 1 << 31)
    request["SecretId"] = qcloud_secret_id
    request["SignatureMethod"] = "HmacSHA256" if hmac_method == "sha256" else "HmacSHA1"
    request.update(action_request)
    request = normalize_dict(request)
    request["Signature"] = get_qcloud_signature(request, qcloud_secret_key, request_method, hmac_method)

    return request


def get_qcloud_subdomain_record(
        domain: str,
        subdomain: str,
        master_password: str,
        salt: str,
        request_method: str="GET",
        hmac_method: str="sha256",
    ) -> List[Dict[str, str]]:
    """Get subdomain's record id and previous value, return None if it does not exist."""
    request = copy.copy(QCLOUD_DNS_API["RecordList"])
    request["domain"] = domain
    request["subDomain"] = subdomain
    request = get_full_request("RecordList", request, master_password, salt, request_method, hmac_method)
    response = requests.get(f"https://{QCLOUD_API_HOSTNAME}{QCLOUD_API_PATH}", params=request).json()

    if response["code"] != 0:
        raise RuntimeError(response["message"])
    ret = []
    for record in response["data"]["records"]:
        assert record["name"] == subdomain
        filtered_record = {
            "recordId": record["id"],
            "recordType": record["type"],
            "recordLine": record["line"],
            "value": record["value"],
        }
        if record["type"] == "MX":
            filtered_record["mx"] = record["mx"]
        ret.append(filtered_record)

    return ret


def update_qcloud_subdomain_record(
        domain: str,
        subdomain: str,
        master_password: str,
        salt: str,
        request_method: str="GET",
        hmac_method: str="sha256",
        get_ip_method: str="ipify",
        dry_run: bool=False,
    ):
    current_records = get_qcloud_subdomain_record(domain, subdomain, master_password, salt, request_method, hmac_method)
    ipv4, ipv6 = get_public_ip_addresses(get_ip_method)

    updating_records = []
    for record in current_records:
        if record["recordType"] == "A" and record["value"] == ipv4:
            continue
        if record["recordType"] == "AAAA":
            if (ipv6 is None) or (ipv6 and record["value"] == ipv6):
                continue
        update_record = copy.copy(QCLOUD_DNS_API["RecordModify"])
        update_record["domain"] = domain
        update_record["subDomain"] = subdomain
        update_record.update(record)
        update_record = normalize_dict(update_record)
        updating_records.append(update_record)
    
    if dry_run:
        print("These records are going to be updated:")
        pprint(updating_records)
    else:
        new_records = []
        for request in updating_records:
            request = get_full_request("RecordModify", request, master_password, salt, request_method, hmac_method)
            response = requests.get(f"https://{QCLOUD_API_HOSTNAME}{QCLOUD_API_PATH}", params=request).json()
            if response["code"] != 0:
                raise RuntimeError(response["message"])
            else:
                new_records.append(response["data"]["record"])
        print("Updated records:")
        pprint(new_records)


if __name__ == "__main__":
    parser = ArgumentParser("Update QCloud DNS records by host IP addresses.")
    parser.add_argument("--domain", "-d", help="Domain to be updated.")
    parser.add_argument("--sub-domain", "-s", help="Sub-domain to be updated.")
    parser.add_argument("--password", "-p", help="Password to decrypt API key.")
    parser.add_argument("--salt", "-t", help="Salt to decrypt API key.")
    parser.add_argument("--request-method", default="GET", help="Method to call QCloud API.")
    parser.add_argument("--hmac-method", default="sha256", help="Method to hash QCloud signature.")
    parser.add_argument("--get-ip-method", default="ipify", help="Method to get host public IP addresses.")
    parser.add_argument("--dry-run", "-n", action="store_true", help="Print modifications and don't actually perform them.")
    args = parser.parse_args()

    update_qcloud_subdomain_record(args.domain, args.sub_domain, args.password, args.salt, args.request_method, args.hmac_method, args.get_ip_method, args.dry_run)
