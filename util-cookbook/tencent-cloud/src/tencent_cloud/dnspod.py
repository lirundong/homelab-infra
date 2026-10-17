"""Tencent Cloud DNSPod API client."""

import copy
from typing import Any

from tencent_cloud import qcloud_api

QCLOUD_DNS_API: dict[str, dict[str, str | None]] = {
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


def normalize_dict[V](src: dict[str, V | None]) -> dict[str, V]:
    return {k: v for k, v in src.items() if v is not None}


def _signed_request(action: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Sign and POST a DNSPod request. Returns the unwrapped Response payload."""
    version = payload.pop("X-TC-Version")
    return qcloud_api.signed_request("dnspod", version, action, payload)


def get_qcloud_subdomain_record(domain: str, subdomain: str) -> list[dict[str, str]]:
    """Fetch all records for a subdomain. Returns an empty list if none exist."""
    payload = copy.copy(QCLOUD_DNS_API["DescribeRecordList"])
    payload["Domain"] = domain
    payload["Subdomain"] = subdomain
    payload = normalize_dict(payload)

    response = _signed_request("DescribeRecordList", payload)

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


def modify_record(payload: dict[str, Any]) -> None:
    """Send a single ModifyRecord request. Raises on API error."""
    _signed_request("ModifyRecord", payload)
