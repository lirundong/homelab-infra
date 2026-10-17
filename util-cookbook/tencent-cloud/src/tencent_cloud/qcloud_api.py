"""Tencent Cloud API 3.0 client (TC3-HMAC-SHA256 signed requests)."""

import copy
import hashlib
import hmac
import json
from datetime import datetime
from datetime import timezone
from typing import Any

import requests

from common import secrets


def get_qcloud_auth(headers: dict[str, str], payload: dict[str, Any], service: str) -> str:
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
    headers.setdefault("Host", f"{service}.tencentcloudapi.com")
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


def signed_request(
    service: str, version: str, action: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """Sign and POST an API 3.0 request. Returns the unwrapped Response payload."""
    headers = {
        "X-TC-Action": action,
        "X-TC-Version": version,
        "X-TC-Timestamp": str(int(datetime.now(timezone.utc).timestamp())),
    }
    headers["Authorization"] = get_qcloud_auth(headers, payload, service)

    response = requests.post(
        f"https://{service}.tencentcloudapi.com", json=payload, headers=headers, timeout=30
    ).json()["Response"]

    if response.get("Error"):
        err_code = response["Error"]["Code"]
        err_msg = response["Error"]["Message"]
        raise RuntimeError(f"{action} {err_code}: {err_msg}")
    return response
