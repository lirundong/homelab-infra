"""Tencent Cloud SSL certificate API client (free TrustAsia DV certificates)."""

import io
import zipfile
from dataclasses import dataclass
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from typing import Any

import requests

from tencent_cloud import qcloud_api

SSL_API_VERSION = "2019-12-05"
# Certificate times are reported in Beijing time.
CST = timezone(timedelta(hours=8))
STATUS_ISSUED = 1
# 0: under review; 4: auto DNS validation record being added.
STATUS_PENDING = frozenset({0, 4})
STATUS_FAILED = 2


@dataclass(frozen=True)
class Certificate:
    certificate_id: str
    domain: str
    status: int
    status_name: str
    insert_time: datetime
    end_time: datetime | None

    @classmethod
    def from_response(cls, raw: dict[str, Any]) -> "Certificate":
        return cls(
            certificate_id=raw["CertificateId"],
            domain=raw["Domain"],
            status=int(raw["Status"]),
            status_name=raw.get("StatusName") or "",
            insert_time=_parse_time(raw["InsertTime"]),
            end_time=_parse_time(raw["CertEndTime"]) if raw.get("CertEndTime") else None,
        )

    @property
    def is_pending(self) -> bool:
        return self.status in STATUS_PENDING

    def days_left(self, now: datetime) -> float | None:
        if self.status != STATUS_ISSUED or self.end_time is None:
            return None
        return (self.end_time - now) / timedelta(days=1)


def _parse_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=CST)


def _request(action: str, payload: dict[str, Any]) -> dict[str, Any]:
    return qcloud_api.signed_request("ssl", SSL_API_VERSION, action, payload)


def describe_certificates(search_key: str, page_size: int = 100) -> list[Certificate]:
    """List all certificates whose domain contains `search_key`."""
    certs: list[Certificate] = []
    while True:
        response = _request(
            "DescribeCertificates",
            {"SearchKey": search_key, "Offset": len(certs), "Limit": page_size},
        )
        page = response["Certificates"] or []
        certs.extend(Certificate.from_response(c) for c in page)
        if len(page) < page_size or len(certs) >= response["TotalCount"]:
            return certs


def describe_certificate(certificate_id: str) -> Certificate:
    return Certificate.from_response(
        _request("DescribeCertificate", {"CertificateId": certificate_id})
    )


def apply_certificate(domain: str) -> str:
    """Apply for a free RSA 2048 DV certificate validated through DNSPod. Returns CertificateId."""
    # Explicit CsrEncryptAlgo/CsrKeyParameter are rejected as an invalid domain; RSA 2048 is
    # the default.
    response = _request(
        "ApplyCertificate",
        {"DvAuthMethod": "DNS_AUTO", "DomainName": domain, "DeleteDnsAutoRecord": True},
    )
    return str(response["CertificateId"])


def download_certificate(certificate_id: str, service_type: str) -> zipfile.ZipFile:
    """Download the certificate bundle formatted for `service_type` (e.g. nginx, apache)."""
    response = _request(
        "DescribeDownloadCertificateUrl",
        {"CertificateId": certificate_id, "ServiceType": service_type},
    )
    try:
        archive = requests.get(response["DownloadCertificateUrl"], timeout=60)
        archive.raise_for_status()
    except requests.RequestException as e:
        # The presigned URL grants access to the private key; keep it out of tracebacks.
        raise RuntimeError(f"Downloading {certificate_id} failed: {type(e).__name__}") from None
    return zipfile.ZipFile(io.BytesIO(archive.content))


def delete_certificate(certificate_id: str) -> None:
    response = _request("DeleteCertificate", {"CertificateId": certificate_id})
    if not response.get("DeleteResult"):
        raise RuntimeError(f"DeleteCertificate {certificate_id} returned {response}.")
