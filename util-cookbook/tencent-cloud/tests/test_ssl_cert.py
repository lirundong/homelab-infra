from typing import Any

import pytest

from tencent_cloud import qcloud_api
from tencent_cloud import ssl_cert
from tencent_cloud.ssl_cert import CST


def raw_cert(cid: str, end: str = "2026-10-09 09:59:59") -> dict[str, Any]:
    return {
        "CertificateId": cid,
        "Domain": "nas.example.com",
        "Status": 1,
        "StatusName": "issued",
        "InsertTime": "2026-07-10 10:00:00",
        "CertEndTime": end,
    }


def test_from_response_parses_beijing_time() -> None:
    cert = ssl_cert.Certificate.from_response(raw_cert("c1"))
    assert cert.end_time is not None and cert.end_time.tzinfo == CST
    assert cert.end_time.hour == 9
    assert ssl_cert.Certificate.from_response(raw_cert("c2", end="")).end_time is None


def test_describe_certificates_paginates(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []
    total = 150

    def fake(service: str, version: str, action: str, payload: dict[str, Any]) -> dict:
        assert (service, version, action) == ("ssl", "2019-12-05", "DescribeCertificates")
        calls.append(payload)
        count = min(payload["Limit"], total - payload["Offset"])
        page = [raw_cert(f"c{payload['Offset'] + i}") for i in range(count)]
        return {"TotalCount": total, "Certificates": page}

    monkeypatch.setattr(qcloud_api, "signed_request", fake)
    certs = ssl_cert.describe_certificates("example.com")
    assert len(certs) == total
    assert [c["Offset"] for c in calls] == [0, 100]


def test_signed_request_targets_service(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class FakeSecrets:
        QCLOUD_API_SECRET_ID = "AKIDtest"
        QCLOUD_API_SECRET_KEY = "keytest"

    class FakeResponse:
        def json(self) -> dict[str, Any]:
            return {"Response": {"Error": {"Code": "AuthFailure", "Message": "nope"}}}

    def fake_post(url: str, **kwargs: Any) -> FakeResponse:
        captured.update(url=url, **kwargs)
        return FakeResponse()

    monkeypatch.setattr(qcloud_api, "secrets", FakeSecrets)
    monkeypatch.setattr(qcloud_api.requests, "post", fake_post)
    with pytest.raises(RuntimeError, match="ApplyCertificate AuthFailure: nope"):
        qcloud_api.signed_request("ssl", "2019-12-05", "ApplyCertificate", {"A": 1})

    assert captured["url"] == "https://ssl.tencentcloudapi.com"
    auth = captured["headers"]["Authorization"]
    assert auth.startswith("TC3-HMAC-SHA256 Credential=AKIDtest/")
    assert "/ssl/tc3_request" in auth
    assert "SignedHeaders=content-type;host;x-tc-action;x-tc-timestamp;x-tc-version" in auth


def test_download_failure_hides_presigned_url(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://bucket.cos.example/key.zip?sign=SECRET"
    monkeypatch.setattr(qcloud_api, "signed_request", lambda *_: {"DownloadCertificateUrl": url})

    def fail(*_: Any, **__: Any) -> None:
        raise ssl_cert.requests.ConnectionError(url)

    monkeypatch.setattr(ssl_cert.requests, "get", fail)
    with pytest.raises(RuntimeError) as exc:
        ssl_cert.download_certificate("c1", "nginx")
    assert "SECRET" not in str(exc.value) and exc.value.__cause__ is None
    assert exc.value.__suppress_context__


def test_apply_certificate_cleans_up_dns_record(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake(service: str, version: str, action: str, payload: dict[str, Any]) -> dict:
        captured.update(action=action, payload=payload)
        return {"CertificateId": "new"}

    monkeypatch.setattr(qcloud_api, "signed_request", fake)
    assert ssl_cert.apply_certificate("nas.example.com") == "new"
    assert captured == {
        "action": "ApplyCertificate",
        "payload": {
            "DvAuthMethod": "DNS_AUTO",
            "DomainName": "nas.example.com",
            "DeleteDnsAutoRecord": True,
        },
    }
