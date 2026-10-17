import io
import stat
import zipfile
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from tencent_cloud import fetch_cert
from tencent_cloud import ssl_cert
from tencent_cloud.ssl_cert import CST
from tencent_cloud.ssl_cert import Certificate

NOW = datetime(2026, 10, 17, 12, 0, tzinfo=CST)
FQDN = "nas.example.com"
# DER encoding of the AES-256-CBC OID (2.16.840.1.101.3.4.1.42).
AES_256_CBC_OID = bytes.fromhex("060960864801650304012a")


def cert(
    status: int = 1,
    days_left: float | None = 60,
    domain: str = FQDN,
    cid: str = "c1",
    inserted: int = 0,
) -> Certificate:
    return Certificate(
        certificate_id=cid,
        domain=domain,
        status=status,
        status_name=f"status-{status}",
        insert_time=NOW - timedelta(days=100 - inserted),
        end_time=NOW + timedelta(days=days_left) if days_left is not None else None,
    )


class FakeApi:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, certs: list[Certificate]) -> None:
        self.certs = certs
        self.applied: list[str] = []
        self.downloaded: list[tuple[str, str]] = []
        self.statuses: list[int] = []
        self.deleted: list[str] = []
        monkeypatch.setattr(ssl_cert, "describe_certificates", lambda key: self.certs)
        monkeypatch.setattr(ssl_cert, "apply_certificate", self.apply)
        monkeypatch.setattr(ssl_cert, "describe_certificate", self.describe)
        monkeypatch.setattr(ssl_cert, "download_certificate", self.download)
        monkeypatch.setattr(ssl_cert, "delete_certificate", self.deleted.append)
        monkeypatch.setattr(fetch_cert.time, "sleep", lambda _: None)

    def apply(self, domain: str) -> str:
        self.applied.append(domain)
        return "new"

    def describe(self, cid: str) -> Certificate:
        return cert(status=self.statuses.pop(0), cid=cid)

    def download(self, cid: str, service_type: str) -> zipfile.ZipFile:
        self.downloaded.append((cid, service_type))
        return make_zip({f"{FQDN}_{service_type}/{FQDN}_bundle.crt": b"crt", "x.key": b"key"})


def make_zip(files: dict[str, bytes]) -> zipfile.ZipFile:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return zipfile.ZipFile(io.BytesIO(buf.getvalue()))


@pytest.mark.parametrize(
    ("certificate", "state"),
    [
        (None, "missing"),
        (cert(status=0, days_left=None), "pending"),
        (cert(status=4, days_left=None), "pending"),
        (cert(status=2, days_left=None), "failed"),
        (cert(status=3, days_left=-8), "expired"),
        (cert(days_left=-1), "expired"),
        (cert(days_left=10), "expiring"),
        (cert(days_left=30), "expiring"),
        (cert(days_left=31), "valid"),
    ],
)
def test_classify(certificate: Certificate | None, state: str) -> None:
    assert fetch_cert.classify(certificate, NOW, renew_days=30) == state


def test_latest_by_domain_picks_newest() -> None:
    old = cert(cid="old", inserted=0)
    new = cert(cid="new", inserted=50, status=0, days_left=None)
    assert fetch_cert.latest_by_domain([new, old])[FQDN].certificate_id == "new"


def test_fqdn_of_apex() -> None:
    assert fetch_cert.fqdn_of("example.com", "@") == "example.com"
    assert fetch_cert.fqdn_of("example.com", "nas") == FQDN


def test_fetch_valid_downloads_without_applying(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    api = FakeApi(monkeypatch, [cert(days_left=60)])
    assert fetch_cert.fetch(FQDN, "apache", tmp_path, 30, NOW) == fetch_cert.EXIT_OK
    assert api.applied == []
    assert api.downloaded == [("c1", "apache")]
    assert sorted(p.name for p in (tmp_path / FQDN / "apache").iterdir()) == [
        f"{FQDN}_bundle.crt",
        "x.key",
    ]


def test_fetch_pending_does_not_reapply(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    api = FakeApi(monkeypatch, [cert(status=0, days_left=None)])
    assert fetch_cert.fetch(FQDN, "nginx", tmp_path, 30, NOW) == fetch_cert.EXIT_ACTION_NEEDED
    assert api.applied == []
    assert api.downloaded == []


@pytest.mark.parametrize("existing", [[], [cert(days_left=5)], [cert(status=3, days_left=-8)]])
def test_fetch_applies_when_missing_expiring_or_expired(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, existing: list[Certificate]
) -> None:
    api = FakeApi(monkeypatch, existing)
    assert fetch_cert.fetch(FQDN, "nginx", tmp_path, 30, NOW) == fetch_cert.EXIT_ACTION_NEEDED
    assert api.applied == [FQDN]
    assert api.downloaded == []


def test_fetch_failed_requires_force(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    api = FakeApi(monkeypatch, [cert(status=2, days_left=None)])
    with pytest.raises(RuntimeError, match="--force"):
        fetch_cert.fetch(FQDN, "nginx", tmp_path, 30, NOW)
    assert fetch_cert.fetch(FQDN, "nginx", tmp_path, 30, NOW, force=True) == 2
    assert api.applied == [FQDN]


def test_fetch_force_with_valid(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    api = FakeApi(monkeypatch, [cert(days_left=60)])
    fetch_cert.fetch(FQDN, "nginx", tmp_path, 30, NOW, force=True)
    assert api.applied == [FQDN]


def test_fetch_wait_downloads_once_issued(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    api = FakeApi(monkeypatch, [])
    api.statuses = [0, 4, 1]
    assert fetch_cert.fetch(FQDN, "nginx", tmp_path, 30, NOW, wait_minutes=5) == 0
    assert api.downloaded == [("new", "nginx")]


def test_fetch_wait_times_out(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    api = FakeApi(monkeypatch, [cert(status=0, days_left=None)])
    api.statuses = [0]
    assert fetch_cert.fetch(FQDN, "nginx", tmp_path, 30, NOW, wait_minutes=0.1) == 2
    assert api.downloaded == []


def test_fetch_wait_raises_on_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    api = FakeApi(monkeypatch, [])
    api.statuses = [0, 2]
    with pytest.raises(RuntimeError, match="status-2"):
        fetch_cert.fetch(FQDN, "nginx", tmp_path, 30, NOW, wait_minutes=5)


def test_check_only_reports_latest_per_domain(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    FakeApi(
        monkeypatch,
        [
            cert(cid="old", status=3, days_left=-90, inserted=0),
            cert(cid="cur", days_left=60, inserted=10),
            cert(cid="other", domain="plex.example.com", days_left=60),
            cert(cid="foreign", domain="nas.example.com.cn", days_left=-1),
        ],
    )
    assert fetch_cert.check_only("example.com", None, 30, NOW) == fetch_cert.EXIT_OK
    out = capsys.readouterr().out
    assert "cur" in out and "other" in out
    assert "old" not in out and "foreign" not in out


def test_check_only_flags_expiring_and_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeApi(monkeypatch, [cert(days_left=10)])
    assert fetch_cert.check_only("example.com", None, 30, NOW) == 2
    assert fetch_cert.check_only("example.com", "plex.example.com", 30, NOW) == 2


def test_save_bundle_flattens_with_private_mode(tmp_path: Path) -> None:
    archive = make_zip({"a/one.crt": b"1", "b/two.key": b"2", "dir/": b""})
    written = fetch_cert.save_bundle(archive, tmp_path)
    assert [p.name for p in written] == ["one.crt", "two.key"]
    for path in written:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_save_bundle_rejects_duplicate_names(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="Duplicate"):
        fetch_cert.save_bundle(make_zip({"a/x.crt": b"1", "b/x.crt": b"2"}), tmp_path)


def _nginx_bundle() -> tuple[zipfile.ZipFile, rsa.RSAPrivateKey]:
    def name(cn: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def sign(subject: str, public_key: Any, issuer: str) -> x509.Certificate:
        return (
            x509.CertificateBuilder()
            .subject_name(name(subject))
            .issuer_name(name(issuer))
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=1))
            .not_valid_after(NOW + timedelta(days=90))
            .sign(ca_key, hashes.SHA256())
        )

    leaf = sign(FQDN, key.public_key(), "Test CA")
    ca = sign("Test CA", ca_key.public_key(), "Test CA")
    pem = serialization.Encoding.PEM
    key_pem = key.private_bytes(
        pem, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )
    archive = make_zip(
        {
            f"{FQDN}_nginx/{FQDN}_bundle.crt": leaf.public_bytes(pem) + ca.public_bytes(pem),
            f"{FQDN}_nginx/{FQDN}.key": key_pem,
            f"{FQDN}_nginx/{FQDN}.csr": b"csr",
        }
    )
    return archive, key


def test_to_plex_pkcs12_round_trip() -> None:
    archive, key = _nginx_bundle()
    p12 = fetch_cert.to_plex_pkcs12(archive, FQDN, b"secret")

    assert AES_256_CBC_OID in p12
    loaded = pkcs12.load_pkcs12(p12, b"secret")
    assert loaded.key is not None and loaded.cert is not None
    assert loaded.key.private_numbers() == key.private_numbers()  # type: ignore[union-attr]
    assert loaded.cert.friendly_name == FQDN.encode()
    assert [c.certificate.subject.rfc4514_string() for c in loaded.additional_certs] == [
        "CN=Test CA"
    ]
    with pytest.raises(ValueError):
        pkcs12.load_pkcs12(p12, b"wrong")


def test_to_plex_pkcs12_rejects_mismatched_key() -> None:
    archive, _ = _nginx_bundle()
    other, _ = _nginx_bundle()
    mixed = make_zip(
        {
            "a_bundle.crt": archive.read(f"{FQDN}_nginx/{FQDN}_bundle.crt"),
            "a.key": other.read(f"{FQDN}_nginx/{FQDN}.key"),
        }
    )
    with pytest.raises(RuntimeError, match="does not match"):
        fetch_cert.to_plex_pkcs12(mixed, FQDN, b"secret")


def test_fetch_plex_writes_p12(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    archive, _ = _nginx_bundle()
    api = FakeApi(monkeypatch, [cert(days_left=60)])
    monkeypatch.setattr(api, "download", lambda cid, service_type: archive)
    monkeypatch.setattr(ssl_cert, "download_certificate", api.download)
    monkeypatch.setattr(fetch_cert, "secrets", SimpleNamespace(PLEX_CERT_PASSWORD="pw"))

    assert fetch_cert.fetch(FQDN, "plex", tmp_path, 30, NOW) == 0
    p12 = tmp_path / FQDN / "plex" / f"{FQDN}.p12"
    assert stat.S_IMODE(p12.stat().st_mode) == 0o600
    assert pkcs12.load_pkcs12(p12.read_bytes(), b"pw").cert is not None


def test_cli_usage_error_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["fetch-cert", "-d", "example.com"])
    with pytest.raises(SystemExit) as exc:
        fetch_cert.main()
    assert exc.value.code == fetch_cert.EXIT_ERROR


def delete_fixture(monkeypatch: pytest.MonkeyPatch, answer: str | None) -> FakeApi:
    def fake_input(prompt: str) -> str:
        if answer is None:
            raise EOFError
        return answer

    monkeypatch.setattr("builtins.input", fake_input)
    return FakeApi(
        monkeypatch,
        [
            cert(cid="expired", status=3, days_left=-8),
            cert(cid="failed", status=2, days_left=None),
            cert(cid="pending", status=0, days_left=None),
            cert(cid="expiring", days_left=10),
            cert(cid="valid", days_left=60, domain="plex.example.com"),
            cert(cid="foreign", status=3, days_left=-8, domain="nas.example.com.cn"),
        ],
    )


@pytest.mark.parametrize(
    ("force", "expected"),
    [(False, ["expired", "failed"]), (True, ["expired", "failed", "expiring", "valid"])],
)
def test_delete_selects_targets(
    monkeypatch: pytest.MonkeyPatch, force: bool, expected: list[str]
) -> None:
    api = delete_fixture(monkeypatch, "y")
    assert fetch_cert.delete("example.com", None, 30, NOW, force=force) == fetch_cert.EXIT_OK
    assert sorted(api.deleted) == sorted(expected)


def test_delete_scoped_to_fqdn(monkeypatch: pytest.MonkeyPatch) -> None:
    api = delete_fixture(monkeypatch, "Y")
    fetch_cert.delete("example.com", "plex.example.com", 30, NOW, force=True)
    assert api.deleted == ["valid"]


@pytest.mark.parametrize("answer", ["n", "", "yes", None])
def test_delete_aborts_without_y(monkeypatch: pytest.MonkeyPatch, answer: str | None) -> None:
    api = delete_fixture(monkeypatch, answer)
    assert fetch_cert.delete("example.com", None, 30, NOW) == fetch_cert.EXIT_ERROR
    assert api.deleted == []


def test_delete_nothing_skips_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("prompted"))
    FakeApi(monkeypatch, [cert(days_left=60)])
    assert fetch_cert.delete("example.com", None, 30, NOW) == fetch_cert.EXIT_OK


def test_delete_stops_on_first_error(monkeypatch: pytest.MonkeyPatch) -> None:
    api = delete_fixture(monkeypatch, "y")

    def fail(cid: str) -> None:
        api.deleted.append(cid)
        raise RuntimeError("BoundResources")

    monkeypatch.setattr(ssl_cert, "delete_certificate", fail)
    with pytest.raises(RuntimeError, match="BoundResources"):
        fetch_cert.delete("example.com", None, 30, NOW)
    assert len(api.deleted) == 1


@pytest.mark.parametrize(
    "argv",
    [
        ["--check-only", "--force"],
        ["--check-only", "--delete"],
        ["--delete", "--wait", "5"],
        ["-s", "nas", "--force-new"],
    ],
)
def test_cli_rejects_invalid_combinations(
    monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    monkeypatch.setattr("sys.argv", ["fetch-cert", "-d", "example.com", *argv])
    with pytest.raises(SystemExit) as exc:
        fetch_cert.main()
    assert exc.value.code == fetch_cert.EXIT_ERROR


def test_fetch_plex_uses_named_secret(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    archive, _ = _nginx_bundle()
    api = FakeApi(monkeypatch, [cert(days_left=60)])
    monkeypatch.setattr(ssl_cert, "download_certificate", lambda cid, service_type: archive)
    monkeypatch.setattr(fetch_cert, "secrets", SimpleNamespace(OTHER_P12="other"))

    fetch_cert.fetch(FQDN, "plex", tmp_path, 30, NOW, plex_password_secret="OTHER_P12")
    p12 = (tmp_path / FQDN / "plex" / f"{FQDN}.p12").read_bytes()
    assert pkcs12.load_pkcs12(p12, b"other").cert is not None
    assert api.applied == []


def test_fetch_plex_missing_secret_fails_before_api(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(ssl_cert, "describe_certificates", lambda key: pytest.fail("API called"))
    monkeypatch.setattr(fetch_cert, "secrets", SimpleNamespace())
    with pytest.raises(AttributeError):
        fetch_cert.fetch(FQDN, "plex", tmp_path, 30, NOW, plex_password_secret="MISSING")


def test_non_plex_fetch_ignores_secret(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    FakeApi(monkeypatch, [cert(days_left=60)])
    monkeypatch.setattr(fetch_cert, "secrets", SimpleNamespace())
    assert fetch_cert.fetch(FQDN, "nginx", tmp_path, 30, NOW, plex_password_secret="X") == 0
