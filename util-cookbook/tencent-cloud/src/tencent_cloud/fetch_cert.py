#!/usr/bin/env python3

"""Apply for, check, and download Tencent Cloud free SSL certificates."""

import os
import sys
import time
import zipfile
from argparse import ArgumentParser
from datetime import datetime
from pathlib import Path
from pathlib import PurePosixPath
from typing import NoReturn

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from common import secrets
from tencent_cloud import ssl_cert
from tencent_cloud.ssl_cert import Certificate

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_ACTION_NEEDED = 2

# Tencent Cloud native download formats, plus `plex` (PKCS#12 converted from nginx).
CERT_TYPES = ("nginx", "apache", "tomcat", "iis", "jks", "plex")
POLL_INTERVAL_SECONDS = 30


class _Parser(ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # Exit code 2 is reserved for "action needed".
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")


def fqdn_of(domain: str, subdomain: str) -> str:
    return domain if subdomain == "@" else f"{subdomain}.{domain}"


def latest_by_domain(certs: list[Certificate]) -> dict[str, Certificate]:
    latest: dict[str, Certificate] = {}
    for cert in certs:
        if cert.domain not in latest or cert.insert_time > latest[cert.domain].insert_time:
            latest[cert.domain] = cert
    return latest


def classify(cert: Certificate | None, now: datetime, renew_days: int) -> str:
    """One of: missing, pending, failed, valid, expiring, expired."""
    if cert is None:
        return "missing"
    if cert.is_pending:
        return "pending"
    if cert.status == ssl_cert.STATUS_FAILED:
        return "failed"
    days_left = cert.days_left(now)
    if days_left is None or days_left <= 0:
        return "expired"
    return "valid" if days_left > renew_days else "expiring"


def describe(cert: Certificate, state: str, now: datetime) -> str:
    days_left = cert.days_left(now)
    days = f"{days_left:.0f} days left" if days_left is not None else cert.status_name
    end = cert.end_time.strftime("%Y-%m-%d %H:%M %Z") if cert.end_time else "-"
    return f"{cert.domain:<32} {state:<9} {days:<16} ends {end:<22} id {cert.certificate_id}"


def check_only(domain: str, fqdn: str | None, renew_days: int, now: datetime) -> int:
    def wanted(name: str) -> bool:
        return name == fqdn if fqdn else name == domain or name.endswith(f".{domain}")

    certs = ssl_cert.describe_certificates(fqdn or domain)
    latest = latest_by_domain([c for c in certs if wanted(c.domain)])
    if fqdn and fqdn not in latest:
        print(f"{fqdn:<32} missing")
        return EXIT_ACTION_NEEDED

    exit_code = EXIT_OK
    for name in sorted(latest):
        state = classify(latest[name], now, renew_days)
        print(describe(latest[name], state, now))
        if state != "valid":
            exit_code = EXIT_ACTION_NEEDED
    return exit_code


def wait_for_issue(certificate_id: str, wait_minutes: float) -> bool:
    deadline = time.monotonic() + wait_minutes * 60
    while True:
        cert = ssl_cert.describe_certificate(certificate_id)
        if cert.status == ssl_cert.STATUS_ISSUED:
            return True
        if not cert.is_pending:
            raise RuntimeError(f"Certificate {certificate_id} is {cert.status_name}.")
        if time.monotonic() + POLL_INTERVAL_SECONDS > deadline:
            return False
        print(f"Waiting for {certificate_id}: {cert.status_name}")
        time.sleep(POLL_INTERVAL_SECONDS)


def write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(data)


def save_bundle(archive: zipfile.ZipFile, dest: Path) -> list[Path]:
    """Flatten the archive into `dest`; every file is owner-only readable."""
    written: list[Path] = []
    for info in archive.infolist():
        if info.is_dir():
            continue
        path = dest / PurePosixPath(info.filename).name
        if path in written:
            raise RuntimeError(f"Duplicate file name {path.name} in certificate archive.")
        write_private(path, archive.read(info))
        written.append(path)
    return written


def _single_member(archive: zipfile.ZipFile, suffixes: tuple[str, ...]) -> bytes:
    names = [n for n in archive.namelist() if n.endswith(suffixes)]
    if len(names) != 1:
        raise RuntimeError(f"Expected one {'/'.join(suffixes)} file in archive, got {names}.")
    return archive.read(names[0])


def to_plex_pkcs12(archive: zipfile.ZipFile, fqdn: str, password: bytes) -> bytes:
    """Convert an nginx bundle into a PKCS#12 file Plex (OpenSSL 3) accepts."""
    certs = x509.load_pem_x509_certificates(_single_member(archive, ("_bundle.crt",)))
    key = serialization.load_pem_private_key(_single_member(archive, (".key",)), password=None)
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise RuntimeError(f"Unsupported private key type {type(key).__name__}.")
    leaf, chain = certs[0], certs[1:]
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    pem = serialization.Encoding.PEM
    if leaf.public_key().public_bytes(pem, spki) != key.public_key().public_bytes(pem, spki):
        raise RuntimeError("Private key does not match the leaf certificate.")
    encryption = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC)
        .hmac_hash(hashes.SHA256())
        .build(password)
    )
    return pkcs12.serialize_key_and_certificates(
        fqdn.encode("utf-8"), key, leaf, chain, encryption
    )


def download(certificate_id: str, fqdn: str, cert_type: str, output_dir: Path) -> None:
    dest = output_dir / fqdn
    dest.mkdir(parents=True, exist_ok=True)
    if cert_type == "plex":
        archive = ssl_cert.download_certificate(certificate_id, "nginx")
        path = dest / f"{fqdn}.p12"
        password = secrets.PLEX_CERT_PASSWORD.encode("utf-8")
        write_private(path, to_plex_pkcs12(archive, fqdn, password))
        written = [path]
    else:
        written = save_bundle(ssl_cert.download_certificate(certificate_id, cert_type), dest)
    print(f"Downloaded {certificate_id} ({cert_type}):")
    for path in written:
        print(f"  {path}")


def fetch(
    fqdn: str,
    cert_type: str,
    output_dir: Path,
    renew_days: int,
    now: datetime,
    force_new: bool = False,
    wait_minutes: float = 0,
) -> int:
    if cert_type == "plex":
        # Fail before touching the API if the PKCS#12 password is not registered.
        secrets.PLEX_CERT_PASSWORD
    cert = latest_by_domain(ssl_cert.describe_certificates(fqdn)).get(fqdn)
    state = classify(cert, now, renew_days)
    if cert is not None:
        print(f"Latest: {describe(cert, state, now)}")

    if state == "valid" and not force_new:
        assert cert is not None
        download(cert.certificate_id, fqdn, cert_type, output_dir)
        return EXIT_OK
    if state == "failed" and not force_new:
        raise RuntimeError(
            f"Latest certificate for {fqdn} failed validation; inspect it in the console "
            "or rerun with --force-new."
        )
    if state == "pending" and not force_new:
        assert cert is not None
        certificate_id = cert.certificate_id
    else:
        certificate_id = ssl_cert.apply_certificate(fqdn)
        print(f"Applied for a new certificate for {fqdn}: {certificate_id}")

    if wait_minutes > 0 and wait_for_issue(certificate_id, wait_minutes):
        download(certificate_id, fqdn, cert_type, output_dir)
        return EXIT_OK
    print(
        f"Certificate {certificate_id} is pending issuance, which usually takes a few minutes. "
        "Rerun the same command once Tencent Cloud notifies you."
    )
    return EXIT_ACTION_NEEDED


def main() -> None:
    parser = _Parser(
        "fetch-cert",
        description="Apply for, check, and download Tencent Cloud free SSL certificates. "
        f"Exits {EXIT_OK} on success, {EXIT_ERROR} on errors, and {EXIT_ACTION_NEEDED} when "
        "a certificate is pending, expiring, or missing.",
    )
    parser.add_argument("--domain", "-d", required=True, help="Apex domain in DNSPod.")
    parser.add_argument(
        "--sub-domain",
        "-s",
        help="Sub-domain of the certificate, `@` for the apex. "
        "Optional with --check-only, which then checks the whole domain.",
    )
    parser.add_argument(
        "--type", "-t", choices=CERT_TYPES, default="nginx", help="Certificate format."
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=Path("."),
        help="Files are written into <output-dir>/<fqdn>/.",
    )
    parser.add_argument(
        "--renew-if-expiring-within-days",
        type=int,
        default=30,
        metavar="DAYS",
        help="Apply for a new certificate when the current one expires within DAYS.",
    )
    parser.add_argument(
        "--check-only",
        "-n",
        action="store_true",
        help="Only report certificate status; never apply or download.",
    )
    parser.add_argument(
        "--force-new",
        action="store_true",
        help="Apply for a new certificate even if a valid or pending one exists.",
    )
    parser.add_argument(
        "--wait",
        type=float,
        default=0,
        metavar="MINUTES",
        help="Poll up to MINUTES for issuance and download once issued.",
    )
    args = parser.parse_args()

    now = datetime.now(ssl_cert.CST)
    if args.check_only:
        fqdn = fqdn_of(args.domain, args.sub_domain) if args.sub_domain else None
        sys.exit(check_only(args.domain, fqdn, args.renew_if_expiring_within_days, now))
    if not args.sub_domain:
        parser.error("--sub-domain is required unless --check-only is given")
    sys.exit(
        fetch(
            fqdn=fqdn_of(args.domain, args.sub_domain),
            cert_type=args.type,
            output_dir=args.output_dir,
            renew_days=args.renew_if_expiring_within_days,
            now=now,
            force_new=args.force_new,
            wait_minutes=args.wait,
        )
    )


if __name__ == "__main__":
    main()
