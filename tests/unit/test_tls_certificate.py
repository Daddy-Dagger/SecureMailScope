"""Milestone 4 unit tests for X.509 certificate and chain extraction."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
import pytest

from backend.app.models.analysis import (
    CertificateMetadata,
    SessionSchema,
)
from core.pcap.tshark_adapter import PacketMetadata
from core.tls.certificate import (
    CertificateParseError,
    extract_tls_certificates,
    parse_x509_certificate,
)


def _generate_rsa_cert(
    *,
    common_name: str = "mail.example.com",
    issuer_name: str | None = None,
    serial: int = 1,
    key_size: int = 2048,
    days_valid: int = 90,
    sans: list[x509.GeneralName] | None = None,
    signing_key: rsa.RSAPrivateKey | None = None,
) -> tuple[bytes, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = (
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])
        if issuer_name is not None
        else subject
    )
    now = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days_valid))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans),
            critical=False,
        )
    signer = signing_key or key
    cert = builder.sign(signer, hashes.SHA256())
    return cert.public_bytes(Encoding.DER), key


def _generate_ec_cert(
    *,
    common_name: str = "ec.example.com",
    curve: ec.EllipticCurve = ec.SECP256R1(),
) -> bytes:
    key = ec.generate_private_key(curve)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(42)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


def _generate_ed25519_cert(*, common_name: str = "ed.example.com") -> bytes:
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(99)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .sign(key, None)
    )
    return cert.public_bytes(Encoding.DER)


def test_rsa_certificate_metadata_extraction() -> None:
    der, _ = _generate_rsa_cert(common_name="mail.example.com", serial=0x2A, key_size=2048)
    ref_time = datetime(2026, 9, 2, 0, 0, 0, tzinfo=timezone.utc)
    meta = parse_x509_certificate(
        der,
        chain_index=0,
        frame_number=15,
        reference_time=ref_time,
    )

    assert meta is not None
    CertificateMetadata.model_validate(meta)

    assert meta["chain_index"] == 0
    assert meta["subject"] == "CN=mail.example.com"
    assert meta["issuer"] == "CN=mail.example.com"
    assert meta["serial_number"] == "0x2a"
    assert meta["not_before"] == "2026-09-01T00:00:00Z"
    assert meta["not_after"] == "2026-11-30T00:00:00Z"
    assert meta["days_remaining"] == 89
    assert meta["public_key"] == {
        "algorithm": "RSA",
        "size_bits": 2048,
        "curve": None,
    }
    assert meta["signature_algorithm"] == "sha256WithRSAEncryption"
    assert meta["self_issued"] is True
    assert meta["self_signed"] is True
    assert meta["evidence"]["certificate_frame"] == 15
    assert isinstance(meta["fingerprint_sha256"], str)
    assert len(meta["fingerprint_sha256"]) == 64


def test_ec_certificate_metadata_extraction() -> None:
    der = _generate_ec_cert(common_name="ec.example.com", curve=ec.SECP256R1())
    meta = parse_x509_certificate(der, chain_index=0, frame_number=20)

    assert meta is not None
    CertificateMetadata.model_validate(meta)

    assert meta["public_key"]["algorithm"] == "EC"
    assert meta["public_key"]["size_bits"] == 256
    assert meta["public_key"]["curve"] == "secp256r1"
    assert meta["signature_algorithm"] == "ecdsa-with-SHA256"
    assert meta["self_issued"] is True
    assert meta["self_signed"] is True


def test_ed25519_certificate_metadata_extraction() -> None:
    der = _generate_ed25519_cert(common_name="ed.example.com")
    meta = parse_x509_certificate(der, chain_index=0, frame_number=21)

    assert meta is not None
    CertificateMetadata.model_validate(meta)

    assert meta["public_key"]["algorithm"] == "Ed25519"
    assert meta["public_key"]["size_bits"] == 256
    assert meta["public_key"]["curve"] is None
    assert meta["signature_algorithm"] == "ed25519"
    assert meta["self_issued"] is True
    assert meta["self_signed"] is True


def test_certificate_chain_ordering() -> None:
    root_der, root_key = _generate_rsa_cert(
        common_name="Example Root CA",
        serial=1,
    )
    intermediate_der, inter_key = _generate_rsa_cert(
        common_name="Example Intermediate CA",
        issuer_name="Example Root CA",
        serial=2,
        signing_key=root_key,
    )
    leaf_der, _ = _generate_rsa_cert(
        common_name="mail.example.com",
        issuer_name="Example Intermediate CA",
        serial=3,
        signing_key=inter_key,
    )

    packet = PacketMetadata(
        frame_number=10,
        timestamp=1788220800.0,
        src_ip="192.0.2.20",
        src_port=465,
        dst_ip="192.0.2.10",
        dst_port=51000,
        tcp_stream="0",
        tls_record=True,
        tls_certificates=(leaf_der, intermediate_der, root_der),
    )

    chain = extract_tls_certificates([packet])

    assert len(chain) == 3
    assert [c["chain_index"] for c in chain] == [0, 1, 2]
    assert chain[0]["subject"] == "CN=mail.example.com"
    assert chain[0]["issuer"] == "CN=Example Intermediate CA"
    assert chain[0]["self_issued"] is False
    assert chain[0]["self_signed"] is False
    assert chain[0]["evidence"]["certificate_frame"] == 10

    assert chain[1]["subject"] == "CN=Example Intermediate CA"
    assert chain[1]["issuer"] == "CN=Example Root CA"
    assert chain[1]["self_issued"] is False
    assert chain[1]["self_signed"] is False

    assert chain[2]["subject"] == "CN=Example Root CA"
    assert chain[2]["issuer"] == "CN=Example Root CA"
    assert chain[2]["self_issued"] is True
    assert chain[2]["self_signed"] is True


def test_validity_date_parsing_and_utc_normalization() -> None:
    der, _ = _generate_rsa_cert(days_valid=45)
    meta = parse_x509_certificate(
        der,
        reference_time=datetime(2026, 9, 11, 0, 0, 0, tzinfo=timezone.utc),
    )
    assert meta is not None
    assert meta["not_before"].endswith("Z")
    assert meta["not_after"].endswith("Z")
    assert meta["days_remaining"] == 35


def test_days_remaining_calculation_with_epoch_float() -> None:
    der, _ = _generate_rsa_cert(days_valid=10)
    ref_epoch = datetime(2026, 9, 6, 0, 0, 0, tzinfo=timezone.utc).timestamp()
    meta = parse_x509_certificate(der, reference_time=ref_epoch)
    assert meta is not None
    assert meta["days_remaining"] == 5


def test_days_remaining_none_without_reference_time() -> None:
    der, _ = _generate_rsa_cert()
    meta = parse_x509_certificate(der, reference_time=None)
    assert meta is not None
    assert meta["days_remaining"] is None


def test_days_remaining_past_expiration() -> None:
    der, _ = _generate_rsa_cert(days_valid=10)
    past_epoch = datetime(2026, 9, 20, 0, 0, 0, tzinfo=timezone.utc).timestamp()
    meta = parse_x509_certificate(der, reference_time=past_epoch)
    assert meta is not None
    assert meta["days_remaining"] < 0


def test_san_extraction_multiple_types() -> None:
    sans: list[x509.GeneralName] = [
        x509.DNSName("mail.example.com"),
        x509.DNSName("smtp.example.com"),
        x509.IPAddress(ipaddress.IPv4Address("192.0.2.25")),
        x509.RFC822Name("postmaster@example.com"),
    ]
    der, _ = _generate_rsa_cert(sans=sans)
    meta = parse_x509_certificate(der)
    assert meta is not None
    assert meta["subject_alternative_names"] == [
        "mail.example.com",
        "smtp.example.com",
        "192.0.2.25",
        "postmaster@example.com",
    ]


def test_certificate_without_sans() -> None:
    der, _ = _generate_rsa_cert(sans=None)
    meta = parse_x509_certificate(der)
    assert meta is not None
    assert meta["subject_alternative_names"] == []


def test_self_issued_and_self_signed_true() -> None:
    der, _ = _generate_rsa_cert(common_name="SelfSignedCA")
    meta = parse_x509_certificate(der)
    assert meta is not None
    assert meta["self_issued"] is True
    assert meta["self_signed"] is True


def test_self_issued_spoofed_signature_is_false() -> None:
    k_legit = rsa.generate_private_key(65537, 2048)
    k_attacker = rsa.generate_private_key(65537, 2048)

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SpoofedOrg")])
    now = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(k_legit.public_key())
        .serial_number(777)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .sign(k_attacker, hashes.SHA256())
    )
    der = cert.public_bytes(Encoding.DER)

    meta = parse_x509_certificate(der)
    assert meta is not None
    assert meta["self_issued"] is True
    assert meta["self_signed"] is False


def test_ca_signed_certificate_not_self_issued() -> None:
    root_der, root_key = _generate_rsa_cert(common_name="Real CA")
    leaf_der, _ = _generate_rsa_cert(
        common_name="client.example.com",
        issuer_name="Real CA",
        signing_key=root_key,
    )
    meta = parse_x509_certificate(leaf_der)
    assert meta is not None
    assert meta["self_issued"] is False
    assert meta["self_signed"] is False


def test_missing_certificate_data_returns_empty_list() -> None:
    packet = PacketMetadata(
        frame_number=1,
        timestamp=1.0,
        src_ip="192.0.2.10",
        src_port=51000,
        dst_ip="192.0.2.20",
        dst_port=465,
        tcp_stream="0",
        tls_record=True,
        tls_certificates=(),
    )
    assert extract_tls_certificates([packet]) == []


def test_malformed_certificate_der_bytes() -> None:
    corrupt = b"\x30\x82\x01\x00\x00\xff\xee\xdd"
    with pytest.raises(CertificateParseError):
        parse_x509_certificate(corrupt, strict=True)

    assert parse_x509_certificate(corrupt, strict=False) is None

    packet = PacketMetadata(
        frame_number=2,
        timestamp=2.0,
        src_ip="192.0.2.20",
        src_port=465,
        dst_ip="192.0.2.10",
        dst_port=51000,
        tcp_stream="0",
        tls_certificates=(corrupt,),
    )
    assert extract_tls_certificates([packet]) == []


def test_empty_certificate_bytes() -> None:
    with pytest.raises(CertificateParseError):
        parse_x509_certificate(b"", strict=True)

    assert parse_x509_certificate(b"", strict=False) is None


def test_backward_compatibility_with_milestones_1_to_3() -> None:
    legacy_session = {
        "session_id": "smtp-001",
        "protocol": "SMTP",
        "client_ip": "192.168.1.10",
        "client_port": 51544,
        "server_ip": "192.168.1.20",
        "server_port": 25,
        "packet_count": 42,
        "start_time": "2026-09-02T10:10:10Z",
        "end_time": "2026-09-02T10:10:15Z",
        "application_events": [],
        "transport_security": {
            "mode": "PLAINTEXT",
            "upgrade_status": "UNKNOWN",
            "advertised": False,
            "requested": False,
            "accepted": False,
            "tls_detected": False,
            "upgrade_command": "STARTTLS",
            "evidence": {},
        },
        "tls": {
            "detected": False,
            "handshake_status": "NOT_APPLICABLE",
            "offered_versions": [],
            "offered_groups": [],
            "version": None,
            "cipher_suite": None,
            "key_exchange": None,
            "evidence": {},
        },
    }
    validated = SessionSchema.model_validate(legacy_session)
    assert validated.certificates == []
    assert validated.crypto_features is None
