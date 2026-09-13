"""Unit tests for deterministic cryptographic and transport security rules.

Tests cover positive and negative scenarios for:
- TLS version rules (TLS 1.0, 1.1, modern TLS, unknown)
- Cipher suite rules (weak/deprecated, modern AEAD, unknown)
- Fatal handshake failure
- Forward Secrecy (ECDHE/DHE, static RSA, unknown)
- Transport security / STARTTLS (advertised unused, rejected, incomplete, plaintext, implicit TLS, POP3 STLS)
- Certificate validity (expired, not yet valid, valid, missing certs)
- Public key strength (weak RSA, acceptable RSA, weak DSA)
- Signature algorithm (MD5, SHA-1, modern SHA-2)
- Self-signed vs self-issued
- Contract compliance against finding_schema.json and backend FindingSchema
"""

import json
from pathlib import Path
from typing import Any

import pytest

from backend.app.models.analysis import FindingSchema
from core.rules import (
    evaluate_analysis_result,
    evaluate_certificate_rules,
    evaluate_cipher_suite,
    evaluate_fatal_handshake,
    evaluate_forward_secrecy,
    evaluate_rules,
    evaluate_session_rules,
    evaluate_tls_version,
    evaluate_transport_security,
)


@pytest.fixture
def finding_schema() -> dict[str, Any]:
    """Load canonical finding JSON schema."""
    schema_path = (
        Path(__file__).resolve().parents[2]
        / "shared"
        / "contracts"
        / "finding_schema.json"
    )
    with open(schema_path, encoding="utf-8") as f:
        return json.load(f)


def _assert_valid_finding(finding: dict[str, Any], schema: dict[str, Any]) -> None:
    """Verify that finding complies with both JSON schema contract and Pydantic model."""
    # Verify required fields
    for req in schema["required"]:
        assert req in finding, f"Missing required finding field '{req}'"
    # Verify allowed properties (additionalProperties: false)
    allowed = set(schema["properties"].keys())
    assert set(finding.keys()).issubset(
        allowed
    ), f"Finding has unexpected keys: {set(finding.keys()) - allowed}"
    # Verify severity enum
    assert finding["severity"] in schema["properties"]["severity"]["enum"]
    # Verify evidence subfields if present
    if finding.get("evidence") is not None:
        ev_allowed = set(schema["properties"]["evidence"]["properties"].keys())
        assert set(finding["evidence"].keys()).issubset(ev_allowed)
    # Verify Pydantic validation (extra='forbid')
    validated = FindingSchema.model_validate(finding)
    assert validated.finding_id == finding["finding_id"]
    assert validated.severity == finding["severity"]


# ==============================================================================
# TLS Version Rule Tests
# ==============================================================================


def test_tls_1_0_positive(finding_schema: dict[str, Any]) -> None:
    """TLS 1.0 session produces TLS-DEPRECATED-1.0 HIGH finding with frame evidence."""
    session = {
        "session_id": "smtp-001",
        "tls": {
            "detected": True,
            "version": "TLS 1.0",
            "evidence": {"selected_version_frame": 15, "server_hello_frame": 15},
        },
    }
    findings = evaluate_tls_version(session)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_id"] == "TLS-DEPRECATED-1.0"
    assert f["severity"] == "HIGH"
    assert f["session_id"] == "smtp-001"
    assert f["evidence"]["frame_number"] == 15
    assert f["evidence"]["observed_value"] == "TLS 1.0"
    _assert_valid_finding(f, finding_schema)


def test_tls_1_1_positive(finding_schema: dict[str, Any]) -> None:
    """TLS 1.1 session produces TLS-DEPRECATED-1.1 HIGH finding with frame evidence."""
    session = {
        "session_id": "imap-001",
        "tls": {
            "detected": True,
            "version": "TLS 1.1",
            "evidence": {"selected_version_frame": 24},
        },
    }
    findings = evaluate_tls_version(session)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_id"] == "TLS-DEPRECATED-1.1"
    assert f["severity"] == "HIGH"
    assert f["session_id"] == "imap-001"
    assert f["evidence"]["frame_number"] == 24
    _assert_valid_finding(f, finding_schema)


def test_modern_tls_negative() -> None:
    """Modern TLS versions (TLS 1.2, TLS 1.3) produce no deprecated TLS findings."""
    for version in ("TLS 1.2", "TLS 1.3"):
        session = {
            "session_id": "sess-modern",
            "tls": {"detected": True, "version": version},
        }
        assert evaluate_tls_version(session) == []


def test_unknown_or_absent_tls_version_negative() -> None:
    """Unknown or absent TLS version produces no unsupported findings."""
    for tls_payload in (None, {}, {"detected": False}, {"detected": True, "version": None}, {"detected": True, "version": "UNKNOWN"}):
        session = {"session_id": "sess-unknown", "tls": tls_payload}
        assert evaluate_tls_version(session) == []


# ==============================================================================
# Cipher Suite Rule Tests
# ==============================================================================


@pytest.mark.parametrize(
    "cipher_name,cipher_id,expected_sev,match_str",
    [
        ("TLS_RSA_WITH_NULL_SHA", "0x0002", "CRITICAL", "NULL"),
        ("TLS_RSA_EXPORT_WITH_RC4_40_MD5", "0x0003", "CRITICAL", "export"),
        ("TLS_DH_anon_WITH_AES_128_CBC_SHA", "0x0034", "CRITICAL", "anonymous"),
        ("TLS_RSA_WITH_RC4_128_SHA", "0x0005", "HIGH", "RC4"),
        ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "0x000a", "HIGH", "3DES"),
        ("TLS_RSA_WITH_AES_128_CBC_MD5", None, "HIGH", "MD5"),
    ],
)
def test_weak_cipher_suites_positive(
    cipher_name: str,
    cipher_id: str | None,
    expected_sev: str,
    match_str: str,
    finding_schema: dict[str, Any],
) -> None:
    """Known weak/deprecated cipher suites produce TLS-WEAK-CIPHER findings."""
    session = {
        "session_id": "smtp-weak-cipher",
        "tls": {
            "detected": True,
            "cipher_suite": {"id": cipher_id or "0xffff", "name": cipher_name},
            "evidence": {"selected_cipher_frame": 18},
        },
    }
    findings = evaluate_cipher_suite(session)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_id"] == "TLS-WEAK-CIPHER"
    assert f["severity"] == expected_sev
    assert f["evidence"]["frame_number"] == 18
    assert match_str.lower() in f["explanation"].lower()
    _assert_valid_finding(f, finding_schema)


def test_modern_aead_cipher_negative() -> None:
    """Modern AEAD ciphers produce no weak cipher findings."""
    modern_ciphers = [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    ]
    for c in modern_ciphers:
        session = {
            "session_id": "modern-cipher",
            "tls": {
                "detected": True,
                "cipher_suite": {"id": "0x1302", "name": c},
            },
        }
        assert evaluate_cipher_suite(session) == []


def test_unknown_cipher_negative() -> None:
    """Unknown or unresolved cipher IDs produce no unsupported findings."""
    for cipher_val in (
        None,
        {"id": "0x9999", "name": None},
        {"id": "0x9999", "name": "UNKNOWN"},
    ):
        session = {
            "session_id": "unknown-cipher",
            "tls": {
                "detected": True,
                "cipher_suite": cipher_val,
            },
        }
        assert evaluate_cipher_suite(session) == []


# ==============================================================================
# Fatal TLS Handshake Tests
# ==============================================================================


def test_fatal_tls_handshake_positive(finding_schema: dict[str, Any]) -> None:
    """Handshake status FAILED produces TLS-HANDSHAKE-FATAL finding."""
    session = {
        "session_id": "smtp-fatal",
        "tls": {
            "detected": True,
            "handshake_status": "FAILED",
            "evidence": {"alert_frame": 28},
        },
    }
    findings = evaluate_fatal_handshake(session)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_id"] == "TLS-HANDSHAKE-FATAL"
    assert f["severity"] == "HIGH"
    assert f["evidence"]["frame_number"] == 28
    assert f["evidence"]["observed_value"] == "FAILED"
    _assert_valid_finding(f, finding_schema)


def test_fatal_tls_handshake_negative() -> None:
    """Non-failed handshake states produce no fatal alert finding."""
    for status in ("COMPLETE", "INCOMPLETE", "UNKNOWN", "NOT_APPLICABLE"):
        session = {"tls": {"handshake_status": status}}
        assert evaluate_fatal_handshake(session) == []


# ==============================================================================
# Forward Secrecy Tests
# ==============================================================================


@pytest.mark.parametrize("method", ["ECDHE", "DHE"])
def test_forward_secrecy_supported_positive(
    method: str, finding_schema: dict[str, Any]
) -> None:
    """Ephemeral key exchange (ECDHE, DHE) produces INFO TLS-FORWARD-SECRECY-SUPPORTED."""
    session = {
        "session_id": "sess-fs",
        "tls": {
            "detected": True,
            "key_exchange": {"method": method, "group": {"name": "x25519"}},
            "evidence": {"key_exchange_frame": 22},
        },
    }
    findings = evaluate_forward_secrecy(session)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_id"] == "TLS-FORWARD-SECRECY-SUPPORTED"
    assert f["severity"] == "INFO"
    assert f["evidence"]["observed_value"] == method
    _assert_valid_finding(f, finding_schema)


def test_static_rsa_no_forward_secrecy_positive(
    finding_schema: dict[str, Any],
) -> None:
    """Static RSA key exchange produces MEDIUM TLS-NO-FORWARD-SECRECY finding."""
    session = {
        "session_id": "sess-no-fs",
        "tls": {
            "detected": True,
            "key_exchange": {"method": "RSA", "group": None},
            "evidence": {"key_exchange_frame": 19},
        },
    }
    findings = evaluate_forward_secrecy(session)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_id"] == "TLS-NO-FORWARD-SECRECY"
    assert f["severity"] == "MEDIUM"
    assert f["evidence"]["observed_value"] == "RSA"
    _assert_valid_finding(f, finding_schema)


def test_unknown_key_exchange_no_unsupported_claim() -> None:
    """Unknown key exchange method produces no unsupported findings."""
    for kx in (None, {}, {"method": None}, {"method": "UNKNOWN"}):
        session = {"tls": {"detected": True, "key_exchange": kx}}
        assert evaluate_forward_secrecy(session) == []


# ==============================================================================
# STARTTLS and Transport Security Tests
# ==============================================================================


def test_starttls_advertised_not_used_positive(
    finding_schema: dict[str, Any],
) -> None:
    """STARTTLS advertised but unused produces STARTTLS-ADVERTISED-NOT-USED finding."""
    session = {
        "session_id": "smtp-adv-unused",
        "protocol": "SMTP",
        "transport_security": {
            "mode": "STARTTLS",
            "upgrade_status": "ADVERTISED_NOT_REQUESTED",
            "advertised": True,
            "requested": False,
            "accepted": False,
            "tls_detected": False,
            "upgrade_command": "STARTTLS",
            "evidence": {"advertised_frame": 12},
        },
    }
    findings = evaluate_transport_security(session)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_id"] == "STARTTLS-ADVERTISED-NOT-USED"
    assert f["severity"] == "MEDIUM"
    assert f["evidence"]["frame_number"] == 12
    assert "cleartext" in f["explanation"].lower()
    _assert_valid_finding(f, finding_schema)


def test_starttls_rejected_positive(finding_schema: dict[str, Any]) -> None:
    """STARTTLS upgrade rejected produces STARTTLS-REJECTED HIGH finding."""
    session = {
        "session_id": "smtp-rejected",
        "protocol": "SMTP",
        "transport_security": {
            "mode": "STARTTLS",
            "upgrade_status": "FAILED",
            "advertised": True,
            "requested": True,
            "accepted": False,
            "tls_detected": False,
            "upgrade_command": "STARTTLS",
            "evidence": {"request_frame": 14},
        },
    }
    findings = evaluate_transport_security(session)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_id"] == "STARTTLS-REJECTED"
    assert f["severity"] == "HIGH"
    assert f["evidence"]["frame_number"] == 14
    _assert_valid_finding(f, finding_schema)


def test_incomplete_starttls_positive(finding_schema: dict[str, Any]) -> None:
    """STARTTLS upgrade incomplete produces STARTTLS-INCOMPLETE HIGH finding."""
    session = {
        "session_id": "smtp-incomplete",
        "protocol": "SMTP",
        "transport_security": {
            "mode": "STARTTLS",
            "upgrade_status": "INCOMPLETE",
            "advertised": True,
            "requested": True,
            "accepted": True,
            "tls_detected": False,
            "upgrade_command": "STARTTLS",
            "evidence": {"request_frame": 16, "accept_frame": 17},
        },
    }
    findings = evaluate_transport_security(session)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_id"] == "STARTTLS-INCOMPLETE"
    assert f["severity"] == "HIGH"
    assert f["evidence"]["frame_number"] == 16
    _assert_valid_finding(f, finding_schema)


def test_successful_starttls_negative() -> None:
    """Successful UPGRADED session produces no transport security warning findings."""
    session = {
        "session_id": "smtp-clean",
        "protocol": "SMTP",
        "transport_security": {
            "mode": "STARTTLS",
            "upgrade_status": "UPGRADED",
            "advertised": True,
            "requested": True,
            "accepted": True,
            "tls_detected": True,
            "upgrade_command": "STARTTLS",
            "evidence": {"advertised_frame": 10, "tls_start_frame": 14},
        },
    }
    assert evaluate_transport_security(session) == []


def test_implicit_tls_no_false_positive() -> None:
    """Implicit TLS sessions must NEVER be flagged for missing STARTTLS or cleartext."""
    for proto, port in [("SMTP", 465), ("IMAP", 993), ("POP3", 995)]:
        session = {
            "session_id": f"implicit-{proto.lower()}",
            "protocol": proto,
            "server_port": port,
            "transport_security": {
                "mode": "IMPLICIT_TLS",
                "upgrade_status": "NOT_APPLICABLE",
                "advertised": False,
                "requested": False,
                "accepted": False,
                "tls_detected": True,
                "upgrade_command": None,
                "evidence": {"tls_start_frame": 1},
            },
        }
        assert evaluate_transport_security(session) == []


def test_pop3_stls_handled_correctly(finding_schema: dict[str, Any]) -> None:
    """POP3 STLS command name is used correctly in finding title and explanation."""
    session = {
        "session_id": "pop3-001",
        "protocol": "POP3",
        "transport_security": {
            "mode": "STARTTLS",
            "upgrade_status": "ADVERTISED_NOT_REQUESTED",
            "advertised": True,
            "requested": False,
            "accepted": False,
            "tls_detected": False,
            "upgrade_command": "STLS",
            "evidence": {"advertised_frame": 8},
        },
    }
    findings = evaluate_transport_security(session)
    assert len(findings) == 1
    f = findings[0]
    assert "STLS" in f["title"]
    assert "STLS" in f["explanation"]
    _assert_valid_finding(f, finding_schema)


def test_plaintext_session_positive(finding_schema: dict[str, Any]) -> None:
    """Cleartext email session produces TRANSPORT-PLAINTEXT-SESSION HIGH finding."""
    session = {
        "session_id": "smtp-cleartext",
        "protocol": "SMTP",
        "transport_security": {
            "mode": "PLAINTEXT",
            "upgrade_status": "NOT_ADVERTISED",
            "advertised": False,
            "requested": False,
            "accepted": False,
            "tls_detected": False,
            "upgrade_command": "STARTTLS",
            "evidence": {"advertised_frame": 5},
        },
    }
    findings = evaluate_transport_security(session)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_id"] == "TRANSPORT-PLAINTEXT-SESSION"
    assert f["severity"] == "HIGH"
    _assert_valid_finding(f, finding_schema)


# ==============================================================================
# Certificate Rule Tests
# ==============================================================================


def test_expired_certificate_positive(finding_schema: dict[str, Any]) -> None:
    """Negative days_remaining relative to reference time produces CERT-EXPIRED."""
    session = {
        "session_id": "sess-expired",
        "start_time": "2026-09-02T10:00:00Z",
        "certificates": [
            {
                "chain_index": 0,
                "subject": "CN=mail.expired.org",
                "issuer": "CN=Old CA",
                "days_remaining": -45,
                "not_after": "2026-07-19T00:00:00Z",
                "evidence": {"certificate_frame": 25},
            }
        ],
    }
    findings = evaluate_certificate_rules(session)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_id"] == "CERT-EXPIRED"
    assert f["severity"] == "HIGH"
    assert f["evidence"]["frame_number"] == 25
    assert "expired 45 day(s)" in f["explanation"].lower()
    _assert_valid_finding(f, finding_schema)


def test_not_yet_valid_certificate_positive(
    finding_schema: dict[str, Any],
) -> None:
    """Certificate with not_before after session reference time produces CERT-NOT-YET-VALID."""
    session = {
        "session_id": "sess-future",
        "start_time": "2026-09-02T10:00:00Z",
        "certificates": [
            {
                "chain_index": 0,
                "subject": "CN=mail.future.org",
                "not_before": "2026-09-10T00:00:00Z",
                "not_after": "2027-09-10T00:00:00Z",
                "days_remaining": 373,
                "evidence": {"certificate_frame": 30},
            }
        ],
    }
    findings = evaluate_certificate_rules(session)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_id"] == "CERT-NOT-YET-VALID"
    assert f["severity"] == "HIGH"
    assert f["evidence"]["frame_number"] == 30
    _assert_valid_finding(f, finding_schema)


def test_valid_certificate_negative() -> None:
    """Valid certificate within its validity window produces no expiration findings."""
    session = {
        "session_id": "sess-valid",
        "start_time": "2026-09-02T10:00:00Z",
        "certificates": [
            {
                "chain_index": 0,
                "subject": "CN=mail.valid.org",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
                "days_remaining": 121,
                "public_key": {"algorithm": "RSA", "size_bits": 2048},
                "signature_algorithm": "sha256WithRSAEncryption",
                "self_signed": False,
            }
        ],
    }
    assert evaluate_certificate_rules(session) == []


def test_weak_rsa_key_positive(finding_schema: dict[str, Any]) -> None:
    """RSA key under 2048 bits produces CERT-WEAK-RSA-KEY HIGH finding."""
    for bits in (512, 1024):
        session = {
            "session_id": "sess-weak-rsa",
            "certificates": [
                {
                    "subject": "CN=mail.weak.org",
                    "public_key": {"algorithm": "RSA", "size_bits": bits},
                    "evidence": {"certificate_frame": 22},
                }
            ],
        }
        findings = evaluate_certificate_rules(session)
        assert len(findings) == 1
        f = findings[0]
        assert f["finding_id"] == "CERT-WEAK-RSA-KEY"
        assert f["severity"] == "HIGH"
        assert f["evidence"]["observed_value"] == f"RSA {bits} bits"
        _assert_valid_finding(f, finding_schema)


def test_acceptable_rsa_key_negative() -> None:
    """RSA keys >= 2048 bits produce no weak key finding."""
    for bits in (2048, 3072, 4096):
        session = {
            "session_id": "sess-ok-rsa",
            "certificates": [
                {
                    "subject": "CN=mail.good.org",
                    "public_key": {"algorithm": "RSA", "size_bits": bits},
                    "signature_algorithm": "sha256WithRSAEncryption",
                }
            ],
        }
        assert evaluate_certificate_rules(session) == []


def test_weak_dsa_key_positive(finding_schema: dict[str, Any]) -> None:
    """DSA key under 2048 bits produces CERT-WEAK-DSA-KEY HIGH finding."""
    session = {
        "session_id": "sess-dsa",
        "certificates": [
            {
                "subject": "CN=mail.dsa.org",
                "public_key": {"algorithm": "DSA", "size_bits": 1024},
                "evidence": {"certificate_frame": 19},
            }
        ],
    }
    findings = evaluate_certificate_rules(session)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_id"] == "CERT-WEAK-DSA-KEY"
    assert f["severity"] == "HIGH"
    _assert_valid_finding(f, finding_schema)


def test_deprecated_signature_algorithms_positive(
    finding_schema: dict[str, Any],
) -> None:
    """MD5 (CRITICAL) and SHA-1 (HIGH) certificate signatures produce findings."""
    # MD5
    session_md5 = {
        "session_id": "sess-md5",
        "certificates": [
            {
                "subject": "CN=mail.md5.org",
                "signature_algorithm": "md5WithRSAEncryption",
                "evidence": {"certificate_frame": 20},
            }
        ],
    }
    f_md5 = evaluate_certificate_rules(session_md5)
    assert len(f_md5) == 1
    assert f_md5[0]["finding_id"] == "CERT-SIG-MD5"
    assert f_md5[0]["severity"] == "CRITICAL"
    _assert_valid_finding(f_md5[0], finding_schema)

    # SHA-1
    session_sha1 = {
        "session_id": "sess-sha1",
        "certificates": [
            {
                "subject": "CN=mail.sha1.org",
                "signature_algorithm": "sha1WithRSAEncryption",
                "evidence": {"certificate_frame": 21},
            }
        ],
    }
    f_sha1 = evaluate_certificate_rules(session_sha1)
    assert len(f_sha1) == 1
    assert f_sha1[0]["finding_id"] == "CERT-SIG-SHA1"
    assert f_sha1[0]["severity"] == "HIGH"
    _assert_valid_finding(f_sha1[0], finding_schema)


def test_modern_signature_negative() -> None:
    """Modern SHA-2 signatures produce no deprecated signature findings."""
    for sig in ("sha256WithRSAEncryption", "sha384WithRSAEncryption", "ecdsa-with-SHA256", "ed25519"):
        session = {
            "session_id": "sess-modern-sig",
            "certificates": [
                {
                    "subject": "CN=mail.modern.org",
                    "signature_algorithm": sig,
                    "public_key": {"algorithm": "RSA", "size_bits": 2048},
                }
            ],
        }
        assert evaluate_certificate_rules(session) == []


def test_verified_self_signed_certificate_positive(
    finding_schema: dict[str, Any],
) -> None:
    """Verified self-signed certificate (self_signed == True) produces CERT-SELF-SIGNED."""
    session = {
        "session_id": "sess-self-signed",
        "certificates": [
            {
                "chain_index": 0,
                "subject": "CN=mail.self.org",
                "issuer": "CN=mail.self.org",
                "self_issued": True,
                "self_signed": True,
                "public_key": {"algorithm": "RSA", "size_bits": 2048},
                "signature_algorithm": "sha256WithRSAEncryption",
                "evidence": {"certificate_frame": 22},
            }
        ],
    }
    findings = evaluate_certificate_rules(session)
    assert len(findings) == 1
    f = findings[0]
    assert f["finding_id"] == "CERT-SELF-SIGNED"
    assert f["severity"] == "MEDIUM"
    _assert_valid_finding(f, finding_schema)


def test_self_issued_not_self_signed_negative() -> None:
    """Self-issued certificate where self_signed is False/None must NOT produce CERT-SELF-SIGNED."""
    for ss_flag in (False, None):
        session = {
            "session_id": "sess-self-issued",
            "certificates": [
                {
                    "chain_index": 0,
                    "subject": "CN=mail.spoofed.org",
                    "issuer": "CN=mail.spoofed.org",
                    "self_issued": True,
                    "self_signed": ss_flag,
                    "public_key": {"algorithm": "RSA", "size_bits": 2048},
                    "signature_algorithm": "sha256WithRSAEncryption",
                }
            ],
        }
        assert evaluate_certificate_rules(session) == []


def test_absent_certificates_tolerance() -> None:
    """Empty certificate array (e.g. TLS 1.3 encrypted certs) produces no certificate findings."""
    for certs in ([], None):
        session = {
            "session_id": "sess-no-certs",
            "certificates": certs,
        }
        assert evaluate_certificate_rules(session) == []


# ==============================================================================
# Engine Orchestrator & End-to-End Evaluation Tests
# ==============================================================================


def test_evaluate_session_rules_full(finding_schema: dict[str, Any]) -> None:
    """Test full session evaluation aggregating multiple deterministic findings."""
    session = {
        "session_id": "smtp-vulnerable",
        "protocol": "SMTP",
        "start_time": "2026-09-02T10:00:00Z",
        "transport_security": {
            "mode": "STARTTLS",
            "upgrade_status": "UPGRADED",
            "advertised": True,
            "requested": True,
            "accepted": True,
            "tls_detected": True,
            "upgrade_command": "STARTTLS",
            "evidence": {"tls_start_frame": 20},
        },
        "tls": {
            "detected": True,
            "version": "TLS 1.0",
            "cipher_suite": {"id": "0x0004", "name": "TLS_RSA_WITH_RC4_128_MD5"},
            "key_exchange": {"method": "RSA", "group": None},
            "evidence": {"server_hello_frame": 21, "selected_version_frame": 21, "selected_cipher_frame": 21},
        },
        "certificates": [
            {
                "chain_index": 0,
                "subject": "CN=mail.old.org",
                "days_remaining": -10,
                "public_key": {"algorithm": "RSA", "size_bits": 1024},
                "signature_algorithm": "md5WithRSAEncryption",
                "self_signed": True,
                "evidence": {"certificate_frame": 22},
            }
        ],
    }
    findings = evaluate_session_rules(session)
    finding_ids = [f["finding_id"] for f in findings]

    assert "TLS-DEPRECATED-1.0" in finding_ids
    assert "TLS-WEAK-CIPHER" in finding_ids
    assert "TLS-NO-FORWARD-SECRECY" in finding_ids
    assert "CERT-EXPIRED" in finding_ids
    assert "CERT-WEAK-RSA-KEY" in finding_ids
    assert "CERT-SIG-MD5" in finding_ids
    assert "CERT-SELF-SIGNED" in finding_ids

    for f in findings:
        _assert_valid_finding(f, finding_schema)


def test_evaluate_rules_deterministic_sorting() -> None:
    """Findings across multiple sessions must be sorted deterministically by severity."""
    sessions = [
        {
            "session_id": "session-b",
            "tls": {"detected": True, "version": "TLS 1.0"},
        },
        {
            "session_id": "session-a",
            "tls": {
                "detected": True,
                "cipher_suite": {"id": "0x0001", "name": "TLS_RSA_WITH_NULL_MD5"},
            },
        },
        {
            "session_id": "session-c",
            "tls": {
                "detected": True,
                "key_exchange": {"method": "ECDHE"},
            },
        },
    ]
    findings = evaluate_rules(sessions)
    assert len(findings) == 3
    # CRITICAL (NULL cipher) -> HIGH (TLS 1.0) -> INFO (ECDHE FS)
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["session_id"] == "session-a"
    assert findings[1]["severity"] == "HIGH"
    assert findings[1]["session_id"] == "session-b"
    assert findings[2]["severity"] == "INFO"
    assert findings[2]["session_id"] == "session-c"


def test_evaluate_analysis_result_integration(
    finding_schema: dict[str, Any],
) -> None:
    """evaluate_analysis_result executes on top-level analysis dict and returns findings."""
    analysis = {
        "file": "test.pcap",
        "packet_count": 100,
        "summary": {"smtp_sessions": 1, "imap_sessions": 0, "pop3_sessions": 0},
        "sessions": [
            {
                "session_id": "smtp-01",
                "tls": {
                    "detected": True,
                    "version": "TLS 1.1",
                    "cipher_suite": {"id": "0x000a", "name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
                },
            }
        ],
        "findings": [],
        "overall_score": None,
        "risk_level": None,
    }
    findings = evaluate_analysis_result(analysis)
    assert len(findings) == 2
    for f in findings:
        _assert_valid_finding(f, finding_schema)


def test_backward_compatibility_empty_or_milestone_1_session() -> None:
    """Milestone 1 session with no transport_security or tls generates no false findings."""
    m1_session = {
        "session_id": "smtp-m1",
        "protocol": "SMTP",
        "client_ip": "192.168.1.10",
        "client_port": 50000,
        "server_ip": "192.168.1.20",
        "server_port": 25,
        "packet_count": 50,
        "start_time": "2026-09-02T10:10:10Z",
        "end_time": "2026-09-02T10:10:15Z",
    }
    assert evaluate_session_rules(m1_session) == []
