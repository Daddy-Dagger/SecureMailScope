"""Milestone 4 unit tests for cryptographic feature extraction."""

from __future__ import annotations

from backend.app.models.analysis import CryptoFeatures
from core.tls.crypto_features import extract_crypto_features


def test_crypto_features_aggregation_with_tls_and_certificate() -> None:
    tls = {
        "detected": True,
        "handshake_status": "COMPLETE",
        "offered_versions": ["TLS 1.3", "TLS 1.2"],
        "offered_groups": [{"id": "0x001d", "name": "x25519"}],
        "version": "TLS 1.3",
        "cipher_suite": {
            "id": "0x1302",
            "name": "TLS_AES_256_GCM_SHA384",
        },
        "key_exchange": {
            "method": "ECDHE",
            "group": {"id": "0x001d", "name": "x25519"},
        },
        "evidence": {"server_hello_frame": 2},
    }
    certificates = [
        {
            "chain_index": 0,
            "subject": "CN=mail.example.com",
            "issuer": "CN=Example CA",
            "serial_number": "0x1234",
            "fingerprint_sha256": "a" * 64,
            "not_before": "2026-09-01T00:00:00Z",
            "not_after": "2026-11-30T00:00:00Z",
            "days_remaining": 89,
            "subject_alternative_names": ["mail.example.com"],
            "self_issued": False,
            "self_signed": False,
            "public_key": {
                "algorithm": "RSA",
                "size_bits": 2048,
                "curve": None,
            },
            "signature_algorithm": "sha256WithRSAEncryption",
            "evidence": {"certificate_frame": 3},
        }
    ]

    features = extract_crypto_features(tls, certificates)
    CryptoFeatures.model_validate(features)

    assert features == {
        "tls_version": "TLS 1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "key_exchange": "ECDHE",
        "named_group": "x25519",
        "certificate_public_key_algorithm": "RSA",
        "certificate_public_key_bits": 2048,
        "certificate_signature_algorithm": "sha256WithRSAEncryption",
        "certificate_days_remaining": 89,
        "certificate_self_signed": False,
    }


def test_crypto_features_without_certificate() -> None:
    tls = {
        "detected": True,
        "handshake_status": "INCOMPLETE",
        "version": "TLS 1.2",
        "cipher_suite": {
            "id": "0xc02f",
            "name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        },
        "key_exchange": {"method": "ECDHE", "group": None},
    }
    features = extract_crypto_features(tls, [])
    CryptoFeatures.model_validate(features)

    assert features["tls_version"] == "TLS 1.2"
    assert features["cipher_suite"] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert features["key_exchange"] == "ECDHE"
    assert features["named_group"] is None
    assert features["certificate_public_key_algorithm"] is None
    assert features["certificate_public_key_bits"] is None
    assert features["certificate_signature_algorithm"] is None
    assert features["certificate_days_remaining"] is None
    assert features["certificate_self_signed"] is None


def test_crypto_features_without_tls() -> None:
    features = extract_crypto_features(None, None)
    CryptoFeatures.model_validate(features)

    assert features == {
        "tls_version": None,
        "cipher_suite": None,
        "key_exchange": None,
        "named_group": None,
        "certificate_public_key_algorithm": None,
        "certificate_public_key_bits": None,
        "certificate_signature_algorithm": None,
        "certificate_days_remaining": None,
        "certificate_self_signed": None,
    }


def test_crypto_features_with_numeric_cipher_id_only() -> None:
    tls = {
        "detected": True,
        "version": "TLS 1.2",
        "cipher_suite": {"id": "0xfefe", "name": None},
        "key_exchange": {"method": "UNKNOWN", "group": {"id": "0xfe01", "name": None}},
    }
    features = extract_crypto_features(tls, [])
    assert features["cipher_suite"] == "0xfefe"
    assert features["named_group"] == "0xfe01"


def test_crypto_features_with_ecdsa_leaf_cert() -> None:
    certificates = [
        {
            "chain_index": 0,
            "subject": "CN=ec.example.com",
            "issuer": "CN=ec.example.com",
            "serial_number": "0x01",
            "fingerprint_sha256": "b" * 64,
            "not_before": "2026-09-01T00:00:00Z",
            "not_after": "2026-10-01T00:00:00Z",
            "days_remaining": 30,
            "subject_alternative_names": ["ec.example.com"],
            "self_issued": True,
            "self_signed": True,
            "public_key": {
                "algorithm": "EC",
                "size_bits": 256,
                "curve": "secp256r1",
            },
            "signature_algorithm": "ecdsa-with-SHA256",
            "evidence": {"certificate_frame": 4},
        }
    ]
    features = extract_crypto_features(None, certificates)
    assert features["certificate_public_key_algorithm"] == "EC"
    assert features["certificate_public_key_bits"] == 256
    assert features["certificate_signature_algorithm"] == "ecdsa-with-SHA256"
    assert features["certificate_self_signed"] is True
