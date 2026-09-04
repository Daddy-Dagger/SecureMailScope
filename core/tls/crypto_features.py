"""Extract normalized factual cryptographic features from handshake and certificate data."""

from __future__ import annotations

from typing import Any


def extract_crypto_features(
    tls: dict[str, Any] | None,
    certificates: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Aggregate factual crypto properties into a normalized feature structure.

    Extracts cryptographic facts observable from TLS handshake metadata and
    the leaf certificate. Unobserved or unobservable features are set to None
    without assigning quality/risk scores.
    """
    tls_data = tls or {}
    certs = certificates or []
    leaf_cert = certs[0] if certs else None

    cipher = tls_data.get("cipher_suite")
    cipher_name: str | None = None
    if isinstance(cipher, dict):
        cipher_name = cipher.get("name") or cipher.get("id")

    key_ex = tls_data.get("key_exchange")
    key_ex_method: str | None = None
    group_name: str | None = None
    if isinstance(key_ex, dict):
        key_ex_method = key_ex.get("method")
        group = key_ex.get("group")
        if isinstance(group, dict):
            group_name = group.get("name") or group.get("id")

    pubkey = leaf_cert.get("public_key") if isinstance(leaf_cert, dict) else None

    return {
        "tls_version": tls_data.get("version"),
        "cipher_suite": cipher_name,
        "key_exchange": key_ex_method,
        "named_group": group_name,
        "certificate_public_key_algorithm": pubkey.get("algorithm") if isinstance(pubkey, dict) else None,
        "certificate_public_key_bits": pubkey.get("size_bits") if isinstance(pubkey, dict) else None,
        "certificate_signature_algorithm": leaf_cert.get("signature_algorithm") if isinstance(leaf_cert, dict) else None,
        "certificate_days_remaining": leaf_cert.get("days_remaining") if isinstance(leaf_cert, dict) else None,
        "certificate_self_signed": leaf_cert.get("self_signed") if isinstance(leaf_cert, dict) else None,
    }
