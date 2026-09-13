"""Deterministic X.509 certificate security rule definitions.

Evaluates structured certificate metadata against deterministic cryptographic rules
without parsing PCAPs or raw certificate DER/PEM bytes directly.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _parse_iso_utc(timestamp_str: str | None) -> datetime | None:
    """Safely parse an ISO 8601 UTC timestamp string into an aware datetime."""
    if not timestamp_str or not isinstance(timestamp_str, str):
        return None
    try:
        normalized = timestamp_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def evaluate_certificate_rules(session: dict[str, Any]) -> list[dict[str, Any]]:
    """Evaluate deterministic security rules against extracted certificate metadata."""
    findings: list[dict[str, Any]] = []
    certificates = session.get("certificates")
    if not isinstance(certificates, list) or not certificates:
        # Missing certificate data (e.g. encrypted TLS 1.3 or non-TLS session)
        # must not produce false certificate findings.
        return findings

    session_id = session.get("session_id")
    session_start_time = session.get("start_time")
    session_dt = _parse_iso_utc(session_start_time)

    for cert in certificates:
        if not isinstance(cert, dict):
            continue

        evidence_dict = cert.get("evidence") or {}
        frame_number = evidence_dict.get("certificate_frame")
        subject = cert.get("subject") or "Unknown Subject"

        # 1. Expired certificate relative to forensic capture reference time
        days_remaining = cert.get("days_remaining")
        if days_remaining is not None and days_remaining < 0:
            not_after = cert.get("not_after") or "unknown"
            findings.append(
                {
                    "finding_id": "CERT-EXPIRED",
                    "title": "Expired X.509 Certificate",
                    "severity": "HIGH",
                    "explanation": (
                        f"The certificate for '{subject}' expired {abs(days_remaining)} day(s) "
                        f"before the capture reference time (validity ended {not_after})."
                    ),
                    "recommendation": (
                        "Renew the expired certificate and deploy a valid certificate issued by a trusted CA."
                    ),
                    "session_id": session_id,
                    "evidence": {
                        "frame_number": frame_number,
                        "observed_value": f"days_remaining={days_remaining}",
                    },
                }
            )

        # 2. Not-yet-valid certificate relative to session timestamp
        not_before = cert.get("not_before")
        if not_before and session_dt:
            cert_nb_dt = _parse_iso_utc(not_before)
            if cert_nb_dt and cert_nb_dt > session_dt:
                findings.append(
                    {
                        "finding_id": "CERT-NOT-YET-VALID",
                        "title": "Certificate Not Yet Valid",
                        "severity": "HIGH",
                        "explanation": (
                            f"The certificate for '{subject}' is not yet valid at the capture reference time "
                            f"(validity window begins {not_before})."
                        ),
                        "recommendation": (
                            "Verify host clock synchronization or ensure the certificate validity period has begun."
                        ),
                        "session_id": session_id,
                        "evidence": {
                            "frame_number": frame_number,
                            "observed_value": f"not_before={not_before}",
                        },
                    }
                )

        # 3. Public key strength (RSA, DSA)
        pk = cert.get("public_key")
        if isinstance(pk, dict):
            algo = (pk.get("algorithm") or "").upper()
            bits = pk.get("size_bits")

            if algo == "RSA" and bits is not None and bits < 2048:
                findings.append(
                    {
                        "finding_id": "CERT-WEAK-RSA-KEY",
                        "title": "Weak RSA Public Key Size",
                        "severity": "HIGH",
                        "explanation": (
                            f"The certificate for '{subject}' uses an RSA key size of {bits} bits, "
                            "which is below the industry standard minimum of 2048 bits."
                        ),
                        "recommendation": (
                            "Reissue the certificate with an RSA key of at least 2048 bits (3072 or 4096 bits "
                            "recommended), or migrate to modern ECDSA (P-256) or Ed25519."
                        ),
                        "session_id": session_id,
                        "evidence": {
                            "frame_number": frame_number,
                            "observed_value": f"RSA {bits} bits",
                        },
                    }
                )
            elif algo == "DSA" and bits is not None and bits < 2048:
                findings.append(
                    {
                        "finding_id": "CERT-WEAK-DSA-KEY",
                        "title": "Weak DSA Public Key Size",
                        "severity": "HIGH",
                        "explanation": (
                            f"The certificate for '{subject}' uses a DSA key size of {bits} bits, "
                            "which is cryptographically obsolete and insecure."
                        ),
                        "recommendation": (
                            "Replace legacy DSA keys with modern ECDSA, Ed25519, or 2048+ bit RSA keys."
                        ),
                        "session_id": session_id,
                        "evidence": {
                            "frame_number": frame_number,
                            "observed_value": f"DSA {bits} bits",
                        },
                    }
                )

        # 4. Deprecated signature algorithms (MD5, SHA-1)
        sig_algo = cert.get("signature_algorithm")
        if sig_algo and isinstance(sig_algo, str):
            sig_lower = sig_algo.lower()
            if "md5" in sig_lower:
                findings.append(
                    {
                        "finding_id": "CERT-SIG-MD5",
                        "title": "Deprecated MD5 Certificate Signature Algorithm",
                        "severity": "CRITICAL",
                        "explanation": (
                            f"The certificate for '{subject}' was signed using MD5 ({sig_algo}), "
                            "which is vulnerable to practical collision attacks and rejected by modern TLS clients."
                        ),
                        "recommendation": (
                            "Reissue the certificate immediately using SHA-256 or stronger signature hash algorithm."
                        ),
                        "session_id": session_id,
                        "evidence": {
                            "frame_number": frame_number,
                            "observed_value": sig_algo,
                        },
                    }
                )
            elif "sha1" in sig_lower or "sha-1" in sig_lower:
                findings.append(
                    {
                        "finding_id": "CERT-SIG-SHA1",
                        "title": "Deprecated SHA-1 Certificate Signature Algorithm",
                        "severity": "HIGH",
                        "explanation": (
                            f"The certificate for '{subject}' was signed using SHA-1 ({sig_algo}), "
                            "which is cryptographically broken and untrusted by modern systems."
                        ),
                        "recommendation": (
                            "Reissue the certificate using SHA-256 or stronger signature hash algorithm."
                        ),
                        "session_id": session_id,
                        "evidence": {
                            "frame_number": frame_number,
                            "observed_value": sig_algo,
                        },
                    }
                )

        # 5. Verified self-signed certificate
        # CRITICAL RULE: only flag when self_signed is explicitly True.
        # Do NOT flag when self_issued is True but self_signed is False or None.
        if cert.get("self_signed") is True:
            findings.append(
                {
                    "finding_id": "CERT-SELF-SIGNED",
                    "title": "Self-Signed X.509 Certificate",
                    "severity": "MEDIUM",
                    "explanation": (
                        f"The certificate for '{subject}' is self-signed and was not issued by a "
                        "recognized or externally verified Certificate Authority."
                    ),
                    "recommendation": (
                        "Replace self-signed certificates in production with certificates issued by a "
                        "publicly trusted CA or enterprise managed PKI."
                    ),
                    "session_id": session_id,
                    "evidence": {
                        "frame_number": frame_number,
                        "observed_value": "self_signed=True",
                    },
                }
            )

    return findings
