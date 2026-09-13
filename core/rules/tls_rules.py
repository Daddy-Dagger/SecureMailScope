"""Deterministic TLS and transport security rule definitions.

Evaluates structured session metadata against deterministic cryptographic and
transport security rules without parsing PCAPs directly.
"""

from __future__ import annotations

import re
from typing import Any

# Known weak cipher identifier patterns and numeric IDs
_NULL_CIPHER_RE = re.compile(r"(?:^|_)NULL(?:_|$)", re.IGNORECASE)
_EXPORT_CIPHER_RE = re.compile(r"(?:^|_)(?:EXPORT|EXP)(?:_|$)", re.IGNORECASE)
_ANON_CIPHER_RE = re.compile(
    r"(?:_anon_|^ADH-|^AECDH-|TLS_DH_anon_|TLS_ECDH_anon_)", re.IGNORECASE
)
_RC4_CIPHER_RE = re.compile(r"(?:RC4|ARCFOUR)", re.IGNORECASE)
_3DES_DES_CIPHER_RE = re.compile(
    r"(?:3DES|DES-CBC3|_DES_|DES40)", re.IGNORECASE
)
_MD5_MAC_CIPHER_RE = re.compile(r"(?:_MD5$|-MD5$)", re.IGNORECASE)

# Hex ID set for known weak/deprecated ciphers
_KNOWN_WEAK_CIPHER_IDS: dict[str, tuple[str, str, str]] = {
    "0x0001": (
        "CRITICAL",
        "The cipher suite (0x0001: TLS_RSA_WITH_NULL_MD5) provides no encryption and uses broken MD5 MAC.",
        "NULL cipher without encryption",
    ),
    "0x0002": (
        "CRITICAL",
        "The cipher suite (0x0002: TLS_RSA_WITH_NULL_SHA) provides no encryption.",
        "NULL cipher without encryption",
    ),
    "0x0003": (
        "CRITICAL",
        "The cipher suite (0x0003: TLS_RSA_EXPORT_WITH_RC4_40_MD5) uses export-grade weak crypto and RC4.",
        "Export-grade cipher",
    ),
    "0x0004": (
        "HIGH",
        "The cipher suite (0x0004: TLS_RSA_WITH_RC4_128_MD5) uses RC4 stream cipher and MD5 MAC.",
        "RC4 / MD5 cipher",
    ),
    "0x0005": (
        "HIGH",
        "The cipher suite (0x0005: TLS_RSA_WITH_RC4_128_SHA) uses deprecated RC4 stream cipher.",
        "RC4 cipher",
    ),
    "0x000a": (
        "HIGH",
        "The cipher suite (0x000a: TLS_RSA_WITH_3DES_EDE_CBC_SHA) uses 64-bit block cipher 3DES.",
        "3DES cipher",
    ),
    "0x0017": (
        "CRITICAL",
        "The cipher suite (0x0017: TLS_DH_anon_WITH_RC4_128_MD5) is unauthenticated and uses RC4/MD5.",
        "Anonymous RC4 cipher",
    ),
    "0x0018": (
        "CRITICAL",
        "The cipher suite (0x0018: TLS_DH_anon_WITH_3DES_EDE_CBC_SHA) is unauthenticated.",
        "Anonymous 3DES cipher",
    ),
}


def evaluate_tls_version(session: dict[str, Any]) -> list[dict[str, Any]]:
    """Flag deprecated TLS versions (TLS 1.0, TLS 1.1) per RFC 8996."""
    findings: list[dict[str, Any]] = []
    tls = session.get("tls")
    if not isinstance(tls, dict) or not tls.get("detected"):
        return findings

    version = tls.get("version")
    if not version:
        crypto_features = session.get("crypto_features")
        if isinstance(crypto_features, dict):
            version = crypto_features.get("tls_version")

    if not version or version in ("UNKNOWN", None):
        return findings

    evidence_dict = tls.get("evidence") or {}
    frame_number = evidence_dict.get("selected_version_frame") or evidence_dict.get(
        "server_hello_frame"
    )
    session_id = session.get("session_id")

    if version == "TLS 1.0":
        findings.append(
            {
                "finding_id": "TLS-DEPRECATED-1.0",
                "title": "Deprecated TLS 1.0 Protocol Version",
                "severity": "HIGH",
                "explanation": (
                    "The session negotiated TLS 1.0, which was formally deprecated by RFC 8996 "
                    "due to known cryptographic weaknesses (e.g., BEAST, POODLE) and lack of "
                    "support for modern AEAD ciphers."
                ),
                "recommendation": (
                    "Disable TLS 1.0 on mail servers and clients; enforce TLS 1.2 or TLS 1.3."
                ),
                "session_id": session_id,
                "evidence": {
                    "frame_number": frame_number,
                    "observed_value": "TLS 1.0",
                },
            }
        )
    elif version == "TLS 1.1":
        findings.append(
            {
                "finding_id": "TLS-DEPRECATED-1.1",
                "title": "Deprecated TLS 1.1 Protocol Version",
                "severity": "HIGH",
                "explanation": (
                    "The session negotiated TLS 1.1, which was formally deprecated by RFC 8996 "
                    "due to lack of support for modern AEAD cipher suites and secure hash algorithms."
                ),
                "recommendation": (
                    "Disable TLS 1.1 on mail servers and clients; enforce TLS 1.2 or TLS 1.3."
                ),
                "session_id": session_id,
                "evidence": {
                    "frame_number": frame_number,
                    "observed_value": "TLS 1.1",
                },
            }
        )

    return findings


def evaluate_cipher_suite(session: dict[str, Any]) -> list[dict[str, Any]]:
    """Flag known weak or deprecated cipher suites (NULL, EXPORT, ANON, RC4, 3DES, MD5)."""
    findings: list[dict[str, Any]] = []
    tls = session.get("tls")
    if not isinstance(tls, dict) or not tls.get("detected"):
        return findings

    cipher = tls.get("cipher_suite")
    cipher_name: str | None = None
    cipher_id: str | None = None

    if isinstance(cipher, dict):
        cipher_name = cipher.get("name")
        cipher_id = cipher.get("id")

    if not cipher_name:
        crypto_features = session.get("crypto_features")
        if isinstance(crypto_features, dict):
            cipher_name = crypto_features.get("cipher_suite")

    # If cipher is unknown or unobserved, do not generate unsupported claims
    if not cipher_name and not cipher_id:
        return findings
    if cipher_name == "UNKNOWN":
        return findings

    evidence_dict = tls.get("evidence") or {}
    frame_number = evidence_dict.get("selected_cipher_frame") or evidence_dict.get(
        "server_hello_frame"
    )
    session_id = session.get("session_id")
    observed = cipher_name or cipher_id

    # Check hex ID lookup
    if cipher_id and cipher_id.lower() in _KNOWN_WEAK_CIPHER_IDS:
        severity, explanation, _ = _KNOWN_WEAK_CIPHER_IDS[cipher_id.lower()]
        findings.append(
            {
                "finding_id": "TLS-WEAK-CIPHER",
                "title": "Insecure or Deprecated Cipher Suite",
                "severity": severity,
                "explanation": explanation,
                "recommendation": (
                    "Configure the server to exclusively permit modern AEAD cipher suites "
                    "(e.g., AES-GCM or CHACHA20-POLY1305) and disable legacy ciphers."
                ),
                "session_id": session_id,
                "evidence": {
                    "frame_number": frame_number,
                    "observed_value": observed,
                },
            }
        )
        return findings

    if not cipher_name:
        return findings

    # Pattern checks on cipher name
    name_upper = cipher_name.upper()

    if _NULL_CIPHER_RE.search(name_upper):
        findings.append(
            {
                "finding_id": "TLS-WEAK-CIPHER",
                "title": "Insecure or Deprecated Cipher Suite",
                "severity": "CRITICAL",
                "explanation": (
                    f"The negotiated cipher suite ({cipher_name}) uses NULL encryption, "
                    "transmitting all application data in cleartext despite TLS framing."
                ),
                "recommendation": (
                    "Disable NULL cipher suites immediately and enforce authenticated encryption."
                ),
                "session_id": session_id,
                "evidence": {
                    "frame_number": frame_number,
                    "observed_value": observed,
                },
            }
        )
    elif _EXPORT_CIPHER_RE.search(name_upper):
        findings.append(
            {
                "finding_id": "TLS-WEAK-CIPHER",
                "title": "Insecure or Deprecated Cipher Suite",
                "severity": "CRITICAL",
                "explanation": (
                    f"The negotiated cipher suite ({cipher_name}) uses deliberately weakened "
                    "export-grade cryptography vulnerable to key recovery attacks (e.g. FREAK, Logjam)."
                ),
                "recommendation": (
                    "Disable export-grade cipher suites and require strong 128-bit or 256-bit encryption."
                ),
                "session_id": session_id,
                "evidence": {
                    "frame_number": frame_number,
                    "observed_value": observed,
                },
            }
        )
    elif _ANON_CIPHER_RE.search(name_upper):
        findings.append(
            {
                "finding_id": "TLS-WEAK-CIPHER",
                "title": "Insecure or Deprecated Cipher Suite",
                "severity": "CRITICAL",
                "explanation": (
                    f"The negotiated cipher suite ({cipher_name}) is unauthenticated (anonymous), "
                    "allowing active machine-in-the-middle (MITM) interception without certificate checks."
                ),
                "recommendation": (
                    "Disable anonymous cipher suites and require peer certificate authentication."
                ),
                "session_id": session_id,
                "evidence": {
                    "frame_number": frame_number,
                    "observed_value": observed,
                },
            }
        )
    elif _RC4_CIPHER_RE.search(name_upper):
        findings.append(
            {
                "finding_id": "TLS-WEAK-CIPHER",
                "title": "Insecure or Deprecated Cipher Suite",
                "severity": "HIGH",
                "explanation": (
                    f"The negotiated cipher suite ({cipher_name}) uses the RC4 stream cipher, "
                    "which is cryptographically broken and prohibited by RFC 7465."
                ),
                "recommendation": (
                    "Disable RC4 cipher suites and migrate to modern AEAD ciphers."
                ),
                "session_id": session_id,
                "evidence": {
                    "frame_number": frame_number,
                    "observed_value": observed,
                },
            }
        )
    elif _3DES_DES_CIPHER_RE.search(name_upper):
        findings.append(
            {
                "finding_id": "TLS-WEAK-CIPHER",
                "title": "Insecure or Deprecated Cipher Suite",
                "severity": "HIGH",
                "explanation": (
                    f"The negotiated cipher suite ({cipher_name}) uses a 64-bit block cipher (DES/3DES), "
                    "vulnerable to collision attacks such as Sweet32 (CVE-2016-2183)."
                ),
                "recommendation": (
                    "Disable 3DES/DES cipher suites and configure 128-bit or 256-bit block ciphers."
                ),
                "session_id": session_id,
                "evidence": {
                    "frame_number": frame_number,
                    "observed_value": observed,
                },
            }
        )
    elif _MD5_MAC_CIPHER_RE.search(name_upper):
        findings.append(
            {
                "finding_id": "TLS-WEAK-CIPHER",
                "title": "Insecure or Deprecated Cipher Suite",
                "severity": "HIGH",
                "explanation": (
                    f"The negotiated cipher suite ({cipher_name}) uses MD5 for message authentication (HMAC-MD5), "
                    "which is prone to collision weaknesses and cryptographically deprecated."
                ),
                "recommendation": (
                    "Disable cipher suites using MD5 MAC and require SHA-256 or AEAD ciphers."
                ),
                "session_id": session_id,
                "evidence": {
                    "frame_number": frame_number,
                    "observed_value": observed,
                },
            }
        )

    return findings


def evaluate_fatal_handshake(session: dict[str, Any]) -> list[dict[str, Any]]:
    """Flag fatal TLS alert failures observed during handshake negotiation."""
    findings: list[dict[str, Any]] = []
    tls = session.get("tls")
    if not isinstance(tls, dict):
        return findings

    if tls.get("handshake_status") == "FAILED":
        evidence_dict = tls.get("evidence") or {}
        frame_number = evidence_dict.get("alert_frame") or evidence_dict.get(
            "server_hello_frame"
        )
        findings.append(
            {
                "finding_id": "TLS-HANDSHAKE-FATAL",
                "title": "Fatal TLS Handshake Failure",
                "severity": "HIGH",
                "explanation": (
                    "A fatal TLS alert occurred during handshake negotiation, aborting "
                    "the encrypted channel setup."
                ),
                "recommendation": (
                    "Examine client and server TLS version/cipher compatibility, certificate validity, "
                    "and trust chains to resolve the handshake abort."
                ),
                "session_id": session.get("session_id"),
                "evidence": {
                    "frame_number": frame_number,
                    "observed_value": "FAILED",
                },
            }
        )

    return findings


def evaluate_forward_secrecy(session: dict[str, Any]) -> list[dict[str, Any]]:
    """Evaluate Perfect Forward Secrecy posture based on key exchange mechanism."""
    findings: list[dict[str, Any]] = []
    tls = session.get("tls")
    if not isinstance(tls, dict) or not tls.get("detected"):
        return findings

    kx = tls.get("key_exchange")
    method: str | None = None
    if isinstance(kx, dict):
        method = kx.get("method")

    if not method:
        crypto_features = session.get("crypto_features")
        if isinstance(crypto_features, dict):
            method = crypto_features.get("key_exchange")

    if not method or method in ("UNKNOWN", None):
        return findings

    evidence_dict = tls.get("evidence") or {}
    frame_number = evidence_dict.get("key_exchange_frame") or evidence_dict.get(
        "server_hello_frame"
    )
    session_id = session.get("session_id")

    method_upper = method.upper()
    if method_upper in ("ECDHE", "DHE"):
        findings.append(
            {
                "finding_id": "TLS-FORWARD-SECRECY-SUPPORTED",
                "title": "Forward Secrecy Supported",
                "severity": "INFO",
                "explanation": (
                    f"The session negotiated an ephemeral key exchange ({method_upper}) providing "
                    "Perfect Forward Secrecy (PFS). Prior recorded traffic cannot be decrypted even "
                    "if the server private key is compromised in the future."
                ),
                "recommendation": (
                    "Maintain modern ephemeral key exchange configuration (ECDHE with X25519/P-256 or DHE)."
                ),
                "session_id": session_id,
                "evidence": {
                    "frame_number": frame_number,
                    "observed_value": method_upper,
                },
            }
        )
    elif method_upper == "RSA":
        findings.append(
            {
                "finding_id": "TLS-NO-FORWARD-SECRECY",
                "title": "Lack of Forward Secrecy (Static RSA Key Exchange)",
                "severity": "MEDIUM",
                "explanation": (
                    "The session negotiated static RSA key exchange without ephemeral Diffie-Hellman parameters. "
                    "If the server private key is compromised in the future, all past recorded session traffic "
                    "can be decrypted retrospectively."
                ),
                "recommendation": (
                    "Disable static RSA key exchange suites and require ephemeral key exchange "
                    "(ECDHE or DHE) to ensure Forward Secrecy."
                ),
                "session_id": session_id,
                "evidence": {
                    "frame_number": frame_number,
                    "observed_value": "RSA",
                },
            }
        )

    return findings


def evaluate_transport_security(session: dict[str, Any]) -> list[dict[str, Any]]:
    """Evaluate STARTTLS/STLS and transport security transition states."""
    findings: list[dict[str, Any]] = []
    ts = session.get("transport_security")
    if not isinstance(ts, dict):
        return findings

    mode = ts.get("mode")
    status = ts.get("upgrade_status")
    cmd = ts.get("upgrade_command") or (
        "STLS" if session.get("protocol") == "POP3" else "STARTTLS"
    )
    evidence = ts.get("evidence") or {}
    session_id = session.get("session_id")

    # Implicit TLS sessions (ports 465, 993, 995) negotiate TLS from the first packet.
    # They do NOT use STARTTLS, so must NEVER be flagged as missing STARTTLS.
    if mode == "IMPLICIT_TLS":
        return findings

    if status == "ADVERTISED_NOT_REQUESTED":
        findings.append(
            {
                "finding_id": "STARTTLS-ADVERTISED-NOT-USED",
                "title": f"{cmd} Advertised But Not Requested",
                "severity": "MEDIUM",
                "explanation": (
                    f"The mail server advertised {cmd} capability, but the client did not request "
                    "an encryption upgrade. Session communication proceeded in unencrypted cleartext."
                ),
                "recommendation": (
                    f"Configure the mail client to enforce {cmd} when connecting to this mail service."
                ),
                "session_id": session_id,
                "evidence": {
                    "frame_number": evidence.get("advertised_frame"),
                    "observed_value": "ADVERTISED_NOT_REQUESTED",
                },
            }
        )
    elif status == "FAILED":
        findings.append(
            {
                "finding_id": "STARTTLS-REJECTED",
                "title": f"{cmd} Upgrade Request Rejected by Server",
                "severity": "HIGH",
                "explanation": (
                    f"The client requested a {cmd} upgrade, but the server rejected the command "
                    "with an error response, preventing secure channel negotiation."
                ),
                "recommendation": (
                    f"Inspect server configuration and TLS certificates to determine why {cmd} requests are rejected."
                ),
                "session_id": session_id,
                "evidence": {
                    "frame_number": evidence.get("request_frame")
                    or evidence.get("accept_frame"),
                    "observed_value": "REJECTED",
                },
            }
        )
    elif status == "INCOMPLETE":
        findings.append(
            {
                "finding_id": "STARTTLS-INCOMPLETE",
                "title": f"Incomplete {cmd} Upgrade Transition",
                "severity": "HIGH",
                "explanation": (
                    f"A {cmd} upgrade was initiated or accepted, but expected TLS traffic did not follow "
                    "or the encrypted session failed to complete establishment."
                ),
                "recommendation": (
                    "Inspect network path stability, timeout settings, and firewall inspection devices "
                    f"for interference during the {cmd} upgrade transition."
                ),
                "session_id": session_id,
                "evidence": {
                    "frame_number": evidence.get("request_frame")
                    or evidence.get("accept_frame"),
                    "observed_value": "INCOMPLETE",
                },
            }
        )
    elif mode == "PLAINTEXT" and status in ("NOT_ADVERTISED", "UNKNOWN"):
        findings.append(
            {
                "finding_id": "TRANSPORT-PLAINTEXT-SESSION",
                "title": "Cleartext Email Communication Without Encryption",
                "severity": "HIGH",
                "explanation": (
                    f"The {session.get('protocol', 'email')} session was conducted entirely in unencrypted "
                    "cleartext without transport security, exposing communication metadata, message content, "
                    "and authentication credentials."
                ),
                "recommendation": (
                    f"Enable transport security ({cmd} or implicit TLS) on the mail server and require "
                    "encrypted connections for all email clients."
                ),
                "session_id": session_id,
                "evidence": {
                    "frame_number": evidence.get("advertised_frame") or 1,
                    "observed_value": "PLAINTEXT",
                },
            }
        )

    return findings
