"""Deterministic security rule engine orchestrator.

Consumes structured session objects conforming to shared/contracts/session_schema.json
and executes deterministic cryptographic and transport security rules.
"""

from __future__ import annotations

from typing import Any

from core.rules.certificate_rules import evaluate_certificate_rules
from core.rules.tls_rules import (
    evaluate_cipher_suite,
    evaluate_fatal_handshake,
    evaluate_forward_secrecy,
    evaluate_tls_version,
    evaluate_transport_security,
)

_SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def evaluate_session_rules(session: dict[str, Any]) -> list[dict[str, Any]]:
    """Execute all deterministic rules on a single extracted session.

    Args:
        session: Extracted session dictionary adhering to session_schema.json.

    Returns:
        List of finding dictionaries conforming to finding_schema.json.
    """
    findings: list[dict[str, Any]] = []

    # 1. Transport security and STARTTLS transition rules
    findings.extend(evaluate_transport_security(session))

    # 2. TLS protocol version rules (TLS 1.0, 1.1)
    findings.extend(evaluate_tls_version(session))

    # 3. Cipher suite rules (weak/deprecated ciphers)
    findings.extend(evaluate_cipher_suite(session))

    # 4. Fatal handshake failure rules
    findings.extend(evaluate_fatal_handshake(session))

    # 5. Perfect Forward Secrecy posture rules
    findings.extend(evaluate_forward_secrecy(session))

    # 6. X.509 certificate rules
    findings.extend(evaluate_certificate_rules(session))

    return findings


def evaluate_rules(sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Execute all deterministic rules across all extracted sessions.

    Findings are sorted deterministically:
    1. Severity precedence (CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO)
    2. Session ID (alphabetical)
    3. Finding ID (alphabetical)

    Args:
        sessions: List of session dictionaries.

    Returns:
        Deterministic, evidence-linked findings adhering to finding_schema.json.
    """
    all_findings: list[dict[str, Any]] = []
    for session in sessions:
        if isinstance(session, dict):
            all_findings.extend(evaluate_session_rules(session))

    def _sort_key(f: dict[str, Any]) -> tuple[int, str, str]:
        sev_rank = _SEVERITY_ORDER.get(f.get("severity", "INFO"), 5)
        sid = f.get("session_id") or ""
        fid = f.get("finding_id") or ""
        return (sev_rank, sid, fid)

    all_findings.sort(key=_sort_key)
    return all_findings


def evaluate_analysis_result(analysis_result: dict[str, Any]) -> list[dict[str, Any]]:
    """Convenience helper to evaluate rules for a top-level analysis result dictionary."""
    sessions = analysis_result.get("sessions") or []
    return evaluate_rules(sessions)
