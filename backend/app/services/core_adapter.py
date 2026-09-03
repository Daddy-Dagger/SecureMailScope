"""Core engine adapter boundary for SecureMailScope.

Defines the integration interface between the FastAPI backend and the core/
forensic engine.

STATUS: AWAITING CORE ENGINE IMPLEMENTATION (Milestone 1 by Member 1 / Lead).

This adapter layer decouples the HTTP transport and reporting layers from
underlying PCAP parsing and analysis engines. It allows the backend to:
1. Accept uploaded PCAP files and forward raw bytes to a core engine.
2. Validate structured outputs returned by the core engine against shared contracts:
   - shared/contracts/analysis_result_schema.json
   - shared/contracts/session_schema.json
   - shared/contracts/finding_schema.json
3. Fall back gracefully to a contract-compliant baseline when core parsing
   modules in core/ are not yet implemented.
"""

from __future__ import annotations

import importlib
import logging
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


class CoreEngineError(Exception):
    """Base exception for core analysis engine failures."""


class CoreEngineUnavailableError(CoreEngineError):
    """Raised when real core engine execution is requested but unavailable."""


@runtime_checkable
class CoreAnalysisEngine(Protocol):
    """Protocol defining the interface required by the backend from the core engine.

    Any core implementation provided by Member 1 (lead/core-engine) must
    implement this interface to integrate seamlessly with the backend.
    """

    @property
    def is_available(self) -> bool:
        """Indicate whether the engine is ready to perform real PCAP analysis."""
        ...

    def analyze(self, filename: str, content: bytes) -> dict[str, Any]:
        """Analyze raw PCAP content and return structured dictionary results.

        The returned dictionary MUST strictly conform to:
        shared/contracts/analysis_result_schema.json

        Expected structure:
        {
            "file": str,
            "packet_count": int (>= 0),
            "summary": {
                "smtp_sessions": int (>= 0),
                "imap_sessions": int (>= 0),
                "pop3_sessions": int (>= 0),
            },
            "sessions": list[dict],   # conforming to session_schema.json
            "findings": list[dict],   # conforming to finding_schema.json
            "overall_score": float | None,
            "risk_level": str | None,
        }
        """
        ...


class DeferredCoreEngineAdapter:
    """Default adapter used while core/ modules are under development.

    Awaiting Milestone 1 (PCAP -> SMTP/IMAP/POP3 sessions -> JSON) from
    Member 1 (lead/core-engine).

    Does NOT perform PCAP parsing in the backend. Returns a safe,
    contract-compliant baseline response.
    """

    @property
    def is_available(self) -> bool:
        """Core engine is not yet available; implementation is deferred."""
        return False

    def analyze(self, filename: str, content: bytes) -> dict[str, Any]:
        """Produce a contract-compliant baseline placeholder result.

        Logs that real core analysis is deferred to core/ engine.
        """
        file_size = len(content) if content is not None else 0
        logger.info(
            "DeferredCoreEngineAdapter: PCAP analysis requested for '%s' (%d bytes). "
            "Real core engine is deferred (awaiting Milestone 1 by lead/core-engine); "
            "returning contract-compliant placeholder baseline.",
            filename,
            file_size,
        )

        return {
            "file": filename,
            "packet_count": 0,
            "summary": {
                "smtp_sessions": 0,
                "imap_sessions": 0,
                "pop3_sessions": 0,
            },
            "sessions": [],
            "findings": [],
            "overall_score": None,
            "risk_level": None,
        }


def get_core_engine() -> CoreAnalysisEngine:
    """Factory to obtain the active core analysis engine.

    Inspects core/ modules to detect if a real implementation has been provided.
    If core/ still consists of deferred stubs, returns DeferredCoreEngineAdapter.
    """
    try:
        # Check if core.pcap exposes an active analyzer entrypoint
        pcap_module = importlib.import_module("core.pcap.session_builder")
        analyzer = getattr(pcap_module, "analyze_pcap", None)
        if callable(analyzer):
            # Future bridge when lead implements analyze_pcap
            logger.info("Active core engine analyzer detected in core.pcap.session_builder.")
            # If a callable is found in the future, it would be wrapped here.
    except (ImportError, AttributeError):
        pass

    logger.debug("Core engine analysis is deferred; using DeferredCoreEngineAdapter.")
    return DeferredCoreEngineAdapter()
