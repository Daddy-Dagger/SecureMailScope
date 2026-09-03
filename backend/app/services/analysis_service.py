"""Analysis service orchestration boundary.

Coordinates analysis workflows between API transport and core analysis engines.
Core protocol parsing, TLS extraction, and security scoring remain in core/
(owned by Member 1 / Lead) and will be integrated here via the CoreAnalysisEngine
adapter interface once implemented.
"""

from __future__ import annotations

import logging

from backend.app.models.analysis import AnalysisResultResponse
from backend.app.services.core_adapter import (
    CoreAnalysisEngine,
    get_core_engine,
)

logger = logging.getLogger(__name__)


class AnalysisService:
    """Orchestrates PCAP analysis requests between HTTP transport and core engines."""

    def __init__(self, core_engine: CoreAnalysisEngine | None = None) -> None:
        self._core_engine: CoreAnalysisEngine = core_engine or get_core_engine()

    @property
    def core_engine(self) -> CoreAnalysisEngine:
        """Return the currently configured core analysis engine."""
        return self._core_engine

    @property
    def has_active_core_engine(self) -> bool:
        """Indicate whether an active, non-deferred core engine is connected."""
        return getattr(self._core_engine, "is_available", False)

    def set_core_engine(self, engine: CoreAnalysisEngine) -> None:
        """Set or swap the core analysis engine (e.g. for testing or runtime injection)."""
        self._core_engine = engine

    def analyze_pcap(
        self,
        filename: str,
        content: bytes | None = None,
    ) -> AnalysisResultResponse:
        """Process a PCAP analysis request.

        Forwards the PCAP payload to the configured CoreAnalysisEngine,
        validates the structured output against shared data contracts
        via Pydantic, and returns a verified AnalysisResultResponse.

        NOTE: Real PCAP parsing belongs to core/ (owned by Lead) and is
        deferred until Milestone 1 is delivered. If the active engine is
        the DeferredCoreEngineAdapter, this method returns a contract-compliant
        baseline response.
        """
        payload = content if content is not None else b""
        logger.info(
            "AnalysisService.analyze_pcap called for '%s' (bytes=%d). Active engine: %s (available=%s).",
            filename,
            len(payload),
            type(self._core_engine).__name__,
            self.has_active_core_engine,
        )

        raw_result = self._core_engine.analyze(filename=filename, content=payload)

        # Validate core engine output strictly against the shared contract schema
        validated_response = AnalysisResultResponse.model_validate(raw_result)

        return validated_response


analysis_service = AnalysisService()
