"""Analysis service orchestration boundary.

Coordinates analysis workflows between API transport and core analysis engines.
Core protocol parsing, TLS extraction, and security scoring remain in core/
and will be integrated here once implemented.
"""

import logging

from backend.app.models.analysis import (
    AnalysisResultResponse,
    ProtocolSummary,
)

logger = logging.getLogger(__name__)


class AnalysisService:
    """Orchestrates PCAP analysis requests."""

    def analyze_pcap(
        self,
        filename: str,
        content: bytes | None = None,
    ) -> AnalysisResultResponse:
        """Process a PCAP analysis request.

        NOTE: Real PCAP parsing, protocol extraction (SMTP/IMAP/POP3),
        and cryptographic inspection belong to the core/ engine (owned by Lead)
        and are currently deferred.

        This service returns a contract-compliant placeholder structure
        strictly matching shared/contracts/analysis_result_schema.json,
        ready to receive structured output from core/ when available.
        """
        file_size = len(content) if content is not None else 0
        logger.info(
            "AnalysisService.analyze_pcap called for '%s' (bytes=%d). "
            "Core parsing is deferred; returning contract placeholder.",
            filename,
            file_size,
        )

        return AnalysisResultResponse(
            file=filename,
            packet_count=0,
            summary=ProtocolSummary(
                smtp_sessions=0,
                imap_sessions=0,
                pop3_sessions=0,
            ),
            sessions=[],
            findings=[],
            overall_score=None,
            risk_level=None,
        )


analysis_service = AnalysisService()
