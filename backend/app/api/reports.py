"""Report export API routes for SecureMailScope."""

from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Response, status

from backend.app.models.analysis import AnalysisResultResponse
from backend.app.models.reports import ReportExportRequest
from reports.html_report import generate_html_report
from reports.json_report import generate_json_report
from reports.pdf_report import generate_pdf_report

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/reports", tags=["reports"])

ALLOWED_FORMATS = {"json", "html", "pdf"}


@router.post(
    "/export",
    summary="Export analysis result as a downloadable forensic report",
    description=(
        "Accepts a validated analysis result and generates a downloadable forensic report "
        "in JSON, HTML, or PDF format. Reuses existing standalone report generators without "
        "modifying or duplicating core data contracts."
    ),
    responses={
        status.HTTP_200_OK: {
            "description": "Report file attachment",
            "content": {
                "application/json": {},
                "text/html": {},
                "application/pdf": {},
            },
        },
        status.HTTP_400_BAD_REQUEST: {
            "description": "Unsupported report format requested",
        },
        422: {
            "description": "Validation error for malformed analysis data",
        },
    },
)
async def export_report(
    payload: ReportExportRequest | AnalysisResultResponse,
    format: str | None = Query(
        None,
        description="Optional export format override ('json', 'html', or 'pdf')",
    ),
) -> Response:
    """Generate and return a downloadable report in the requested format."""
    if isinstance(payload, ReportExportRequest):
        target_format = payload.format.lower()
        analysis_data = payload.analysis_result
    else:
        target_format = (format or "json").lower()
        analysis_data = payload

    if target_format not in ALLOWED_FORMATS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Unsupported report format '{target_format}'. "
                f"Allowed formats: {', '.join(sorted(ALLOWED_FORMATS))}."
            ),
        )

    logger.info(
        "Generating '%s' report export for file '%s'.",
        target_format,
        analysis_data.file,
    )

    if target_format == "json":
        content = generate_json_report(analysis_data)
        media_type = "application/json"
        filename = "securemailscope-report.json"
    elif target_format == "html":
        content = generate_html_report(analysis_data)
        media_type = "text/html; charset=utf-8"
        filename = "securemailscope-report.html"
    elif target_format == "pdf":
        # In-memory byte generation (no temporary file created on disk)
        content = generate_pdf_report(analysis_data)
        media_type = "application/pdf"
        filename = "securemailscope-report.pdf"
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported format '{target_format}'.",
        )

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
    }

    return Response(
        content=content,
        media_type=media_type,
        headers=headers,
    )
