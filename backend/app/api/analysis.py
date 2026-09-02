"""Analysis API routes for SecureMailScope."""

import os

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from backend.app.models.analysis import AnalysisResultResponse
from backend.app.services.analysis_service import analysis_service

router = APIRouter(prefix="/api", tags=["analysis"])

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB safety limit for local prototype


@router.post(
    "/analyze",
    response_model=AnalysisResultResponse,
    status_code=status.HTTP_200_OK,
    summary="Submit a PCAP file for analysis",
    description=(
        "Accepts a PCAP network capture file (.pcap, .pcapng, .cap), "
        "validates input, and returns an analysis result structure conforming "
        "to shared/contracts/analysis_result_schema.json. "
        "NOTE: Deep PCAP parsing is deferred until core engine integration is complete; "
        "currently returns a contract-compliant placeholder response."
    ),
)
async def analyze_capture(
    file: UploadFile = File(..., description="PCAP capture file to analyze"),
) -> AnalysisResultResponse:
    """Validate and process an uploaded PCAP file."""
    if not file.filename or not file.filename.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename must not be empty.",
        )

    filename = file.filename.strip()
    _, ext = os.path.splitext(filename.lower())

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Unsupported file extension '{ext}'. "
                f"Allowed extensions: {', '.join(sorted(ALLOWED_EXTENSIONS))}."
            ),
        )

    content = await file.read()

    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty (0 bytes).",
        )

    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=(
                f"File size ({len(content)} bytes) exceeds maximum "
                f"allowed limit ({MAX_FILE_SIZE_BYTES} bytes)."
            ),
        )

    return analysis_service.analyze_pcap(filename=filename, content=content)
