"""Integration tests for SecureMailScope Report Export API (POST /api/reports/export)."""

import json
from pathlib import Path

import httpx
import pytest

from backend.app.main import app


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def sample_analysis_data() -> dict:
    return {
        "file": "audit_capture.pcap",
        "packet_count": 1420,
        "summary": {
            "smtp_sessions": 1,
            "imap_sessions": 1,
            "pop3_sessions": 0,
        },
        "sessions": [
            {
                "session_id": "smtp-audit-001",
                "protocol": "SMTP",
                "client_ip": "10.0.1.5",
                "client_port": 49152,
                "server_ip": "10.0.1.25",
                "server_port": 25,
                "packet_count": 60,
                "start_time": "2026-09-03T12:00:00Z",
                "end_time": "2026-09-03T12:00:05Z",
            }
        ],
        "findings": [
            {
                "finding_id": "TLS-DEPR-001",
                "title": "Deprecated TLS 1.0 Negotiated",
                "severity": "HIGH",
                "explanation": "Client negotiated TLS 1.0 with weak cipher suite.",
                "recommendation": "Configure mail transfer agent to enforce TLS 1.3 or 1.2 minimum.",
            }
        ],
        "overall_score": None,
        "risk_level": None,
    }


@pytest.mark.anyio
async def test_export_json_report_success(sample_analysis_data: dict) -> None:
    """1. Test that POST /api/reports/export generates and returns valid JSON report."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "format": "json",
            "analysis_result": sample_analysis_data,
        }
        response = await client.post("/api/reports/export", json=payload)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert "content-disposition" in response.headers
    assert response.headers["content-disposition"] == 'attachment; filename="securemailscope-report.json"'

    # Validate JSON content integrity
    data = json.loads(response.text)
    assert data["file"] == "audit_capture.pcap"
    assert data["packet_count"] == 1420
    assert data["summary"]["smtp_sessions"] == 1
    assert data["sessions"][0]["session_id"] == "smtp-audit-001"
    assert data["findings"][0]["finding_id"] == "TLS-DEPR-001"
    assert data["overall_score"] is None
    assert data["risk_level"] is None


@pytest.mark.anyio
async def test_export_html_report_success(sample_analysis_data: dict) -> None:
    """2. Test that POST /api/reports/export generates and returns valid standalone HTML report."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "format": "html",
            "analysis_result": sample_analysis_data,
        }
        response = await client.post("/api/reports/export", json=payload)

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert response.headers["content-disposition"] == 'attachment; filename="securemailscope-report.html"'

    # Validate HTML content
    html_text = response.text
    assert "<!DOCTYPE html>" in html_text
    assert "SecureMailScope — Email Cryptographic Security Analysis" in html_text
    assert "audit_capture.pcap" in html_text
    assert "smtp-audit-001" in html_text
    assert "TLS-DEPR-001" in html_text
    assert "Not available" in html_text


@pytest.mark.anyio
async def test_export_pdf_report_success(sample_analysis_data: dict) -> None:
    """3. Test that POST /api/reports/export generates and returns valid in-memory PDF report."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "format": "pdf",
            "analysis_result": sample_analysis_data,
        }
        response = await client.post("/api/reports/export", json=payload)

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["content-disposition"] == 'attachment; filename="securemailscope-report.pdf"'

    # Validate PDF binary signature
    pdf_bytes = response.content
    assert pdf_bytes.startswith(b"%PDF-")
    assert b"%%EOF" in pdf_bytes
    assert len(pdf_bytes) > 1000


@pytest.mark.anyio
async def test_export_with_query_param_format(sample_analysis_data: dict) -> None:
    """4. Test POST /api/reports/export?format=html with raw AnalysisResultResponse payload."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/reports/export?format=html", json=sample_analysis_data)

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert response.headers["content-disposition"] == 'attachment; filename="securemailscope-report.html"'
    assert "audit_capture.pcap" in response.text


@pytest.mark.anyio
async def test_export_rejects_unsupported_format(sample_analysis_data: dict) -> None:
    """5. Test that unsupported formats (e.g. 'docx', 'csv') are rejected with 400 or 422."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # In request model format field
        payload = {
            "format": "docx",
            "analysis_result": sample_analysis_data,
        }
        response = await client.post("/api/reports/export", json=payload)
        assert response.status_code == 422

        # In query parameter override
        response_qp = await client.post("/api/reports/export?format=csv", json=sample_analysis_data)
        assert response_qp.status_code == 400
        assert "Unsupported report format" in response_qp.json()["detail"]


@pytest.mark.anyio
async def test_export_rejects_invalid_analysis_data() -> None:
    """6. Test that malformed analysis data (e.g. missing required fields) is rejected with 422."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "format": "json",
            "analysis_result": {
                # Missing 'file' and 'summary'
                "packet_count": 10,
                "sessions": [],
                "findings": [],
                "overall_score": None,
                "risk_level": None,
            },
        }
        response = await client.post("/api/reports/export", json=payload)

    assert response.status_code == 422


@pytest.mark.anyio
async def test_export_rejects_extra_uncontracted_fields(sample_analysis_data: dict) -> None:
    """7. Test that extra unapproved schema fields are rejected with 422 due to extra='forbid'."""
    corrupted_data = dict(sample_analysis_data)
    corrupted_data["unexpected_injected_field"] = "payload"

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "format": "json",
            "analysis_result": corrupted_data,
        }
        response = await client.post("/api/reports/export", json=payload)

    assert response.status_code == 422
