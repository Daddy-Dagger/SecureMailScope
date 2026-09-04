"""Tests for SecureMailScope JSON report generation."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from backend.app.models.analysis import (
    AnalysisResultResponse,
    FindingSchema,
    ProtocolSummary,
    SessionSchema,
)
from reports.json_report import export_json_report, generate_json_report


@pytest.fixture
def contract_schema() -> dict:
    """Load canonical analysis result schema contract."""
    contract_path = Path(__file__).resolve().parents[2] / "shared" / "contracts" / "analysis_result_schema.json"
    with open(contract_path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def minimal_analysis_dict() -> dict:
    return {
        "file": "minimal.pcap",
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


@pytest.fixture
def full_analysis_dict() -> dict:
    return {
        "file": "corporate_mail.pcap",
        "packet_count": 1250,
        "summary": {
            "smtp_sessions": 1,
            "imap_sessions": 1,
            "pop3_sessions": 0,
        },
        "sessions": [
            {
                "session_id": "smtp-001",
                "protocol": "SMTP",
                "client_ip": "192.168.1.10",
                "client_port": 51544,
                "server_ip": "192.168.1.20",
                "server_port": 25,
                "packet_count": 63,
                "start_time": "2026-09-02T10:10:10Z",
                "end_time": "2026-09-02T10:10:15Z",
            },
            {
                "session_id": "imap-001",
                "protocol": "IMAP",
                "client_ip": "192.168.1.15",
                "client_port": 52100,
                "server_ip": "192.168.1.20",
                "server_port": 143,
                "packet_count": 120,
                "start_time": "2026-09-02T10:11:00Z",
                "end_time": "2026-09-02T10:11:30Z",
            },
        ],
        "findings": [
            {
                "finding_id": "TLS-001",
                "title": "Deprecated TLS version",
                "severity": "HIGH",
                "explanation": "The session used an outdated TLS version.",
                "recommendation": "Disable outdated TLS versions.",
            },
            {
                "finding_id": "CERT-001",
                "title": "Self-signed certificate",
                "severity": "MEDIUM",
                "explanation": "The certificate presented was self-signed.",
                "recommendation": "Use certificates issued by trusted CAs.",
            },
        ],
        "overall_score": None,
        "risk_level": None,
    }


def test_1_valid_minimal_analysis_result(minimal_analysis_dict: dict) -> None:
    """1. Test that a minimal analysis result generates valid JSON from dict and model."""
    # From dict
    json_str = generate_json_report(minimal_analysis_dict)
    assert isinstance(json_str, str)
    data = json.loads(json_str)
    assert data["file"] == "minimal.pcap"
    assert data["packet_count"] == 0
    assert data["sessions"] == []
    assert data["findings"] == []

    # From Pydantic model instance
    model = AnalysisResultResponse.model_validate(minimal_analysis_dict)
    json_str_model = generate_json_report(model)
    assert json_str == json_str_model


def test_2_valid_analysis_result_containing_sessions(full_analysis_dict: dict) -> None:
    """2. Test valid analysis result containing multiple email sessions."""
    json_str = generate_json_report(full_analysis_dict)
    data = json.loads(json_str)
    assert len(data["sessions"]) == 2
    assert data["summary"]["smtp_sessions"] == 1
    assert data["summary"]["imap_sessions"] == 1
    assert data["summary"]["pop3_sessions"] == 0
    assert data["sessions"][0]["protocol"] == "SMTP"
    assert data["sessions"][1]["protocol"] == "IMAP"


def test_3_valid_analysis_result_containing_findings(full_analysis_dict: dict) -> None:
    """3. Test valid analysis result containing security findings."""
    json_str = generate_json_report(full_analysis_dict)
    data = json.loads(json_str)
    assert len(data["findings"]) == 2
    assert data["findings"][0]["finding_id"] == "TLS-001"
    assert data["findings"][0]["severity"] == "HIGH"
    assert data["findings"][1]["finding_id"] == "CERT-001"
    assert data["findings"][1]["severity"] == "MEDIUM"


def test_4_null_overall_score_and_risk_level(minimal_analysis_dict: dict) -> None:
    """4. Test that null overall_score and risk_level are explicitly serialized as null in JSON."""
    json_str = generate_json_report(minimal_analysis_dict)
    data = json.loads(json_str)
    assert "overall_score" in data
    assert data["overall_score"] is None
    assert "risk_level" in data
    assert data["risk_level"] is None
    # Ensure 'null' literally appears in the raw JSON text
    assert '"overall_score": null' in json_str
    assert '"risk_level": null' in json_str


def test_5_json_validity(full_analysis_dict: dict) -> None:
    """5. Test that the output is deterministic, valid JSON that round-trips cleanly."""
    json_str_1 = generate_json_report(full_analysis_dict, indent=2)
    json_str_2 = generate_json_report(full_analysis_dict, indent=2)
    assert json_str_1 == json_str_2  # Deterministic

    parsed = json.loads(json_str_1)
    assert isinstance(parsed, dict)


def test_6_required_fields_preserved(minimal_analysis_dict: dict, contract_schema: dict) -> None:
    """6. Test that all required fields from the shared contract schema are preserved."""
    json_str = generate_json_report(minimal_analysis_dict)
    data = json.loads(json_str)

    for required_field in contract_schema["required"]:
        assert required_field in data, f"Required field '{required_field}' missing from generated report"


def test_7_nested_session_data_preserved(full_analysis_dict: dict) -> None:
    """7. Test that all 9 fields of extracted sessions are preserved exactly."""
    json_str = generate_json_report(full_analysis_dict)
    data = json.loads(json_str)

    expected_session = full_analysis_dict["sessions"][0]
    actual_session = data["sessions"][0]

    for key, val in expected_session.items():
        assert actual_session[key] == val, f"Session field '{key}' differed: expected {val}, got {actual_session[key]}"


def test_8_nested_finding_data_preserved(full_analysis_dict: dict) -> None:
    """8. Test that all 5 fields of security findings are preserved exactly."""
    json_str = generate_json_report(full_analysis_dict)
    data = json.loads(json_str)

    expected_finding = full_analysis_dict["findings"][0]
    actual_finding = data["findings"][0]

    for key, val in expected_finding.items():
        assert actual_finding[key] == val, f"Finding field '{key}' differed: expected {val}, got {actual_finding[key]}"


def test_9_invalid_analysis_result_rejected() -> None:
    """9. Test that invalid analysis results fail clearly with ValidationError or TypeError."""
    # Missing required field 'file'
    with pytest.raises(ValidationError):
        generate_json_report({
            "packet_count": 0,
            "summary": {"smtp_sessions": 0, "imap_sessions": 0, "pop3_sessions": 0},
            "sessions": [],
            "findings": [],
            "overall_score": None,
            "risk_level": None,
        })

    # Negative packet count
    with pytest.raises(ValidationError):
        generate_json_report({
            "file": "test.pcap",
            "packet_count": -5,
            "summary": {"smtp_sessions": 0, "imap_sessions": 0, "pop3_sessions": 0},
            "sessions": [],
            "findings": [],
            "overall_score": None,
            "risk_level": None,
        })

    # Invalid session protocol
    with pytest.raises(ValidationError):
        generate_json_report({
            "file": "test.pcap",
            "packet_count": 10,
            "summary": {"smtp_sessions": 0, "imap_sessions": 0, "pop3_sessions": 0},
            "sessions": [
                {
                    "session_id": "s-1",
                    "protocol": "UNSUPPORTED",
                    "client_ip": "1.2.3.4",
                    "client_port": 80,
                    "server_ip": "5.6.7.8",
                    "server_port": 80,
                    "packet_count": 10,
                    "start_time": "2026-09-02T10:10:10Z",
                    "end_time": "2026-09-02T10:10:15Z",
                }
            ],
            "findings": [],
            "overall_score": None,
            "risk_level": None,
        })

    # Invalid finding severity
    with pytest.raises(ValidationError):
        generate_json_report({
            "file": "test.pcap",
            "packet_count": 10,
            "summary": {"smtp_sessions": 0, "imap_sessions": 0, "pop3_sessions": 0},
            "sessions": [],
            "findings": [
                {
                    "finding_id": "F-1",
                    "title": "Title",
                    "severity": "INVALID_SEVERITY",
                    "explanation": "Expl",
                    "recommendation": "Rec",
                }
            ],
            "overall_score": None,
            "risk_level": None,
        })

    # Non-dict, non-model input raises TypeError
    with pytest.raises(TypeError, match="Expected AnalysisResultResponse or dict"):
        generate_json_report("not a valid analysis result")  # type: ignore

    with pytest.raises(TypeError, match="Expected AnalysisResultResponse or dict"):
        generate_json_report(12345)  # type: ignore


def test_10_no_unexpected_fields_silently_added(minimal_analysis_dict: dict, contract_schema: dict) -> None:
    """10. Test that extra uncontracted fields are rejected and not silently added."""
    invalid_data = dict(minimal_analysis_dict)
    invalid_data["unapproved_extra_field"] = "malicious_payload"

    with pytest.raises(ValidationError):
        generate_json_report(invalid_data)

    # Verify generated JSON has strictly the permitted schema keys
    json_str = generate_json_report(minimal_analysis_dict)
    data = json.loads(json_str)
    allowed_keys = set(contract_schema["properties"].keys())
    assert set(data.keys()).issubset(allowed_keys)


def test_export_json_report_to_file(tmp_path: Path, minimal_analysis_dict: dict) -> None:
    """Verify that export_json_report writes formatted JSON to the specified file path."""
    dest_path = tmp_path / "reports" / "report.json"
    written_path = export_json_report(minimal_analysis_dict, dest_path)

    assert written_path == dest_path
    assert dest_path.exists()
    content = dest_path.read_text(encoding="utf-8")
    data = json.loads(content)
    assert data["file"] == "minimal.pcap"


# ============================================================================
# HTML Report Generator Tests
# ============================================================================

from reports.html_report import export_html_report, generate_html_report


def test_html_1_valid_minimal_analysis_result(minimal_analysis_dict: dict) -> None:
    """1. Test that a minimal analysis result generates valid standalone HTML."""
    html_str = generate_html_report(minimal_analysis_dict)
    assert isinstance(html_str, str)
    assert "minimal.pcap" in html_str

    # Test from Pydantic model instance
    model = AnalysisResultResponse.model_validate(minimal_analysis_dict)
    html_model = generate_html_report(model)
    assert html_str == html_model


def test_html_2_valid_analysis_result_containing_sessions(full_analysis_dict: dict) -> None:
    """2. Test HTML generation with multiple active sessions."""
    html_str = generate_html_report(full_analysis_dict)
    assert "smtp-001" in html_str
    assert "imap-001" in html_str
    assert "192.168.1.10:51544" in html_str
    assert "192.168.1.20:25" in html_str
    assert "SMTP Sessions" in html_str
    assert "IMAP Sessions" in html_str


def test_html_3_valid_analysis_result_containing_findings(full_analysis_dict: dict) -> None:
    """3. Test HTML generation with security findings and severity badges."""
    html_str = generate_html_report(full_analysis_dict)
    assert "TLS-001" in html_str
    assert "Deprecated TLS version" in html_str
    assert "badge-high" in html_str
    assert "HIGH" in html_str
    assert "CERT-001" in html_str
    assert "Self-signed certificate" in html_str
    assert "badge-medium" in html_str
    assert "MEDIUM" in html_str
    assert "The session used an outdated TLS version." in html_str
    assert "Disable outdated TLS versions." in html_str


def test_html_4_null_overall_score_and_risk_level(minimal_analysis_dict: dict) -> None:
    """4. Test that null overall_score and risk_level are displayed as 'Not available'."""
    html_str = generate_html_report(minimal_analysis_dict)
    assert "Not available" in html_str
    # Verify neither fake numeric scores nor fake risk levels are fabricated
    assert "90/100" not in html_str
    assert "LOW RISK" not in html_str


def test_html_5_document_validity_and_structure(minimal_analysis_dict: dict) -> None:
    """5. Test basic HTML document structure and mandatory tags."""
    html_str = generate_html_report(minimal_analysis_dict)
    assert html_str.startswith("<!DOCTYPE html>")
    assert "<html lang=\"en\">" in html_str
    assert "<head>" in html_str
    assert "<meta charset=\"utf-8\">" in html_str
    assert "<meta name=\"viewport\"" in html_str
    assert "<style>" in html_str
    assert "</style>" in html_str
    assert "<body>" in html_str
    assert "</html>" in html_str


def test_html_6_required_sections_exist(minimal_analysis_dict: dict) -> None:
    """6. Test that all mandatory sections are present."""
    html_str = generate_html_report(minimal_analysis_dict)
    assert "SecureMailScope — Email Cryptographic Security Analysis" in html_str
    assert "Capture Overview &amp; Assessment" in html_str
    assert "Extracted Email Sessions" in html_str
    assert "Cryptographic Security Findings" in html_str


def test_html_7_session_information_preserved(full_analysis_dict: dict) -> None:
    """7. Test that session details (ID, protocol, endpoints, counts, times) are preserved."""
    html_str = generate_html_report(full_analysis_dict)
    assert "smtp-001" in html_str
    assert "SMTP" in html_str
    assert "192.168.1.10:51544" in html_str
    assert "192.168.1.20:25" in html_str
    assert "63" in html_str
    assert "2026-09-02T10:10:10Z" in html_str
    assert "2026-09-02T10:10:15Z" in html_str


def test_html_8_finding_information_preserved(full_analysis_dict: dict) -> None:
    """8. Test that finding details (ID, title, severity, explanation, recommendation) are preserved."""
    html_str = generate_html_report(full_analysis_dict)
    assert "TLS-001" in html_str
    assert "Deprecated TLS version" in html_str
    assert "HIGH" in html_str
    assert "The session used an outdated TLS version." in html_str
    assert "Disable outdated TLS versions." in html_str


def test_html_9_empty_session_state(minimal_analysis_dict: dict) -> None:
    """9. Test empty sessions state message."""
    html_str = generate_html_report(minimal_analysis_dict)
    assert "No sessions detected." in html_str


def test_html_10_empty_findings_state(minimal_analysis_dict: dict) -> None:
    """10. Test empty findings state message."""
    html_str = generate_html_report(minimal_analysis_dict)
    assert "No security findings available." in html_str


def test_html_11_invalid_analysis_result_rejected() -> None:
    """11. Test that invalid analysis results are rejected with ValidationError or TypeError."""
    with pytest.raises(ValidationError):
        generate_html_report({
            "packet_count": 0,
            "summary": {"smtp_sessions": 0, "imap_sessions": 0, "pop3_sessions": 0},
            "sessions": [],
            "findings": [],
            "overall_score": None,
            "risk_level": None,
        })

    with pytest.raises(TypeError, match="Expected AnalysisResultResponse or dict"):
        generate_html_report("invalid raw string")  # type: ignore


def test_html_12_extra_uncontracted_fields_rejected(minimal_analysis_dict: dict) -> None:
    """12. Test that unapproved extra fields are rejected due to extra='forbid'."""
    bad_dict = dict(minimal_analysis_dict)
    bad_dict["unauthorized_key"] = "payload"

    with pytest.raises(ValidationError):
        generate_html_report(bad_dict)


def test_html_13_html_escaping_and_security() -> None:
    """13. Test that malicious HTML/script injections in dynamic data are safely auto-escaped."""
    malicious_data = {
        "file": "<script>alert('xss-file')</script>.pcap",
        "packet_count": 10,
        "summary": {"smtp_sessions": 1, "imap_sessions": 0, "pop3_sessions": 0},
        "sessions": [
            {
                "session_id": "<img src=x onerror=alert('session')>",
                "protocol": "SMTP",
                "client_ip": "1.1.1.1",
                "client_port": 25,
                "server_ip": "2.2.2.2",
                "server_port": 25,
                "packet_count": 10,
                "start_time": "2026-09-02T10:10:10Z",
                "end_time": "2026-09-02T10:10:15Z",
            }
        ],
        "findings": [
            {
                "finding_id": "XSS-001",
                "title": "<b onmouseover=alert(1)>Malicious Title</b>",
                "severity": "HIGH",
                "explanation": "<script>stealSession()</script>",
                "recommendation": "<iframe src='evil.com'></iframe>",
            }
        ],
        "overall_score": None,
        "risk_level": None,
    }

    html_str = generate_html_report(malicious_data)

    # Ensure unescaped tags do NOT appear in the rendered document
    assert "<script>alert('xss-file')</script>" not in html_str
    assert "<img src=x onerror=alert('session')>" not in html_str
    assert "<b onmouseover=alert(1)>" not in html_str
    assert "<script>stealSession()</script>" not in html_str
    assert "<iframe src='evil.com'></iframe>" not in html_str

    # Ensure escaped entities DO appear
    assert "&lt;script&gt;alert(&#39;xss-file&#39;)&lt;/script&gt;" in html_str
    assert "&lt;img src=x onerror=alert(&#39;session&#39;)&gt;" in html_str
    assert "&lt;script&gt;stealSession()&lt;/script&gt;" in html_str


def test_html_14_export_html_report_to_file(tmp_path: Path, minimal_analysis_dict: dict) -> None:
    """14. Test that export_html_report writes HTML to disk correctly."""
    dest_path = tmp_path / "reports" / "report.html"
    written_path = export_html_report(minimal_analysis_dict, dest_path)

    assert written_path == dest_path
    assert dest_path.exists()
    content = dest_path.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "minimal.pcap" in content


def test_html_15_offline_and_no_external_cdn(minimal_analysis_dict: dict) -> None:
    """15. Verify that report is 100% offline with no external CDN, scripts, or font links."""
    html_str = generate_html_report(minimal_analysis_dict)
    # Check head section specifically for external resource links
    head_content = html_str.split("</head>")[0]
    assert "http://" not in head_content
    assert "https://" not in head_content
    assert "cdn." not in head_content
    assert "fonts.googleapis.com" not in head_content
    assert "<script" not in html_str


# ============================================================================
# PDF Report Generator Tests
# ============================================================================

from reports.pdf_report import export_pdf_report, generate_pdf_report


def test_pdf_1_valid_minimal_analysis_result(minimal_analysis_dict: dict) -> None:
    """1. Test that a minimal analysis result generates valid PDF bytes from dict and model."""
    pdf_bytes = generate_pdf_report(minimal_analysis_dict)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-")
    assert b"%%EOF" in pdf_bytes

    # From Pydantic model instance
    model = AnalysisResultResponse.model_validate(minimal_analysis_dict)
    pdf_bytes_model = generate_pdf_report(model)
    assert isinstance(pdf_bytes_model, bytes)
    assert pdf_bytes_model.startswith(b"%PDF-")


def test_pdf_2_valid_analysis_result_with_sessions(full_analysis_dict: dict) -> None:
    """2. Test PDF generation with active extracted sessions."""
    pdf_bytes = generate_pdf_report(full_analysis_dict)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 1000


def test_pdf_3_valid_analysis_result_with_findings(full_analysis_dict: dict) -> None:
    """3. Test PDF generation with security findings and recommendations."""
    pdf_bytes = generate_pdf_report(full_analysis_dict)
    assert isinstance(pdf_bytes, bytes)
    assert b"%%EOF" in pdf_bytes


def _extract_text_from_pdf(pdf_bytes: bytes) -> str:
    """Extract decompressed text from ReportLab PDF streams for content verification."""
    import base64
    import zlib

    text_parts = []
    idx = pdf_bytes.find(b"stream")
    while idx != -1:
        end_idx = pdf_bytes.find(b"endstream", idx)
        if end_idx == -1:
            break
        raw = pdf_bytes[idx + 6:end_idx].strip()
        if raw.startswith(b"<~") and raw.endswith(b"~>"):
            raw = raw[2:-2]
        try:
            decoded = base64.a85decode(raw, adobe=True)
            decomp = zlib.decompress(decoded)
            text_parts.append(decomp.decode("latin1", errors="ignore"))
        except Exception:
            text_parts.append(raw.decode("latin1", errors="ignore"))
        idx = pdf_bytes.find(b"stream", end_idx + 9)

    return " ".join(text_parts)


def test_pdf_4_null_overall_score_and_risk_level(minimal_analysis_dict: dict) -> None:
    """4. Test that null overall_score and risk_level render 'Not available' without fabrication."""
    pdf_bytes = generate_pdf_report(minimal_analysis_dict)
    text = _extract_text_from_pdf(pdf_bytes)
    assert "Not available" in text
    assert "90/100" not in text
    assert "HIGH RISK" not in text


def test_pdf_5_file_created_on_disk(tmp_path: Path, minimal_analysis_dict: dict) -> None:
    """5. Test that generate_pdf_report writes PDF to disk when output_path is provided."""
    dest_path = tmp_path / "report.pdf"
    result_path = generate_pdf_report(minimal_analysis_dict, output_path=dest_path)

    assert result_path == dest_path
    assert dest_path.exists()
    assert dest_path.is_file()


def test_pdf_6_pdf_is_non_empty(tmp_path: Path, minimal_analysis_dict: dict) -> None:
    """6. Test that the generated PDF file has a non-trivial file size."""
    dest_path = tmp_path / "non_empty_report.pdf"
    generate_pdf_report(minimal_analysis_dict, output_path=dest_path)
    assert dest_path.stat().st_size > 1000


def test_pdf_7_valid_pdf_signature_and_trailer(tmp_path: Path, minimal_analysis_dict: dict) -> None:
    """7. Test standard PDF magic bytes signature (%PDF-) and end-of-file trailer (%%EOF)."""
    dest_path = tmp_path / "signature_test.pdf"
    generate_pdf_report(minimal_analysis_dict, output_path=dest_path)
    file_bytes = dest_path.read_bytes()
    assert file_bytes.startswith(b"%PDF-")
    assert b"%%EOF" in file_bytes


def test_pdf_8_important_report_text_present(full_analysis_dict: dict) -> None:
    """8. Test that important report text (project ID, filename, session IDs) is present."""
    pdf_bytes = generate_pdf_report(full_analysis_dict)
    text = _extract_text_from_pdf(pdf_bytes)
    assert "SIH26159" in text
    assert "SecureMailScope" in text
    assert "corporate_mail.pcap" in text
    assert "smtp-001" in text
    assert "TLS-001" in text



def test_pdf_9_multiple_sessions_and_findings_pagination(tmp_path: Path) -> None:
    """9. Test that multi-session and multi-finding reports paginate cleanly without crashing."""
    many_sessions = [
        {
            "session_id": f"smtp-{i:03d}",
            "protocol": "SMTP",
            "client_ip": f"10.0.0.{i}",
            "client_port": 50000 + i,
            "server_ip": "10.0.1.1",
            "server_port": 25,
            "packet_count": 100 + i,
            "start_time": "2026-09-02T10:10:10Z",
            "end_time": "2026-09-02T10:10:20Z",
        }
        for i in range(1, 15)
    ]
    many_findings = [
        {
            "finding_id": f"FIND-{i:03d}",
            "title": f"Security finding number {i}",
            "severity": "HIGH" if i % 2 == 0 else "MEDIUM",
            "explanation": f"Detailed forensic explanation for issue {i}.",
            "recommendation": f"Remediation steps for issue {i}.",
        }
        for i in range(1, 8)
    ]

    large_data = {
        "file": "large_capture.pcap",
        "packet_count": 5000,
        "summary": {"smtp_sessions": 14, "imap_sessions": 0, "pop3_sessions": 0},
        "sessions": many_sessions,
        "findings": many_findings,
        "overall_score": None,
        "risk_level": None,
    }

    dest_path = tmp_path / "large_report.pdf"
    result_path = generate_pdf_report(large_data, output_path=dest_path)
    assert result_path.exists()
    assert result_path.stat().st_size > 5000


def test_pdf_10_long_text_wrapping_does_not_crash(tmp_path: Path) -> None:
    """10. Test that very long descriptions and recommendations wrap properly without error."""
    long_data = {
        "file": "a" * 100 + ".pcap",
        "packet_count": 10,
        "summary": {"smtp_sessions": 1, "imap_sessions": 0, "pop3_sessions": 0},
        "sessions": [
            {
                "session_id": "long-session-id-" + "x" * 50,
                "protocol": "SMTP",
                "client_ip": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                "client_port": 50000,
                "server_ip": "2001:0db8:85a3:0000:0000:8a2e:0370:7335",
                "server_port": 587,
                "packet_count": 10,
                "start_time": "2026-09-02T10:10:10Z",
                "end_time": "2026-09-02T10:10:15Z",
            }
        ],
        "findings": [
            {
                "finding_id": "LONG-001",
                "title": "Title with special characters: <>&\"' and long description",
                "severity": "CRITICAL",
                "explanation": "This is a very long explanation. " * 30,
                "recommendation": "This is a very long remediation recommendation. " * 20,
            }
        ],
        "overall_score": None,
        "risk_level": None,
    }

    dest_path = tmp_path / "long_text_report.pdf"
    result_path = generate_pdf_report(long_data, output_path=dest_path)
    assert result_path.exists()


def test_pdf_11_invalid_analysis_result_rejected() -> None:
    """11. Test that invalid analysis results fail with ValidationError or TypeError."""
    with pytest.raises(ValidationError):
        generate_pdf_report({
            "packet_count": 0,
            "summary": {"smtp_sessions": 0, "imap_sessions": 0, "pop3_sessions": 0},
            "sessions": [],
            "findings": [],
            "overall_score": None,
            "risk_level": None,
        })

    with pytest.raises(TypeError, match="Expected AnalysisResultResponse or dict"):
        generate_pdf_report(99999)  # type: ignore


def test_pdf_12_extra_uncontracted_fields_rejected(minimal_analysis_dict: dict) -> None:
    """12. Test that unapproved extra fields are rejected due to extra='forbid'."""
    bad_dict = dict(minimal_analysis_dict)
    bad_dict["unauthorized_field"] = "injected"

    with pytest.raises(ValidationError):
        generate_pdf_report(bad_dict)


def test_pdf_13_output_parent_directory_auto_created(tmp_path: Path, minimal_analysis_dict: dict) -> None:
    """13. Test that deeply nested missing parent directories are automatically created."""
    deep_path = tmp_path / "sub1" / "sub2" / "sub3" / "auto_dir_report.pdf"
    assert not deep_path.parent.exists()

    result_path = generate_pdf_report(minimal_analysis_dict, output_path=deep_path)
    assert result_path == deep_path
    assert deep_path.exists()


def test_pdf_14_export_pdf_report_alias(tmp_path: Path, minimal_analysis_dict: dict) -> None:
    """14. Test export_pdf_report convenience helper function."""
    dest_path = tmp_path / "export_alias.pdf"
    result = export_pdf_report(minimal_analysis_dict, dest_path)
    assert result == dest_path
    assert dest_path.exists()
    assert dest_path.read_bytes().startswith(b"%PDF-")
