import json
from pathlib import Path

import httpx
import pytest

from backend.app.main import app
from backend.app.models.analysis import AnalysisResultResponse
from backend.app.services.analysis_service import analysis_service


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_analyze_valid_pcap_file() -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("capture.pcap", b"\xd4\xc3\xb2\xa1test-pcap-bytes", "application/vnd.tcpdump.pcap")}
        response = await client.post("/api/analyze", files=files)

    assert response.status_code == 200
    data = response.json()
    assert data["file"] == "capture.pcap"
    assert data["packet_count"] == 0
    assert data["summary"] == {
        "smtp_sessions": 0,
        "imap_sessions": 0,
        "pop3_sessions": 0,
    }
    assert data["sessions"] == []
    assert data["findings"] == []
    assert data["overall_score"] is None
    assert data["risk_level"] is None


@pytest.mark.anyio
async def test_analyze_supported_extensions() -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        for ext in ["test.pcapng", "test.cap"]:
            files = {"file": (ext, b"dummy content", "application/octet-stream")}
            response = await client.post("/api/analyze", files=files)
            assert response.status_code == 200
            assert response.json()["file"] == ext


@pytest.mark.anyio
async def test_analyze_conforms_to_shared_contract() -> None:
    # Read contract directly from repository
    contract_path = Path(__file__).resolve().parents[2] / "shared" / "contracts" / "analysis_result_schema.json"
    assert contract_path.exists(), f"Contract file not found at {contract_path}"

    with open(contract_path, encoding="utf-8") as f:
        contract = json.load(f)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("traffic.pcap", b"dummy capture bytes", "application/octet-stream")}
        response = await client.post("/api/analyze", files=files)

    assert response.status_code == 200
    data = response.json()

    # Verify all required fields from JSON schema contract
    for required_field in contract["required"]:
        assert required_field in data, f"Missing required field '{required_field}' from contract"

    # Verify additionalProperties: false - no unexpected root keys
    allowed_keys = set(contract["properties"].keys())
    assert set(data.keys()).issubset(allowed_keys), f"Response has extra keys not in schema: {set(data.keys()) - allowed_keys}"

    # Verify summary required fields and no extra keys
    summary_contract = contract["properties"]["summary"]
    for required_summary in summary_contract["required"]:
        assert required_summary in data["summary"], f"Missing required summary field '{required_summary}'"
    assert set(data["summary"].keys()) == set(summary_contract["required"])


@pytest.mark.anyio
async def test_analyze_rejects_missing_file() -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/analyze")

    assert response.status_code == 422


@pytest.mark.anyio
async def test_analyze_rejects_invalid_file_extension() -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("malicious.exe", b"binarycontent", "application/octet-stream")}
        response = await client.post("/api/analyze", files=files)

    assert response.status_code == 400
    assert "Unsupported file extension" in response.json()["detail"]


@pytest.mark.anyio
async def test_analyze_rejects_empty_file() -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("empty.pcap", b"", "application/octet-stream")}
        response = await client.post("/api/analyze", files=files)

    assert response.status_code == 400
    assert "Uploaded file is empty" in response.json()["detail"]


@pytest.mark.anyio
async def test_analyze_rejects_whitespace_filename() -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("   ", b"dummy", "application/octet-stream")}
        response = await client.post("/api/analyze", files=files)

    assert response.status_code == 400
    assert "Filename must not be empty" in response.json()["detail"]


@pytest.mark.anyio
async def test_analyze_rejects_empty_filename_upload() -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("", b"dummy", "application/octet-stream")}
        response = await client.post("/api/analyze", files=files)

    assert response.status_code in (400, 422)


def test_analysis_service_unit() -> None:
    result = analysis_service.analyze_pcap("unit_test.pcap", b"raw-bytes")
    assert isinstance(result, AnalysisResultResponse)
    assert result.file == "unit_test.pcap"
    assert result.packet_count == 0
    assert result.overall_score is None
    assert result.risk_level is None


@pytest.mark.anyio
async def test_analyze_case_insensitive_extension() -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("TEST_SAMPLE.PCAP", b"dummy content", "application/octet-stream")}
        response = await client.post("/api/analyze", files=files)
        assert response.status_code == 200
        assert response.json()["file"] == "TEST_SAMPLE.PCAP"


@pytest.mark.anyio
async def test_analyze_rejects_oversized_file(monkeypatch: pytest.MonkeyPatch) -> None:
    import backend.app.api.analysis as analysis_module
    monkeypatch.setattr(analysis_module, "MAX_FILE_SIZE_BYTES", 10)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("large.pcap", b"more than 10 bytes here", "application/octet-stream")}
        response = await client.post("/api/analyze", files=files)

    assert response.status_code == 413
    assert "exceeds maximum allowed limit" in response.json()["detail"]


def test_models_forbid_extra_attributes() -> None:
    from pydantic import ValidationError
    from backend.app.models.analysis import ProtocolSummary

    with pytest.raises(ValidationError):
        ProtocolSummary(
            smtp_sessions=0,
            imap_sessions=0,
            pop3_sessions=0,
            extra_field="disallowed",
        )


def test_deferred_core_engine_adapter_defaults() -> None:
    from backend.app.services.core_adapter import DeferredCoreEngineAdapter

    adapter = DeferredCoreEngineAdapter()
    assert adapter.is_available is False
    result = adapter.analyze("test.pcap", b"raw-bytes")
    assert result["file"] == "test.pcap"
    assert result["packet_count"] == 0
    assert result["sessions"] == []
    assert result["findings"] == []
    assert result["overall_score"] is None
    assert result["risk_level"] is None


def test_core_engine_detection_returns_deferred() -> None:
    from backend.app.services.core_adapter import DeferredCoreEngineAdapter, get_core_engine

    engine = get_core_engine()
    assert isinstance(engine, DeferredCoreEngineAdapter)
    assert engine.is_available is False


def test_analysis_service_with_mock_engine_valid_data() -> None:
    """Test that AnalysisService validates and passes through valid core output."""
    from backend.app.services.analysis_service import AnalysisService

    class MockCoreEngine:
        is_available: bool = True

        def analyze(self, filename: str, content: bytes) -> dict:
            return {
                "file": filename,
                "packet_count": 42,
                "summary": {
                    "smtp_sessions": 1,
                    "imap_sessions": 0,
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
                        "packet_count": 42,
                        "start_time": "2026-09-02T10:10:10Z",
                        "end_time": "2026-09-02T10:10:15Z",
                    }
                ],
                "findings": [
                    {
                        "finding_id": "TLS-001",
                        "title": "Deprecated TLS version",
                        "severity": "HIGH",
                        "explanation": "The session used an outdated TLS version.",
                        "recommendation": "Disable outdated TLS versions.",
                    }
                ],
                "overall_score": None,
                "risk_level": None,
            }

    service = AnalysisService(core_engine=MockCoreEngine())
    assert service.has_active_core_engine is True

    result = service.analyze_pcap("valid_session.pcap", b"mock-pcap-bytes")
    assert isinstance(result, AnalysisResultResponse)
    assert result.file == "valid_session.pcap"
    assert result.packet_count == 42
    assert result.summary.smtp_sessions == 1
    assert len(result.sessions) == 1
    assert result.sessions[0].session_id == "smtp-001"
    assert result.sessions[0].protocol == "SMTP"
    assert len(result.findings) == 1
    assert result.findings[0].finding_id == "TLS-001"
    assert result.findings[0].severity == "HIGH"


def test_analysis_service_with_mock_engine_invalid_session_fails_validation() -> None:
    """Test that AnalysisService rejects core output that violates session_schema.json."""
    from pydantic import ValidationError
    from backend.app.services.analysis_service import AnalysisService

    class CorruptSessionEngine:
        is_available: bool = True

        def analyze(self, filename: str, content: bytes) -> dict:
            return {
                "file": filename,
                "packet_count": 10,
                "summary": {"smtp_sessions": 1, "imap_sessions": 0, "pop3_sessions": 0},
                "sessions": [
                    {
                        "session_id": "bad-001",
                        "protocol": "UNSUPPORTED_PROTO",  # violates enum ["SMTP", "IMAP", "POP3"]
                        "client_ip": "10.0.0.1",
                        "client_port": 99999,  # violates le=65535
                        "server_ip": "10.0.0.2",
                        "server_port": 25,
                        "packet_count": 10,
                        "start_time": "2026-09-02T10:10:10Z",
                        "end_time": "2026-09-02T10:10:15Z",
                    }
                ],
                "findings": [],
                "overall_score": None,
                "risk_level": None,
            }

    service = AnalysisService(core_engine=CorruptSessionEngine())
    with pytest.raises(ValidationError):
        service.analyze_pcap("corrupt.pcap", b"raw-bytes")


def test_analysis_service_with_mock_engine_extra_fields_fails_validation() -> None:
    """Test that AnalysisService rejects core output with unexpected root fields."""
    from pydantic import ValidationError
    from backend.app.services.analysis_service import AnalysisService

    class ExtraFieldEngine:
        is_available: bool = True

        def analyze(self, filename: str, content: bytes) -> dict:
            return {
                "file": filename,
                "packet_count": 0,
                "summary": {"smtp_sessions": 0, "imap_sessions": 0, "pop3_sessions": 0},
                "sessions": [],
                "findings": [],
                "overall_score": None,
                "risk_level": None,
                "unauthorized_extra_key": "injected_data",
            }

    service = AnalysisService(core_engine=ExtraFieldEngine())
    with pytest.raises(ValidationError):
        service.analyze_pcap("extra.pcap", b"raw-bytes")


def test_analysis_service_with_mock_engine_raising_error() -> None:
    """Test that AnalysisService propagates core engine errors appropriately."""
    from backend.app.services.analysis_service import AnalysisService
    from backend.app.services.core_adapter import CoreEngineError

    class FaultyCoreEngine:
        is_available: bool = True

        def analyze(self, filename: str, content: bytes) -> dict:
            raise CoreEngineError("TShark process terminated unexpectedly")

    service = AnalysisService(core_engine=FaultyCoreEngine())
    with pytest.raises(CoreEngineError, match="TShark process terminated unexpectedly"):
        service.analyze_pcap("faulty.pcap", b"raw-bytes")


@pytest.mark.anyio
async def test_api_analyze_with_mock_core_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end API test verifying POST /api/analyze integrates with an active CoreAnalysisEngine."""
    from backend.app.services.analysis_service import analysis_service

    class TestDoubleCoreEngine:
        is_available: bool = True

        def analyze(self, filename: str, content: bytes) -> dict:
            return {
                "file": filename,
                "packet_count": 88,
                "summary": {
                    "smtp_sessions": 1,
                    "imap_sessions": 0,
                    "pop3_sessions": 0,
                },
                "sessions": [
                    {
                        "session_id": "smtp-e2e-001",
                        "protocol": "SMTP",
                        "client_ip": "172.16.0.5",
                        "client_port": 49152,
                        "server_ip": "172.16.0.10",
                        "server_port": 587,
                        "packet_count": 88,
                        "start_time": "2026-09-03T12:00:00Z",
                        "end_time": "2026-09-03T12:00:05Z",
                    }
                ],
                "findings": [],
                "overall_score": None,
                "risk_level": None,
            }

    monkeypatch.setattr(analysis_service, "_core_engine", TestDoubleCoreEngine())

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("capture.pcap", b"\xd4\xc3\xb2\xa1test-content", "application/vnd.tcpdump.pcap")}
        response = await client.post("/api/analyze", files=files)

    assert response.status_code == 200
    data = response.json()
    assert data["file"] == "capture.pcap"
    assert data["packet_count"] == 88
    assert data["summary"]["smtp_sessions"] == 1
    assert len(data["sessions"]) == 1
    assert data["sessions"][0]["session_id"] == "smtp-e2e-001"
    assert data["sessions"][0]["protocol"] == "SMTP"
    assert data["sessions"][0]["server_port"] == 587
