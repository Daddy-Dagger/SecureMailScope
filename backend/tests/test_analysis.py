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
