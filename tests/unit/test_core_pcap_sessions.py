"""Unit tests for Milestone 1 using mocked TShark packet metadata."""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.app.models.analysis import AnalysisResultResponse
from backend.app.services.analysis_service import AnalysisService
from core.pcap.loader import (
    EmptyCaptureError,
    PcapFileNotFoundError,
    UnsupportedCaptureTypeError,
    read_pcap_bytes,
    read_pcap_file,
)
from core.pcap.session_builder import PcapAnalysisEngine, build_analysis_result
from core.pcap.tshark_adapter import PacketMetadata
from core.protocols import protocols_from_labels


def packet(
    frame: int,
    timestamp: float,
    src_ip: str | None,
    src_port: int | None,
    dst_ip: str | None,
    dst_port: int | None,
    *,
    stream: str | None = "0",
    labels: tuple[str, ...] = (),
    syn: bool = False,
    ack: bool = False,
    payload: str | bytes = b"",
    tls: bool = False,
) -> PacketMetadata:
    return PacketMetadata(
        frame_number=frame,
        timestamp=timestamp,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        tcp_stream=stream,
        tcp_syn=syn,
        tcp_ack=ack,
        protocol_labels=labels,
        tcp_payload=payload.encode() if isinstance(payload, str) else payload,
        tls_record=tls,
    )


def test_smtp_bidirectional_packets_form_one_session() -> None:
    packets = [
        packet(1, 1_788_493_810.0, "192.168.1.10", 51544, "192.168.1.20", 25, syn=True),
        packet(2, 1_788_493_811.0, "192.168.1.20", 25, "192.168.1.10", 51544, ack=True),
        packet(3, 1_788_493_815.0, "192.168.1.10", 51544, "192.168.1.20", 25),
        packet(4, 1_788_493_816.0, None, None, None, None, stream=None),
    ]

    result = build_analysis_result("sample.pcap", packets)

    assert result["packet_count"] == 4
    assert result["summary"] == {
        "smtp_sessions": 1,
        "imap_sessions": 0,
        "pop3_sessions": 0,
    }
    assert result["sessions"] == [
        {
            "session_id": "smtp-001",
            "protocol": "SMTP",
            "client_ip": "192.168.1.10",
            "client_port": 51544,
            "server_ip": "192.168.1.20",
            "server_port": 25,
            "packet_count": 3,
            "start_time": "2026-09-04T03:50:10Z",
            "end_time": "2026-09-04T03:50:15Z",
            "application_events": [],
            "transport_security": {
                "mode": "UNKNOWN",
                "upgrade_status": "UNKNOWN",
                "advertised": False,
                "requested": False,
                "accepted": False,
                "tls_detected": False,
                "upgrade_command": "STARTTLS",
                "evidence": {},
            },
            "tls": {
                "detected": False,
                "handshake_status": "NOT_APPLICABLE",
                "offered_versions": [],
                "offered_groups": [],
                "version": None,
                "cipher_suite": None,
                "key_exchange": None,
                "evidence": {},
            },
        }
    ]


def test_bidirectional_endpoint_fallback_without_stream_identifier() -> None:
    packets = [
        packet(1, 1.0, "10.0.0.4", 52000, "10.0.0.8", 110, stream=None),
        packet(2, 2.0, "10.0.0.8", 110, "10.0.0.4", 52000, stream=None),
    ]

    result = build_analysis_result("no-stream-id.pcap", packets)

    assert len(result["sessions"]) == 1
    assert result["sessions"][0]["protocol"] == "POP3"
    assert result["sessions"][0]["packet_count"] == 2


@pytest.mark.parametrize(
    ("protocol", "server_port", "expected_id", "summary_key"),
    [
        ("SMTP", 587, "smtp-001", "smtp_sessions"),
        ("IMAP", 143, "imap-001", "imap_sessions"),
        ("POP3", 110, "pop3-001", "pop3_sessions"),
    ],
)
def test_email_protocol_session_grouping(
    protocol: str,
    server_port: int,
    expected_id: str,
    summary_key: str,
) -> None:
    result = build_analysis_result(
        "mail.pcap",
        [
            packet(1, 10.0, "10.0.0.4", 52000, "10.0.0.8", server_port, syn=True),
            packet(2, 11.0, "10.0.0.8", server_port, "10.0.0.4", 52000, ack=True),
        ],
    )

    assert len(result["sessions"]) == 1
    assert result["sessions"][0]["protocol"] == protocol
    assert result["sessions"][0]["session_id"] == expected_id
    assert result["sessions"][0]["packet_count"] == 2
    assert result["summary"][summary_key] == 1


@pytest.mark.parametrize(
    ("server_port", "protocol"),
    [
        (25, "SMTP"),
        (465, "SMTP"),
        (587, "SMTP"),
        (143, "IMAP"),
        (993, "IMAP"),
        (110, "POP3"),
        (995, "POP3"),
    ],
)
def test_well_known_port_fallback(server_port: int, protocol: str) -> None:
    result = build_analysis_result(
        "encrypted-or-undissected.pcap",
        [packet(1, 10.0, "203.0.113.5", 53000, "203.0.113.9", server_port, syn=True)],
    )
    assert [session["protocol"] for session in result["sessions"]] == [protocol]


@pytest.mark.parametrize(
    ("label", "protocol"),
    [("smtp", "SMTP"), ("IMAP", "IMAP"), ("pop", "POP3"), ("POP3", "POP3")],
)
def test_protocol_label_detection_on_nonstandard_port(label: str, protocol: str) -> None:
    result = build_analysis_result(
        "labelled.pcap",
        [
            packet(
                1,
                10.0,
                "198.51.100.4",
                54000,
                "198.51.100.9",
                2526,
                labels=("eth:ip:tcp", label),
                syn=True,
            )
        ],
    )
    assert result["sessions"][0]["protocol"] == protocol
    assert result["sessions"][0]["client_port"] == 54000
    assert result["sessions"][0]["server_port"] == 2526


def test_exact_protocol_labels_do_not_match_substrings() -> None:
    assert protocols_from_labels(("smtp/imf",)) == {"SMTP"}
    assert protocols_from_labels(("smtps", "exampleimapvalue")) == set()


def test_no_email_packets_return_empty_sessions() -> None:
    result = build_analysis_result(
        "web-only.pcap",
        [
            packet(1, 1.0, "10.0.0.1", 51000, "10.0.0.2", 443, syn=True),
            packet(2, 2.0, "10.0.0.2", 443, "10.0.0.1", 51000, ack=True),
        ],
    )
    assert result["packet_count"] == 2
    assert result["sessions"] == []
    assert result["summary"] == {
        "smtp_sessions": 0,
        "imap_sessions": 0,
        "pop3_sessions": 0,
    }


def test_ambiguous_port_only_flow_is_not_fabricated() -> None:
    result = build_analysis_result(
        "ambiguous.pcap",
        [packet(1, 1.0, "10.0.0.1", 25, "10.0.0.2", 143)],
    )
    assert result["sessions"] == []


def test_contract_compatible_engine_output(monkeypatch: pytest.MonkeyPatch) -> None:
    packets = [packet(1, 1.0, "10.0.0.1", 51000, "10.0.0.2", 995, syn=True)]
    monkeypatch.setattr("core.pcap.session_builder.read_pcap_bytes", lambda *_: packets)
    monkeypatch.setattr("core.pcap.session_builder.tshark_path", lambda: "/usr/bin/tshark")

    engine = PcapAnalysisEngine()
    result = engine.analyze("mail.pcap", b"mocked-capture")

    assert engine.is_available is True
    validated = AnalysisResultResponse.model_validate(result)
    assert validated.sessions[0].protocol == "POP3"
    assert validated.sessions[0].transport_security is not None
    assert validated.sessions[0].transport_security.mode == "IMPLICIT_TLS"
    assert validated.sessions[0].transport_security.upgrade_status == "NOT_APPLICABLE"
    assert validated.sessions[0].transport_security.tls_detected is False
    assert validated.findings == []
    assert validated.overall_score is None
    assert validated.risk_level is None


def test_member4_analysis_service_can_consume_core_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packets = [packet(1, 1.0, "10.0.0.1", 51000, "10.0.0.2", 143, syn=True)]
    monkeypatch.setattr("core.pcap.session_builder.read_pcap_bytes", lambda *_: packets)

    result = AnalysisService(core_engine=PcapAnalysisEngine()).analyze_pcap(
        "mail.pcap",
        b"mocked-capture",
    )

    assert result.packet_count == 1
    assert result.sessions[0].protocol == "IMAP"
    assert result.summary.imap_sessions == 1


def test_empty_and_invalid_file_handling(tmp_path: Path) -> None:
    empty_capture = tmp_path / "empty.pcap"
    empty_capture.touch()

    with pytest.raises(EmptyCaptureError):
        read_pcap_file(empty_capture)
    with pytest.raises(EmptyCaptureError):
        read_pcap_bytes("empty.pcap", b"")
    with pytest.raises(UnsupportedCaptureTypeError):
        read_pcap_bytes("capture.txt", b"bytes")
    with pytest.raises(PcapFileNotFoundError):
        read_pcap_file(tmp_path / "missing.pcap")


def test_loader_can_use_mocked_metadata_extractor(tmp_path: Path) -> None:
    capture = tmp_path / "mock.pcap"
    capture.write_bytes(b"not-read-by-mock")
    expected = [packet(1, 1.0, "10.0.0.1", 50000, "10.0.0.2", 25)]

    assert read_pcap_file(capture, extractor=lambda _: expected) == expected
    assert read_pcap_bytes("mock.pcap", b"bytes", extractor=lambda _: expected) == expected
