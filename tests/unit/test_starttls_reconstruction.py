"""Milestone 2 metadata-only reconstruction and STARTTLS/STLS state tests."""

from __future__ import annotations

from backend.app.models.analysis import AnalysisResultResponse
from core.pcap.session_builder import build_analysis_result
from core.pcap.tshark_adapter import PacketMetadata


def packet(
    frame: int,
    source: str,
    source_port: int,
    destination: str,
    destination_port: int,
    payload: str | bytes = b"",
    *,
    protocol: str = "SMTP",
    tls: bool = False,
) -> PacketMetadata:
    return PacketMetadata(
        frame_number=frame,
        timestamp=float(frame),
        src_ip=source,
        src_port=source_port,
        dst_ip=destination,
        dst_port=destination_port,
        tcp_stream="0",
        protocol_labels=(protocol.casefold(),),
        tcp_payload=payload.encode() if isinstance(payload, str) else payload,
        tls_record=tls,
    )


def smtp(
    frame: int,
    direction: str,
    payload: str | bytes = b"",
    *,
    tls: bool = False,
) -> PacketMetadata:
    client = ("192.0.2.10", 51000)
    server = ("192.0.2.20", 25)
    source, destination = (client, server) if direction == "C" else (server, client)
    return packet(frame, *source, *destination, payload, tls=tls)


def imap(
    frame: int,
    direction: str,
    payload: str | bytes = b"",
    *,
    tls: bool = False,
) -> PacketMetadata:
    client = ("192.0.2.10", 51001)
    server = ("192.0.2.20", 143)
    source, destination = (client, server) if direction == "C" else (server, client)
    return packet(frame, *source, *destination, payload, protocol="IMAP", tls=tls)


def pop3(
    frame: int,
    direction: str,
    payload: str | bytes = b"",
    *,
    tls: bool = False,
) -> PacketMetadata:
    client = ("192.0.2.10", 51002)
    server = ("192.0.2.20", 110)
    source, destination = (client, server) if direction == "C" else (server, client)
    return packet(frame, *source, *destination, payload, protocol="POP3", tls=tls)


def security(packets: list[PacketMetadata]) -> dict:
    return build_analysis_result("mail.pcap", packets)["sessions"][0]["transport_security"]


def test_smtp_starttls_upgrade_and_evidence() -> None:
    packets = [
        smtp(1, "S", "220 mail.example ESMTP\r\n"),
        smtp(2, "C", "EHLO client.example\r\n"),
        smtp(3, "S", "250-mail.example\r\n250-STARTTLS\r\n250 SIZE 1000\r\n"),
        smtp(4, "C", "STARTTLS\r\n"),
        smtp(5, "S", "220 Ready to start TLS\r\n"),
        smtp(6, "C", b"\x16\x03\x03\x00\x04\x01\x00\x00\x00", tls=True),
    ]

    analysis = build_analysis_result("smtp.pcap", packets)
    AnalysisResultResponse.model_validate(analysis)
    session = analysis["sessions"][0]

    assert session["transport_security"] == {
        "mode": "STARTTLS",
        "upgrade_status": "UPGRADED",
        "advertised": True,
        "requested": True,
        "accepted": True,
        "tls_detected": True,
        "upgrade_command": "STARTTLS",
        "evidence": {
            "advertised_frame": 3,
            "request_frame": 4,
            "accept_frame": 5,
            "tls_start_frame": 6,
        },
    }
    assert [(event["kind"], event["name"]) for event in session["application_events"]] == [
        ("GREETING", "220"),
        ("COMMAND", "EHLO"),
        ("CAPABILITY", "STARTTLS"),
        ("COMMAND", "STARTTLS"),
        ("RESPONSE", "220"),
        ("TLS_START", "TLS"),
    ]


def test_smtp_advertised_but_not_requested() -> None:
    result = security([
        smtp(1, "C", "EHLO client\r\n"),
        smtp(2, "S", "250-STARTTLS\r\n250 SIZE 100\r\n"),
        smtp(3, "C", "QUIT\r\n"),
    ])
    assert result["upgrade_status"] == "ADVERTISED_NOT_REQUESTED"
    assert result["advertised"] is True
    assert result["requested"] is False


def test_smtp_requested_but_explicitly_rejected_is_failed() -> None:
    result = security([
        smtp(1, "C", "STARTTLS\r\n"),
        smtp(2, "S", "454 TLS temporarily unavailable\r\n"),
    ])
    assert result["upgrade_status"] == "FAILED"
    assert result["requested"] is True
    assert result["accepted"] is False


def test_smtp_missing_acceptance_is_incomplete_even_when_tls_is_seen() -> None:
    result = security([
        smtp(1, "C", "STARTTLS\r\n"),
        smtp(3, "C", b"\x16\x03\x03\x00\x04\x01\x00\x00\x00", tls=True),
    ])
    assert result["upgrade_status"] == "INCOMPLETE"
    assert result["tls_detected"] is True
    assert result["evidence"] == {"request_frame": 1, "tls_start_frame": 3}


def test_smtp_complete_capability_response_without_starttls_is_not_advertised() -> None:
    result = security([
        smtp(1, "C", "EHLO client\r\n"),
        smtp(2, "S", "250-mail.example\r\n250 SIZE 100\r\n"),
    ])
    assert result["mode"] == "PLAINTEXT"
    assert result["upgrade_status"] == "NOT_ADVERTISED"


def test_implicit_tls_ports_are_not_starttls_failures() -> None:
    cases = [
        ("SMTP", 465, 52000),
        ("IMAP", 993, 52001),
        ("POP3", 995, 52002),
    ]
    for protocol, server_port, client_port in cases:
        packets = [packet(
            1,
            "198.51.100.10",
            client_port,
            "198.51.100.20",
            server_port,
            b"\x16\x03\x03\x00\x04\x01\x00\x00\x00",
            protocol=protocol,
            tls=True,
        )]
        analysis = build_analysis_result("implicit.pcap", packets)
        AnalysisResultResponse.model_validate(analysis)
        result = analysis["sessions"][0]["transport_security"]
        assert result["mode"] == "IMPLICIT_TLS"
        assert result["upgrade_status"] == "NOT_APPLICABLE"
        assert result["tls_detected"] is True
        assert result["upgrade_command"] is None


def test_imap_starttls_upgrade_preserves_tag() -> None:
    packets = [
        imap(1, "S", "* OK IMAP ready\r\n"),
        imap(2, "C", "A001 CAPABILITY\r\n"),
        imap(3, "S", "* CAPABILITY IMAP4rev1 STARTTLS\r\nA001 OK done\r\n"),
        imap(4, "C", "A002 STARTTLS\r\n"),
        imap(5, "S", "A002 OK Begin TLS\r\n"),
        imap(6, "C", b"\x16\x03\x03\x00\x04\x01\x00\x00\x00", tls=True),
    ]
    session = build_analysis_result("imap.pcap", packets)["sessions"][0]
    assert session["transport_security"]["upgrade_status"] == "UPGRADED"
    assert session["transport_security"]["evidence"] == {
        "advertised_frame": 3,
        "request_frame": 4,
        "accept_frame": 5,
        "tls_start_frame": 6,
    }
    request = next(
        event
        for event in session["application_events"]
        if event["kind"] == "COMMAND" and event["name"] == "STARTTLS"
    )
    assert request["tag"] == "A002"


def test_pop3_stls_upgrade_maps_to_common_status_and_preserves_command() -> None:
    packets = [
        pop3(1, "S", "+OK POP3 ready\r\n"),
        pop3(2, "C", "CAPA\r\n"),
        pop3(3, "S", "+OK capabilities\r\nSTLS\r\nUIDL\r\n.\r\n"),
        pop3(4, "C", "STLS\r\n"),
        pop3(5, "S", "+OK Begin TLS\r\n"),
        pop3(6, "C", b"\x16\x03\x03\x00\x04\x01\x00\x00\x00", tls=True),
    ]
    result = security(packets)
    assert result["upgrade_status"] == "UPGRADED"
    assert result["upgrade_command"] == "STLS"
    assert result["evidence"] == {
        "advertised_frame": 3,
        "request_frame": 4,
        "accept_frame": 5,
        "tls_start_frame": 6,
    }


def test_packet_order_and_reverse_tcp_direction_do_not_break_reconstruction() -> None:
    packets = [
        smtp(6, "C", b"\x16\x03\x03\x00\x04\x01\x00\x00\x00", tls=True),
        smtp(3, "S", "250-START"),
        smtp(1, "S", "220 ready\r\n"),
        smtp(5, "S", "220 go\r\n"),
        smtp(2, "C", "EHLO client\r\n"),
        smtp(3, "S", "TLS\r\n250 OK\r\n"),
        smtp(4, "C", "STARTTLS\r\n"),
    ]
    session = build_analysis_result("ordered.pcap", packets)["sessions"][0]
    frames = [event["frame_number"] for event in session["application_events"]]
    assert frames == sorted(frames)
    assert session["transport_security"]["upgrade_status"] == "UPGRADED"
    assert session["client_ip"] == "192.0.2.10"
    assert session["server_ip"] == "192.0.2.20"


def test_plain_session_without_state_evidence_remains_valid_and_unknown() -> None:
    result = security([smtp(1, "S", "220 ready\r\n"), smtp(2, "C", "QUIT\r\n")])
    assert result["mode"] == "PLAINTEXT"
    assert result["upgrade_status"] == "UNKNOWN"
    assert result["tls_detected"] is False
