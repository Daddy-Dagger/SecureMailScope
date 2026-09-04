"""Milestone 3 tests for factual TLS handshake metadata extraction."""

from __future__ import annotations

from dataclasses import replace

from backend.app.models.analysis import AnalysisResultResponse
from core.pcap.session_builder import build_analysis_result
from core.pcap.tshark_adapter import PacketMetadata
from core.tls.handshake import extract_tls_handshake


def tls_packet(
    frame: int,
    direction: str,
    *,
    handshake_types: tuple[int, ...] = (),
    handshake_versions: tuple[int, ...] = (),
    supported_versions: tuple[int, ...] = (),
    cipher_suites: tuple[int, ...] = (),
    key_share_groups: tuple[int, ...] = (),
    supported_groups: tuple[int, ...] = (),
    alert_level: int | None = None,
    server_port: int = 465,
    payload: bytes = b"\x16\x03\x03\x00\x01\x00",
) -> PacketMetadata:
    client = ("192.0.2.10", 51000)
    server = ("192.0.2.20", server_port)
    source, destination = (client, server) if direction == "C" else (server, client)
    return PacketMetadata(
        frame_number=frame,
        timestamp=float(frame),
        src_ip=source[0],
        src_port=source[1],
        dst_ip=destination[0],
        dst_port=destination[1],
        tcp_stream="0",
        protocol_labels=("smtp", "tls"),
        tcp_payload=payload,
        tls_record=True,
        tls_record_content_types=(22,),
        tls_handshake_types=handshake_types,
        tls_handshake_versions=handshake_versions,
        tls_supported_versions=supported_versions,
        tls_cipher_suites=cipher_suites,
        tls_key_share_groups=key_share_groups,
        tls_supported_groups=supported_groups,
        tls_alert_level=alert_level,
    )


def extract(packets: list[PacketMetadata]) -> dict:
    return extract_tls_handshake(
        packets,
        client_ip="192.0.2.10",
        client_port=51000,
    )


def complete_packets(
    *,
    client_version: int,
    server_version: int,
    cipher: int,
    supported_versions: tuple[int, ...] = (),
    selected_version: tuple[int, ...] = (),
    client_group: tuple[int, ...] = (),
    server_group: tuple[int, ...] = (),
    server_port: int = 465,
) -> list[PacketMetadata]:
    return [
        tls_packet(
            1,
            "C",
            handshake_types=(1,),
            handshake_versions=(client_version,),
            supported_versions=supported_versions,
            cipher_suites=(cipher,),
            key_share_groups=client_group,
            supported_groups=client_group,
            server_port=server_port,
        ),
        tls_packet(
            2,
            "S",
            handshake_types=(2,),
            handshake_versions=(server_version,),
            supported_versions=selected_version,
            cipher_suites=(cipher,),
            key_share_groups=server_group,
            server_port=server_port,
        ),
        tls_packet(3, "S", handshake_types=(20,), server_port=server_port),
        tls_packet(4, "C", handshake_types=(20,), server_port=server_port),
    ]


def test_tls12_complete_handshake_metadata_and_ecdhe_cipher() -> None:
    result = extract(
        complete_packets(
            client_version=0x0303,
            server_version=0x0303,
            cipher=0xC02F,
            client_group=(0x0017,),
        )
    )

    assert result["handshake_status"] == "COMPLETE"
    assert result["version"] == "TLS 1.2"
    assert result["cipher_suite"] == {
        "id": "0xc02f",
        "name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    }
    assert result["key_exchange"] == {"method": "ECDHE", "group": None}
    assert result["evidence"]["handshake_complete_frame"] == 4


def test_tls13_uses_supported_version_instead_of_legacy_tls12_value() -> None:
    result = extract(
        complete_packets(
            client_version=0x0303,
            server_version=0x0303,
            cipher=0x1302,
            supported_versions=(0x0304, 0x0303),
            selected_version=(0x0304,),
            client_group=(0x001D,),
            server_group=(0x001D,),
        )
    )

    assert result["offered_versions"] == ["TLS 1.3", "TLS 1.2"]
    assert result["version"] == "TLS 1.3"
    assert result["cipher_suite"] == {
        "id": "0x1302",
        "name": "TLS_AES_256_GCM_SHA384",
    }
    assert result["key_exchange"] == {
        "method": "ECDHE",
        "group": {"id": "0x001d", "name": "x25519"},
    }


def test_unknown_cipher_preserves_numeric_id_without_a_name() -> None:
    packets = complete_packets(
        client_version=0x0303,
        server_version=0x0303,
        cipher=0xFEFE,
    )
    result = extract(packets)
    assert result["cipher_suite"] == {"id": "0xfefe", "name": None}
    assert result["key_exchange"]["method"] == "UNKNOWN"


def test_rsa_key_exchange_is_derived_only_from_selected_legacy_suite() -> None:
    result = extract(
        complete_packets(
            client_version=0x0303,
            server_version=0x0303,
            cipher=0x009C,
        )
    )
    assert result["key_exchange"] == {"method": "RSA", "group": None}


def test_missing_server_hello_is_incomplete() -> None:
    result = extract([
        tls_packet(
            1,
            "C",
            handshake_types=(1,),
            handshake_versions=(0x0303,),
            supported_versions=(0x0304, 0x0303),
        )
    ])
    assert result["handshake_status"] == "INCOMPLETE"
    assert result["evidence"] == {"client_hello_frame": 1}
    assert result["version"] is None


def test_server_hello_without_finished_messages_is_incomplete() -> None:
    packets = complete_packets(
        client_version=0x0303,
        server_version=0x0303,
        cipher=0xC02F,
    )[:2]
    assert extract(packets)["handshake_status"] == "INCOMPLETE"


def test_no_tls_is_not_applicable() -> None:
    plain = PacketMetadata(
        frame_number=1,
        timestamp=1.0,
        src_ip="192.0.2.10",
        src_port=51000,
        dst_ip="192.0.2.20",
        dst_port=25,
        tcp_stream="0",
        protocol_labels=("smtp",),
    )
    result = extract([plain])
    assert result["detected"] is False
    assert result["handshake_status"] == "NOT_APPLICABLE"
    assert result["key_exchange"] is None


def test_tls_record_without_handshake_metadata_is_detected() -> None:
    result = extract([tls_packet(1, "C")])
    assert result["detected"] is True
    assert result["handshake_status"] == "DETECTED"
    assert result["version"] is None
    assert result["key_exchange"] == {"method": "UNKNOWN", "group": None}


def test_malformed_or_unrecognized_handshake_metadata_is_unknown() -> None:
    result = extract([
        tls_packet(
            1,
            "C",
            handshake_types=(255,),
            handshake_versions=(0xFFFF,),
        )
    ])
    assert result["handshake_status"] == "UNKNOWN"
    assert result["version"] is None


def test_fatal_alert_marks_incomplete_handshake_failed() -> None:
    packets = [
        tls_packet(1, "C", handshake_types=(1,), handshake_versions=(0x0303,)),
        tls_packet(2, "S", alert_level=2),
    ]
    result = extract(packets)
    assert result["handshake_status"] == "FAILED"
    assert result["evidence"]["alert_frame"] == 2


def test_implicit_tls_session_exposes_handshake_metadata() -> None:
    analysis = build_analysis_result(
        "implicit.pcap",
        complete_packets(
            client_version=0x0303,
            server_version=0x0303,
            cipher=0xC02F,
        ),
    )
    AnalysisResultResponse.model_validate(analysis)
    session = analysis["sessions"][0]
    assert session["transport_security"]["mode"] == "IMPLICIT_TLS"
    assert session["tls"]["handshake_status"] == "COMPLETE"


def test_starttls_upgraded_session_exposes_handshake_metadata() -> None:
    plaintext = [
        PacketMetadata(
            frame_number=1,
            timestamp=1.0,
            src_ip="192.0.2.10",
            src_port=51000,
            dst_ip="192.0.2.20",
            dst_port=25,
            tcp_stream="0",
            protocol_labels=("smtp",),
            tcp_payload=b"STARTTLS\r\n",
        ),
        PacketMetadata(
            frame_number=2,
            timestamp=2.0,
            src_ip="192.0.2.20",
            src_port=25,
            dst_ip="192.0.2.10",
            dst_port=51000,
            tcp_stream="0",
            protocol_labels=("smtp",),
            tcp_payload=b"220 Ready\r\n",
        ),
    ]
    handshake = complete_packets(
        client_version=0x0303,
        server_version=0x0303,
        cipher=0xC02F,
        server_port=25,
    )
    handshake = [
        replace(
            packet,
            frame_number=packet.frame_number + 2,
            timestamp=packet.timestamp + 2,
        )
        for packet in handshake
    ]

    analysis = build_analysis_result("starttls.pcap", [*plaintext, *handshake])
    AnalysisResultResponse.model_validate(analysis)
    session = analysis["sessions"][0]
    assert session["transport_security"]["upgrade_status"] == "UPGRADED"
    assert session["tls"]["handshake_status"] == "COMPLETE"
    assert session["tls"]["evidence"]["client_hello_frame"] == 3
