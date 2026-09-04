"""Real-PCAP integration tests for the TShark Milestone 1 path."""

from __future__ import annotations

from pathlib import Path
import shutil

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from core.pcap.session_builder import analyze_pcap_file
from core.pcap.tshark_adapter import InvalidCaptureError, extract_packet_metadata

pytestmark = pytest.mark.skipif(shutil.which("tshark") is None, reason="TShark is not installed")


def _write_packets(path: Path, packets: list) -> None:
    for index, packet in enumerate(packets):
        packet.time = 1_788_493_810.0 + index
    wrpcap(str(path), packets)


def _tls_handshake_record(message_type: int, body: bytes) -> bytes:
    message = bytes((message_type,)) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(message).to_bytes(2, "big") + message


def _tls_extension(extension_type: int, data: bytes) -> bytes:
    return extension_type.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data


def _tls13_client_hello() -> bytes:
    supported_versions = _tls_extension(0x002B, b"\x02\x03\x04")
    key_share_entry = b"\x00\x1d\x00\x20" + (b"\x11" * 32)
    key_share = _tls_extension(
        0x0033,
        len(key_share_entry).to_bytes(2, "big") + key_share_entry,
    )
    supported_groups = _tls_extension(0x000A, b"\x00\x02\x00\x1d")
    extensions = supported_versions + key_share + supported_groups
    body = (
        b"\x03\x03"
        + (b"\x01" * 32)
        + b"\x00"
        + b"\x00\x04\x13\x02\xc0\x2f"
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    return _tls_handshake_record(1, body)


def _tls13_server_hello() -> bytes:
    supported_version = _tls_extension(0x002B, b"\x03\x04")
    key_share = _tls_extension(0x0033, b"\x00\x1d\x00\x20" + (b"\x22" * 32))
    extensions = supported_version + key_share
    body = (
        b"\x03\x03"
        + (b"\x02" * 32)
        + b"\x00"
        + b"\x13\x02"
        + b"\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    return _tls_handshake_record(2, body)


def test_real_pcap_groups_bidirectional_smtp_session(tmp_path: Path) -> None:
    capture = tmp_path / "smtp.pcap"
    _write_packets(
        capture,
        [
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.168.1.10", dst="192.168.1.20")
            / TCP(sport=51544, dport=25, flags="S", seq=1),
            Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
            / IP(src="192.168.1.20", dst="192.168.1.10")
            / TCP(sport=25, dport=51544, flags="SA", seq=2, ack=2),
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.168.1.10", dst="192.168.1.20")
            / TCP(sport=51544, dport=25, flags="PA", seq=2, ack=3)
            / Raw(b"EHLO example.test\r\n"),
        ],
    )

    result = analyze_pcap_file(capture)
    metadata = extract_packet_metadata(capture)

    assert result["file"] == "smtp.pcap"
    assert result["packet_count"] == 3
    assert result["summary"]["smtp_sessions"] == 1
    assert len(result["sessions"]) == 1
    session = result["sessions"][0]
    assert session["protocol"] == "SMTP"
    assert session["client_ip"] == "192.168.1.10"
    assert session["client_port"] == 51544
    assert session["server_ip"] == "192.168.1.20"
    assert session["server_port"] == 25
    assert session["packet_count"] == 3
    assert metadata[0].tcp_syn is True
    assert metadata[0].tcp_ack is False
    assert metadata[1].tcp_syn is True
    assert metadata[1].tcp_ack is True


def test_real_pcap_reconstructs_smtp_starttls_upgrade(tmp_path: Path) -> None:
    capture = tmp_path / "smtp-starttls.pcap"
    client = {"src": "192.168.1.10", "dst": "192.168.1.20"}
    server = {"src": "192.168.1.20", "dst": "192.168.1.10"}
    tls_record = b"\x16\x03\x03\x00\x04\x01\x00\x00\x00"
    _write_packets(
        capture,
        [
            Ether() / IP(**server) / TCP(sport=25, dport=51544, flags="PA", seq=1)
            / Raw(b"220 mail.example ESMTP\r\n"),
            Ether() / IP(**client) / TCP(sport=51544, dport=25, flags="PA", seq=1)
            / Raw(b"EHLO client.example\r\n"),
            Ether() / IP(**server) / TCP(sport=25, dport=51544, flags="PA", seq=25)
            / Raw(b"250-mail.example\r\n250-STARTTLS\r\n250 SIZE 1000\r\n"),
            Ether() / IP(**client) / TCP(sport=51544, dport=25, flags="PA", seq=22)
            / Raw(b"STARTTLS\r\n"),
            Ether() / IP(**server) / TCP(sport=25, dport=51544, flags="PA", seq=76)
            / Raw(b"220 Ready to start TLS\r\n"),
            Ether() / IP(**client) / TCP(sport=51544, dport=25, flags="PA", seq=32)
            / Raw(tls_record),
        ],
    )

    session = analyze_pcap_file(capture)["sessions"][0]

    assert session["transport_security"]["upgrade_status"] == "UPGRADED"
    assert session["transport_security"]["evidence"] == {
        "advertised_frame": 3,
        "request_frame": 4,
        "accept_frame": 5,
        "tls_start_frame": 6,
    }
    assert session["application_events"][-1]["kind"] == "TLS_START"


def test_generated_real_pcap_extracts_tls13_server_selection(tmp_path: Path) -> None:
    capture = tmp_path / "implicit-tls13.pcap"
    client_hello = _tls13_client_hello()
    server_hello = _tls13_server_hello()
    _write_packets(
        capture,
        [
            Ether()
            / IP(src="192.0.2.10", dst="192.0.2.20")
            / TCP(sport=51544, dport=465, flags="PA", seq=1)
            / Raw(client_hello),
            Ether()
            / IP(src="192.0.2.20", dst="192.0.2.10")
            / TCP(sport=465, dport=51544, flags="PA", seq=1)
            / Raw(server_hello),
        ],
    )

    session = analyze_pcap_file(capture)["sessions"][0]

    assert session["transport_security"]["mode"] == "IMPLICIT_TLS"
    assert session["tls"]["handshake_status"] == "INCOMPLETE"
    assert session["tls"]["offered_versions"] == ["TLS 1.3"]
    assert session["tls"]["version"] == "TLS 1.3"
    assert session["tls"]["cipher_suite"] == {
        "id": "0x1302",
        "name": "TLS_AES_256_GCM_SHA384",
    }
    assert session["tls"]["key_exchange"] == {
        "method": "ECDHE",
        "group": {"id": "0x001d", "name": "x25519"},
    }
    assert session["tls"]["evidence"]["client_hello_frame"] == 1
    assert session["tls"]["evidence"]["server_hello_frame"] == 2


def test_real_no_email_pcap_returns_no_sessions(tmp_path: Path) -> None:
    capture = tmp_path / "dns.pcap"
    _write_packets(
        capture,
        [
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.0.2.10", dst="192.0.2.53")
            / UDP(sport=53000, dport=53)
            / Raw(b"not-dns"),
        ],
    )

    result = analyze_pcap_file(capture)

    assert result["packet_count"] == 1
    assert result["sessions"] == []


def test_nonempty_invalid_capture_is_rejected_by_tshark(tmp_path: Path) -> None:
    capture = tmp_path / "invalid.pcap"
    capture.write_bytes(b"this is not a packet capture")

    with pytest.raises(InvalidCaptureError):
        analyze_pcap_file(capture)
