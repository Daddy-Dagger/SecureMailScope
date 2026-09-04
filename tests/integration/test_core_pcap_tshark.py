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
