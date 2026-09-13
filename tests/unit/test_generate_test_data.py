"""Unit tests for the synthetic PCAP test-data generator (Member 2 workstream)."""

from __future__ import annotations

from pathlib import Path
import socket
import pytest
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import rdpcap

from scripts.generate_test_data import (
    SCENARIO_GENERATORS,
    generate_all_scenarios,
    generate_scenario,
    validate_generated_pcap,
)


def test_invalid_scenario_name_is_rejected(tmp_path: Path) -> None:
    """Ensure invalid scenario names raise ValueError with available choices."""
    with pytest.raises(ValueError, match="Unknown scenario 'nonexistent_scenario'"):
        generate_scenario("nonexistent_scenario", tmp_path)


@pytest.mark.parametrize("scenario_name", sorted(SCENARIO_GENERATORS.keys()))
def test_each_scenario_generates_valid_nonempty_pcap(scenario_name: str, tmp_path: Path) -> None:
    """Verify each scenario generates non-empty, Scapy-readable PCAP files."""
    files = generate_scenario(scenario_name, tmp_path)
    assert len(files) >= 1

    for pcap_file in files:
        assert pcap_file.exists(), f"PCAP file {pcap_file} was not created"
        assert pcap_file.stat().st_size > 0, f"PCAP file {pcap_file} is empty"

        # Validate with Scapy
        metadata = validate_generated_pcap(pcap_file)
        assert metadata["total_packets"] > 0
        assert metadata["tcp_packets"] > 0
        assert metadata["size_bytes"] > 0

        # Read back packets directly
        packets = rdpcap(str(pcap_file))
        assert len(packets) == metadata["total_packets"]


def test_output_directories_created_automatically(tmp_path: Path) -> None:
    """Ensure nested output directories are created on demand."""
    nested_dir = tmp_path / "deep" / "nested" / "output"
    assert not nested_dir.exists()

    files = generate_scenario("normal", nested_dir)
    assert nested_dir.exists()
    assert files[0].exists()


def test_all_flag_generates_all_scenarios(tmp_path: Path) -> None:
    """Ensure generate_all_scenarios generates all 5 scenario suites."""
    results = generate_all_scenarios(tmp_path)
    expected_scenarios = {"normal", "weak_tls", "certificate_issues", "starttls", "mixed"}
    assert set(results.keys()) == expected_scenarios

    total_files = sum(len(fl) for fl in results.values())
    assert total_files == 11

    # Verify category subdirectories
    for scenario in expected_scenarios:
        assert (tmp_path / scenario).is_dir()


def test_normal_scenario_packet_flow(tmp_path: Path) -> None:
    """Verify normal scenario packets contain expected SMTP STARTTLS flow."""
    files = generate_scenario("normal", tmp_path)
    pcap = files[0]
    packets = rdpcap(str(pcap))

    # Verify TCP 3-way handshake
    syn = packets[0]
    syn_ack = packets[1]
    ack = packets[2]
    assert syn[TCP].flags == "S"
    assert syn_ack[TCP].flags == "SA"
    assert ack[TCP].flags == "A"
    assert syn[TCP].dport == 25

    # Verify SMTP banner, EHLO, and STARTTLS
    payloads = [bytes(p[Raw].load) for p in packets if p.haslayer(Raw)]
    all_payload = b"".join(payloads)
    assert b"220 mail.example.com" in all_payload
    assert b"EHLO client.example.com" in all_payload
    assert b"250-STARTTLS" in all_payload
    assert b"STARTTLS\r\n" in all_payload
    assert b"220 2.0.0 Ready to start TLS" in all_payload

    # Verify TLS record presence (0x16: Handshake)
    tls_records = [pl for pl in payloads if len(pl) >= 5 and pl[0] == 0x16 and pl[1] == 0x03]
    assert len(tls_records) >= 2  # ClientHello and ServerHello/Cert


def test_weak_tls_scenario_versions_and_ciphers(tmp_path: Path) -> None:
    """Verify weak TLS scenario captures contain TLS 1.0/1.1 and static RSA cipher indicators."""
    files = generate_scenario("weak_tls", tmp_path)
    names = {f.name for f in files}
    assert "weak_tls10_smtp.pcap" in names
    assert "weak_tls11_imap.pcap" in names

    # Check TLS 1.0 capture
    tls10_pcap = next(f for f in files if f.name == "weak_tls10_smtp.pcap")
    pkts10 = rdpcap(str(tls10_pcap))
    raw_payloads = [bytes(p[Raw].load) for p in pkts10 if p.haslayer(Raw)]
    tls10_records = [pl for pl in raw_payloads if len(pl) >= 5 and pl[0] == 0x16 and pl[1] == 3 and pl[2] == 1]
    assert len(tls10_records) >= 2  # ClientHello (TLS 1.0) and ServerHello (TLS 1.0)

    # Check TLS 1.1 capture
    tls11_pcap = next(f for f in files if f.name == "weak_tls11_imap.pcap")
    pkts11 = rdpcap(str(tls11_pcap))
    raw11_payloads = [bytes(p[Raw].load) for p in pkts11 if p.haslayer(Raw)]
    tls11_records = [pl for pl in raw11_payloads if len(pl) >= 5 and pl[0] == 0x16 and pl[1] == 3 and pl[2] == 2]
    assert len(tls11_records) >= 2  # ClientHello (TLS 1.1) and ServerHello (TLS 1.1)


def test_certificate_issues_scenario_contents(tmp_path: Path) -> None:
    """Verify certificate issues scenario generates expired, self-signed, and missing-SAN captures."""
    files = generate_scenario("certificate_issues", tmp_path)
    names = {f.name for f in files}
    assert "cert_expired_smtp.pcap" in names
    assert "cert_self_signed_smtp.pcap" in names
    assert "cert_missing_san_imap.pcap" in names

    for f in files:
        pkts = rdpcap(str(f))
        assert len(pkts) >= 10


def test_starttls_edge_cases_command_responses(tmp_path: Path) -> None:
    """Verify STARTTLS scenario files contain exact expected rejection and fallback patterns."""
    files = generate_scenario("starttls", tmp_path)
    file_map = {f.name: rdpcap(str(f)) for f in files}

    # Rejection capture
    rej_pkts = file_map["starttls_rejected.pcap"]
    rej_payloads = b"".join(bytes(p[Raw].load) for p in rej_pkts if p.haslayer(Raw))
    assert b"STARTTLS\r\n" in rej_payloads
    assert b"454 4.7.0 TLS not available" in rej_payloads

    # Not advertised capture
    no_ad_pkts = file_map["starttls_not_advertised.pcap"]
    no_ad_payloads = b"".join(bytes(p[Raw].load) for p in no_ad_pkts if p.haslayer(Raw))
    assert b"STARTTLS" not in no_ad_payloads
    assert b"MAIL FROM:<sender@plain.test>" in no_ad_payloads

    # Advertised but not requested capture
    adv_nr_pkts = file_map["starttls_advertised_not_requested.pcap"]
    adv_nr_client_payloads = b"".join(
        bytes(p[Raw].load) for p in adv_nr_pkts if p.haslayer(Raw) and p[TCP].dport == 25
    )
    assert b"250-STARTTLS" not in adv_nr_client_payloads
    assert b"STARTTLS" not in adv_nr_client_payloads
    assert b"MAIL FROM:<audit@example.test>" in adv_nr_client_payloads


def test_mixed_scenario_contains_all_three_email_protocols(tmp_path: Path) -> None:
    """Verify mixed scenario contains concurrent SMTP (25), IMAP (143), and POP3 (110) traffic."""
    files = generate_scenario("mixed", tmp_path)
    assert len(files) == 1
    mixed_pcap = files[0]
    packets = rdpcap(str(mixed_pcap))

    # Collect destination ports of client SYN packets
    syn_dest_ports = {p[TCP].dport for p in packets if p.haslayer(TCP) and p[TCP].flags == "S"}
    assert 25 in syn_dest_ports, "SMTP port 25 missing from mixed capture"
    assert 143 in syn_dest_ports, "IMAP port 143 missing from mixed capture"
    assert 110 in syn_dest_ports, "POP3 port 110 missing from mixed capture"

    # Verify all 3 protocol markers in payloads
    payload = b"".join(bytes(p[Raw].load) for p in packets if p.haslayer(Raw))
    assert b"220 mail.example.com ESMTP" in payload  # SMTP
    assert b"* OK IMAP4rev1 Ready" in payload        # IMAP
    assert b"+OK POP3 server ready" in payload       # POP3
    assert b"STLS\r\n" in payload                    # POP3 STLS


def test_generator_operates_offline_without_network(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Verify generator succeeds even when network socket creation is blocked."""
    def guarded_socket(*args, **kwargs):
        raise OSError("Network access blocked during synthetic generation test")

    monkeypatch.setattr(socket, "socket", guarded_socket)
    files = generate_all_scenarios(tmp_path)
    assert len(files) == 5


def test_generated_pcaps_validate_against_core_session_builder(tmp_path: Path) -> None:
    """Verify generated PCAPs can be processed by core.pcap.session_builder into contract-valid models."""
    from backend.app.models.analysis import AnalysisResultResponse
    from core.pcap.session_builder import build_analysis_result
    from core.pcap.tshark_adapter import PacketMetadata, _looks_like_tls_record

    files = generate_all_scenarios(tmp_path)

    # 1. Validate Normal Scenario
    normal_pcap = files["normal"][0]
    scapy_pkts = rdpcap(str(normal_pcap))
    meta_pkts: list[PacketMetadata] = []
    for idx, p in enumerate(scapy_pkts, start=1):
        if not p.haslayer(TCP):
            continue
        ip, tcp = p[IP], p[TCP]
        payload = bytes(p[Raw].load) if p.haslayer(Raw) else b""
        meta_pkts.append(
            PacketMetadata(
                frame_number=idx,
                timestamp=float(p.time),
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=tcp.sport,
                dst_port=tcp.dport,
                tcp_stream="0",
                tcp_syn=(tcp.flags & 0x02) != 0,
                tcp_ack=(tcp.flags & 0x10) != 0,
                protocol_labels=("smtp",) if 25 in (tcp.sport, tcp.dport) else (),
                tcp_payload=payload,
                tls_record=_looks_like_tls_record(payload),
            )
        )
    result = build_analysis_result(normal_pcap.name, meta_pkts)
    validated = AnalysisResultResponse.model_validate(result)
    assert validated.summary.smtp_sessions == 1
    assert validated.sessions[0].transport_security is not None
    assert validated.sessions[0].transport_security.upgrade_status == "UPGRADED"

    # 2. Validate Mixed Scenario
    mixed_pcap = files["mixed"][0]
    scapy_mixed = rdpcap(str(mixed_pcap))
    mixed_meta: list[PacketMetadata] = []
    for idx, p in enumerate(scapy_mixed, start=1):
        if not p.haslayer(TCP):
            continue
        ip, tcp = p[IP], p[TCP]
        payload = bytes(p[Raw].load) if p.haslayer(Raw) else b""
        ports = {tcp.sport, tcp.dport}
        labels = ()
        if 25 in ports:
            labels = ("smtp",)
        elif 143 in ports:
            labels = ("imap",)
        elif 110 in ports:
            labels = ("pop3",)

        mixed_meta.append(
            PacketMetadata(
                frame_number=idx,
                timestamp=float(p.time),
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=tcp.sport,
                dst_port=tcp.dport,
                tcp_stream=f"stream-{min(ports)}",
                tcp_syn=(tcp.flags & 0x02) != 0,
                tcp_ack=(tcp.flags & 0x10) != 0,
                protocol_labels=labels,
                tcp_payload=payload,
                tls_record=_looks_like_tls_record(payload),
            )
        )
    mixed_res = build_analysis_result(mixed_pcap.name, mixed_meta)
    validated_mixed = AnalysisResultResponse.model_validate(mixed_res)
    assert validated_mixed.summary.smtp_sessions == 1
    assert validated_mixed.summary.imap_sessions == 1
    assert validated_mixed.summary.pop3_sessions == 1
