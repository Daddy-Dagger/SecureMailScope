"""Build contract-compatible email sessions from packet metadata."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Hashable

from core.pcap.loader import read_pcap_bytes, read_pcap_file
from core.pcap.tshark_adapter import PacketMetadata, tshark_path
from core.protocols import (
    EmailProtocol,
    IMAP,
    POP3,
    SERVER_PORTS,
    SMTP,
    protocols_from_labels,
    protocols_from_ports,
)
from core.protocols.session_reconstruction import reconstruct_security_state
from core.tls import extract_tls_handshake

AnalysisResult = dict[str, Any]


def analyze_pcap(filename: str, content: bytes) -> AnalysisResult:
    """Analyze uploaded PCAP bytes and return the shared analysis-result shape."""
    packets = read_pcap_bytes(filename, content)
    return build_analysis_result(Path(filename).name, packets)


def analyze_pcap_file(capture_path: str | Path) -> AnalysisResult:
    """Read a PCAP/PCAPNG file and return the shared analysis-result shape."""
    path = Path(capture_path)
    packets = read_pcap_file(path)
    return build_analysis_result(path.name, packets)


def build_analysis_result(
    filename: str,
    packets: Iterable[PacketMetadata],
) -> AnalysisResult:
    """Group packet metadata into deterministic SMTP/IMAP/POP3 sessions."""
    packet_list = list(packets)
    flows = _group_tcp_flows(packet_list)
    candidates: list[tuple[float, str, EmailProtocol, list[PacketMetadata]]] = []

    for flow_key, flow_packets in flows.items():
        protocol = _identify_protocol(flow_packets)
        if protocol is None:
            continue
        start = min(packet.timestamp for packet in flow_packets)
        candidates.append((start, repr(flow_key), protocol, flow_packets))

    candidates.sort(key=lambda candidate: (candidate[0], candidate[1]))
    counters: dict[EmailProtocol, int] = defaultdict(int)
    sessions: list[dict[str, Any]] = []

    for _, _, protocol, flow_packets in candidates:
        endpoints = _identify_client_server(flow_packets, protocol)
        if endpoints is None:
            continue
        client_ip, client_port, server_ip, server_port = endpoints
        counters[protocol] += 1
        start_time = min(packet.timestamp for packet in flow_packets)
        end_time = max(packet.timestamp for packet in flow_packets)
        application_events, transport_security = reconstruct_security_state(
            protocol,
            flow_packets,
            client_ip=client_ip,
            client_port=client_port,
            server_port=server_port,
        )
        tls = extract_tls_handshake(
            flow_packets,
            client_ip=client_ip,
            client_port=client_port,
        )
        sessions.append(
            {
                "session_id": f"{protocol.casefold()}-{counters[protocol]:03d}",
                "protocol": protocol,
                "client_ip": client_ip,
                "client_port": client_port,
                "server_ip": server_ip,
                "server_port": server_port,
                "packet_count": len(flow_packets),
                "start_time": _iso_utc(start_time),
                "end_time": _iso_utc(end_time),
                "application_events": [
                    {**event, "timestamp": _iso_utc(event["timestamp"])}
                    for event in application_events
                ],
                "transport_security": transport_security,
                "tls": tls,
            }
        )

    return {
        "file": filename,
        "packet_count": len(packet_list),
        "summary": {
            "smtp_sessions": counters[SMTP],
            "imap_sessions": counters[IMAP],
            "pop3_sessions": counters[POP3],
        },
        "sessions": sessions,
        "findings": [],
        "overall_score": None,
        "risk_level": None,
    }


class PcapAnalysisEngine:
    """Core engine implementation compatible with Member 4's adapter protocol."""

    @property
    def is_available(self) -> bool:
        return tshark_path() is not None

    def analyze(self, filename: str, content: bytes) -> AnalysisResult:
        return analyze_pcap(filename, content)


def _group_tcp_flows(
    packets: Iterable[PacketMetadata],
) -> dict[Hashable, list[PacketMetadata]]:
    flows: dict[Hashable, list[PacketMetadata]] = defaultdict(list)
    for packet in packets:
        if not packet.is_tcp:
            continue
        if packet.tcp_stream is not None:
            key: Hashable = ("tcp.stream", packet.tcp_stream)
        else:
            source = (packet.src_ip, packet.src_port)
            destination = (packet.dst_ip, packet.dst_port)
            key = ("endpoints", *sorted((source, destination)))
        flows[key].append(packet)
    return flows


def _identify_protocol(flow_packets: list[PacketMetadata]) -> EmailProtocol | None:
    label_matches: set[EmailProtocol] = set()
    for packet in flow_packets:
        label_matches.update(protocols_from_labels(packet.protocol_labels))
    if len(label_matches) == 1:
        return next(iter(label_matches))
    if len(label_matches) > 1:
        return None

    initial_syn = next(
        (packet for packet in flow_packets if packet.tcp_syn and not packet.tcp_ack),
        None,
    )
    if initial_syn is not None:
        syn_matches = protocols_from_ports((initial_syn.dst_port,))
        if len(syn_matches) == 1:
            return next(iter(syn_matches))

    port_matches = protocols_from_ports(
        port
        for packet in flow_packets
        for port in (packet.src_port, packet.dst_port)
    )
    if len(port_matches) == 1:
        return next(iter(port_matches))
    return None


def _identify_client_server(
    flow_packets: list[PacketMetadata],
    protocol: EmailProtocol,
) -> tuple[str, int, str, int] | None:
    first = min(flow_packets, key=lambda packet: (packet.timestamp, packet.frame_number))
    assert first.src_ip is not None and first.dst_ip is not None
    assert first.src_port is not None and first.dst_port is not None

    endpoints = {
        (packet.src_ip, packet.src_port)
        for packet in flow_packets
        if packet.src_ip is not None and packet.src_port is not None
    }
    endpoints.update(
        (packet.dst_ip, packet.dst_port)
        for packet in flow_packets
        if packet.dst_ip is not None and packet.dst_port is not None
    )
    if len(endpoints) != 2:
        return None

    server_candidates = {
        endpoint for endpoint in endpoints if endpoint[1] in SERVER_PORTS[protocol]
    }
    if len(server_candidates) == 1:
        server_ip, server_port = next(iter(server_candidates))
        client_ip, client_port = next(
            endpoint for endpoint in endpoints if endpoint not in server_candidates
        )
        return client_ip, client_port, server_ip, server_port

    initial_syn = next(
        (packet for packet in flow_packets if packet.tcp_syn and not packet.tcp_ack),
        None,
    )
    if initial_syn is not None:
        assert initial_syn.src_ip is not None and initial_syn.dst_ip is not None
        assert initial_syn.src_port is not None and initial_syn.dst_port is not None
        return (
            initial_syn.src_ip,
            initial_syn.src_port,
            initial_syn.dst_ip,
            initial_syn.dst_port,
        )

    return first.src_ip, first.src_port, first.dst_ip, first.dst_port


def _iso_utc(timestamp: float) -> str:
    value = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    return value.replace("+00:00", "Z")
