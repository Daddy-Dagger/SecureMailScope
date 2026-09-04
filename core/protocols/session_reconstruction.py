"""Metadata-only plaintext reconstruction and STARTTLS/STLS state detection.

Only protocol lines needed to understand the encryption transition are retained.
Arbitrary commands, authentication values, and email message bodies are excluded.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import re
from typing import Any

from core.pcap.tshark_adapter import PacketMetadata
from core.protocols import EmailProtocol, IMAP, POP3, SMTP

IMPLICIT_TLS_PORTS: dict[EmailProtocol, int] = {SMTP: 465, IMAP: 993, POP3: 995}


@dataclass(frozen=True, slots=True)
class _Line:
    text: str
    direction: str
    frame_number: int
    timestamp: float
    order: int


def reconstruct_security_state(
    protocol: EmailProtocol,
    packets: Iterable[PacketMetadata],
    *,
    client_ip: str,
    client_port: int,
    server_port: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return ordered safe events and the common transport-security result."""
    ordered_packets = sorted(packets, key=lambda packet: packet.frame_number)
    tls_packet = next((packet for packet in ordered_packets if packet.tls_record), None)

    if server_port == IMPLICIT_TLS_PORTS[protocol]:
        events: list[dict[str, Any]] = []
        if tls_packet is not None:
            event = _event(
                tls_packet,
                "CLIENT_TO_SERVER"
                if _from_client(tls_packet, client_ip, client_port)
                else "SERVER_TO_CLIENT",
                "TLS_START",
                "TLS",
            )
            event.pop("_order")
            events.append(event)
        evidence = {}
        if tls_packet is not None:
            evidence["tls_start_frame"] = tls_packet.frame_number
        return events, {
            "mode": "IMPLICIT_TLS",
            "upgrade_status": "NOT_APPLICABLE",
            "advertised": False,
            "requested": False,
            "accepted": False,
            "tls_detected": tls_packet is not None,
            "upgrade_command": None,
            "evidence": evidence,
        }

    lines = _reconstruct_lines(
        ordered_packets,
        client_ip=client_ip,
        client_port=client_port,
        tls_start_frame=tls_packet.frame_number if tls_packet else None,
    )
    if protocol == SMTP:
        events, state = _smtp_state(lines)
    elif protocol == IMAP:
        events, state = _imap_state(lines)
    else:
        events, state = _pop3_state(lines)

    if tls_packet is not None:
        events.append(
            _event(
                tls_packet,
                "CLIENT_TO_SERVER"
                if _from_client(tls_packet, client_ip, client_port)
                else "SERVER_TO_CLIENT",
                "TLS_START",
                "TLS",
            )
        )
    events.sort(key=lambda event: (event["frame_number"], event["_order"]))
    for event in events:
        event.pop("_order")

    request_frame = state["evidence"].get("request_frame")
    accepted_frame = state["evidence"].get("accept_frame")
    tls_after_request = (
        tls_packet is not None
        and request_frame is not None
        and tls_packet.frame_number > request_frame
    )
    upgraded = (
        tls_after_request
        and state["accepted"]
        and accepted_frame is not None
        and tls_packet is not None
        and tls_packet.frame_number > accepted_frame
    )
    if tls_after_request and tls_packet is not None:
        state["tls_detected"] = True
        state["evidence"]["tls_start_frame"] = tls_packet.frame_number
    rejected = state.pop("rejected")
    capabilities_complete = state.pop("capabilities_complete")
    if upgraded:
        state["upgrade_status"] = "UPGRADED"
    else:
        if rejected:
            state["upgrade_status"] = "FAILED"
        elif state["requested"] or state["accepted"]:
            state["upgrade_status"] = "INCOMPLETE"
        elif state["advertised"]:
            state["upgrade_status"] = "ADVERTISED_NOT_REQUESTED"
        elif capabilities_complete:
            state["upgrade_status"] = "NOT_ADVERTISED"
            state["mode"] = "PLAINTEXT"
        else:
            state["upgrade_status"] = "UNKNOWN"
            state["mode"] = "PLAINTEXT" if lines else "UNKNOWN"

    return events, state


def _reconstruct_lines(
    packets: list[PacketMetadata],
    *,
    client_ip: str,
    client_port: int,
    tls_start_frame: int | None,
) -> list[_Line]:
    buffers: dict[str, bytearray] = {
        "CLIENT_TO_SERVER": bytearray(),
        "SERVER_TO_CLIENT": bytearray(),
    }
    starts: dict[str, tuple[int, float] | None] = {
        "CLIENT_TO_SERVER": None,
        "SERVER_TO_CLIENT": None,
    }
    lines: list[_Line] = []
    order = 0

    for packet in packets:
        if tls_start_frame is not None and packet.frame_number >= tls_start_frame:
            continue
        if not packet.tcp_payload:
            continue
        direction = (
            "CLIENT_TO_SERVER" if _from_client(packet, client_ip, client_port)
            else "SERVER_TO_CLIENT"
        )
        if not buffers[direction]:
            starts[direction] = (packet.frame_number, packet.timestamp)
        buffers[direction].extend(packet.tcp_payload)
        while b"\n" in buffers[direction]:
            raw, _, remainder = buffers[direction].partition(b"\n")
            buffers[direction] = bytearray(remainder)
            start_frame, start_time = starts[direction] or (packet.frame_number, packet.timestamp)
            text = raw.rstrip(b"\r").decode("utf-8", errors="replace").strip()
            if text:
                lines.append(_Line(text, direction, start_frame, start_time, order))
                order += 1
            starts[direction] = (
                (packet.frame_number, packet.timestamp) if buffers[direction] else None
            )

    # A capture may end before CRLF. Retain only a recognizable protocol-state line.
    for direction, buffer in buffers.items():
        if not buffer:
            continue
        text = bytes(buffer).rstrip(b"\r").decode("utf-8", errors="replace").strip()
        if _is_relevant_fragment(text):
            frame, timestamp = starts[direction] or (0, 0.0)
            lines.append(_Line(text, direction, frame, timestamp, order))
            order += 1

    return sorted(lines, key=lambda line: (line.frame_number, line.order))


def _smtp_state(lines: list[_Line]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    events: list[dict[str, Any]] = []
    state = _initial_state("STARTTLS")
    awaiting_capabilities = False
    awaiting_upgrade = False

    for line in lines:
        upper = line.text.upper()
        if line.direction == "CLIENT_TO_SERVER":
            command = upper.split(maxsplit=1)[0] if upper else ""
            if command in {"EHLO", "HELO"}:
                awaiting_capabilities = True
                events.append(_line_event(line, "COMMAND", command))
            elif command == "STARTTLS":
                state["requested"] = True
                state["mode"] = "STARTTLS"
                state["evidence"].setdefault("request_frame", line.frame_number)
                awaiting_upgrade = True
                events.append(_line_event(line, "COMMAND", "STARTTLS"))
            continue

        match = re.match(r"^(\d{3})([- ])?(.*)$", line.text)
        if not match:
            continue
        code, separator, detail = match.groups()
        if not events and code == "220":
            events.append(_line_event(line, "GREETING", "220"))
        if awaiting_capabilities and code == "250":
            if "STARTTLS" in _tokens(detail):
                _advertise(state, line.frame_number)
                events.append(_line_event(line, "CAPABILITY", "STARTTLS"))
            if separator != "-":
                state["capabilities_complete"] = True
                awaiting_capabilities = False
        if awaiting_upgrade:
            events.append(_line_event(line, "RESPONSE", code))
            if code == "220":
                _accept(state, line.frame_number)
            elif code.startswith(("4", "5")):
                state["rejected"] = True
            awaiting_upgrade = False

    return events, state


def _imap_state(lines: list[_Line]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    events: list[dict[str, Any]] = []
    state = _initial_state("STARTTLS")
    capability_tag: str | None = None
    upgrade_tag: str | None = None

    for line in lines:
        parts = line.text.split()
        upper_parts = [part.upper() for part in parts]
        if line.direction == "CLIENT_TO_SERVER" and len(parts) >= 2:
            tag, command = parts[0], upper_parts[1]
            if command == "CAPABILITY":
                capability_tag = tag
                events.append(_line_event(line, "COMMAND", "CAPABILITY", tag=tag))
            elif command == "STARTTLS":
                state["requested"] = True
                state["mode"] = "STARTTLS"
                state["evidence"].setdefault("request_frame", line.frame_number)
                upgrade_tag = tag
                events.append(_line_event(line, "COMMAND", "STARTTLS", tag=tag))
            continue

        if line.direction != "SERVER_TO_CLIENT" or not parts:
            continue
        if not events and upper_parts[0] == "*" and len(parts) > 1:
            events.append(_line_event(line, "GREETING", upper_parts[1]))
        if "STARTTLS" in _tokens(line.text) and (
            (len(upper_parts) > 1 and upper_parts[0] == "*" and upper_parts[1] == "CAPABILITY")
            or "[CAPABILITY" in line.text.upper()
        ):
            _advertise(state, line.frame_number)
            events.append(_line_event(line, "CAPABILITY", "STARTTLS"))
        if (
            capability_tag
            and parts[0].casefold() == capability_tag.casefold()
            and len(parts) > 1
        ):
            if upper_parts[1] in {"OK", "NO", "BAD"}:
                state["capabilities_complete"] = True
                capability_tag = None
        if (
            upgrade_tag
            and parts[0].casefold() == upgrade_tag.casefold()
            and len(parts) > 1
        ):
            response = upper_parts[1]
            events.append(_line_event(line, "RESPONSE", response, tag=parts[0]))
            if response == "OK":
                _accept(state, line.frame_number)
            elif response in {"NO", "BAD"}:
                state["rejected"] = True
            upgrade_tag = None

    return events, state


def _pop3_state(lines: list[_Line]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    events: list[dict[str, Any]] = []
    state = _initial_state("STLS")
    awaiting_capa_response = False
    reading_capabilities = False
    awaiting_upgrade = False

    for line in lines:
        upper = line.text.upper()
        if line.direction == "CLIENT_TO_SERVER":
            command = upper.split(maxsplit=1)[0] if upper else ""
            if command == "CAPA":
                awaiting_capa_response = True
                events.append(_line_event(line, "COMMAND", "CAPA"))
            elif command == "STLS":
                state["requested"] = True
                state["mode"] = "STARTTLS"
                state["evidence"].setdefault("request_frame", line.frame_number)
                awaiting_upgrade = True
                events.append(_line_event(line, "COMMAND", "STLS"))
            continue

        if not events and upper.startswith(("+OK", "-ERR")):
            events.append(
                _line_event(
                    line,
                    "GREETING",
                    "+OK" if upper.startswith("+OK") else "-ERR",
                )
            )
        if awaiting_capa_response and upper.startswith("+OK"):
            reading_capabilities = True
            awaiting_capa_response = False
        elif awaiting_capa_response and upper.startswith("-ERR"):
            state["capabilities_complete"] = True
            awaiting_capa_response = False
        elif reading_capabilities:
            if upper == ".":
                state["capabilities_complete"] = True
                reading_capabilities = False
            elif upper.split(maxsplit=1)[0] == "STLS":
                _advertise(state, line.frame_number)
                events.append(_line_event(line, "CAPABILITY", "STLS"))
        if awaiting_upgrade and upper.startswith(("+OK", "-ERR")):
            response = "+OK" if upper.startswith("+OK") else "-ERR"
            events.append(_line_event(line, "RESPONSE", response))
            if response == "+OK":
                _accept(state, line.frame_number)
            else:
                state["rejected"] = True
            awaiting_upgrade = False

    return events, state


def _initial_state(command: str) -> dict[str, Any]:
    return {
        "mode": "PLAINTEXT",
        "upgrade_status": "UNKNOWN",
        "advertised": False,
        "requested": False,
        "accepted": False,
        "tls_detected": False,
        "upgrade_command": command,
        "evidence": {},
        "rejected": False,
        "capabilities_complete": False,
    }


def _advertise(state: dict[str, Any], frame_number: int) -> None:
    state["advertised"] = True
    state["mode"] = "STARTTLS"
    state["evidence"].setdefault("advertised_frame", frame_number)


def _accept(state: dict[str, Any], frame_number: int) -> None:
    state["accepted"] = True
    state["evidence"].setdefault("accept_frame", frame_number)


def _line_event(
    line: _Line,
    kind: str,
    name: str,
    *,
    tag: str | None = None,
) -> dict[str, Any]:
    event = {
        "direction": line.direction,
        "kind": kind,
        "name": name,
        "frame_number": line.frame_number,
        "timestamp": line.timestamp,
        "_order": line.order,
    }
    if tag is not None:
        event["tag"] = tag
    return event


def _event(
    packet: PacketMetadata,
    direction: str,
    kind: str,
    name: str,
) -> dict[str, Any]:
    return {
        "direction": direction,
        "kind": kind,
        "name": name,
        "frame_number": packet.frame_number,
        "timestamp": packet.timestamp,
        "_order": 1_000_000,
    }


def _from_client(packet: PacketMetadata, client_ip: str, client_port: int) -> bool:
    return packet.src_ip == client_ip and packet.src_port == client_port


def _tokens(value: str) -> set[str]:
    return {token.upper() for token in re.findall(r"[A-Za-z0-9_-]+", value)}


def _is_relevant_fragment(value: str) -> bool:
    upper = value.upper()
    return bool(
        re.match(r"^\d{3}(?:[- ]|$)", upper)
        or upper.startswith(
            ("EHLO", "HELO", "STARTTLS", "STLS", "CAPA", "+OK", "-ERR", "* OK")
        )
        or re.match(r"^[^\s]+\s+(?:CAPABILITY|STARTTLS|OK|NO|BAD)(?:\s|$)", upper)
    )
