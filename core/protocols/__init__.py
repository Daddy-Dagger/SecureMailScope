"""Conservative SMTP, IMAP, and POP3 metadata identification."""

from __future__ import annotations

from collections.abc import Iterable
import re
from typing import Literal

from core.protocols.imap import PROTOCOL as IMAP, SERVER_PORTS as IMAP_PORTS, has_imap_label
from core.protocols.pop3 import PROTOCOL as POP3, SERVER_PORTS as POP3_PORTS, has_pop3_label
from core.protocols.smtp import PROTOCOL as SMTP, SERVER_PORTS as SMTP_PORTS, has_smtp_label

EmailProtocol = Literal["SMTP", "IMAP", "POP3"]

SERVER_PORTS: dict[EmailProtocol, frozenset[int]] = {
    SMTP: SMTP_PORTS,
    IMAP: IMAP_PORTS,
    POP3: POP3_PORTS,
}


def normalize_protocol_labels(values: Iterable[str]) -> tuple[str, ...]:
    """Split TShark layer/column values into normalized, exact label tokens."""
    tokens: list[str] = []
    for value in values:
        tokens.extend(token.casefold() for token in re.findall(r"[A-Za-z0-9]+", value))
    return tuple(tokens)


def protocols_from_labels(labels: Iterable[str]) -> set[EmailProtocol]:
    """Return protocols supported by explicit dissector labels."""
    normalized = normalize_protocol_labels(labels)
    matches: set[EmailProtocol] = set()
    if has_smtp_label(normalized):
        matches.add(SMTP)
    if has_imap_label(normalized):
        matches.add(IMAP)
    if has_pop3_label(normalized):
        matches.add(POP3)
    return matches


def protocols_from_ports(ports: Iterable[int | None]) -> set[EmailProtocol]:
    """Return protocols suggested by approved well-known server ports."""
    present = {port for port in ports if port is not None}
    return {
        protocol
        for protocol, server_ports in SERVER_PORTS.items()
        if present.intersection(server_ports)
    }


__all__ = [
    "EmailProtocol",
    "IMAP",
    "POP3",
    "SMTP",
    "SERVER_PORTS",
    "normalize_protocol_labels",
    "protocols_from_labels",
    "protocols_from_ports",
]
