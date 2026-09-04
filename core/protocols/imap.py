"""IMAP identification helpers for packet metadata."""

from collections.abc import Iterable

PROTOCOL = "IMAP"
SERVER_PORTS = frozenset({143, 993})
_LABELS = frozenset({"imap"})


def has_imap_label(labels: Iterable[str]) -> bool:
    """Return whether TShark supplied an explicit IMAP protocol label."""
    return any(label.casefold() in _LABELS for label in labels)


def uses_imap_port(port: int | None) -> bool:
    """Return whether *port* is a conventional IMAP server port."""
    return port in SERVER_PORTS
