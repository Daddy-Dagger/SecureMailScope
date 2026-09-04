"""SMTP identification helpers for packet metadata."""

from collections.abc import Iterable

PROTOCOL = "SMTP"
SERVER_PORTS = frozenset({25, 465, 587})
_LABELS = frozenset({"smtp"})


def has_smtp_label(labels: Iterable[str]) -> bool:
    """Return whether TShark supplied an explicit SMTP protocol label."""
    return any(label.casefold() in _LABELS for label in labels)


def uses_smtp_port(port: int | None) -> bool:
    """Return whether *port* is a conventional SMTP server port."""
    return port in SERVER_PORTS
