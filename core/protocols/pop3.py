"""POP3 identification helpers for packet metadata."""

from collections.abc import Iterable

PROTOCOL = "POP3"
SERVER_PORTS = frozenset({110, 995})
_LABELS = frozenset({"pop", "pop3"})


def has_pop3_label(labels: Iterable[str]) -> bool:
    """Return whether TShark supplied an explicit POP/POP3 protocol label."""
    return any(label.casefold() in _LABELS for label in labels)


def uses_pop3_port(port: int | None) -> bool:
    """Return whether *port* is a conventional POP3 server port."""
    return port in SERVER_PORTS
