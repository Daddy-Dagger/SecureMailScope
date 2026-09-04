"""Validated file and in-memory PCAP loading helpers."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
import tempfile

from core.pcap.tshark_adapter import PacketMetadata, extract_packet_metadata

SUPPORTED_EXTENSIONS = frozenset({".pcap", ".pcapng", ".cap"})


class PcapInputError(ValueError):
    """Base exception for invalid PCAP input."""


class PcapFileNotFoundError(PcapInputError):
    """Raised when a requested capture path does not exist."""


class UnsupportedCaptureTypeError(PcapInputError):
    """Raised when a filename does not use a supported capture extension."""


class EmptyCaptureError(PcapInputError):
    """Raised when a capture input contains no bytes."""


Extractor = Callable[[str | Path], list[PacketMetadata]]


def read_pcap_file(
    capture_path: str | Path,
    *,
    extractor: Extractor = extract_packet_metadata,
) -> list[PacketMetadata]:
    """Validate a capture path and extract all packet metadata with TShark."""
    path = Path(capture_path)
    if not path.exists() or not path.is_file():
        raise PcapFileNotFoundError(f"Capture file does not exist: {path}")
    _validate_extension(path.name)
    if path.stat().st_size == 0:
        raise EmptyCaptureError(f"Capture file is empty: {path}")
    return extractor(path)


def read_pcap_bytes(
    filename: str,
    content: bytes,
    *,
    extractor: Extractor = extract_packet_metadata,
) -> list[PacketMetadata]:
    """Write uploaded bytes to a private temporary file for TShark extraction."""
    _validate_extension(filename)
    if not content:
        raise EmptyCaptureError(f"Capture file is empty: {filename}")

    suffix = Path(filename).suffix.casefold()
    with tempfile.NamedTemporaryFile(suffix=suffix) as temporary_capture:
        temporary_capture.write(content)
        temporary_capture.flush()
        return extractor(temporary_capture.name)


def _validate_extension(filename: str) -> None:
    suffix = Path(filename).suffix.casefold()
    if suffix not in SUPPORTED_EXTENSIONS:
        allowed = ", ".join(sorted(SUPPORTED_EXTENSIONS))
        raise UnsupportedCaptureTypeError(
            f"Unsupported capture extension {suffix or '<none>'!r}; expected one of: {allowed}."
        )
