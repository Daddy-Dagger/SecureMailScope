"""Extract minimal packet metadata from captures with TShark."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess

from core.protocols import normalize_protocol_labels


class TSharkError(RuntimeError):
    """Base exception for TShark metadata extraction failures."""


class TSharkUnavailableError(TSharkError):
    """Raised when the TShark executable cannot be found."""


class InvalidCaptureError(TSharkError):
    """Raised when TShark cannot read the supplied capture."""


@dataclass(frozen=True, slots=True)
class PacketMetadata:
    """The packet fields needed for Milestone 1 session extraction."""

    frame_number: int
    timestamp: float
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_stream: str | None = None
    tcp_syn: bool = False
    tcp_ack: bool = False
    protocol_labels: tuple[str, ...] = ()

    @property
    def is_tcp(self) -> bool:
        """Return whether complete TCP endpoint metadata is present."""
        return (
            self.src_ip is not None
            and self.dst_ip is not None
            and self.src_port is not None
            and self.dst_port is not None
        )


_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "frame.protocols",
    "_ws.col.Protocol",
)


def tshark_path() -> str | None:
    """Return the available TShark executable path, if any."""
    return shutil.which("tshark")


def extract_packet_metadata(
    capture_path: str | Path,
    *,
    executable: str | None = None,
    timeout_seconds: int = 120,
) -> list[PacketMetadata]:
    """Read every frame and return only metadata needed by the session builder."""
    binary = executable or tshark_path()
    if binary is None:
        raise TSharkUnavailableError(
            "TShark was not found. Install Wireshark/TShark and ensure 'tshark' is on PATH."
        )

    command = [
        binary,
        "-n",
        "-r",
        str(capture_path),
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    for field in _FIELDS:
        command.extend(("-e", field))

    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise TSharkError(
            f"TShark did not finish within {timeout_seconds} seconds."
        ) from exc
    except OSError as exc:
        raise TSharkError(f"Unable to execute TShark: {exc}") from exc

    if completed.returncode != 0:
        detail = completed.stderr.strip() or "unknown TShark error"
        raise InvalidCaptureError(f"TShark could not read the capture: {detail}")

    packets: list[PacketMetadata] = []
    reader = csv.reader(completed.stdout.splitlines(), delimiter="\t", quotechar='"')
    for row in reader:
        padded = row + [""] * (len(_FIELDS) - len(row))
        try:
            frame_number = int(padded[0])
            timestamp = float(padded[1])
        except (TypeError, ValueError) as exc:
            raise InvalidCaptureError(
                "TShark returned incomplete frame number or timestamp metadata."
            ) from exc

        src_ip = padded[2] or padded[3] or None
        dst_ip = padded[4] or padded[5] or None
        packets.append(
            PacketMetadata(
                frame_number=frame_number,
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=_optional_int(padded[6]),
                dst_port=_optional_int(padded[7]),
                tcp_stream=padded[8] or None,
                tcp_syn=_parse_bool(padded[9]),
                tcp_ack=_parse_bool(padded[10]),
                protocol_labels=normalize_protocol_labels((padded[11], padded[12])),
            )
        )

    return packets


def _optional_int(value: str) -> int | None:
    if not value:
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise InvalidCaptureError(f"TShark returned an invalid integer field: {value!r}") from exc


def _parse_bool(value: str) -> bool:
    return value.casefold() in {"1", "true"}
