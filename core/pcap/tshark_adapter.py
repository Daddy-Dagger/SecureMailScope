"""Extract packet metadata needed for email-session reconstruction."""

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
    """The packet fields needed for session and STARTTLS reconstruction."""

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
    tcp_payload: bytes = b""
    tls_record: bool = False
    tls_record_content_types: tuple[int, ...] = ()
    tls_handshake_types: tuple[int, ...] = ()
    tls_handshake_versions: tuple[int, ...] = ()
    tls_supported_versions: tuple[int, ...] = ()
    tls_cipher_suites: tuple[int, ...] = ()
    tls_key_share_groups: tuple[int, ...] = ()
    tls_selected_groups: tuple[int, ...] = ()
    tls_supported_groups: tuple[int, ...] = ()
    tls_change_cipher_spec: bool = False
    tls_alert_level: int | None = None
    tls_alert_description: int | None = None
    tls_certificates: tuple[bytes, ...] = ()

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
    "tcp.payload",
    "tls.record.content_type",
    "tls.handshake.type",
    "tls.handshake.version",
    "tls.handshake.extensions.supported_version",
    "tls.handshake.ciphersuite",
    "tls.handshake.extensions_key_share_group",
    "tls.handshake.extensions_key_share_selected_group",
    "tls.handshake.extensions_supported_group",
    "tls.change_cipher_spec",
    "tls.alert_message.level",
    "tls.alert_message.desc",
    "tls.handshake.certificate",
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
        "occurrence=a",
        "-E",
        "aggregator=,",
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

        src_ip = _first(padded[2]) or _first(padded[3]) or None
        dst_ip = _first(padded[4]) or _first(padded[5]) or None
        protocol_labels = normalize_protocol_labels((padded[11], padded[12]))
        tcp_payload = _parse_hex_bytes(_first(padded[13]))
        tls_record_content_types = _parse_ints(padded[14])
        packets.append(
            PacketMetadata(
                frame_number=frame_number,
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=_optional_int(_first(padded[6])),
                dst_port=_optional_int(_first(padded[7])),
                tcp_stream=_first(padded[8]) or None,
                tcp_syn=_parse_bool(_first(padded[9])),
                tcp_ack=_parse_bool(_first(padded[10])),
                protocol_labels=protocol_labels,
                tcp_payload=tcp_payload,
                tls_record=(
                    bool(tls_record_content_types)
                    or "tls" in protocol_labels
                    or "ssl" in protocol_labels
                    or _looks_like_tls_record(tcp_payload)
                ),
                tls_record_content_types=tls_record_content_types,
                tls_handshake_types=_parse_ints(padded[15]),
                tls_handshake_versions=_parse_ints(padded[16]),
                tls_supported_versions=_parse_ints(padded[17]),
                tls_cipher_suites=_parse_ints(padded[18]),
                tls_key_share_groups=_parse_ints(padded[19]),
                tls_selected_groups=_parse_ints(padded[20]),
                tls_supported_groups=_parse_ints(padded[21]),
                tls_change_cipher_spec=bool(padded[22]),
                tls_alert_level=_optional_protocol_int(_first(padded[23])),
                tls_alert_description=_optional_protocol_int(_first(padded[24])),
                tls_certificates=_parse_certificates(padded[25]),
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


def _first(value: str) -> str:
    """Return the first occurrence of an aggregated TShark field."""
    return value.split(",", 1)[0]


def _parse_ints(value: str) -> tuple[int, ...]:
    """Parse decimal or hexadecimal repeated protocol values from TShark."""
    parsed: list[int] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            parsed.append(int(item, 0))
        except ValueError as exc:
            raise InvalidCaptureError(
                f"TShark returned an invalid TLS integer field: {item!r}"
            ) from exc
    return tuple(parsed)


def _optional_protocol_int(value: str) -> int | None:
    if not value:
        return None
    try:
        return int(value, 0)
    except ValueError as exc:
        raise InvalidCaptureError(
            f"TShark returned an invalid TLS integer field: {value!r}"
        ) from exc


def _parse_hex_bytes(value: str) -> bytes:
    """Decode TShark's colon-delimited ``FT_BYTES`` representation."""
    if not value:
        return b""
    try:
        return bytes.fromhex(value.replace(":", ""))
    except ValueError as exc:
        raise InvalidCaptureError(
            "TShark returned an invalid TCP payload byte field."
        ) from exc


def _parse_certificates(value: str) -> tuple[bytes, ...]:
    """Parse colon/hex-encoded DER certificate bytes from TShark."""
    certs: list[bytes] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            certs.append(bytes.fromhex(item.replace(":", "")))
        except ValueError:
            continue
    return tuple(certs)


def _looks_like_tls_record(payload: bytes) -> bool:
    """Recognize a complete TLS record header without parsing the handshake."""
    if len(payload) < 5 or payload[0] not in {20, 21, 22, 23}:
        return False
    if payload[1] != 3 or payload[2] > 4:
        return False
    record_length = int.from_bytes(payload[3:5], "big")
    return 0 < record_length <= 18_432 and len(payload) >= record_length + 5
