"""Conservative TLS handshake metadata extraction from TShark packet fields."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from core.pcap.tshark_adapter import PacketMetadata

_CLIENT_HELLO = 1
_SERVER_HELLO = 2
_FINISHED = 20
_FATAL_ALERT = 2

_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# Common suites are named here so output does not depend on localized TShark
# display text. Unknown/new suites retain their numeric ID and a null name.
_CIPHER_SUITES = {
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}

_GROUPS = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
    0x0103: "ffdhe6144",
    0x0104: "ffdhe8192",
}


def extract_tls_handshake(
    packets: Iterable[PacketMetadata],
    *,
    client_ip: str,
    client_port: int,
) -> dict[str, Any]:
    """Summarize observable handshake facts without inferring security quality."""
    ordered = sorted(packets, key=lambda packet: packet.frame_number)
    detected = any(
        packet.tls_record or packet.tls_handshake_types for packet in ordered
    )
    result: dict[str, Any] = {
        "detected": detected,
        "handshake_status": "NOT_APPLICABLE" if not detected else "DETECTED",
        "offered_versions": [],
        "offered_groups": [],
        "version": None,
        "cipher_suite": None,
        "key_exchange": None,
        "evidence": {},
    }
    if not detected:
        return result

    client_hello = _first_with_type(ordered, _CLIENT_HELLO)
    server_hello = _first_with_type(ordered, _SERVER_HELLO)

    if client_hello is not None:
        result["evidence"]["client_hello_frame"] = client_hello.frame_number
        offered_versions = client_hello.tls_supported_versions
        if not offered_versions:
            offered_versions = client_hello.tls_handshake_versions
        result["offered_versions"] = _known_version_names(offered_versions)

        offered_groups = _unique(
            (*client_hello.tls_key_share_groups, *client_hello.tls_supported_groups)
        )
        result["offered_groups"] = [
            _group(group_id) for group_id in offered_groups
        ]

    selected_cipher_id: int | None = None
    selected_group_id: int | None = None
    if server_hello is not None:
        result["evidence"]["server_hello_frame"] = server_hello.frame_number
        selected_version = _selected_version(server_hello)
        if selected_version is not None:
            result["version"] = selected_version
            result["evidence"]["selected_version_frame"] = server_hello.frame_number

        if server_hello.tls_cipher_suites:
            selected_cipher_id = server_hello.tls_cipher_suites[0]
            result["cipher_suite"] = _cipher_suite(selected_cipher_id)
            result["evidence"]["selected_cipher_frame"] = server_hello.frame_number

        server_groups = (
            server_hello.tls_key_share_groups or server_hello.tls_selected_groups
        )
        if server_groups:
            selected_group_id = server_groups[0]

    if selected_group_id is not None or selected_cipher_id is not None:
        result["key_exchange"] = _key_exchange(
            selected_group_id,
            selected_cipher_id,
        )
        if server_hello is not None:
            result["evidence"]["key_exchange_frame"] = server_hello.frame_number
    else:
        result["key_exchange"] = {"method": "UNKNOWN", "group": None}

    # A complete handshake requires an observable Finished message from each
    # direction. This stays conservative when encrypted handshakes hide them.
    finished_packets = [
        packet
        for packet in ordered
        if _FINISHED in packet.tls_handshake_types
        and (server_hello is None or packet.frame_number > server_hello.frame_number)
    ]
    finished_directions = {
        _direction(packet, client_ip, client_port) for packet in finished_packets
    }
    complete_frame = None
    if finished_directions == {"CLIENT_TO_SERVER", "SERVER_TO_CLIENT"}:
        complete_frame = max(packet.frame_number for packet in finished_packets)
        result["evidence"]["handshake_complete_frame"] = complete_frame

    fatal_alert = next(
        (packet for packet in ordered if packet.tls_alert_level == _FATAL_ALERT),
        None,
    )
    if fatal_alert is not None:
        result["evidence"]["alert_frame"] = fatal_alert.frame_number

    if complete_frame is not None and (
        fatal_alert is None or fatal_alert.frame_number > complete_frame
    ):
        result["handshake_status"] = "COMPLETE"
    elif fatal_alert is not None:
        result["handshake_status"] = "FAILED"
    elif client_hello is not None or server_hello is not None:
        result["handshake_status"] = "INCOMPLETE"
    elif any(packet.tls_handshake_types for packet in ordered):
        result["handshake_status"] = "UNKNOWN"

    return result


def _first_with_type(
    packets: list[PacketMetadata],
    handshake_type: int,
) -> PacketMetadata | None:
    return next(
        (packet for packet in packets if handshake_type in packet.tls_handshake_types),
        None,
    )


def _selected_version(packet: PacketMetadata) -> str | None:
    # RFC 8446 requires the ServerHello supported_versions selection to override
    # the legacy 0x0303 compatibility field for TLS 1.3.
    if packet.tls_supported_versions:
        return _VERSIONS.get(packet.tls_supported_versions[0])
    if packet.tls_handshake_versions:
        return _VERSIONS.get(packet.tls_handshake_versions[0])
    return None


def _known_version_names(version_ids: Iterable[int]) -> list[str]:
    return [
        name
        for version_id in _unique(version_ids)
        if (name := _VERSIONS.get(version_id)) is not None
    ]


def _cipher_suite(cipher_id: int) -> dict[str, str | None]:
    return {"id": f"0x{cipher_id:04x}", "name": _CIPHER_SUITES.get(cipher_id)}


def _group(group_id: int) -> dict[str, str | None]:
    return {"id": f"0x{group_id:04x}", "name": _GROUPS.get(group_id)}


def _key_exchange(
    group_id: int | None,
    cipher_id: int | None,
) -> dict[str, Any]:
    method = "UNKNOWN"
    group = _group(group_id) if group_id is not None else None
    if group_id is not None:
        if 0x0100 <= group_id <= 0x0104:
            method = "DHE"
        elif group_id in _GROUPS:
            method = "ECDHE"
    if method == "UNKNOWN" and cipher_id is not None:
        cipher_name = _CIPHER_SUITES.get(cipher_id, "")
        if "_ECDHE_" in cipher_name:
            method = "ECDHE"
        elif "_DHE_" in cipher_name:
            method = "DHE"
        elif "_PSK_" in cipher_name:
            method = "PSK"
        elif "_RSA_" in cipher_name:
            method = "RSA"
    return {"method": method, "group": group}


def _direction(
    packet: PacketMetadata,
    client_ip: str,
    client_port: int,
) -> str:
    if packet.src_ip == client_ip and packet.src_port == client_port:
        return "CLIENT_TO_SERVER"
    return "SERVER_TO_CLIENT"


def _unique(values: Iterable[int]) -> tuple[int, ...]:
    return tuple(dict.fromkeys(values))
