"""Synthetic PCAP test-data generator for SecureMailScope.

Generates reproducible, offline, synthetic network captures (.pcap) to test
SecureMailScope's core email-session reconstruction, STARTTLS tracking, TLS
handshake inspection, and X.509 certificate parsing pipelines.

SAFETY GUARANTEES:
- 100% synthetic traffic constructed in memory via Scapy.
- Zero real-world network captures, credentials, personal data, or private keys.
- Completely offline operation (no sockets, no network requests, no live sniffing).
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import rdpcap, wrpcap

# Base reference timestamp for deterministic epoch timestamps (2026-09-01T00:00:00Z)
BASE_TIMESTAMP = 1_788_220_800.0

# Standard synthetic hardware MAC addresses (avoids Scapy /dev/bpf0 MAC resolution)
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"

# Well-known cipher suites recognized by core/tls/handshake.py
CIPHER_RSA_AES_128_CBC_SHA = 0x002F      # TLS 1.0/1.1 static RSA (no forward secrecy)
CIPHER_RSA_AES_256_CBC_SHA = 0x0035      # TLS 1.0/1.1 static RSA (no forward secrecy)
CIPHER_ECDHE_RSA_AES_128_GCM_SHA256 = 0xC02F  # TLS 1.2 modern ECDHE
CIPHER_AES_256_GCM_SHA384 = 0x1302       # TLS 1.3 modern AEAD


# ==============================================================================
# Low-Level Packet & TLS Record Construction Helpers
# ==============================================================================


def _tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    flags: str,
    seq: int,
    ack: int,
    timestamp: float,
    payload: bytes = b"",
    *,
    is_client: bool = True,
) -> Packet:
    """Construct a clean, self-contained Ethernet/IP/TCP packet with explicit MACs."""
    src_mac = CLIENT_MAC if is_client else SERVER_MAC
    dst_mac = SERVER_MAC if is_client else CLIENT_MAC
    eth = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=src_port, dport=dst_port, flags=flags, seq=seq, ack=ack)
    packet = eth / ip / tcp
    if payload:
        packet = packet / Raw(payload)
    packet.time = timestamp
    return packet


def _tls_record(content_type: int, version: tuple[int, int], body: bytes) -> bytes:
    """Format a standard TLS Record layer (RFC 5246 / RFC 8446)."""
    return bytes([content_type, version[0], version[1]]) + len(body).to_bytes(2, "big") + body


def _tls_handshake_msg(msg_type: int, body: bytes) -> bytes:
    """Format a TLS Handshake protocol message (Type + 3-byte length + Body)."""
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def _tls_extension(ext_type: int, data: bytes) -> bytes:
    """Format a TLS Hello Extension (Type + 2-byte length + Data)."""
    return ext_type.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data


def _build_client_hello(
    version: tuple[int, int],
    cipher_suites: Sequence[int],
    extensions: bytes = b"",
) -> bytes:
    """Construct a synthetic TLS ClientHello message wrapped in a Handshake Record."""
    body = bytes([version[0], version[1]]) + (b"\x01" * 32) + b"\x00"  # Version + Random + Session ID (0)
    ciphers_bytes = b"".join(cs.to_bytes(2, "big") for cs in cipher_suites)
    body += len(ciphers_bytes).to_bytes(2, "big") + ciphers_bytes
    body += b"\x01\x00"  # Compression methods (1 method: NULL 0x00)
    if extensions:
        body += len(extensions).to_bytes(2, "big") + extensions
    elif version == (3, 3):
        body += b"\x00\x00"
    msg = _tls_handshake_msg(1, body)
    return _tls_record(22, version, msg)


def _build_server_hello(
    version: tuple[int, int],
    selected_cipher: int,
    extensions: bytes = b"",
) -> bytes:
    """Construct a synthetic TLS ServerHello message wrapped in a Handshake Record."""
    body = bytes([version[0], version[1]]) + (b"\x02" * 32) + b"\x00"  # Version + Random + Session ID (0)
    body += selected_cipher.to_bytes(2, "big")
    body += b"\x00"  # Selected compression NULL
    if extensions:
        body += len(extensions).to_bytes(2, "big") + extensions
    msg = _tls_handshake_msg(2, body)
    return _tls_record(22, version, msg)


def _build_certificate_record(version: tuple[int, int], cert_ders: Sequence[bytes]) -> bytes:
    """Construct a TLS Certificate Handshake Record containing raw X.509 DER certificates."""
    payload = b"".join(len(cert).to_bytes(3, "big") + cert for cert in cert_ders)
    certs_list = len(payload).to_bytes(3, "big") + payload
    msg = _tls_handshake_msg(11, certs_list)
    return _tls_record(22, version, msg)


# ==============================================================================
# X.509 Certificate Generation Helpers
# ==============================================================================


def _generate_synthetic_rsa_key() -> rsa.RSAPrivateKey:
    """Generate a standard 2048-bit RSA private key in memory."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _create_x509_certificate(
    subject_cn: str,
    issuer_cn: str,
    subject_key: rsa.RSAPrivateKey,
    issuer_key: rsa.RSAPrivateKey,
    *,
    serial_number: int = 1,
    not_valid_before: datetime | None = None,
    not_valid_after: datetime | None = None,
    san_dns_names: list[str] | None = None,
) -> bytes:
    """Create and sign an in-memory X.509 certificate and return DER bytes."""
    ref_now = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)
    nvb = not_valid_before or (ref_now - timedelta(days=10))
    nva = not_valid_after or (ref_now + timedelta(days=90))

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(serial_number)
        .not_valid_before(nvb)
        .not_valid_after(nva)
    )

    if san_dns_names:
        san = x509.SubjectAlternativeName([x509.DNSName(name) for name in san_dns_names])
        builder = builder.add_extension(san, critical=False)

    cert = builder.sign(issuer_key, hashes.SHA256())
    return cert.public_bytes(Encoding.DER)


# ==============================================================================
# Scenario 1 — Normal Baseline Capture
# ==============================================================================


def generate_normal_scenario(output_dir: Path) -> list[Path]:
    """Generate modern, secure email traffic: SMTP with STARTTLS and valid TLS 1.2."""
    target_dir = output_dir / "normal"
    target_dir.mkdir(parents=True, exist_ok=True)
    out_file = target_dir / "normal_smtp_starttls.pcap"

    client_ip, client_port = "192.168.1.10", 51544
    server_ip, server_port = "192.168.1.20", 25
    t = BASE_TIMESTAMP

    # Generate CA Root and Leaf certificates
    root_key = _generate_synthetic_rsa_key()
    root_der = _create_x509_certificate(
        subject_cn="SecureMailScope Test Root CA",
        issuer_cn="SecureMailScope Test Root CA",
        subject_key=root_key,
        issuer_key=root_key,
        serial_number=1,
    )
    server_key = _generate_synthetic_rsa_key()
    leaf_der = _create_x509_certificate(
        subject_cn="mail.example.com",
        issuer_cn="SecureMailScope Test Root CA",
        subject_key=server_key,
        issuer_key=root_key,
        serial_number=2,
        san_dns_names=["mail.example.com", "smtp.example.com"],
    )

    client_hello = _build_client_hello((3, 3), [CIPHER_ECDHE_RSA_AES_128_GCM_SHA256])
    server_hello = _build_server_hello((3, 3), CIPHER_ECDHE_RSA_AES_128_GCM_SHA256)
    cert_record = _build_certificate_record((3, 3), [leaf_der, root_der])

    packets: list[Packet] = [
        # TCP 3-Way Handshake
        _tcp_packet(client_ip, server_ip, client_port, server_port, "S", 1, 0, t + 0.1, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "SA", 100, 2, t + 0.2, is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "A", 2, 101, t + 0.3, is_client=True),
        # SMTP Plaintext Prelude
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 101, 2, t + 0.4, b"220 mail.example.com ESMTP Postfix\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 2, 137, t + 0.5, b"EHLO client.example.com\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 137, 27, t + 0.6, b"250-mail.example.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 27, 227, t + 0.7, b"STARTTLS\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 227, 37, t + 0.8, b"220 2.0.0 Ready to start TLS\r\n", is_client=False),
        # TLS Handshake Records
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 37, 259, t + 0.9, client_hello, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 259, 37 + len(client_hello), t + 1.0, server_hello, is_client=False),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 259 + len(server_hello), 37 + len(client_hello), t + 1.1, cert_record, is_client=False),
    ]

    wrpcap(str(out_file), packets)
    return [out_file]


# ==============================================================================
# Scenario 2 — Weak TLS Captures
# ==============================================================================


def generate_weak_tls_scenario(output_dir: Path) -> list[Path]:
    """Generate captures with deprecated TLS versions and weak/static ciphers."""
    target_dir = output_dir / "weak_tls"
    target_dir.mkdir(parents=True, exist_ok=True)
    generated: list[Path] = []

    # Capture A: SMTP with TLS 1.0 and static RSA cipher (no forward secrecy)
    file_a = target_dir / "weak_tls10_smtp.pcap"
    client_ip, client_port = "192.168.1.10", 52100
    server_ip, server_port = "192.168.1.20", 25
    t = BASE_TIMESTAMP + 100

    ch_tls10 = _build_client_hello((3, 1), [CIPHER_RSA_AES_128_CBC_SHA, CIPHER_RSA_AES_256_CBC_SHA])
    sh_tls10 = _build_server_hello((3, 1), CIPHER_RSA_AES_128_CBC_SHA)

    packets_a: list[Packet] = [
        _tcp_packet(client_ip, server_ip, client_port, server_port, "S", 1, 0, t + 0.1, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "SA", 100, 2, t + 0.2, is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "A", 2, 101, t + 0.3, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 101, 2, t + 0.4, b"220 legacy.example.com ESMTP\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 2, 131, t + 0.5, b"EHLO client.example.com\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 131, 27, t + 0.6, b"250-legacy.example.com\r\n250-STARTTLS\r\n250 OK\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 27, 180, t + 0.7, b"STARTTLS\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 180, 37, t + 0.8, b"220 Ready to start TLS\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 37, 204, t + 0.9, ch_tls10, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 204, 37 + len(ch_tls10), t + 1.0, sh_tls10, is_client=False),
    ]
    wrpcap(str(file_a), packets_a)
    generated.append(file_a)

    # Capture B: IMAP on port 143 with TLS 1.1 and static RSA cipher
    file_b = target_dir / "weak_tls11_imap.pcap"
    client_ip, client_port = "192.168.1.11", 52101
    server_ip, server_port = "192.168.1.25", 143
    t = BASE_TIMESTAMP + 200

    ch_tls11 = _build_client_hello((3, 2), [CIPHER_RSA_AES_256_CBC_SHA])
    sh_tls11 = _build_server_hello((3, 2), CIPHER_RSA_AES_256_CBC_SHA)

    packets_b: list[Packet] = [
        _tcp_packet(client_ip, server_ip, client_port, server_port, "S", 1, 0, t + 0.1, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "SA", 100, 2, t + 0.2, is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "A", 2, 101, t + 0.3, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 101, 2, t + 0.4, b"* OK IMAP4rev1 Service Ready\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 2, 131, t + 0.5, b"a001 CAPABILITY\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 131, 18, t + 0.6, b"* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK CAPABILITY completed\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 18, 192, t + 0.7, b"a002 STARTTLS\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 192, 33, t + 0.8, b"a002 OK Begin TLS negotiation now\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 33, 227, t + 0.9, ch_tls11, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 227, 33 + len(ch_tls11), t + 1.0, sh_tls11, is_client=False),
    ]
    wrpcap(str(file_b), packets_b)
    generated.append(file_b)

    return generated


# ==============================================================================
# Scenario 3 — Certificate Issues Captures
# ==============================================================================


def generate_certificate_issues_scenario(output_dir: Path) -> list[Path]:
    """Generate captures containing expired, self-signed, and SAN-missing certificates."""
    target_dir = output_dir / "certificate_issues"
    target_dir.mkdir(parents=True, exist_ok=True)
    generated: list[Path] = []

    # 1. Expired Certificate (SMTP)
    file_exp = target_dir / "cert_expired_smtp.pcap"
    client_ip, client_port = "192.168.1.10", 53100
    server_ip, server_port = "192.168.1.20", 25
    t = BASE_TIMESTAMP + 300

    exp_key = _generate_synthetic_rsa_key()
    expired_der = _create_x509_certificate(
        subject_cn="expired.example.com",
        issuer_cn="SecureMailScope Test Root CA",
        subject_key=exp_key,
        issuer_key=exp_key,
        serial_number=99,
        not_valid_before=datetime(2019, 1, 1, tzinfo=timezone.utc),
        not_valid_after=datetime(2020, 1, 1, tzinfo=timezone.utc),  # Expired relative to 2026
        san_dns_names=["expired.example.com"],
    )

    ch = _build_client_hello((3, 3), [CIPHER_ECDHE_RSA_AES_128_GCM_SHA256])
    sh = _build_server_hello((3, 3), CIPHER_ECDHE_RSA_AES_128_GCM_SHA256)
    cert_exp_rec = _build_certificate_record((3, 3), [expired_der])

    packets_exp: list[Packet] = [
        _tcp_packet(client_ip, server_ip, client_port, server_port, "S", 1, 0, t + 0.1, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "SA", 100, 2, t + 0.2, is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "A", 2, 101, t + 0.3, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 101, 2, t + 0.4, b"220 expired.example.com ESMTP\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 2, 131, t + 0.5, b"EHLO client.example.com\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 131, 27, t + 0.6, b"250-expired.example.com\r\n250-STARTTLS\r\n250 OK\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 27, 180, t + 0.7, b"STARTTLS\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 180, 37, t + 0.8, b"220 Ready to start TLS\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 37, 204, t + 0.9, ch, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 204, 37 + len(ch), t + 1.0, sh, is_client=False),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 204 + len(sh), 37 + len(ch), t + 1.1, cert_exp_rec, is_client=False),
    ]
    wrpcap(str(file_exp), packets_exp)
    generated.append(file_exp)

    # 2. Self-Signed Certificate (SMTP)
    file_self = target_dir / "cert_self_signed_smtp.pcap"
    client_ip, client_port = "192.168.1.10", 53101
    server_ip, server_port = "192.168.1.20", 25
    t = BASE_TIMESTAMP + 400

    self_key = _generate_synthetic_rsa_key()
    self_der = _create_x509_certificate(
        subject_cn="self-signed.example.com",
        issuer_cn="self-signed.example.com",  # Self-issued
        subject_key=self_key,
        issuer_key=self_key,  # Self-signed
        serial_number=101,
        san_dns_names=["self-signed.example.com"],
    )
    cert_self_rec = _build_certificate_record((3, 3), [self_der])

    packets_self: list[Packet] = [
        _tcp_packet(client_ip, server_ip, client_port, server_port, "S", 1, 0, t + 0.1, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "SA", 100, 2, t + 0.2, is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "A", 2, 101, t + 0.3, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 101, 2, t + 0.4, b"220 self.example.com ESMTP\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 2, 128, t + 0.5, b"EHLO client.example.com\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 128, 27, t + 0.6, b"250-self.example.com\r\n250-STARTTLS\r\n250 OK\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 27, 177, t + 0.7, b"STARTTLS\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 177, 37, t + 0.8, b"220 Ready to start TLS\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 37, 201, t + 0.9, ch, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 201, 37 + len(ch), t + 1.0, sh, is_client=False),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 201 + len(sh), 37 + len(ch), t + 1.1, cert_self_rec, is_client=False),
    ]
    wrpcap(str(file_self), packets_self)
    generated.append(file_self)

    # 3. Missing SAN Certificate (IMAP)
    file_nosan = target_dir / "cert_missing_san_imap.pcap"
    client_ip, client_port = "192.168.1.11", 53102
    server_ip, server_port = "192.168.1.25", 143
    t = BASE_TIMESTAMP + 500

    ca_key = _generate_synthetic_rsa_key()
    nosan_key = _generate_synthetic_rsa_key()
    nosan_der = _create_x509_certificate(
        subject_cn="nosan.example.org",
        issuer_cn="SecureMailScope Test Root CA",
        subject_key=nosan_key,
        issuer_key=ca_key,
        serial_number=102,
        san_dns_names=None,  # Explicitly omitted SAN
    )
    cert_nosan_rec = _build_certificate_record((3, 3), [nosan_der])

    packets_nosan: list[Packet] = [
        _tcp_packet(client_ip, server_ip, client_port, server_port, "S", 1, 0, t + 0.1, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "SA", 100, 2, t + 0.2, is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "A", 2, 101, t + 0.3, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 101, 2, t + 0.4, b"* OK IMAP4rev1 Ready\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 2, 123, t + 0.5, b"a001 CAPABILITY\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 123, 18, t + 0.6, b"* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK CAPABILITY completed\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 18, 184, t + 0.7, b"a002 STARTTLS\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 184, 33, t + 0.8, b"a002 OK Begin TLS negotiation now\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 33, 219, t + 0.9, ch, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 219, 33 + len(ch), t + 1.0, sh, is_client=False),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 219 + len(sh), 33 + len(ch), t + 1.1, cert_nosan_rec, is_client=False),
    ]
    wrpcap(str(file_nosan), packets_nosan)
    generated.append(file_nosan)

    return generated


# ==============================================================================
# Scenario 4 — STARTTLS Edge Cases
# ==============================================================================


def generate_starttls_scenario(output_dir: Path) -> list[Path]:
    """Generate captures for STARTTLS upgrade states (success, reject, not-offered, not-requested)."""
    target_dir = output_dir / "starttls"
    target_dir.mkdir(parents=True, exist_ok=True)
    generated: list[Path] = []

    client_ip, client_port = "192.168.1.10", 54100
    server_ip, server_port = "192.168.1.20", 25

    # 1. Successful Upgrade
    file_succ = target_dir / "starttls_upgrade_success.pcap"
    t = BASE_TIMESTAMP + 600
    ch = _build_client_hello((3, 3), [CIPHER_ECDHE_RSA_AES_128_GCM_SHA256])
    packets_succ: list[Packet] = [
        _tcp_packet(client_ip, server_ip, client_port, server_port, "S", 1, 0, t + 0.1, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "SA", 100, 2, t + 0.2, is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "A", 2, 101, t + 0.3, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 101, 2, t + 0.4, b"220 mail.example.com ESMTP\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 2, 129, t + 0.5, b"EHLO client.example.com\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 129, 27, t + 0.6, b"250-mail.example.com\r\n250-STARTTLS\r\n250 OK\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 27, 178, t + 0.7, b"STARTTLS\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 178, 37, t + 0.8, b"220 2.0.0 Ready to start TLS\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 37, 210, t + 0.9, ch, is_client=True),
    ]
    wrpcap(str(file_succ), packets_succ)
    generated.append(file_succ)

    # 2. STARTTLS Rejection (Server returns 454)
    file_rej = target_dir / "starttls_rejected.pcap"
    t = BASE_TIMESTAMP + 700
    packets_rej: list[Packet] = [
        _tcp_packet(client_ip, server_ip, client_port, server_port, "S", 1, 0, t + 0.1, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "SA", 100, 2, t + 0.2, is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "A", 2, 101, t + 0.3, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 101, 2, t + 0.4, b"220 mail.example.com ESMTP\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 2, 129, t + 0.5, b"EHLO client.example.com\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 129, 27, t + 0.6, b"250-mail.example.com\r\n250-STARTTLS\r\n250 OK\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 27, 178, t + 0.7, b"STARTTLS\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 178, 37, t + 0.8, b"454 4.7.0 TLS not available due to temporary reason\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 37, 230, t + 0.9, b"QUIT\r\n", is_client=True),
    ]
    wrpcap(str(file_rej), packets_rej)
    generated.append(file_rej)

    # 3. STARTTLS Not Offered (Plaintext Fallback)
    file_not_offered = target_dir / "starttls_not_advertised.pcap"
    t = BASE_TIMESTAMP + 800
    packets_no_offer: list[Packet] = [
        _tcp_packet(client_ip, server_ip, client_port, server_port, "S", 1, 0, t + 0.1, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "SA", 100, 2, t + 0.2, is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "A", 2, 101, t + 0.3, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 101, 2, t + 0.4, b"220 mail.plain.test ESMTP\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 2, 128, t + 0.5, b"EHLO client.plain.test\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 128, 26, t + 0.6, b"250-mail.plain.test\r\n250-PIPELINING\r\n250-SIZE 1024000\r\n250 HELP\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 26, 196, t + 0.7, b"MAIL FROM:<sender@plain.test>\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 196, 58, t + 0.8, b"250 2.1.0 Ok\r\n", is_client=False),
    ]
    wrpcap(str(file_not_offered), packets_no_offer)
    generated.append(file_not_offered)

    # 4. STARTTLS Advertised but Client Did Not Request (Plaintext transmission despite capability)
    file_adv_not_req = target_dir / "starttls_advertised_not_requested.pcap"
    t = BASE_TIMESTAMP + 900
    packets_adv_not_req: list[Packet] = [
        _tcp_packet(client_ip, server_ip, client_port, server_port, "S", 1, 0, t + 0.1, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "SA", 100, 2, t + 0.2, is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "A", 2, 101, t + 0.3, is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 101, 2, t + 0.4, b"220 mail.example.com ESMTP\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 2, 129, t + 0.5, b"EHLO client.example.com\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 129, 27, t + 0.6, b"250-mail.example.com\r\n250-STARTTLS\r\n250 OK\r\n", is_client=False),
        _tcp_packet(client_ip, server_ip, client_port, server_port, "PA", 27, 178, t + 0.7, b"MAIL FROM:<audit@example.test>\r\n", is_client=True),
        _tcp_packet(server_ip, client_ip, server_port, client_port, "PA", 178, 59, t + 0.8, b"250 2.1.0 Ok\r\n", is_client=False),
    ]
    wrpcap(str(file_adv_not_req), packets_adv_not_req)
    generated.append(file_adv_not_req)

    return generated


# ==============================================================================
# Scenario 5 — Mixed Concurrent Protocols
# ==============================================================================


def generate_mixed_scenario(output_dir: Path) -> list[Path]:
    """Generate a combined capture containing concurrent SMTP, IMAP, and POP3 sessions."""
    target_dir = output_dir / "mixed"
    target_dir.mkdir(parents=True, exist_ok=True)
    out_file = target_dir / "mixed_email_traffic.pcap"

    t = BASE_TIMESTAMP + 1000
    packets: list[Packet] = []

    # Stream 1: SMTP STARTTLS
    smtp_cli, smtp_srv = ("192.168.1.10", 55001), ("192.168.1.20", 25)
    packets.extend([
        _tcp_packet(smtp_cli[0], smtp_srv[0], smtp_cli[1], smtp_srv[1], "S", 1, 0, t + 0.1, is_client=True),
        _tcp_packet(smtp_srv[0], smtp_cli[0], smtp_srv[1], smtp_cli[1], "SA", 100, 2, t + 0.2, is_client=False),
        _tcp_packet(smtp_cli[0], smtp_srv[0], smtp_cli[1], smtp_srv[1], "A", 2, 101, t + 0.3, is_client=True),
        _tcp_packet(smtp_srv[0], smtp_cli[0], smtp_srv[1], smtp_cli[1], "PA", 101, 2, t + 0.4, b"220 mail.example.com ESMTP\r\n", is_client=False),
        _tcp_packet(smtp_cli[0], smtp_srv[0], smtp_cli[1], smtp_srv[1], "PA", 2, 129, t + 0.5, b"EHLO client.example.com\r\n", is_client=True),
        _tcp_packet(smtp_srv[0], smtp_cli[0], smtp_srv[1], smtp_cli[1], "PA", 129, 27, t + 0.6, b"250-mail.example.com\r\n250-STARTTLS\r\n250 OK\r\n", is_client=False),
        _tcp_packet(smtp_cli[0], smtp_srv[0], smtp_cli[1], smtp_srv[1], "PA", 27, 178, t + 0.7, b"STARTTLS\r\n", is_client=True),
        _tcp_packet(smtp_srv[0], smtp_cli[0], smtp_srv[1], smtp_cli[1], "PA", 178, 37, t + 0.8, b"220 2.0.0 Ready to start TLS\r\n", is_client=False),
        _tcp_packet(smtp_cli[0], smtp_srv[0], smtp_cli[1], smtp_srv[1], "PA", 37, 210, t + 0.9, _build_client_hello((3, 3), [CIPHER_ECDHE_RSA_AES_128_GCM_SHA256]), is_client=True),
    ])

    # Stream 2: IMAP STARTTLS
    imap_cli, imap_srv = ("192.168.1.11", 55002), ("192.168.1.25", 143)
    packets.extend([
        _tcp_packet(imap_cli[0], imap_srv[0], imap_cli[1], imap_srv[1], "S", 1, 0, t + 0.15, is_client=True),
        _tcp_packet(imap_srv[0], imap_cli[0], imap_srv[1], imap_cli[1], "SA", 200, 2, t + 0.25, is_client=False),
        _tcp_packet(imap_cli[0], imap_srv[0], imap_cli[1], imap_srv[1], "A", 2, 201, t + 0.35, is_client=True),
        _tcp_packet(imap_srv[0], imap_cli[0], imap_srv[1], imap_cli[1], "PA", 201, 2, t + 0.45, b"* OK IMAP4rev1 Ready\r\n", is_client=False),
        _tcp_packet(imap_cli[0], imap_srv[0], imap_cli[1], imap_srv[1], "PA", 2, 223, t + 0.55, b"a001 CAPABILITY\r\n", is_client=True),
        _tcp_packet(imap_srv[0], imap_cli[0], imap_srv[1], imap_cli[1], "PA", 223, 18, t + 0.65, b"* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK CAPABILITY completed\r\n", is_client=False),
        _tcp_packet(imap_cli[0], imap_srv[0], imap_cli[1], imap_srv[1], "PA", 18, 284, t + 0.75, b"a002 STARTTLS\r\n", is_client=True),
        _tcp_packet(imap_srv[0], imap_cli[0], imap_srv[1], imap_cli[1], "PA", 284, 33, t + 0.85, b"a002 OK Begin TLS negotiation now\r\n", is_client=False),
        _tcp_packet(imap_cli[0], imap_srv[0], imap_cli[1], imap_srv[1], "PA", 33, 319, t + 0.95, _build_client_hello((3, 3), [CIPHER_ECDHE_RSA_AES_128_GCM_SHA256]), is_client=True),
    ])

    # Stream 3: POP3 STLS
    pop3_cli, pop3_srv = ("192.168.1.12", 55003), ("192.168.1.30", 110)
    packets.extend([
        _tcp_packet(pop3_cli[0], pop3_srv[0], pop3_cli[1], pop3_srv[1], "S", 1, 0, t + 0.18, is_client=True),
        _tcp_packet(pop3_srv[0], pop3_cli[0], pop3_srv[1], pop3_cli[1], "SA", 300, 2, t + 0.28, is_client=False),
        _tcp_packet(pop3_cli[0], pop3_srv[0], pop3_cli[1], pop3_srv[1], "A", 2, 301, t + 0.38, is_client=True),
        _tcp_packet(pop3_srv[0], pop3_cli[0], pop3_srv[1], pop3_cli[1], "PA", 301, 2, t + 0.48, b"+OK POP3 server ready\r\n", is_client=False),
        _tcp_packet(pop3_cli[0], pop3_srv[0], pop3_cli[1], pop3_srv[1], "PA", 2, 325, t + 0.58, b"CAPA\r\n", is_client=True),
        _tcp_packet(pop3_srv[0], pop3_cli[0], pop3_srv[1], pop3_cli[1], "PA", 325, 8, t + 0.68, b"+OK Capability list follows\r\nSTLS\r\nUSER\r\n.\r\n", is_client=False),
        _tcp_packet(pop3_cli[0], pop3_srv[0], pop3_cli[1], pop3_srv[1], "PA", 8, 368, t + 0.78, b"STLS\r\n", is_client=True),
        _tcp_packet(pop3_srv[0], pop3_cli[0], pop3_srv[1], pop3_cli[1], "PA", 368, 14, t + 0.88, b"+OK Begin TLS negotiation\r\n", is_client=False),
        _tcp_packet(pop3_cli[0], pop3_srv[0], pop3_cli[1], pop3_srv[1], "PA", 14, 395, t + 0.98, _build_client_hello((3, 3), [CIPHER_ECDHE_RSA_AES_128_GCM_SHA256]), is_client=True),
    ])

    # Sort packets strictly by timestamp across all interleaved streams
    packets.sort(key=lambda p: getattr(p, "time", 0.0))
    wrpcap(str(out_file), packets)
    return [out_file]


# ==============================================================================
# CLI Orchestrator and Validation
# ==============================================================================

SCENARIO_GENERATORS = {
    "normal": generate_normal_scenario,
    "weak_tls": generate_weak_tls_scenario,
    "certificate_issues": generate_certificate_issues_scenario,
    "starttls": generate_starttls_scenario,
    "mixed": generate_mixed_scenario,
}

SCENARIO_DESCRIPTIONS = {
    "normal": "Modern secure email baseline (SMTP with STARTTLS, valid TLS 1.2/1.3, CA-signed cert)",
    "weak_tls": "Deprecated TLS versions (TLS 1.0, TLS 1.1) and static RSA ciphers lacking forward secrecy",
    "certificate_issues": "Certificate anomalies: expired cert, self-signed cert, and missing SAN extension",
    "starttls": "STARTTLS transition edge cases: success, server 454 rejection, not advertised, and advertised-not-requested",
    "mixed": "Multi-protocol capture file containing concurrent SMTP, IMAP, and POP3 TCP sessions",
}


def validate_generated_pcap(pcap_path: Path) -> dict[str, Any]:
    """Validate a generated PCAP file using Scapy and report structural characteristics."""
    if not pcap_path.exists():
        raise FileNotFoundError(f"Generated PCAP does not exist: {pcap_path}")
    size = pcap_path.stat().st_size
    if size == 0:
        raise ValueError(f"Generated PCAP is empty (0 bytes): {pcap_path}")

    packets = rdpcap(str(pcap_path))
    tcp_packets = [p for p in packets if p.haslayer(TCP)]
    src_ips = {p[IP].src for p in packets if p.haslayer(IP)}
    dst_ips = {p[IP].dst for p in packets if p.haslayer(IP)}
    ports = {p[TCP].sport for p in tcp_packets} | {p[TCP].dport for p in tcp_packets}

    return {
        "file": pcap_path.name,
        "path": str(pcap_path),
        "size_bytes": size,
        "total_packets": len(packets),
        "tcp_packets": len(tcp_packets),
        "ip_endpoints": len(src_ips | dst_ips),
        "ports": sorted(ports),
    }


def generate_scenario(name: str, output_base: Path, *, validate: bool = True) -> list[Path]:
    """Generate a single scenario by name and optionally validate outputs."""
    generator = SCENARIO_GENERATORS.get(name)
    if not generator:
        available = ", ".join(sorted(SCENARIO_GENERATORS.keys()))
        raise ValueError(f"Unknown scenario '{name}'. Available: {available}")

    files = generator(output_base)
    if validate:
        for f in files:
            validate_generated_pcap(f)
    return files


def generate_all_scenarios(output_base: Path, *, validate: bool = True) -> dict[str, list[Path]]:
    """Generate all available test scenarios into the output directory."""
    results: dict[str, list[Path]] = {}
    for name in SCENARIO_GENERATORS:
        results[name] = generate_scenario(name, output_base, validate=validate)
    return results


def main() -> None:
    """CLI entry point for the synthetic test data generator."""
    parser = argparse.ArgumentParser(
        description="SecureMailScope Synthetic PCAP Test-Data Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python scripts/generate_test_data.py --all
  python scripts/generate_test_data.py --scenario normal
  python scripts/generate_test_data.py --scenario weak_tls --output-dir datasets
  python scripts/generate_test_data.py --list
""",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--scenario",
        choices=sorted(SCENARIO_GENERATORS.keys()),
        help="Generate a specific test scenario",
    )
    group.add_argument(
        "--all",
        action="store_true",
        help="Generate all test scenarios across all dataset categories",
    )
    group.add_argument(
        "--list",
        action="store_true",
        help="List all supported synthetic scenarios with descriptions",
    )
    parser.add_argument(
        "--output-dir",
        default="datasets",
        help="Base output directory for generated PCAPs (default: 'datasets')",
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip post-generation Scapy validation",
    )

    args = parser.parse_args()

    if args.list:
        print("\nAvailable Synthetic PCAP Scenarios:\n" + "=" * 50)
        for name, desc in SCENARIO_DESCRIPTIONS.items():
            print(f"  * {name:<20} : {desc}")
        print()
        sys.exit(0)

    output_base = Path(args.output_dir).resolve()
    do_validate = not args.no_validate

    print(f"\nSecureMailScope PCAP Generator")
    print(f"Output Directory : {output_base}")
    print(f"Post-Validation  : {'Enabled' if do_validate else 'Disabled'}\n" + "-" * 50)

    try:
        if args.all:
            results = generate_all_scenarios(output_base, validate=do_validate)
            total_files = sum(len(fl) for fl in results.values())
            print(f"\n[OK] Successfully generated all {total_files} PCAP files across {len(results)} scenarios:")
            for scenario, files in results.items():
                print(f"  [{scenario}]")
                for f in files:
                    meta = validate_generated_pcap(f)
                    print(f"    - {f.name} ({meta['total_packets']} packets, {meta['size_bytes']} bytes)")
        elif args.scenario:
            files = generate_scenario(args.scenario, output_base, validate=do_validate)
            print(f"\n[OK] Successfully generated scenario '{args.scenario}':")
            for f in files:
                meta = validate_generated_pcap(f)
                print(f"  - {f.name} ({meta['total_packets']} packets, {meta['size_bytes']} bytes)")
    except Exception as exc:
        print(f"\n[ERROR] Generation failed: {exc}", file=sys.stderr)
        sys.exit(1)

    print("\nGeneration complete. Captures are ready in", output_base, "\n")


if __name__ == "__main__":
    main()
