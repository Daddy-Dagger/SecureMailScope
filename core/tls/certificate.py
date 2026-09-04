"""Extract factual X.509 certificate and chain metadata from TLS packets."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    padding,
    rsa,
)
from cryptography.x509.oid import ExtensionOID

if TYPE_CHECKING:
    from core.pcap.tshark_adapter import PacketMetadata


class CertificateError(Exception):
    """Base exception for certificate extraction and parsing errors."""


class CertificateParseError(CertificateError):
    """Raised when raw certificate bytes cannot be parsed as valid X.509."""


def parse_x509_certificate(
    der_bytes: bytes,
    *,
    chain_index: int = 0,
    frame_number: int | None = None,
    reference_time: float | datetime | None = None,
    strict: bool = True,
) -> dict[str, Any] | None:
    """Parse raw DER X.509 certificate bytes into factual metadata.

    Forensic reference time (session or packet timestamp) is used to compute
    factual days remaining rather than wall-clock time. No trust-chain validation
    or security judgment is performed.
    """
    if not der_bytes:
        if strict:
            raise CertificateParseError("Empty certificate byte payload")
        return None

    try:
        cert = x509.load_der_x509_certificate(der_bytes)
    except Exception as exc:
        if strict:
            raise CertificateParseError(f"Failed to parse X.509 DER certificate: {exc}") from exc
        return None

    try:
        subject = cert.subject.rfc4514_string()
    except Exception:
        subject = "UNKNOWN"

    try:
        issuer = cert.issuer.rfc4514_string()
    except Exception:
        issuer = "UNKNOWN"

    serial_number = f"0x{cert.serial_number:x}"

    try:
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    except Exception:
        fingerprint = None

    try:
        not_before_utc = cert.not_valid_before_utc
        not_before = not_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        not_before = "UNKNOWN"
        not_before_utc = None

    try:
        not_after_utc = cert.not_valid_after_utc
        not_after = not_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        not_after = "UNKNOWN"
        not_after_utc = None

    days_remaining = (
        _calculate_days_remaining(not_after_utc, reference_time)
        if not_after_utc is not None
        else None
    )

    sans = _extract_sans(cert)
    pubkey_meta = _extract_public_key(cert)
    sig_algo = _extract_signature_algorithm(cert)

    self_issued = (cert.subject == cert.issuer)
    self_signed: bool | None = None
    if not self_issued:
        self_signed = False
    else:
        self_signed = _verify_self_signature(cert)

    return {
        "chain_index": chain_index,
        "subject": subject,
        "issuer": issuer,
        "serial_number": serial_number,
        "fingerprint_sha256": fingerprint,
        "not_before": not_before,
        "not_after": not_after,
        "days_remaining": days_remaining,
        "subject_alternative_names": sans,
        "self_issued": self_issued,
        "self_signed": self_signed,
        "public_key": pubkey_meta,
        "signature_algorithm": sig_algo,
        "evidence": {
            "certificate_frame": frame_number,
        },
    }


def extract_tls_certificates(
    packets: Iterable[PacketMetadata],
    *,
    reference_time: float | datetime | None = None,
) -> list[dict[str, Any]]:
    """Extract ordered certificate chain metadata from observed TLS frames."""
    ordered = sorted(packets, key=lambda packet: packet.frame_number)
    certificates: list[dict[str, Any]] = []

    for packet in ordered:
        if not packet.tls_certificates:
            continue
        pkt_ref_time = (
            reference_time if reference_time is not None else packet.timestamp
        )
        for der_bytes in packet.tls_certificates:
            cert_meta = parse_x509_certificate(
                der_bytes,
                chain_index=len(certificates),
                frame_number=packet.frame_number,
                reference_time=pkt_ref_time,
                strict=False,
            )
            if cert_meta is not None:
                certificates.append(cert_meta)

    return certificates


def _calculate_days_remaining(
    not_after_utc: datetime,
    reference_time: float | datetime | None,
) -> int | None:
    if reference_time is None:
        return None
    if isinstance(reference_time, (int, float)):
        ref_dt = datetime.fromtimestamp(reference_time, tz=timezone.utc)
    elif isinstance(reference_time, datetime):
        ref_dt = (
            reference_time.astimezone(timezone.utc)
            if reference_time.tzinfo is not None
            else reference_time.replace(tzinfo=timezone.utc)
        )
    else:
        return None
    return int((not_after_utc - ref_dt).total_seconds() // 86400)


def _extract_sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except (x509.ExtensionNotFound, Exception):
        return []

    names: list[str] = []
    for item in ext.value:
        if isinstance(item, x509.IPAddress):
            names.append(str(item.value))
        elif hasattr(item, "value"):
            names.append(str(item.value))
        else:
            names.append(str(item))
    return names


def _extract_public_key(cert: x509.Certificate) -> dict[str, Any]:
    try:
        pubkey = cert.public_key()
    except Exception:
        return {"algorithm": "UNKNOWN", "size_bits": None, "curve": None}

    algo = "UNKNOWN"
    size_bits: int | None = getattr(pubkey, "key_size", None)
    curve: str | None = None

    if isinstance(pubkey, rsa.RSAPublicKey):
        algo = "RSA"
    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        algo = "EC"
        curve = getattr(pubkey.curve, "name", None)
    elif isinstance(pubkey, dsa.DSAPublicKey):
        algo = "DSA"
    elif isinstance(pubkey, ed25519.Ed25519PublicKey):
        algo = "Ed25519"
        size_bits = 256
    elif isinstance(pubkey, ed448.Ed448PublicKey):
        algo = "Ed448"
        size_bits = 448
    elif hasattr(pubkey, "__class__"):
        algo = pubkey.__class__.__name__.replace("PublicKey", "")

    return {
        "algorithm": algo,
        "size_bits": size_bits,
        "curve": curve,
    }


def _extract_signature_algorithm(cert: x509.Certificate) -> str | None:
    try:
        oid = cert.signature_algorithm_oid
        return getattr(oid, "_name", None) or oid.dotted_string
    except Exception:
        return None


def _verify_self_signature(cert: x509.Certificate) -> bool | None:
    """Factually verify whether the certificate is signed by its own public key."""
    try:
        pubkey = cert.public_key()
        if isinstance(pubkey, rsa.RSAPublicKey):
            try:
                pubkey.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
                return True
            except InvalidSignature:
                return False
            except Exception:
                try:
                    pubkey.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(cert.signature_hash_algorithm),
                            salt_length=padding.PSS.AUTO,
                        ),
                        cert.signature_hash_algorithm,
                    )
                    return True
                except Exception:
                    return False
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
            return True
        elif isinstance(pubkey, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pubkey.verify(cert.signature, cert.tbs_certificate_bytes)
            return True
        elif isinstance(pubkey, dsa.DSAPublicKey):
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_hash_algorithm,
            )
            return True
        else:
            return None
    except InvalidSignature:
        return False
    except Exception:
        return None

