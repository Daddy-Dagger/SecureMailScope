"""Analysis request and response schemas matching shared data contracts.

These models strictly mirror:
- shared/contracts/analysis_result_schema.json
- shared/contracts/session_schema.json
- shared/contracts/finding_schema.json
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ProtocolSummary(BaseModel):
    """Session counts per supported email protocol."""

    model_config = ConfigDict(extra="forbid")

    smtp_sessions: int = Field(
        ...,
        ge=0,
        description="Count of identified SMTP sessions",
    )
    imap_sessions: int = Field(
        ...,
        ge=0,
        description="Count of identified IMAP sessions",
    )
    pop3_sessions: int = Field(
        ...,
        ge=0,
        description="Count of identified POP3 sessions",
    )


class ApplicationEvent(BaseModel):
    """Normalized protocol event retained without message or credential content."""

    model_config = ConfigDict(extra="forbid")

    direction: Literal["CLIENT_TO_SERVER", "SERVER_TO_CLIENT"]
    kind: Literal["GREETING", "COMMAND", "CAPABILITY", "RESPONSE", "TLS_START"]
    name: str
    frame_number: int = Field(..., ge=1)
    timestamp: str
    tag: str | None = None


class TransportSecurityEvidence(BaseModel):
    """Packet references supporting the observed upgrade decision."""

    model_config = ConfigDict(extra="forbid")

    advertised_frame: int | None = Field(default=None, ge=1)
    request_frame: int | None = Field(default=None, ge=1)
    accept_frame: int | None = Field(default=None, ge=1)
    tls_start_frame: int | None = Field(default=None, ge=1)


class TransportSecurity(BaseModel):
    """Common STARTTLS/STLS or implicit-TLS transition metadata."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["PLAINTEXT", "STARTTLS", "IMPLICIT_TLS", "UNKNOWN"]
    upgrade_status: Literal[
        "NOT_APPLICABLE",
        "NOT_ADVERTISED",
        "ADVERTISED_NOT_REQUESTED",
        "REQUESTED",
        "ACCEPTED",
        "UPGRADED",
        "FAILED",
        "INCOMPLETE",
        "UNKNOWN",
    ]
    advertised: bool
    requested: bool
    accepted: bool
    tls_detected: bool
    upgrade_command: Literal["STARTTLS", "STLS"] | None
    evidence: TransportSecurityEvidence


class TLSNamedGroup(BaseModel):
    """Numeric and normalized name for an observed TLS named group."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str | None


class TLSCipherSuite(BaseModel):
    """Numeric and normalized name for a ServerHello cipher selection."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str | None


class TLSKeyExchange(BaseModel):
    """Factual key-exchange family and selected group where derivable."""

    model_config = ConfigDict(extra="forbid")

    method: Literal["ECDHE", "DHE", "RSA", "PSK", "UNKNOWN"]
    group: TLSNamedGroup | None


class TLSHandshakeEvidence(BaseModel):
    """Packet references supporting TLS handshake metadata."""

    model_config = ConfigDict(extra="forbid")

    client_hello_frame: int | None = Field(default=None, ge=1)
    server_hello_frame: int | None = Field(default=None, ge=1)
    selected_version_frame: int | None = Field(default=None, ge=1)
    selected_cipher_frame: int | None = Field(default=None, ge=1)
    key_exchange_frame: int | None = Field(default=None, ge=1)
    handshake_complete_frame: int | None = Field(default=None, ge=1)
    alert_frame: int | None = Field(default=None, ge=1)
    certificate_frame: int | None = Field(default=None, ge=1)


class TLSHandshakeMetadata(BaseModel):
    """Observable TLS handshake facts without certificate or risk analysis."""

    model_config = ConfigDict(extra="forbid")

    detected: bool
    handshake_status: Literal[
        "NOT_APPLICABLE",
        "DETECTED",
        "INCOMPLETE",
        "COMPLETE",
        "FAILED",
        "UNKNOWN",
    ]
    offered_versions: list[str]
    offered_groups: list[TLSNamedGroup] = Field(
        ...,
        description="Named groups advertised by ClientHello",
    )
    version: str | None
    cipher_suite: TLSCipherSuite | None
    key_exchange: TLSKeyExchange | None
    evidence: TLSHandshakeEvidence


class CertificatePublicKey(BaseModel):
    """Observable public key algorithm, bit length, and curve."""

    model_config = ConfigDict(extra="forbid")

    algorithm: str
    size_bits: int | None = None
    curve: str | None = None


class CertificateEvidence(BaseModel):
    """Packet references supporting observed certificate data."""

    model_config = ConfigDict(extra="forbid")

    certificate_frame: int | None = Field(default=None, ge=1)


class CertificateMetadata(BaseModel):
    """Observable X.509 certificate metadata without trust validation."""

    model_config = ConfigDict(extra="forbid")

    chain_index: int = Field(..., ge=0)
    subject: str
    issuer: str
    serial_number: str
    fingerprint_sha256: str | None = None
    not_before: str
    not_after: str
    days_remaining: int | None = None
    subject_alternative_names: list[str] = Field(default_factory=list)
    self_issued: bool
    self_signed: bool | None = None
    public_key: CertificatePublicKey
    signature_algorithm: str | None = None
    evidence: CertificateEvidence = Field(default_factory=CertificateEvidence)


class CryptoFeatures(BaseModel):
    """Normalized factual cryptographic feature vector."""

    model_config = ConfigDict(extra="forbid")

    tls_version: str | None = None
    cipher_suite: str | None = None
    key_exchange: str | None = None
    named_group: str | None = None
    certificate_public_key_algorithm: str | None = None
    certificate_public_key_bits: int | None = None
    certificate_signature_algorithm: str | None = None
    certificate_days_remaining: int | None = None
    certificate_self_signed: bool | None = None


class SessionSchema(BaseModel):
    """Schema definition for an extracted email protocol session."""

    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(..., description="Unique session identifier")
    protocol: Literal["SMTP", "IMAP", "POP3"] = Field(
        ...,
        description="Application layer email protocol",
    )
    client_ip: str = Field(..., description="Client IPv4 or IPv6 address")
    client_port: int = Field(
        ...,
        ge=1,
        le=65535,
        description="Client source port",
    )
    server_ip: str = Field(..., description="Server IPv4 or IPv6 address")
    server_port: int = Field(
        ...,
        ge=1,
        le=65535,
        description="Server destination port",
    )
    packet_count: int = Field(
        ...,
        ge=0,
        description="Number of packets in this session",
    )
    start_time: str = Field(
        ...,
        description="Session start timestamp (ISO 8601)",
    )
    end_time: str = Field(
        ...,
        description="Session end timestamp (ISO 8601)",
    )
    application_events: list[ApplicationEvent] | None = Field(
        default=None,
        description="Ordered metadata-only STARTTLS-relevant protocol events",
    )
    transport_security: TransportSecurity | None = Field(
        default=None,
        description="Observed STARTTLS/STLS or implicit-TLS transition state",
    )
    tls: TLSHandshakeMetadata | None = Field(
        default=None,
        description="Observable TLS handshake metadata",
    )
    certificates: list[CertificateMetadata] = Field(
        default_factory=list,
        description="Observable X.509 certificate chain metadata",
    )
    crypto_features: CryptoFeatures | None = Field(
        default=None,
        description="Normalized factual cryptographic feature summary",
    )


class FindingSchema(BaseModel):
    """Minimal schema definition for security findings identified by rules."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(
        ...,
        description="Unique identifier for the finding type or rule",
    )
    title: str = Field(
        ...,
        description="Short descriptive title of the finding",
    )
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO"] = Field(
        ...,
        description="Finding severity level",
    )
    explanation: str = Field(
        ...,
        description="Detailed explanation of the security issue",
    )
    recommendation: str = Field(
        ...,
        description="Recommended remediation steps",
    )


class AnalysisResultResponse(BaseModel):
    """Top-level PCAP analysis result response model matching analysis_result_schema.json."""

    model_config = ConfigDict(extra="forbid")

    file: str = Field(..., description="Name or path of the analyzed PCAP file")
    packet_count: int = Field(..., ge=0, description="Total count of processed packets")
    summary: ProtocolSummary = Field(
        ...,
        description="Session counts per supported email protocol",
    )
    sessions: list[SessionSchema] = Field(
        default_factory=list,
        description="Extracted email protocol sessions",
    )
    findings: list[FindingSchema] = Field(
        default_factory=list,
        description="Security findings produced by security rules",
    )
    overall_score: float | None = Field(
        default=None,
        description="Overall security posture score (null until ML/scoring is implemented)",
    )
    risk_level: str | None = Field(
        default=None,
        description="Overall risk classification level (null until risk assessment is implemented)",
    )
