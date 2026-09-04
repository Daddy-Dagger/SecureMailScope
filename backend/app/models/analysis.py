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
