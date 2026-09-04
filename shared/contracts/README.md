# Shared Data Contracts

This directory defines the JSON schema contracts for SecureMailScope.

## Purpose and Governance

- **Role**: Shared data contracts establish clear interface boundaries between the PCAP parsing engine, security analysis rules, API responses, and frontend UI components.
- **Ownership**: Maintained and controlled exclusively by the **Lead / Member 1**. Any changes to existing fields or additions of new contracts must be coordinated with and approved by the Lead.
- **Runtime Status**: These schemas are currently for **documentation, design contracts, and mocking purposes only**. They are not yet wired directly into runtime code.

## Schemas

1. [`session_schema.json`](session_schema.json) — Schema for individual email protocol sessions (SMTP, IMAP, POP3) extracted from PCAP network captures.
2. [`finding_schema.json`](finding_schema.json) — Schema for security findings detected by deterministic analysis rules.
3. [`analysis_result_schema.json`](analysis_result_schema.json) — Top-level schema encapsulating capture metadata, protocol summary, extracted sessions, security findings, and scoring placeholders.

---

## Safe Minimal Schema Examples

### Session Schema Example

```json
{
  "session_id": "smtp-001",
  "protocol": "SMTP",
  "client_ip": "192.168.1.10",
  "client_port": 51544,
  "server_ip": "192.168.1.20",
  "server_port": 25,
  "packet_count": 63,
  "start_time": "2026-09-02T10:10:10Z",
  "end_time": "2026-09-02T10:10:15Z",
  "application_events": [
    {
      "direction": "CLIENT_TO_SERVER",
      "kind": "COMMAND",
      "name": "STARTTLS",
      "frame_number": 19,
      "timestamp": "2026-09-02T10:10:12Z"
    }
  ],
  "transport_security": {
    "mode": "STARTTLS",
    "upgrade_status": "UPGRADED",
    "advertised": true,
    "requested": true,
    "accepted": true,
    "tls_detected": true,
    "upgrade_command": "STARTTLS",
    "evidence": {
      "advertised_frame": 17,
      "request_frame": 19,
      "accept_frame": 20,
      "tls_start_frame": 21
    }
  }
}
```

`application_events` and `transport_security` are additive Milestone 2 fields.
They are optional in the JSON Schema so previously valid Milestone 1 session
documents remain valid. Core-engine output includes them for newly analyzed
sessions. POP3 reports `upgrade_command: "STLS"` while using the same common
`upgrade_status` vocabulary. No TLS version, cipher, or certificate fields are
part of Milestone 2.

Milestone 3 adds the optional `tls` object. It records detection and handshake
status, offered/selected versions, selected cipher ID/name, factual key-exchange
family/group metadata, and packet evidence. The TLS 1.3 selected version comes
from ServerHello `supported_versions` when observable rather than the legacy
record/hello compatibility value. Unknown cipher or group IDs remain available
with a null name; no weak/strong classification is performed. Certificate fields
remain deferred.

### Finding Schema Example

```json
{
  "finding_id": "TLS-001",
  "title": "Deprecated TLS version",
  "severity": "HIGH",
  "explanation": "The session used an outdated TLS version.",
  "recommendation": "Disable outdated TLS versions."
}
```

### Analysis Result Schema Example

```json
{
  "file": "sample.pcap",
  "packet_count": 4281,
  "summary": {
    "smtp_sessions": 1,
    "imap_sessions": 0,
    "pop3_sessions": 0
  },
  "sessions": [],
  "findings": [],
  "overall_score": null,
  "risk_level": null
}
```

> **Important**:
> `overall_score` and `risk_level` may remain `null` because those features are not yet implemented.
> Do NOT pretend future fields are already supported.

---

## Team Usage Guidelines

- **Member 5 (Frontend)**: Use mock JSON adhering to `analysis_result_schema.json` when the backend analysis endpoint is incomplete.
- **Member 4 (Backend)**: Return mocked core output matching `analysis_result_schema.json` when core engine analysis modules are incomplete.
- **Member 3 (Security Rules)**: Consume structured session objects matching `session_schema.json` rather than parsing raw PCAP files directly, and emit finding objects conforming to `finding_schema.json`.
- **Member 6 (Testing & Docs)**: Use these contract schemas to generate test fixtures and assert response compliance across integration tests.
