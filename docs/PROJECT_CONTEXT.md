# SecureMailScope — Project Context for Team & AI Agents

> **Purpose of this file:** Share this file at the start of a new ChatGPT/Codex/Antigravity session so the agent immediately understands what the team is building, the current repository state, ownership boundaries, and the next milestone.
>
> This file should be treated as the **working project context**, not as a substitute for the official SIH problem statement.

---

## 1. Project Identity

**Project name:** SecureMailScope  
**SIH Problem ID:** SIH26159  
**Hackathon:** Smart India Hackathon 2026  
**Sponsor:** National Technical Research Organisation (NTRO)  
**Category:** Software  
**Theme:** Blockchain & Cybersecurity

### Official problem focus

SecureMailScope is an **AI-assisted passive network-forensics framework** for analyzing captured network traffic (**PCAP files**) containing SMTP, IMAP, and POP3 communications.

The system should assess the **cryptographic security posture** of enterprise email communications.

The core idea is:

> Take recorded email network traffic, reconstruct email sessions, inspect how encryption was used, detect cryptographic weaknesses, explain the risk, and generate evidence-linked findings and reports.

---

## 2. Simple Explanation

A **PCAP** is like a recording of network communication.

SecureMailScope should:

1. Read a PCAP file.
2. Find email conversations inside it.
3. Identify SMTP / IMAP / POP3 sessions.
4. Detect STARTTLS and TLS behavior.
5. Inspect TLS versions, cipher suites, certificates, keys, and related crypto details.
6. Detect known security weaknesses.
7. Use ML only where it adds value, mainly anomaly detection.
8. Produce a clear risk assessment.
9. Link findings back to the actual session/packet evidence.
10. Show results in a dashboard and export reports.

### Important design principle

We are **not building a new Wireshark** and we are **not inventing encryption**.

We are using existing tools and libraries to convert difficult email PCAP evidence into an understandable, explainable cryptographic security assessment.

---

## 3. Prototype vs Final Product

### SIH Prototype / MVP

The MVP only needs to prove the core idea works.

It should work on selected prepared PCAP files and demonstrate:

- email session identification
- basic session reconstruction
- STARTTLS/TLS analysis
- certificate and cryptographic checks
- deterministic security rules
- explainable risk output
- evidence references
- simple dashboard
- JSON / HTML / PDF reports
- later: ML-based anomaly detection

### Final production product

A future production product would additionally need:

- very large and messy real-world PCAPs
- packet loss / malformed traffic handling
- enterprise authentication and RBAC
- long-term history
- strong audit logging
- monitoring
- backups
- scale
- security hardening
- production-grade reliability
- many edge cases
- possible continuous/live passive monitoring

For SIH, **the prototype comes first**.

---

## 4. Current Technical Strategy

### Core principle

Use **deterministic security rules** for known security facts.

Examples:

- outdated TLS version
- expired certificate
- weak key
- weak/deprecated cipher
- unsafe signature algorithm
- STARTTLS failure
- lack of forward secrecy

Use **ML** mainly for:

- unusual TLS behavior
- crypto configuration drift
- anomalous session patterns
- suspicious deviations from normal behavior

### ML plan

The first ML model is expected to be a small classical model such as **Isolation Forest**.

Possible future classifiers include Random Forest, Logistic Regression, or Gradient Boosting.

No GPU is required. The team has:

- RTX 3050 laptop, 6 GB VRAM
- MacBook Air M2, 8 GB RAM
- MacBook Air M4, 16 GB RAM

The MVP should run on CPU.

---

## 5. Planned End-to-End Flow

```text
PCAP
  ↓
Read traffic
  ↓
Identify SMTP / IMAP / POP3
  ↓
Group packets into sessions
  ↓
Reconstruct email conversations
  ↓
Detect STARTTLS / TLS
  ↓
Extract TLS and certificate metadata
  ↓
Deterministic security rules
  ↓
ML anomaly detection
  ↓
Risk engine
  ↓
Evidence-linked findings
  ↓
Dashboard
  ↓
JSON / HTML / PDF reports
```

---

## 6. Strong Demo Vision

The strongest SIH demo is a **before-vs-after comparison**.

Example:

```text
vulnerable.pcap
    ↓
TLS 1.0
Weak cipher
Certificate problem
Score: 34/100
HIGH RISK

        VS

fixed.pcap
    ↓
TLS 1.3
Strong cipher
Valid certificate
Score: 91/100
LOW RISK
```

The goal is to prove that the tool can detect the weakness, explain it, show evidence, and verify improvement after remediation.

---

## 7. Current Repository

Remote repository:

```text
https://github.com/Daddy-Dagger/SecureMailScope.git
```

Milestones 1, 2, and 3 are integrated into `develop` (Milestone 3 merged at `c7e4706`). The local and remote `lead/core-engine` and `develop` branches were synchronized at that commit. The lead branch now contains the verified Milestone 4 X.509 certificate and cryptographic feature extraction implementation.

### Verified working setup

- Backend starts successfully
- Frontend starts successfully
- Frontend production build succeeds
- Frontend can reach `/health`
- CORS works
- TShark 4.6.8 detected
- pytest passes (140/140 on 2026-09-04: 67 backend/report tests, 67 core unit tests, and 6 generated real-PCAP integration tests)
- Python 3.11 environment exists
- ReportLab 5.0.1 is installed and declared for PDF reporting
- real-PCAP TShark integration tests pass with generated, temporary fixtures
- `.gitignore` is configured
- dataset folders exist
- documentation exists
- shared contracts exist
- CODEOWNERS exists
- no functional regressions were introduced during collaboration restructuring

---

## 8. Repository Structure

```text
SecureMailScope/
├── README.md
├── AGENTS.md
├── CONTRIBUTING.md
├── .env.example
├── .gitignore
├── requirements.txt
├── pytest.ini
├── docker-compose.yml
│
├── .github/
│   ├── CODEOWNERS
│   └── pull_request_template.md
│
├── shared/
│   └── contracts/
│       ├── README.md
│       ├── session_schema.json
│       ├── finding_schema.json
│       └── analysis_result_schema.json
│
├── backend/
│   ├── README.md
│   ├── app/
│   │   ├── main.py
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── README.md
│   │   │   ├── analysis.py
│   │   │   └── reports.py
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── README.md
│   │   │   ├── analysis.py
│   │   │   └── reports.py
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── README.md
│   │   │   ├── analysis_service.py
│   │   │   └── core_adapter.py
│   │   └── utils/
│   │       ├── __init__.py
│   │       └── README.md
│   └── tests/
│       ├── __init__.py
│       ├── README.md
│       ├── test_analysis.py
│       ├── test_api_reports.py
│       ├── test_health.py
│       └── test_reports.py
│
├── core/
│   ├── README.md
│   ├── pcap/
│   │   ├── loader.py
│   │   ├── tshark_adapter.py
│   │   └── session_builder.py
│   ├── protocols/
│   │   ├── smtp.py
│   │   ├── imap.py
│   │   ├── pop3.py
│   │   └── session_reconstruction.py
│   ├── tls/
│   │   ├── handshake.py
│   │   ├── certificate.py
│   │   └── crypto_features.py
│   ├── rules/
│   │   ├── tls_rules.py
│   │   ├── certificate_rules.py
│   │   └── scoring.py
│   └── ml/
│       ├── features.py
│       ├── train.py
│       ├── inference.py
│       └── models/
│
├── frontend/
│   ├── README.md
│   ├── package.json
│   ├── package-lock.json
│   ├── vite.config.js
│   ├── index.html
│   └── src/
│       ├── App.jsx
│       ├── main.jsx
│       └── styles.css
│
├── reports/
│   ├── json_report.py
│   ├── html_report.py
│   └── pdf_report.py
│
├── datasets/
│   ├── README.md
│   ├── normal/
│   ├── weak_tls/
│   ├── certificate_issues/
│   ├── starttls/
│   └── mixed/
│
├── scripts/
│   ├── setup.sh
│   ├── setup.ps1
│   ├── checkpoint.sh
│   ├── checkpoint.ps1
│   ├── team-status.sh
│   ├── team-status.ps1
│   ├── check_tshark.py
│   └── generate_test_data.py
│
├── docs/
│   ├── PROJECT_CONTEXT.md
│   ├── AGENT_WORKFLOW.md
│   ├── architecture.md
│   ├── setup.md
│   ├── api.md
│   └── dataset-guide.md
│
└── tests/
    ├── fixtures/
    ├── integration/
    │   └── test_core_pcap_tshark.py
    ├── unit/
    │   ├── test_core_pcap_sessions.py
    │   ├── test_starttls_reconstruction.py
    │   └── test_tls_handshake.py
    └── e2e/
```

---

## 9. Team Ownership

### Member 1 — Lead / Core Engine
**Branch:** `lead/core-engine`

Owns:
```text
core/pcap/
core/protocols/
core/tls/
core/ml/
shared/contracts/
docs/PROJECT_CONTEXT.md
```

Responsibilities:
- overall architecture
- PCAP reading
- session grouping/reconstruction
- SMTP/IMAP/POP3 extraction
- STARTTLS logic
- TLS handshake extraction
- crypto feature extraction
- ML feature design
- anomaly model
- shared JSON contract evolution
- final core integration

### Member 2 — PCAP Lab / Dataset
**Branch:** `member2/pcap-lab`

Owns:
```text
datasets/
scripts/generate_test_data.py
dataset-related documentation
```

Responsibilities:
- generate test PCAPs
- normal and vulnerable scenarios
- SMTP / IMAP / POP3 traffic generation
- dataset organization
- capture documentation
- Wireshark validation of samples

### Member 3 — Security Rules
**Branch:** `member3/security-rules`

Owns:
```text
core/rules/
```

Responsibilities:
- deterministic security rules
- finding severity
- recommendations
- transparent scoring rules
- rule tests

Important: Member 3 should consume structured session/crypto data and should not parse PCAPs directly.

### Member 4 — Backend + Reports
**Branch:** `member4/backend-reports`

Owns:
```text
backend/
reports/
docs/api.md
```

Responsibilities:
- FastAPI
- upload / analysis API
- response formatting
- backend orchestration
- JSON reports
- HTML reports
- PDF reports
- later database/API integration

### Member 5 — Frontend
**Branch:** `member5/frontend`

Owns:
```text
frontend/
```

Responsibilities:
- upload interface
- analysis status
- risk dashboard
- session table
- finding details
- evidence view
- before/after comparison
- report download UI

Important: Frontend should use mock JSON while backend/core is incomplete.

### Member 6 — Testing + Documentation
**Branch:** `member6/testing-docs`

Owns:
```text
tests/
general docs/
README.md
CONTRIBUTING.md
```

Responsibilities:
- unit/integration/E2E tests
- setup documentation
- QA
- regression checks
- malformed input tests
- screenshots/demo checklist
- architecture/project docs
- release verification

---

## 10. Shared Contract Rule

The most important anti-conflict mechanism is the shared data contract.

Shared contracts live in:

```text
shared/contracts/
```

The lead owns contract changes.

### Current session example

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
  "end_time": "2026-09-02T10:10:15Z"
}
```

This Milestone 1 base object remains valid. Milestone 2 core output additionally
includes optional `application_events` and `transport_security` fields, detailed
in Section 13 and `shared/contracts/session_schema.json`.

### Current finding example

```json
{
  "finding_id": "TLS-001",
  "title": "Deprecated TLS version",
  "severity": "HIGH",
  "explanation": "The session used an outdated TLS version.",
  "recommendation": "Disable outdated TLS versions."
}
```

### Current analysis result example

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

`overall_score` and `risk_level` are intentionally null because they are not implemented yet. Do not fabricate future functionality.

---

## 11. Git Workflow

Main branches:

```text
main
develop
lead/core-engine
member2/pcap-lab
member3/security-rules
member4/backend-reports
member5/frontend
member6/testing-docs
```

### Team Collaboration Model

The team follows a simplified, beginner-friendly Git model designed for six concurrent contributors:

- **One permanent branch per member:**
  - `lead/core-engine`
  - `member2/pcap-lab`
  - `member3/security-rules`
  - `member4/backend-reports`
  - `member5/frontend`
  - `member6/testing-docs`
- **One permanent Draft PR per member:** Each member branch targets `develop` with a permanent Draft PR. Pushing commits automatically updates this live record of work for team visibility without premature merging.
- **One-command checkpoint scripts:** Members do not need complex multi-step Git commands. They run:
  - macOS/Linux: `./scripts/checkpoint.sh "what I worked on"`
  - Windows: `.\scripts\checkpoint.ps1 "what I worked on"`
- **State hierarchy:**
  - `docs/PROJECT_CONTEXT.md` = global confirmed project state
  - Draft PRs = live in-progress work
  - `develop` = confirmed integrated state
  - `main` = stable / demo-ready release state

### Rules

- Do not push feature work directly to `main`.
- `main` = stable/demo-ready code.
- `develop` = integration branch.
- Each member works on their own branch.
- Pull Requests merge member branches into `develop`.
- Tested releases move from `develop` to `main`.
- Keep PRs small.
- Pull/merge latest `develop` regularly.
- Do not edit another member's owned folder without coordination.
- Shared contract changes require lead coordination.

### Commit convention

```text
feat:
fix:
docs:
test:
refactor:
chore:
```

Examples:

```text
feat(pcap): detect SMTP sessions
fix(tls): handle missing handshake metadata
docs(setup): clarify Windows TShark setup
test(api): add health endpoint regression test
```

---

## 12. Current Development Status

### Completed

- repository foundation
- backend starter
- frontend starter
- `/health` endpoint
- backend analysis API foundation (`POST /api/analyze`, Pydantic models matching shared contracts, `AnalysisService` boundary, input validation, and tests)
- backend core-engine analysis integration boundary (`CoreAnalysisEngine` protocol, `DeferredCoreEngineAdapter`, strict Pydantic validation of core outputs against shared contracts, and boundary integration tests)
- JSON report generation (`reports/json_report.py`, deterministic serialization, strict contract validation, and comprehensive tests)
- HTML report generation (`reports/html_report.py`, standalone offline rendering, embedded CSS, security auto-escaping, and comprehensive tests)
- PDF report generation (`reports/pdf_report.py`, standalone printable ReportLab rendering, two-pass numbering canvas, and comprehensive tests)
- backend report download/export API (`POST /api/reports/export`, supporting JSON, HTML, and PDF downloadable attachments, in-memory PDF generation, MIME types, and integration tests)
- Member 4 backend/reporting work from commit `644ea76` integrated into `develop` by merge commit `fcb7d37` and re-verified
- **Milestone 1 VERIFIED on `lead/core-engine`:** validated PCAP/PCAPNG/CAP reading through TShark, total packet counting, bidirectional TCP-flow grouping, SMTP/IMAP/POP3 detection, client/server endpoint identification, per-session packet/timestamp metadata, and shared-contract-compatible structured output
- **Milestone 2 VERIFIED on `lead/core-engine`:** reconstructs ordered, normalized STARTTLS-relevant plaintext events; detects SMTP STARTTLS, IMAP STARTTLS, POP3 STLS, explicit rejection versus incomplete evidence, implicit TLS on ports 465/993/995, and the first TLS record after an upgrade; emits packet/timestamp evidence without retaining arbitrary email bodies or credentials
- **Milestone 1, 2, and 3 INTEGRATED into `develop`:** Milestone 3 commit `e163101` was merged into `develop` through merge commit `c7e4706`, verified with 117 tests plus frontend/TShark/compile/diff checks, and pushed to `origin/develop` and `origin/lead/core-engine`.
- **Milestone 4 VERIFIED on `lead/core-engine`:** extracts factual ordered X.509 certificate chains (`chain_index: 0` for leaf), subject/issuer DNs, serial numbers, SHA-256 fingerprints, ISO 8601 UTC validity dates, days remaining relative to forensic capture timestamps, SANs, factual `self_issued` (`subject == issuer`), cryptographically verified `self_signed`, public-key metadata (algorithm, size_bits, curve), signature algorithms, and certificate frame evidence. Aggregates normalized cryptographic feature vectors (`crypto_features`) for downstream rules and ML. Handles missing certificates gracefully (e.g., encrypted TLS 1.3 -> `certificates: []`, `crypto_features` cert fields null).
- the shared session contract now has additive optional `application_events`, `transport_security`, `tls`, `certificates`, and `crypto_features` fields; the backend Pydantic session model has the minimum corresponding compatibility update while continuing to accept Milestone 1, 2, and 3 session objects
- `PcapAnalysisEngine` implements Member 4's `CoreAnalysisEngine` protocol and is verified through `AnalysisService` dependency injection
- TShark verification
- pytest setup
- project documentation
- team ownership model
- CODEOWNERS
- shared JSON contracts
- branch/workflow planning
- beginner collaboration framework (`AGENTS.md`, POSIX and Windows checkpoint/team-status scripts, permanent Draft PR workflow)
- clean GitHub repository

### NOT implemented yet

- deterministic security rules
- risk scoring
- ML model
- anomaly detection
- final dashboard
- default FastAPI auto-activation of `PcapAnalysisEngine` (the interface and dependency-injection path are verified; the default factory remains deferred)
- before/after comparison

---

## 13. Current Milestone

### Milestone 4 — IMPLEMENTED AND VERIFIED on `lead/core-engine`

> **Identified TLS session → extract factual X.509 certificate chain, cryptographic metadata, and normalized crypto feature vector**

Milestones 1, 2, and 3 are integrated into `develop` (Milestone 3 merged at `c7e4706`). The lead branch was synchronized to that exact commit before Milestone 4 began. Milestone 4 is implemented and verified on the lead branch.

### Required output

```json
{
  "file": "sample.pcap",
  "packet_count": 4281,
  "sessions": [
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
      },
      "tls": {
        "detected": true,
        "handshake_status": "COMPLETE",
        "offered_versions": ["TLS 1.3", "TLS 1.2"],
        "offered_groups": [
          {"id": "0x001d", "name": "x25519"}
        ],
        "version": "TLS 1.3",
        "cipher_suite": {
          "id": "0x1302",
          "name": "TLS_AES_256_GCM_SHA384"
        },
        "key_exchange": {
          "method": "ECDHE",
          "group": {"id": "0x001d", "name": "x25519"}
        },
        "evidence": {
          "client_hello_frame": 21,
          "server_hello_frame": 22,
          "selected_version_frame": 22,
          "selected_cipher_frame": 22,
          "key_exchange_frame": 22,
          "handshake_complete_frame": 26,
          "certificate_frame": 23
        }
      },
      "certificates": [
        {
          "chain_index": 0,
          "subject": "CN=mail.example.com",
          "issuer": "CN=Example Root CA",
          "serial_number": "0x2",
          "fingerprint_sha256": "897241746aa4bb70fddfc33b19184fb55b48663e5cb289f633653d9b19d4202c",
          "not_before": "2026-09-01T00:00:00Z",
          "not_after": "2026-11-30T00:00:00Z",
          "days_remaining": 89,
          "subject_alternative_names": ["mail.example.com"],
          "self_issued": false,
          "self_signed": false,
          "public_key": {
            "algorithm": "RSA",
            "size_bits": 2048,
            "curve": null
          },
          "signature_algorithm": "sha256WithRSAEncryption",
          "evidence": {
            "certificate_frame": 23
          }
        }
      ],
      "crypto_features": {
        "tls_version": "TLS 1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "key_exchange": "ECDHE",
        "named_group": "x25519",
        "certificate_public_key_algorithm": "RSA",
        "certificate_public_key_bits": 2048,
        "certificate_signature_algorithm": "sha256WithRSAEncryption",
        "certificate_days_remaining": 89,
        "certificate_self_signed": false
      }
    }
  ],
  "summary": {
    "smtp_sessions": 1,
    "imap_sessions": 0,
    "pop3_sessions": 0
  }
}
```

### Implemented scope

- X.509 certificate extraction from TShark `tls.handshake.certificate` bytes parsed via `cryptography.x509`
- Ordered certificate chain representation (`chain_index: 0` for leaf, followed by intermediate and root certificates)
- Factual metadata: subject and issuer RFC 4514 DN strings, serial numbers in hex, SHA-256 fingerprints
- Validity date parsing normalized to ISO 8601 UTC with `Z` suffix
- `days_remaining` calculated relative to forensic session/packet reference timestamps rather than wall-clock time
- Subject Alternative Names (`subject_alternative_names`) supporting DNSName, IPAddress, RFC822Name, URI, and other name forms
- Explicit `self_issued` (`subject == issuer`) vs cryptographically verified `self_signed` (signature checked against certificate's own public key)
- Public-key metadata (`algorithm`, `size_bits`, `curve`) covering RSA, EC, DSA, Ed25519, and Ed448
- Signature algorithm extraction
- Evidence tracking: `certificate_frame` preserved on both individual certificate entries and `tls.evidence`
- Normalized `crypto_features` structure aggregating TLS version, cipher suite, key exchange, named group, and leaf certificate properties
- Graceful handling of encrypted or absent certificates (e.g. TLS 1.3 without decryption secrets -> `certificates: []`, `crypto_features` cert fields `null`)
- Safe handling of malformed or partial certificate metadata
- No security scoring, weak cipher flagging, or expired certificate findings (deferred to Milestone 5)
- No OS trust-store validation (factual metadata extraction only)

### Verification

- 23 Milestone 1, 10 Milestone 2, and 12 Milestone 3 unit tests remain green.
- 17 new Milestone 4 certificate unit tests cover RSA, EC, Ed25519, chain ordering, date parsing, epoch float reference timestamps, past expiration, SAN types, missing SANs, self-issued + self-signed, self-issued with spoofed signature, CA-signed, missing cert data, malformed DER bytes, empty bytes, and backward compatibility with Milestone 1–3 sessions.
- 5 new Milestone 4 crypto-feature unit tests cover full aggregation, absent certificates, plaintext sessions, numeric cipher IDs, and ECDSA leaf certs.
- 6 generated real-PCAP integration tests pass, including a new end-to-end integration test verifying multi-certificate chain extraction, frame evidence, and crypto feature synthesis through TShark.
- Full result: 140 passed (67 backend/report, 67 core unit, 6 integration).
- Frontend Vite production build passes (16 modules transformed).
- TShark 4.6.8 check, Python compile check, JSON syntax checks, Pydantic model validation against shared contracts, and `git diff --check` pass with zero errors.

### Files changed for Milestone 4

- Core: `core/tls/certificate.py`, `core/tls/crypto_features.py`, `core/tls/__init__.py`, `core/tls/handshake.py`, `core/pcap/tshark_adapter.py`, `core/pcap/session_builder.py`, `core/tls/README.md`, and `core/README.md`.
- Contract: `shared/contracts/session_schema.json` and `shared/contracts/README.md` add optional `certificates` and `crypto_features` structures and `certificate_frame` evidence.
- Minimal backend compatibility: `backend/app/models/analysis.py` adds `CertificatePublicKey`, `CertificateEvidence`, `CertificateMetadata`, `CryptoFeatures`, and fields in `SessionSchema` and `TLSHandshakeEvidence`.
- Tests: new `tests/unit/test_tls_certificate.py` and `tests/unit/test_crypto_features.py`, plus compatibility/integration updates in `tests/unit/test_core_pcap_sessions.py` and `tests/integration/test_core_pcap_tshark.py`.
- Project state: `docs/PROJECT_CONTEXT.md`.

### Shared contract additions

- optional `certificates`: array of certificate metadata objects with `chain_index`, `subject`, `issuer`, `serial_number`, `fingerprint_sha256`, `not_before`, `not_after`, `days_remaining`, `subject_alternative_names`, `self_issued`, `self_signed`, `public_key`, `signature_algorithm`, and `evidence`
- optional `crypto_features`: normalized factual feature vector with `tls_version`, `cipher_suite`, `key_exchange`, `named_group`, `certificate_public_key_algorithm`, `certificate_public_key_bits`, `certificate_signature_algorithm`, `certificate_days_remaining`, and `certificate_self_signed`
- optional `tls.evidence.certificate_frame`: frame number containing the certificate handshake message
- all new fields are optional in the JSON Schema and backend Pydantic model, preserving 100% backward compatibility with Milestone 1–3 sessions

### Known Milestone 4 limitations

- In TLS 1.3, Certificate messages are typically encrypted unless decryption secrets (SSLKEYLOGFILE) are provided to TShark; captures without observable certificate messages produce `certificates: []` and `null` certificate crypto features.
- Trust-chain validation against operating system or CA trust stores is deliberately not performed at this stage; only factual chain ordering as presented in the capture is recorded.
- `days_remaining` is computed relative to forensic capture/packet timestamps; if no reference timestamp is available, it remains `null`.
- Raw certificate DER or PEM bodies are intentionally excluded from normal session output to keep payloads compact and focused on security metadata.
- Cryptographic verification of `self_signed` is performed against the certificate's own public key for supported algorithms (RSA, EC, Ed25519, Ed448, DSA); unsupported algorithms report `self_signed: null` while preserving `self_issued: true`.

### Do NOT implement yet

- deterministic security rules (weak ciphers, deprecated TLS, expired certs)
- security scoring
- ML
- anomaly detection
- final dashboard
- report redesign
- database persistence

---

## 14. Planned Milestone Order

1. **INTEGRATED into develop:** PCAP → SMTP/IMAP/POP3 sessions → JSON
2. **INTEGRATED into develop:** Session reconstruction + STARTTLS/STLS and implicit-TLS detection
3. **INTEGRATED into develop:** TLS handshake metadata extraction
4. **VERIFIED on lead branch:** X.509 certificate and cryptographic feature extraction
5. **NEXT only after integration and explicit confirmation:** Deterministic security rules
6. Generate controlled PCAP dataset
7. Risk scoring
8. ML feature dataset + Isolation Forest anomaly detection
9. Backend integration
10. Dashboard integration
11. JSON / HTML / PDF reports
12. Before-vs-after comparison
13. Testing, performance, offline demo hardening
14. Final SIH polish

---

## 15. Planned Test PCAP Dataset

```text
datasets/
├── normal/
├── weak_tls/
├── certificate_issues/
├── starttls/
└── mixed/
```

Possible scenarios:

- normal modern TLS
- outdated TLS
- expired certificate
- self-signed certificate
- certificate change
- weak crypto
- STARTTLS success
- STARTTLS failure
- mixed sessions

All active tests must be performed only on team-owned or explicitly authorized infrastructure.

---

## 16. Cost Constraint

Prototype target: **₹0**

Use:

- existing laptops
- GitHub
- Python
- Wireshark/TShark
- PyShark / Scapy
- cryptography
- scikit-learn
- FastAPI
- React/Vite
- SQLite
- local test infrastructure

Do not introduce paid APIs, cloud GPUs, paid datasets, enterprise subscriptions, or unnecessary cloud infrastructure unless absolutely required and explicitly approved.

---

## 17. Important Things the AI Agent Must NOT Do

1. Do not redesign the whole project without a concrete reason.
2. Do not move working modules unnecessarily.
3. Do not implement future milestones early.
4. Do not invent SIH requirements.
5. Do not fabricate test results.
6. Do not invent security claims.
7. Do not add unnecessary frameworks.
8. Do not introduce TensorFlow/PyTorch unless later justified.
9. Do not require a GPU.
10. Do not introduce Kubernetes, Kafka, Redis, Celery, vector DBs, or microservices without a demonstrated need.
11. Do not use AI/ML where deterministic rules are more reliable.
12. Do not let ML override known security facts.
13. Do not make unsupported "first in the world", "100% secure", or "no competitor" claims.
14. Do not change shared contracts silently.
15. Do not edit another member's ownership area without explaining why.
16. Always preserve existing tests and working behavior.
17. Keep code understandable for a B.Tech CSE student team.
18. Prefer small, reviewable changes.
19. Run tests after changes.
20. State limitations instead of inventing behavior.

---

## 18. Instructions for a New AI Agent

If this file is provided at the beginning of a new chat, the agent should:

1. Read this entire file first.
2. Treat it as the current project state.
3. Ask which team member/branch the user is working on only if it is not obvious.
4. Respect the ownership map.
5. Respect the milestone sequence.
6. Check repository files before making structural assumptions.
7. Work only on the requested milestone/task.
8. Preserve shared contracts unless an explicit contract change is approved.
9. Provide commands/code appropriate to the member's owned area.
10. Avoid duplicating work already assigned to another member.
11. Explain technical concepts in simple language when the team asks.
12. Keep SecureMailScope local-first, ₹0-first, and prototype-focused.

---

## 19. One-Sentence Project Summary

> **SecureMailScope is a local-first forensic tool that turns captured email network traffic into explainable cryptographic security findings by reconstructing SMTP/IMAP/POP3 sessions, analyzing TLS/STARTTLS and certificates, applying deterministic security rules, and later using lightweight ML to flag unusual behavior.**

---

## 20. Immediate Next Action

> Integrate Milestone 4 into `develop`, then begin Milestone 5: deterministic cryptographic security rules.

Do not begin Milestone 5 or any rules, scoring, ML, or dashboard work without explicit confirmation.


---

## 21. Automatic Project-Context Maintenance Rule

This file is intended to stay synchronized with the real repository.

### Mandatory rule for every coding-agent session

Whenever a CLI coding agent such as Codex, Antigravity, or another repository-aware agent completes a meaningful task, milestone, structural change, contract change, dependency change, branch/workflow change, or test-result change, the agent must also review and update this file before finishing.

The repository copy should live at:

```text
docs/PROJECT_CONTEXT.md
```

### The agent must update this file when any of the following changes

- a milestone is completed
- a new milestone starts
- repository structure changes
- module ownership changes
- branch strategy changes
- shared JSON/data contracts change
- a new dependency is introduced
- a major architectural decision is made
- PCAP generation strategy changes
- test coverage or verification status changes materially
- a new feature becomes genuinely implemented
- a planned feature is removed or postponed
- ML strategy changes
- prototype scope changes
- a known limitation is discovered
- a significant bug or technical risk is discovered
- demo strategy changes

### What must be updated

At minimum, check and update the affected parts of:

1. Current Repository
2. Repository Structure
3. Team Ownership
4. Shared Contracts
5. Current Development Status
6. Current Milestone
7. Planned Milestone Order
8. Known limitations / risks
9. Immediate Next Action

### Accuracy rules

The context file must reflect what is actually present in the repository.

Do not mark a feature as implemented merely because:

- a placeholder file exists
- a mock exists
- a TODO exists
- an AI agent proposed it
- a test fixture simulates it

Only call something implemented when working code exists and the relevant verification has passed.

When useful, label state clearly as:

```text
PLANNED
PARTIAL
BLOCKED
EXPERIMENTAL
IMPLEMENTED
VERIFIED
```

### Automatic end-of-task routine

Before a coding agent finishes any meaningful task, it should:

```text
1. Run the relevant tests/checks.
2. Inspect git diff/status.
3. Determine what project facts changed.
4. Update docs/PROJECT_CONTEXT.md.
5. Add a short entry to the Context Update Log.
6. Re-run any documentation/schema checks if relevant.
7. Include the context-file update in the same PR/commit as the related work.
```

### Context Update Log

Use this format:

```text
YYYY-MM-DD — [branch] — short description
```

Example:

```text
2026-09-03 — lead/core-engine — Milestone 1 completed: SMTP/IMAP/POP3 session extraction now returns contract-valid structured JSON.
```

### Current log

```text
2026-09-02 — develop — Initial development foundation, ownership boundaries, CODEOWNERS, and shared contracts established.
2026-09-02 — main — Established canonical docs/PROJECT_CONTEXT.md, docs/AGENT_WORKFLOW.md, PR template, and context maintenance procedures.
2026-09-02 — member4/backend-reports — Implemented backend analysis API foundation and updated API documentation.
2026-09-02 — lead/core-engine — Established beginner collaboration model (AGENTS.md, checkpoint and team-status scripts for POSIX & Windows, permanent Draft PR workflow).
2026-09-03 — member4/backend-reports — Prepared backend analysis integration boundary for core-engine structured results.
2026-09-03 — member4/backend-reports — Implemented and verified JSON report generation.
2026-09-03 — member4/backend-reports — Implemented and verified offline HTML report generation.
2026-09-03 — member4/backend-reports — Implemented and verified PDF report generation.
2026-09-03 — member4/backend-reports — Implemented backend report download/export API, supporting JSON, HTML, and PDF with full test coverage and API docs.
2026-09-04 — develop — Integrated and re-verified Member 4 backend/reporting foundation from commit 644ea76.
2026-09-04 — lead/core-engine — Synchronized with develop at fcb7d37 and implemented verified Milestone 1 TShark PCAP-to-email-session structured output (93 tests passed).
2026-09-04 — lead/core-engine — Implemented and verified Milestone 2 metadata-only session reconstruction, SMTP/IMAP STARTTLS, POP3 STLS, implicit TLS classification, TLS-transition evidence, and additive shared/backend contract compatibility (104 tests passed).
2026-09-04 — develop — Integrated verified Milestones 1 and 2 through merge commit 625cb88 and pushed the synchronized integration state.
2026-09-04 — lead/core-engine — Synchronized with develop at 625cb88, then implemented and verified Milestone 3 TLS handshake version, cipher, key-exchange, state, and evidence extraction (117 tests passed).
2026-09-04 — develop — Integrated verified Milestone 3 TLS handshake metadata extraction through merge commit c7e4706 and pushed the synchronized integration state.
2026-09-04 — lead/core-engine — Synchronized with develop at c7e4706, then implemented and verified Milestone 4 X.509 certificate chain and cryptographic feature extraction (140 tests passed).
```

---

## 22. Mandatory CLI Agent Context-Update Instruction

Include this instruction in every future implementation prompt:

```text
PROJECT CONTEXT MAINTENANCE — MANDATORY

Before making changes, read:

docs/PROJECT_CONTEXT.md

Treat it as the current project-state reference, but verify relevant claims against the actual repository before relying on them.

After completing the requested task:

1. Run all relevant verification/tests.
2. Review the actual files changed and resulting capabilities.
3. Update docs/PROJECT_CONTEXT.md to reflect the new real repository state.
4. Update only sections affected by this work.
5. Move completed items from NOT IMPLEMENTED/PLANNED to IMPLEMENTED only when they genuinely work.
6. Update the Current Milestone and Immediate Next Action if the milestone state changed.
7. Update repository structure or shared-contract sections if files/contracts changed.
8. Add a dated entry to the Context Update Log with the current branch and a concise summary.
9. Do not fabricate completion, test results, architecture, or functionality.
10. Include the context-file change in the same PR/commit as the implementation work.

If the requested task produces no meaningful project-context change, explicitly state:

"PROJECT_CONTEXT.md reviewed — no update required."
```

---

## 23. One-Time Setup for Automatic Context Maintenance

The repository should use this canonical file:

```text
docs/PROJECT_CONTEXT.md
```

Recommended setup:

1. Place this file at `docs/PROJECT_CONTEXT.md`.
2. Commit it to the repository.
3. Add a rule to `CONTRIBUTING.md` stating that meaningful feature PRs must review/update the project context.
4. Add a Pull Request checklist item:

```text
- [ ] docs/PROJECT_CONTEXT.md reviewed and updated if project state changed
```

5. Add the context-maintenance instruction from Section 22 to every future CLI task prompt.
6. The coding agent should update the context file automatically as part of its normal task completion.
7. Human reviewers should reject a PR if the implementation materially changes project state but the context file remains stale.

### Important limitation

A coding agent can only update the file automatically when it has access to the repository and the prompt explicitly instructs it to do so.

Therefore:

> The canonical truth is the repository plus `docs/PROJECT_CONTEXT.md`, not any individual chat history.

---

## 24. One-Time Context File Setup Prompt for a Coding CLI

Use this prompt once to configure the repository around the context file:

```text
You are working inside the SecureMailScope repository.

This task is ONLY to establish automatic project-context maintenance.
Do not implement cybersecurity functionality.
Do not modify application behavior.

GOAL

Create a canonical repository context file and make future coding work keep it synchronized automatically.

INPUT

A project context Markdown file may already exist in the repository root as:

SecureMailScope_Project_Context.md

or may already exist as:

docs/PROJECT_CONTEXT.md

TASKS

1. Inspect the repository and locate the project context Markdown file.

2. Ensure the canonical location is:

docs/PROJECT_CONTEXT.md

If the file exists elsewhere, copy or move it safely to this path.
Do not lose content.

3. Read the entire context file.

4. Verify that it contains an "Automatic Project-Context Maintenance Rule" section.

If missing, add one requiring coding agents to review and update the context document after meaningful repository changes.

5. Ensure the context file contains a "Context Update Log" using:

YYYY-MM-DD — branch-name — concise description

6. Add this entry if no equivalent entry exists:

2026-09-02 — develop — Initial development foundation, ownership boundaries, CODEOWNERS, and shared contracts established.

7. Update CONTRIBUTING.md with a concise section titled:

Project Context Maintenance

State:

- docs/PROJECT_CONTEXT.md is the canonical AI/team context file.
- Every meaningful implementation PR must review it.
- Update it whenever implementation status, architecture, contracts, dependencies, ownership, milestones, limitations, or repository structure materially change.
- Never mark a feature implemented unless working code and relevant verification exist.
- Context changes should normally be committed with the related implementation.

8. If a Pull Request template exists, add:

- [ ] docs/PROJECT_CONTEXT.md reviewed and updated if project state changed

If no PR template exists, create:

.github/pull_request_template.md

Keep it short and include:
- tests run
- ownership respected
- shared contracts reviewed
- PROJECT_CONTEXT.md reviewed/updated

9. Ensure CODEOWNERS assigns docs/PROJECT_CONTEXT.md to the lead.

If CODEOWNERS currently has a broad /docs/ owner, add a more specific rule AFTER it:

/docs/PROJECT_CONTEXT.md @LEAD_GITHUB

Preserve existing precedence rules.

10. Add:

docs/AGENT_WORKFLOW.md

It should explain this workflow:

READ CONTEXT
→ VERIFY REPOSITORY
→ IMPLEMENT ONLY REQUESTED SCOPE
→ TEST
→ UPDATE PROJECT_CONTEXT
→ REPORT RESULTS

Include this mandatory ending instruction:

"Before finishing, update docs/PROJECT_CONTEXT.md if this task changed the real project state. If it did not, explicitly state that the file was reviewed and no update was required."

11. Do NOT introduce hooks, bots, CI services, GitHub Actions, or external automation yet.

The goal is reliable prompt-driven automation, not unnecessary infrastructure.

12. Run existing tests/build checks after the documentation/setup changes to verify no regression.

13. Do not commit or push unless explicitly requested.

FINAL RESPONSE

Report:

1. Canonical context-file path.
2. Files created.
3. Files modified.
4. CONTRIBUTING rule added.
5. PR checklist added.
6. CODEOWNERS rule added/verified.
7. AGENT_WORKFLOW.md status.
8. Test/build verification.
9. Confirmation that no application behavior changed.
10. Exact sentence that future CLI prompts must contain:

"Read docs/PROJECT_CONTEXT.md before starting and update it before finishing whenever the real project state changes."
```

---

## 25. Recommended Header for Every Future CLI Task

Begin future Codex/Antigravity CLI prompts with:

```text
SECUREMAILSCOPE AGENT RULES

1. Read docs/PROJECT_CONTEXT.md completely before starting.
2. Verify relevant context against the actual repository.
3. Respect CODEOWNERS and team ownership boundaries.
4. Work only on the requested milestone/task.
5. Do not silently change shared contracts.
6. Run relevant tests/checks before finishing.
7. Update docs/PROJECT_CONTEXT.md if the real project state changed.
8. Add a dated Context Update Log entry when updating it.
9. Never claim unimplemented functionality is complete.
10. Include context changes in the same PR/commit as the work.

If no context update is necessary, explicitly report:

"PROJECT_CONTEXT.md reviewed — no update required."
```

Then append the specific milestone/task prompt below it.
