# Member 2 — PCAP Lab & Synthetic Dataset Context

> **Workstream:** `member2/pcap-lab`<br>
> **Ownership:** Member 2 (Datasets & Test Traffic Generation) — Currently taken over by Member 4 (Backend).<br>
> **Status:** IMPLEMENTED & VERIFIED

---

## 1. Workstream Overview

The Member 2 workstream provides reproducible, safe, offline synthetic network captures (`.pcap`) designed to test and demonstrate SecureMailScope's forensic analysis capabilities across:
- Plaintext email session identification (SMTP, IMAP, POP3)
- STARTTLS and STLS protocol state machine tracking
- TLS handshake version, cipher suite, and key-exchange inspection
- X.509 certificate chain decoding, validity calculation, and SAN inspection
- Multi-protocol concurrent traffic extraction

All test captures are generated deterministically using Scapy without real-world traffic, credentials, or network socket interaction.

---

## 2. Generator Implementation (`scripts/generate_test_data.py`)

The primary entry point is:
```text
scripts/generate_test_data.py
```

### Key Technical Architecture:
1. **Scapy Packet Assembly:** Builds full Ethernet/IP/TCP packet frames with explicit MAC addresses (`02:00:00:00:00:01` and `02:00:00:00:00:02`) to completely avoid OS Berkeley Packet Filter (BPF) access or interface lookups.
2. **RFC-Compliant TLS Record Formatting:** Directly constructs standard TLS Record (ContentType 0x16 Handshake) and Handshake messages (ClientHello, ServerHello, Certificate) conforming to RFC 5246 (TLS 1.2) and RFC 2246 (TLS 1.0).
3. **In-Memory Cryptography:** Generates synthetic RSA 2048-bit keypairs in memory to assemble valid, expired, self-signed, and SAN-customized X.509 DER certificates via the `cryptography` library.
4. **Deterministic Timestamps & Addressing:** Uses fixed epoch timestamps (`BASE_TIMESTAMP = 1_788_220_800.0`, corresponding to 2026-09-01T00:00:00Z) and standardized IP subnets (`192.168.1.0/24`).

---

## 3. Scenario Catalog

The generator produces 11 distinct PCAP files across 5 scenario categories in `datasets/`:

### Scenario 1: `normal` (`datasets/normal/`)
- **`normal_smtp_starttls.pcap`** (11 packets, 2577 bytes):
  - Protocol: SMTP on port 25
  - Features: Full TCP 3-way handshake, EHLO greeting, 250-STARTTLS advertisement, STARTTLS command, 220 accept, TLS 1.2 handshake (ECDHE-RSA-AES128-GCM-SHA256), and valid CA-signed X.509 certificate chain.
  - Expected State: `protocol="SMTP"`, `upgrade_status="UPGRADED"`, `tls.version="TLS 1.2"`.

### Scenario 2: `weak_tls` (`datasets/weak_tls/`)
- **`weak_tls10_smtp.pcap`** (10 packets, 958 bytes):
  - Protocol: SMTP on port 25
  - Features: Deprecated TLS 1.0 handshake with static RSA cipher `TLS_RSA_WITH_AES_128_CBC_SHA` (`0x002F`). No forward secrecy.
  - Expected State: `tls.version="TLS 1.0"`, `cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA"`, `key_exchange.method="RSA"`.
- **`weak_tls11_imap.pcap`** (10 packets, 981 bytes):
  - Protocol: IMAP on port 143
  - Features: Deprecated TLS 1.1 handshake with static RSA cipher `TLS_RSA_WITH_AES_256_CBC_SHA` (`0x0035`).

### Scenario 3: `certificate_issues` (`datasets/certificate_issues/`)
- **`cert_expired_smtp.pcap`** (11 packets, 1787 bytes):
  - Features: SMTP STARTTLS presenting an X.509 certificate whose validity ended on 2020-01-01 (`days_remaining < 0` relative to 2026 capture timestamp).
- **`cert_self_signed_smtp.pcap`** (11 packets, 1784 bytes):
  - Features: SMTP STARTTLS presenting a self-issued and self-signed certificate (`subject == issuer == CN=self-signed.example.com`).
- **`cert_missing_san_imap.pcap`** (11 packets, 1764 bytes):
  - Features: IMAP STARTTLS presenting an X.509 certificate with no Subject Alternative Name extension (`subject_alternative_names: []`).

### Scenario 4: `starttls` (`datasets/starttls/`)
- **`starttls_upgrade_success.pcap`** (9 packets, 843 bytes): Successful negotiation -> `UPGRADED`.
- **`starttls_rejected.pcap`** (9 packets, 820 bytes): Server rejects with `454 4.7.0 TLS not available` -> `FAILED`.
- **`starttls_not_advertised.pcap`** (8 packets, 745 bytes): Server capabilities omit STARTTLS -> `NOT_ADVERTISED`, `mode="PLAINTEXT"`.
- **`starttls_advertised_not_requested.pcap`** (8 packets, 727 bytes): Server advertises STARTTLS, but client sends plaintext commands -> `ADVERTISED_NOT_REQUESTED`.

### Scenario 5: `mixed` (`datasets/mixed/`)
- **`mixed_email_traffic.pcap`** (27 packets, 2465 bytes):
  - Features: Multi-stream capture containing concurrent SMTP (port 25), IMAP (port 143), and POP3 (port 110) sessions.
  - Expected State: `summary.smtp_sessions=1`, `summary.imap_sessions=1`, `summary.pop3_sessions=1`.

---

## 4. CLI Usage

```bash
# Generate all scenarios into datasets/
python scripts/generate_test_data.py --all

# Generate a single scenario
python scripts/generate_test_data.py --scenario normal
python scripts/generate_test_data.py --scenario weak_tls
python scripts/generate_test_data.py --scenario certificate_issues
python scripts/generate_test_data.py --scenario starttls
python scripts/generate_test_data.py --scenario mixed

# List scenarios
python scripts/generate_test_data.py --list

# Custom destination directory
python scripts/generate_test_data.py --all --output-dir /tmp/test_captures
```

---

## 5. Testing & Verification

Automated unit tests are located in:
```text
tests/unit/test_generate_test_data.py
```
Test suite coverage (15 tests, 100% pass):
- Non-empty PCAP generation for every scenario
- Scapy readability and packet structure validation
- Automatic directory hierarchy creation
- Validation of TCP handshake and protocol command strings
- Confirmation that weak TLS records carry 0x0301 and 0x0302 versions
- Confirmation that certificate scenarios contain expired/self-signed/missing-SAN properties
- Full verification of STARTTLS rejection, fallback, and advertised-not-requested states
- Multi-protocol detection in mixed capture
- Network isolation verification (operates without network sockets)
- Verification that generated PCAPs pass through `core.pcap.session_builder.build_analysis_result` into contract-compliant `AnalysisResultResponse` models

### Real TShark Host Validation (`TShark 4.6.8`)
- **TShark Binary:** `/opt/homebrew/bin/tshark` (Wireshark 4.6.8, Git commit `e677bf052328`)
- **Full Test Suite Status:** `155 passed, 0 failed, 0 skipped` in 5.49s (including all 6 previously skipped TShark integration tests in `tests/integration/test_core_pcap_tshark.py`).
- **End-to-End Pipeline Execution:** All 11 generated PCAP files were analyzed through the real external TShark subprocess via `core.pcap.session_builder.analyze_pcap_file(pcap_path)`.
- **Contract Conformance:** Every generated session result was strictly validated against `backend.app.models.analysis.AnalysisResultResponse` and `shared/contracts/analysis_result_schema.json` with `extra="forbid"`. Zero validation errors.

### Real TShark Scenario Extraction Summary

| Scenario File | Packets | Protocol | Mode / Upgrade Status | TLS Version | Cipher Suite / Key Exchange | Certificates / Anomalies |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `normal/normal_smtp_starttls.pcap` | 11 | SMTP | STARTTLS / `UPGRADED` | TLS 1.2 | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (ECDHE) | 2 certs: leaf `CN=mail.example.com`, `days_remaining=89`, CA-signed |
| `weak_tls/weak_tls10_smtp.pcap` | 10 | SMTP | STARTTLS / `UPGRADED` | TLS 1.0 | `TLS_RSA_WITH_AES_128_CBC_SHA` (RSA) | 1 cert: `CN=legacy.example.org`, `days_remaining=1089` |
| `weak_tls/weak_tls11_imap.pcap` | 10 | IMAP | STARTTLS / `UPGRADED` | TLS 1.1 | `TLS_RSA_WITH_AES_256_CBC_SHA` (RSA) | 1 cert: `CN=legacy-imap.example.org`, `days_remaining=1089` |
| `certificate_issues/cert_expired_smtp.pcap` | 11 | SMTP | STARTTLS / `UPGRADED` | TLS 1.2 | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (ECDHE) | 1 cert: `CN=expired.example.com`, `days_remaining=-2436` (EXPIRED) |
| `certificate_issues/cert_self_signed_smtp.pcap` | 11 | SMTP | STARTTLS / `UPGRADED` | TLS 1.2 | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (ECDHE) | 1 cert: `CN=self-signed.example.com`, `self_signed=True` |
| `certificate_issues/cert_missing_san_imap.pcap` | 11 | IMAP | STARTTLS / `UPGRADED` | TLS 1.2 | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (ECDHE) | 1 cert: `CN=nosan.example.org`, `subject_alternative_names=[]` (MISSING SAN) |
| `starttls/starttls_upgrade_success.pcap` | 9 | SMTP | STARTTLS / `UPGRADED` | TLS 1.2 | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | Minimal upgrade verification |
| `starttls/starttls_rejected.pcap` | 9 | SMTP | STARTTLS / `FAILED` | None | None (`tls_detected=False`) | Server returned `454 4.7.0 TLS not available` |
| `starttls/starttls_not_advertised.pcap` | 8 | SMTP | PLAINTEXT / `NOT_ADVERTISED` | None | None (`tls_detected=False`) | Server capabilities omitted STARTTLS |
| `starttls/starttls_advertised_not_requested.pcap` | 8 | SMTP | STARTTLS / `ADVERTISED_NOT_REQUESTED` | None | None (`tls_detected=False`) | Client proceeded with plaintext commands |
| `mixed/mixed_email_traffic.pcap` | 27 | Multi (3) | `UPGRADED` (SMTP, IMAP, POP3) | TLS 1.2 | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | 3 distinct concurrent sessions (`smtp-001`, `imap-001`, `pop3-001`) |

---

## 6. Dataset Policy & Git Safety

- In accordance with `.gitignore` lines 31–38 and Rule 13 of `AGENTS.md`, binary `.pcap` files are excluded from Git commits.
- Only code (`scripts/generate_test_data.py`), tests (`tests/unit/test_generate_test_data.py`), and documentation (`datasets/README.md`, `docs/dataset-guide.md`, `docs/MEMBER2_PCAP_CONTEXT.md`) are tracked.
- PCAP files are generated reproducibly on demand by running `python scripts/generate_test_data.py --all`.
