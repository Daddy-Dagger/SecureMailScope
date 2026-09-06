# Dataset Guide & Provenance

## Safety and Provenance

SecureMailScope analyzes captured network traffic containing email protocols (SMTP, IMAP, POP3) and TLS encryption. Real network captures can expose sensitive data, including login credentials, email subject lines, message bodies, private IP topologies, and personal identifiable information (PII).

To ensure zero risk of data leakage and compliance with Smart India Hackathon guidelines:
1. **Zero Real Network Captures in Version Control:** Never commit real institutional, personal, or production PCAP files.
2. **Deterministic Synthetic Captures:** All test fixtures are generated deterministically using Scapy via `scripts/generate_test_data.py`.
3. **No Network Sockets:** The generator operates completely offline without listening on ports or opening sockets.
4. **Git-Ignored Binaries:** All `.pcap`, `.pcapng`, and `.cap` files in `datasets/` are excluded by `.gitignore`.

---

## Synthetic Scenarios

The generator produces 11 deterministic captures across 5 scenario suites in `datasets/`:

### 1. `normal/` — Normal Baseline Traffic
- **`normal_smtp_starttls.pcap`**: Standard secure email exchange. SMTP on port 25 with full 3-way handshake, EHLO greeting, 250-STARTTLS advertisement, client STARTTLS request, 220 accept, TLS 1.2 handshake (ECDHE-RSA-AES128-GCM-SHA256), and valid CA-signed certificate chain.

### 2. `weak_tls/` — Deprecated & Weak Cryptography
- **`weak_tls10_smtp.pcap`**: Outdated TLS 1.0 negotiation using static RSA key exchange and CBC cipher (`TLS_RSA_WITH_AES_128_CBC_SHA`, `0x002F`). Demonstrates absence of forward secrecy and deprecated protocol version.
- **`weak_tls11_imap.pcap`**: Outdated TLS 1.1 negotiation on IMAP port 143 using static RSA cipher `TLS_RSA_WITH_AES_256_CBC_SHA` (`0x0035`).

### 3. `certificate_issues/` — X.509 Certificate Anomalies
- **`cert_expired_smtp.pcap`**: SMTP STARTTLS session where the leaf certificate validity window ended prior to the capture timestamp (`days_remaining < 0`).
- **`cert_self_signed_smtp.pcap`**: SMTP STARTTLS session presenting a self-signed and self-issued certificate (`subject == issuer`).
- **`cert_missing_san_imap.pcap`**: IMAP STARTTLS session presenting an X.509 certificate without a Subject Alternative Name (SAN) extension.

### 4. `starttls/` — Protocol Transition Edge Cases
- **`starttls_upgrade_success.pcap`**: Full upgrade sequence ending in TLS Record (`UPGRADED`).
- **`starttls_rejected.pcap`**: Server rejects STARTTLS request with `454 4.7.0 TLS not available` (`FAILED`).
- **`starttls_not_advertised.pcap`**: Plaintext SMTP conversation where server capabilities do not include STARTTLS (`NOT_ADVERTISED`, mode `PLAINTEXT`).
- **`starttls_advertised_not_requested.pcap`**: Server advertises STARTTLS, but client proceeds with plaintext commands without initiating encryption (`ADVERTISED_NOT_REQUESTED`).

### 5. `mixed/` — Multi-Protocol Concurrency
- **`mixed_email_traffic.pcap`**: Combined capture containing concurrent, interleaved TCP streams for SMTP (port 25), IMAP (port 143), and POP3 (port 110).

---

## Generator Usage

```bash
# Generate all scenarios
python scripts/generate_test_data.py --all

# Generate a single scenario
python scripts/generate_test_data.py --scenario normal

# List available scenarios
python scripts/generate_test_data.py --list

# Specify custom destination
python scripts/generate_test_data.py --all --output-dir /tmp/fixtures
```

---

## Reproducibility Parameters

- **Reference Epoch:** `BASE_TIMESTAMP = 1_788_220_800.0` (2026-09-01T00:00:00Z)
- **Synthetic MAC Addresses:** Client: `02:00:00:00:00:01`, Server: `02:00:00:00:00:02`
- **Synthetic IP Addressing:**
  - Client subnet: `192.168.1.10` - `192.168.1.12`
  - SMTP Server: `192.168.1.20` (Ports: 25, 465)
  - IMAP Server: `192.168.1.25` (Port: 143)
  - POP3 Server: `192.168.1.30` (Port: 110)
