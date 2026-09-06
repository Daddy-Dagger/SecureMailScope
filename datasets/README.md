# Datasets

This directory organizes local, synthetic, reproducible network captures used for development, testing, and SIH demonstrations.

> [!IMPORTANT]
> Capture contents (`.pcap`, `.pcapng`, and `.cap`) are strictly ignored by Git. Do not commit real personal, institutional, or sensitive network traffic. All test captures are generated deterministically using Scapy via `scripts/generate_test_data.py`.

---

## Available Synthetic Scenarios

| Scenario | Category Folder | Generated Files | Description |
|---|---|---|---|
| `normal` | `datasets/normal/` | `normal_smtp_starttls.pcap` | Modern secure email baseline: SMTP with STARTTLS, valid TLS 1.2, CA-signed certificate with SAN. |
| `weak_tls` | `datasets/weak_tls/` | `weak_tls10_smtp.pcap`<br>`weak_tls11_imap.pcap` | Deprecated TLS versions (TLS 1.0, TLS 1.1) and static RSA ciphers (`TLS_RSA_WITH_AES_128_CBC_SHA`, `TLS_RSA_WITH_AES_256_CBC_SHA`) lacking forward secrecy. |
| `certificate_issues` | `datasets/certificate_issues/` | `cert_expired_smtp.pcap`<br>`cert_self_signed_smtp.pcap`<br>`cert_missing_san_imap.pcap` | Certificate anomalies: expired X.509 validity dates, self-signed/self-issued root certificates, and missing Subject Alternative Name (SAN) extensions. |
| `starttls` | `datasets/starttls/` | `starttls_upgrade_success.pcap`<br>`starttls_rejected.pcap`<br>`starttls_not_advertised.pcap`<br>`starttls_advertised_not_requested.pcap` | STARTTLS protocol edge cases: successful upgrade (`UPGRADED`), server 454 error rejection (`FAILED`), unadvertised plaintext fallback (`NOT_ADVERTISED`), and advertised but ignored (`ADVERTISED_NOT_REQUESTED`). |
| `mixed` | `datasets/mixed/` | `mixed_email_traffic.pcap` | Multi-flow capture with concurrent SMTP (port 25), IMAP (port 143), and POP3 (port 110) sessions across distinct TCP streams. |

---

## Generation Commands

To generate all scenarios:
```bash
python scripts/generate_test_data.py --all
```

To generate a specific scenario:
```bash
python scripts/generate_test_data.py --scenario normal
python scripts/generate_test_data.py --scenario weak_tls
python scripts/generate_test_data.py --scenario certificate_issues
python scripts/generate_test_data.py --scenario starttls
python scripts/generate_test_data.py --scenario mixed
```

To list scenarios:
```bash
python scripts/generate_test_data.py --list
```

To specify an alternate output directory:
```bash
python scripts/generate_test_data.py --all --output-dir /tmp/my_captures
```

---

## Safety & Reproducibility Guarantees

1. **100% Synthetic:** Constructed in memory via Scapy packet definitions. No real network interfaces are sniffed, and no production traffic is collected.
2. **Offline Execution:** Operates completely without network connectivity or socket bindings.
3. **No Secrets or Credentials:** Contains zero real usernames, passwords, authentication hashes, or personal emails.
4. **Deterministic Properties:** Fixed IP addresses, ports, sequence numbers, timestamps (`BASE_TIMESTAMP = 1_788_220_800.0`), and reproducible certificate metadata.

---

## Validation Authority

All generated PCAPs are validated against:
1. **Scapy Packet Reader (`rdpcap`):** Verifies layer integrity (Ether, IP, TCP, Raw) and packet counts.
2. **SecureMailScope Core Parser (`core/pcap/`):** Verifies flow grouping, protocol identification, application event extraction, and STARTTLS state reconstruction.
3. **TShark Adapter (`core/pcap/tshark_adapter.py`):** Used during integration tests when TShark is present on PATH.
