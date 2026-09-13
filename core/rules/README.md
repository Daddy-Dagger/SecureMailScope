# Deterministic Security Rules (`core/rules/`)

This package implements deterministic cryptographic and transport security rules for SecureMailScope.

## Design Principles

- **Structured Input Only**: Consumes structured session objects conforming to `shared/contracts/session_schema.json`. Does **not** parse PCAPs, raw frames, or certificate DER/PEM bytes directly.
- **Strictly Factual & Deterministic**: Evaluates known security standards (RFCs, NIST) without probabilistic guesses or fabricated confidence scores.
- **Evidence-Linked**: Findings cite observed packet/frame evidence and concrete observed values.
- **Tolerant of Incomplete Data**: Missing certificate data (e.g. encrypted TLS 1.3) or unobserved fields do not generate unsupported findings.
- **No Early Scoring or ML**: Risk scoring and ML anomaly detection belong to subsequent milestones.

## Rule Catalog

| Finding ID | Title | Severity | Description | Evidence |
| :--- | :--- | :--- | :--- | :--- |
| `TLS-DEPRECATED-1.0` | Deprecated TLS 1.0 Protocol Version | HIGH | Session negotiated TLS 1.0 (deprecated by RFC 8996). | Version frame |
| `TLS-DEPRECATED-1.1` | Deprecated TLS 1.1 Protocol Version | HIGH | Session negotiated TLS 1.1 (deprecated by RFC 8996). | Version frame |
| `TLS-WEAK-CIPHER` | Insecure or Deprecated Cipher Suite | CRITICAL / HIGH | Selected cipher uses NULL, export-grade, anonymous, RC4, 3DES, or MD5 MAC. | Cipher frame |
| `TLS-HANDSHAKE-FATAL` | Fatal TLS Handshake Failure | HIGH | Handshake terminated with a fatal alert. | Alert frame |
| `TLS-FORWARD-SECRECY-SUPPORTED` | Forward Secrecy Supported | INFO | Ephemeral key exchange (ECDHE / DHE) negotiated. | Key exchange frame |
| `TLS-NO-FORWARD-SECRECY` | Lack of Forward Secrecy | MEDIUM | Static RSA key exchange negotiated (no ephemeral parameters). | Key exchange frame |
| `STARTTLS-ADVERTISED-NOT-USED` | STARTTLS Advertised But Not Requested | MEDIUM | Server advertised upgrade, but client did not request it. | Capability frame |
| `STARTTLS-REJECTED` | STARTTLS Upgrade Request Rejected | HIGH | Client requested upgrade, but server rejected or returned error. | Command/response frame |
| `STARTTLS-INCOMPLETE` | Incomplete STARTTLS Upgrade Transition | HIGH | Upgrade accepted but TLS traffic did not establish. | Command/response frame |
| `TRANSPORT-PLAINTEXT-SESSION` | Cleartext Email Communication | HIGH | Entire session unencrypted without transport security. | Protocol frame |
| `CERT-EXPIRED` | Expired X.509 Certificate | HIGH | Certificate expired before session reference timestamp. | Certificate frame |
| `CERT-NOT-YET-VALID` | Certificate Not Yet Valid | HIGH | Certificate validity window begins after session timestamp. | Certificate frame |
| `CERT-WEAK-RSA-KEY` | Weak RSA Public Key Size | HIGH | RSA key size is below 2048 bits. | Certificate frame |
| `CERT-WEAK-DSA-KEY` | Weak DSA Public Key Size | HIGH | DSA key size is below 2048 bits. | Certificate frame |
| `CERT-SIG-MD5` | Deprecated MD5 Certificate Signature | CRITICAL | Certificate was signed using MD5 hash. | Certificate frame |
| `CERT-SIG-SHA1` | Deprecated SHA-1 Certificate Signature | HIGH | Certificate was signed using SHA-1 hash. | Certificate frame |
| `CERT-SELF-SIGNED` | Self-Signed X.509 Certificate | MEDIUM | Verified self-signed certificate (`self_signed == True`). | Certificate frame |

## Special Handling

1. **Implicit TLS**: Sessions with `mode == "IMPLICIT_TLS"` (e.g. ports 465, 993, 995) establish TLS from the first packet and do not use STARTTLS; they are never flagged as missing STARTTLS.
2. **POP3 STLS**: POP3 uses `STLS` command naming and is evaluated with the appropriate command identifier.
3. **Self-Issued vs Self-Signed**: Only certificates with cryptographically verified `self_signed == True` trigger `CERT-SELF-SIGNED`. `self_issued` alone never triggers this finding.
4. **Unknown / Absent Data**: When cipher, key exchange, or certificate data is `null` or `UNKNOWN`, no speculative findings are generated.
