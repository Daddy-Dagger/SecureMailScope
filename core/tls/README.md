# TLS metadata and Cryptographic Feature Extraction

Milestone 3 extracts factual TLS handshake metadata from TShark fields associated with each email TCP session.
Milestone 4 extends this with factual X.509 certificate and cryptographic feature extraction.

Implemented handshake metadata includes:

- ClientHello and ServerHello frame references
- offered and selected protocol versions
- TLS 1.3 `supported_version` handling
- selected cipher-suite numeric ID and normalized name when known
- selected key-share group and conservative ECDHE/DHE/RSA/PSK family derivation
- explicit Finished/fatal-alert evidence and conservative handshake status

Implemented certificate metadata (`certificates`) includes:

- ordered certificate chain representation (leaf at `chain_index: 0`)
- subject and issuer RFC 4514 strings
- serial number (hex string)
- SHA-256 fingerprint (hex)
- validity start and end (`not_before`, `not_after`) normalized to ISO 8601 UTC
- `days_remaining` calculated relative to forensic session/packet timestamp rather than wall-clock time
- Subject Alternative Names (`subject_alternative_names`)
- factual `self_issued` (`subject == issuer`)
- cryptographically verified `self_signed` (verified with certificate's own public key)
- public-key metadata (`algorithm`, `size_bits`, `curve`)
- signature algorithm
- packet frame evidence (`certificate_frame`)

Implemented cryptographic feature vector (`crypto_features`):

- `tls_version`
- `cipher_suite`
- `key_exchange`
- `named_group`
- `certificate_public_key_algorithm`
- `certificate_public_key_bits`
- `certificate_signature_algorithm`
- `certificate_days_remaining`
- `certificate_self_signed`

TLS 1.3 and Encrypted Handshake Handling:
- When certificate messages are encrypted and TLS secrets are unavailable, `certificates` remains empty `[]` and certificate-related fields in `crypto_features` remain `null`. The engine never fabricates certificates.

Deferred functionality:
- Trust-chain validation against OS trust stores is deferred.
- Security risk scoring, weak cipher rules, and expired certificate findings are deferred to Milestone 5 (deterministic security rules).
