# TLS metadata

Milestone 3 extracts factual TLS handshake metadata from TShark fields already
associated with each email TCP session.

Implemented metadata includes:

- ClientHello and ServerHello frame references
- offered and selected protocol versions
- TLS 1.3 `supported_version` handling
- selected cipher-suite numeric ID and normalized name when known
- selected key-share group and conservative ECDHE/DHE/RSA/PSK family derivation
- explicit Finished/fatal-alert evidence and conservative handshake status

A handshake is only `COMPLETE` when Finished messages are observable from both
directions. Encrypted handshake messages that TShark cannot expose therefore
remain `INCOMPLETE`; the engine does not guess.

Certificate extraction, certificate validation, and security classification are
still deferred.
