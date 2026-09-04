# PCAP

Milestones 1 and 2 implement passive PCAP/PCAPNG loading, focused TShark
metadata extraction, bidirectional TCP-flow grouping, metadata-only email
session reconstruction, and contract-compatible STARTTLS/STLS output.

Public entry points:

- `analyze_pcap(filename, content)` analyzes uploaded capture bytes.
- `analyze_pcap_file(path)` analyzes an existing local capture.
- `PcapAnalysisEngine` implements Member 4's `CoreAnalysisEngine` protocol for dependency injection.

The analyzer counts every captured frame, but only TCP flows with complete
endpoint metadata can become sessions. It uses explicit TShark SMTP/IMAP/POP
labels when present, then the approved well-known-port fallback. TCP payload is
used only to recognize relevant plaintext state lines; arbitrary message content
is not included in output. TLS detection stops at confirming that a TLS record
appeared after an accepted upgrade.

The analyzer does not yet extract handshake versions, cipher suites,
certificates, rules, or risk.
