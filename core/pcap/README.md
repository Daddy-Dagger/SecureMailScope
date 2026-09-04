# PCAP

Milestone 1 implements passive PCAP/PCAPNG loading, minimal TShark metadata extraction, bidirectional TCP-flow grouping, and contract-compatible email-session output.

Public entry points:

- `analyze_pcap(filename, content)` analyzes uploaded capture bytes.
- `analyze_pcap_file(path)` analyzes an existing local capture.
- `PcapAnalysisEngine` implements Member 4's `CoreAnalysisEngine` protocol for dependency injection.

The analyzer counts every captured frame, but only complete TCP flows can become sessions. It uses explicit TShark SMTP/IMAP/POP labels when present, then the approved well-known-port fallback. It does not inspect STARTTLS, TLS handshakes, certificates, rules, or risk in Milestone 1.
