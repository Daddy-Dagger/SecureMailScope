# Core analysis engine

The Milestone 1 core reads supplied PCAP/PCAPNG files with TShark and emits structured SMTP, IMAP, and POP3 session metadata matching the shared contract.

Later milestones still own command/session reconstruction, STARTTLS and TLS metadata, certificates, deterministic rules, scoring, and local ML support. None of those future capabilities are claimed by the current parser.
