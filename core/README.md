# Core analysis engine

The verified Milestone 2 core reads supplied PCAP/PCAPNG files with TShark and
emits structured SMTP, IMAP, and POP3 sessions matching the shared contract. It
reconstructs normalized plaintext events relevant to STARTTLS/STLS, records
packet evidence for each transition decision, detects the first TLS record after
an accepted upgrade, and distinguishes implicit TLS ports.

The reconstruction deliberately excludes arbitrary email bodies and credential
content. Later milestones still own TLS handshake versions and ciphers,
certificates, deterministic rules, scoring, and local ML support.
