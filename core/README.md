# Core analysis engine

The verified Milestone 2 core reads supplied PCAP/PCAPNG files with TShark and
emits structured SMTP, IMAP, and POP3 sessions matching the shared contract. It
reconstructs normalized plaintext events relevant to STARTTLS/STLS, records
packet evidence for each transition decision, detects the first TLS record after
an accepted upgrade, distinguishes implicit TLS ports, and extracts observable
ClientHello/ServerHello versions, cipher selection, key-share metadata, and
handshake state.

The reconstruction deliberately excludes arbitrary email bodies and credential
content. Later milestones still own certificates, deterministic security rules,
scoring, and local ML support.
