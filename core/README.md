# Core analysis engine

The verified Milestone 4 core reads supplied PCAP/PCAPNG files with TShark and
emits structured SMTP, IMAP, and POP3 sessions matching the shared contract. It
reconstructs normalized plaintext events relevant to STARTTLS/STLS, records
packet evidence for each transition decision, detects the first TLS record after
an accepted upgrade, distinguishes implicit TLS ports, extracts observable
ClientHello/ServerHello versions, cipher selection, key-share metadata,
handshake state, ordered X.509 certificate chains, and normalized cryptographic
feature vectors.

The reconstruction deliberately excludes arbitrary email bodies and credential
content. Later milestones still own deterministic security rules, scoring, and
local ML support.
