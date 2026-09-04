# Email protocols

Milestone 1 provides conservative SMTP, IMAP, and POP3 identification helpers for TShark packet metadata.

- SMTP ports: 25, 465, 587
- IMAP ports: 143, 993
- POP3 ports: 110, 995

Exact TShark dissector labels take priority. Ports are only a documented fallback when application metadata is absent, including encrypted implicit-TLS traffic. Command reconstruction and STARTTLS/TLS interpretation remain deferred to later milestones.
