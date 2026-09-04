# Email protocols

Milestone 2 provides conservative SMTP, IMAP, and POP3 identification plus
metadata-only reconstruction of the plaintext protocol events needed to assess
STARTTLS/STLS upgrades.

- SMTP ports: 25, 465, 587
- IMAP ports: 143, 993
- POP3 ports: 110, 995

Exact TShark dissector labels take priority. Ports remain a documented fallback
when application metadata is absent, including encrypted implicit-TLS traffic.

`session_reconstruction.py` recognizes greetings, capability exchanges,
STARTTLS/STLS requests, acceptance/rejection responses, and the first TLS record.
It emits normalized event names and evidence frames rather than raw lines, so
credentials and email bodies are not retained. Ports 465, 993, and 995 are
classified as implicit TLS with STARTTLS status `NOT_APPLICABLE`.

TLS versions, cipher suites, certificates, and other handshake details remain
deferred to Milestone 3 and later.
