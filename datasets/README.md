# Datasets

This directory is for local, legally obtained captures used in development and testing.

- `normal/` — expected baseline traffic
- `weak_tls/` — captures selected for weak TLS test cases
- `certificate_issues/` — certificate-related test cases
- `starttls/` — STARTTLS transition test cases
- `mixed/` — mixed-protocol scenarios

Capture contents (`.pcap`, `.pcapng`, and `.cap`) are ignored by Git. Do not commit real personal, institutional, or sensitive network traffic. Prefer small, sanitized, reproducible fixtures with written provenance; an intentional dataset commit requires team review and an explicit `.gitignore` exception.

