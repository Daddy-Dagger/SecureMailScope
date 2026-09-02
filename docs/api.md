# API

This document details the HTTP endpoints provided by the SecureMailScope backend service.

---

## Implemented endpoints

### `GET /health`

Confirms that the local backend service is running and ready.

- **HTTP Method:** `GET`
- **Request Format:** None
- **Response Format:** JSON (`200 OK`)

```json
{
  "status": "ok",
  "service": "SecureMailScope"
}
```

- **Validation / Errors:** None.

---

### `POST /api/analyze`

Submits a PCAP capture file for email session and cryptographic posture analysis. Returns a structured JSON result conforming to the shared contract defined in `shared/contracts/analysis_result_schema.json`.

- **HTTP Method:** `POST`
- **Content-Type:** `multipart/form-data`
- **Request Format:**
  - `file`: Form-data binary file field (required).
  - Accepted file extensions: `.pcap`, `.pcapng`, `.cap` (case-insensitive).
  - Maximum upload size: 100 MB.

#### Successful Response (`200 OK`)

Response conforms to `shared/contracts/analysis_result_schema.json`:

```json
{
  "file": "capture.pcap",
  "packet_count": 0,
  "summary": {
    "smtp_sessions": 0,
    "imap_sessions": 0,
    "pop3_sessions": 0
  },
  "sessions": [],
  "findings": [],
  "overall_score": null,
  "risk_level": null
}
```

#### Field Descriptions

| Field | Type | Description |
|---|---|---|
| `file` | string | Filename of the analyzed capture |
| `packet_count` | integer (&gt;= 0) | Processed packet count (currently `0` while core engine integration is pending) |
| `summary` | object | Extracted session counts per email protocol (`smtp_sessions`, `imap_sessions`, `pop3_sessions`) |
| `sessions` | array | Extracted email session records conforming to `session_schema.json` |
| `findings` | array | Security findings conforming to `finding_schema.json` |
| `overall_score` | number / null | Security score (`null` until ML/scoring milestone is implemented) |
| `risk_level` | string / null | Overall risk level (`null` until risk classification is implemented) |

#### Validation and Error Responses

| Status Code | Condition | Example Response |
|---|---|---|
| `400 Bad Request` | Unsupported file extension (not `.pcap`, `.pcapng`, or `.cap`) | `{"detail": "Unsupported file extension '.txt'. Allowed extensions: .cap, .pcap, .pcapng."}` |
| `400 Bad Request` | Uploaded file is empty (0 bytes) | `{"detail": "Uploaded file is empty (0 bytes)."}` |
| `400 Bad Request` | Filename is whitespace or empty | `{"detail": "Filename must not be empty."}` |
| `413 Content Too Large` | Uploaded file exceeds 100 MB limit | `{"detail": "File size (105000000 bytes) exceeds maximum allowed limit (104857600 bytes)."}` |
| `422 Unprocessable Entity` | Missing `file` field in multipart request or invalid form data | Standard FastAPI validation error object |

#### Current Limitations

- **Core Engine Integration Deferred:** Real PCAP packet parsing, SMTP/IMAP/POP3 extraction, and cryptographic feature inspection are part of Milestone 1 (owned by `lead/core-engine`). The endpoint currently returns a controlled placeholder structure strictly matching `shared/contracts/analysis_result_schema.json`.
- **Scoring & Risk Deferred:** `overall_score` and `risk_level` are explicitly `null` as security scoring and ML anomaly detection belong to later milestones.
- **Reporting Deferred:** Report export endpoints (JSON/HTML/PDF) are not yet implemented.
