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

#### Core Analysis Integration Boundary

`POST /api/analyze` routes requests through `AnalysisService` (`backend/app/services/analysis_service.py`), which communicates with the analysis engine via the `CoreAnalysisEngine` adapter protocol (`backend/app/services/core_adapter.py`):

1. **Upload & Validation:** Transport validation on file extension, file presence, and size limits.
2. **Adapter Invocation:** The raw PCAP byte stream and filename are handed to the configured `CoreAnalysisEngine`.
3. **Contract Validation:** The adapter output is strictly validated against `shared/contracts/analysis_result_schema.json` via Pydantic models before returning to the caller. Any malformed output from core modules is caught and rejected by the boundary.
4. **Graceful Fallback:** While `core/` parsing modules remain in development, `DeferredCoreEngineAdapter` returns the contract-compliant baseline with zero sessions/findings.

#### Current Limitations

- **Core Engine Awaiting Milestone 1:** Real PCAP packet parsing, SMTP/IMAP/POP3 extraction, and cryptographic feature inspection belong to `core/` (owned by `lead/core-engine`). The backend integration boundary is complete, but awaits real engine deliverables from Member 1.
- **Scoring & Risk Deferred:** `overall_score` and `risk_level` are explicitly `null` as security scoring and ML anomaly detection belong to later milestones.

---

### `POST /api/reports/export`

Exports a validated analysis result into a downloadable forensic report file. Reuses existing standalone report generators (`json_report`, `html_report`, `pdf_report`) without duplicating or altering core contracts.

- **HTTP Method:** `POST`
- **Content-Type:** `application/json`
- **Query Parameters:**
  - `format` (optional, string): Format override (`json`, `html`, `pdf`).
- **Request Body Options:**
  1. Wrapped payload with explicit `format` specification:
     ```json
     {
       "format": "json",
       "analysis_result": {
         "file": "audit_capture.pcap",
         "packet_count": 1420,
         "summary": {
           "smtp_sessions": 1,
           "imap_sessions": 0,
           "pop3_sessions": 0
         },
         "sessions": [],
         "findings": [],
         "overall_score": null,
         "risk_level": null
       }
     }
     ```
  2. Direct `AnalysisResultResponse` payload with query parameter:
     `POST /api/reports/export?format=pdf`

#### Supported Formats & MIME Types

| Format | Content-Type | Content-Disposition Header | Description |
|---|---|---|---|
| `json` | `application/json` | `attachment; filename="securemailscope-report.json"` | Deterministic, formatted JSON report adhering to shared contracts |
| `html` | `text/html; charset=utf-8` | `attachment; filename="securemailscope-report.html"` | Standalone, offline-ready HTML5 report with embedded CSS and XSS auto-escaping |
| `pdf` | `application/pdf` | `attachment; filename="securemailscope-report.pdf"` | Standalone, multi-page, printable PDF report generated in-memory via ReportLab |

#### Validation and Error Responses

| Status Code | Condition | Example Response |
|---|---|---|
| `400 Bad Request` | Unsupported format specified (e.g. `format="xml"`) | `{"detail": "Unsupported report format 'xml'. Allowed formats: html, json, pdf."}` |
| `422 Unprocessable Entity` | Malformed analysis result (missing required fields or invalid types) | Standard FastAPI validation error object |
| `422 Unprocessable Entity` | Extra uncontracted fields present in payload (`extra="forbid"`) | Standard FastAPI validation error object |

#### Data Safety Guarantees

- **No Score Fabrication:** If `overall_score` or `risk_level` are `null`, reports render `"Not available"`.
- **In-Memory Generation:** PDF generation streams directly from memory buffers without temporary file overhead or disk leaks.
- **Offline Self-Contained:** HTML and PDF reports require zero external CDNs, fonts, or network requests.
