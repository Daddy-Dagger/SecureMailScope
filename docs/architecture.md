# Architecture

## Scope

SecureMailScope is designed as a local-first, passive analysis application. It will accept files supplied by a user; it is not an active network scanner. This document records module boundaries, not completed functionality.

## Planned data flow

```text
PCAP file
  → capture/protocol session extraction
  → TLS and certificate metadata
  → deterministic security findings
  → optional local anomaly score (later milestone)
  → API response and reports
  → React interface
```

## Boundaries

- `core/` will contain analysis logic independent of FastAPI and React.
- `backend/` exposes application capabilities over a local HTTP API and will initially use SQLite.
- `frontend/` displays API results and should not duplicate security logic.
- `reports/` will render structured results into export formats.
- `datasets/` is local working data and is ignored by default.

The application must work on CPU. TShark is an external system prerequisite used through a future adapter. SQLite and local files are sufficient for the prototype; no cloud service, paid API, task queue, or microservice architecture is required.

## Module boundaries and communication

```text
PCAP Lab
    ↓
Core Engine
    ↓
Security Rules
    ↓
Backend/API
    ↓
Frontend
    ↓
Testing/Docs
```

Each module communicates through agreed structured data contracts (defined in `shared/contracts/`):

- **PCAP Lab & Core Engine**: Extracts network email sessions and cryptographic metadata into structured session objects matching `session_schema.json`.
- **Security Rules**: Evaluates deterministic security policies by consuming structured session inputs rather than parsing PCAP files directly, producing findings conforming to `finding_schema.json`.
- **Backend/API**: Exposes local analysis services and returns responses conforming to `analysis_result_schema.json`.
- **Frontend**: Renders findings and capture details based on `analysis_result_schema.json`, relying on mock JSON contracts when backend endpoints are in progress.
- **Testing/Docs**: Validates contracts across module boundaries through automated tests and documentation.

## Current implementation

Only the backend health endpoint and frontend connectivity check are implemented. All analysis boundaries are placeholders.


