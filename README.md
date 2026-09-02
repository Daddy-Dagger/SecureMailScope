# SecureMailScope

SecureMailScope is a local-first, passive network-forensics prototype for assessing the cryptographic security posture of email traffic captured in PCAP files. The planned system will inspect SMTP, IMAP, POP3, STARTTLS, TLS, and certificate metadata and produce explainable findings.

## Current status

This repository is at the **project setup/environment stage**. It currently provides a minimal FastAPI health endpoint, a React/Vite status page, development scripts, tests, documentation, and empty module boundaries. PCAP analysis, security rules, machine learning, and report generation are **not implemented yet**.

## Repository structure

- `backend/` — FastAPI application and backend tests
- `core/` — future PCAP, protocol, TLS, rule, and local-ML modules
- `frontend/` — minimal React/Vite development UI
- `reports/` — future JSON, HTML, and PDF report generators
- `datasets/` — local dataset layout; captures are ignored by Git
- `scripts/` — setup and environment checks
- `docs/` — architecture, setup, API, and dataset guidance
- `tests/` — shared integration/e2e tests and fixtures

## Prerequisites

- Python 3.11 or newer
- Git
- Node.js 20.19 or newer and npm
- Wireshark/TShark
- Docker Desktop only if you choose the optional container workflow

See [docs/setup.md](docs/setup.md) for Windows and Apple Silicon installation details.

## Install

macOS/Linux:

```bash
./scripts/setup.sh
source .venv/bin/activate
```

Windows PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\setup.ps1
.\.venv\Scripts\Activate.ps1
```

You can also install manually:

```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
cd frontend
npm ci
```

Copy `.env.example` to `.env` if you want to override the development defaults.

## Run the backend

From the repository root with the virtual environment active:

```bash
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

The health endpoint is available at <http://127.0.0.1:8000/health>.

## Run the frontend

In a second terminal:

```bash
cd frontend
npm run dev
```

Open the local URL printed by Vite (normally <http://localhost:5173>).

## Test

```bash
python -m pytest
```

## Check TShark

```bash
python scripts/check_tshark.py
```

## Optional Docker Compose

Docker is not required. If Docker Desktop is installed, run:

```bash
docker compose up
```

The next recommended milestone, after team confirmation, is:

> PCAP → identify SMTP/IMAP/POP3 sessions → structured JSON
