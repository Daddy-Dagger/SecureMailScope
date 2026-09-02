# Development setup

SecureMailScope supports Python 3.11+ and CPU-only development. Run commands from the repository root unless stated otherwise.

## Windows 10/11

1. Install [Git for Windows](https://git-scm.com/download/win).
2. Install Python 3.11 or newer from [python.org](https://www.python.org/downloads/windows/). Enable **Add Python to PATH** during installation. The `py` launcher is normally available afterward.
3. Install Node.js 20.19 or newer (prefer a current LTS release) from [nodejs.org](https://nodejs.org/).
4. Install Wireshark from [wireshark.org](https://www.wireshark.org/download.html). In the installer, keep the TShark command-line component selected. Restart PowerShell after installation. If `tshark` is not found, add the Wireshark installation directory (commonly `C:\Program Files\Wireshark`) to `PATH`.
5. Clone the repository and run:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\scripts\setup.ps1
   .\.venv\Scripts\Activate.ps1
   python scripts\check_tshark.py
   python -m pytest
   ```

If the `python` command is unavailable during manual setup, use `py -3.11` to create the environment:

```powershell
py -3.11 -m venv .venv
```

Npcap is offered by the Wireshark installer for live capture support. This project analyzes existing files, but using the official installer defaults is the simplest lab setup.

## macOS Apple Silicon (M2/M4)

1. Install Apple's command-line developer tools (includes Git):

   ```bash
   xcode-select --install
   ```

2. Install [Homebrew](https://brew.sh/) if it is not already installed. On Apple Silicon its default prefix is `/opt/homebrew`; follow Homebrew's printed shell configuration step.
3. Install Python, Node.js, and Wireshark/TShark:

   ```bash
   brew install python@3.11 node wireshark
   ```

   Homebrew's `wireshark` formula installs the command-line utilities, including TShark. The optional `wireshark-app` cask installs the desktop GUI. If you use Wireshark's official macOS installer instead, also install its command-line utilities and confirm `which tshark` succeeds. Live-capture permissions are not required merely to analyze existing PCAP files.

4. Set up the repository:

   ```bash
   ./scripts/setup.sh
   source .venv/bin/activate
   python scripts/check_tshark.py
   python -m pytest
   ```

No Rosetta or GPU toolkit is required; use native arm64 Python and Node builds.

## Run services

Backend terminal:

```bash
source .venv/bin/activate
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Frontend terminal:

```bash
cd frontend
npm run dev
```

## Environment configuration

The checked-in defaults support local ports 8000 and 5173. To customize them, copy `.env.example` to `.env`. Comma-separate any extra trusted frontend origins in `SECUREMAILSCOPE_CORS_ORIGINS`.

## Docker (optional)

Docker is not required for ordinary development and does not replace installing TShark for future capture analysis. If a developer prefers containers, install Docker Desktop and run `docker compose up`. The current Compose file starts only the health API and frontend placeholder.
