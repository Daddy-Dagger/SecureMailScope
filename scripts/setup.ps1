$ErrorActionPreference = "Stop"

$RepositoryRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepositoryRoot

$PythonCommand = if (Get-Command py -ErrorAction SilentlyContinue) { "py" } elseif (Get-Command python -ErrorAction SilentlyContinue) { "python" } else { $null }
if (-not $PythonCommand) {
    throw "Python 3.11+ is required. See docs/setup.md."
}

if ($PythonCommand -eq "py") {
    & py -3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else "Python 3.11+ is required")'
    & py -3 -m venv .venv
} else {
    & python -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else "Python 3.11+ is required")'
    & python -m venv .venv
}

& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw "Node.js and npm are required for the frontend. See docs/setup.md."
}

& npm --prefix frontend ci

Write-Host "Setup complete. Activate Python with: .\.venv\Scripts\Activate.ps1"
Write-Host "Then verify TShark with: python scripts\check_tshark.py"
