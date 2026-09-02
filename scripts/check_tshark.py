"""Check whether the TShark executable is available to SecureMailScope."""

from __future__ import annotations

import shutil
import subprocess
import sys


def main() -> int:
    tshark_path = shutil.which("tshark")
    if tshark_path is None:
        print(
            "ERROR: TShark was not found on PATH. Install Wireshark with its "
            "TShark command-line component, then restart your terminal. "
            "See docs/setup.md for platform-specific instructions.",
            file=sys.stderr,
        )
        return 1

    try:
        result = subprocess.run(
            [tshark_path, "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"ERROR: TShark exists at {tshark_path} but could not run: {exc}", file=sys.stderr)
        return 1

    version_line = next((line for line in result.stdout.splitlines() if line.strip()), "unknown version")
    print(f"TShark detected: {tshark_path}")
    print(version_line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
