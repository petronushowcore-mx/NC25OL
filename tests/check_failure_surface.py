from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    result = subprocess.run(
        [sys.executable, "-B", str(ROOT / "tools" / "failure_surface.py"), "--check"],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    combined = "\n".join(part for part in (result.stdout, result.stderr) if part)
    if combined:
        print(combined.rstrip())
    if result.returncode != 0:
        raise SystemExit(result.returncode)
    if "FAILURE_SURFACE_RATCHET=1/1 PASS" not in combined:
        raise SystemExit("FAILURE_SURFACE_RATCHET_MARKER_MISSING")


if __name__ == "__main__":
    main()
