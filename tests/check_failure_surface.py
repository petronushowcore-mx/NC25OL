from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def pair_problem(receipt: object, baseline: dict[str, object], minor: str) -> str | None:
    """Check this invocation's assertion pairs against the version-neutral record."""
    if not isinstance(receipt, dict):
        return "FAILURE_ASSERTED_PAIR_INVALID receipt-not-object"
    if receipt.get("python") != minor:
        return f"FAILURE_ASSERTED_VERSION_MISMATCH {receipt.get('python')!r}"
    expected = {
        "python": minor,
        "engine": [[code, minor] for code in baseline["asserted_codes"]],
        "bridge": [[code, minor] for code in baseline["asserted_bridge_codes"]],
        "sites": baseline["assertion_sites"],
    }
    if not all(isinstance(receipt.get(key), list) for key in ("engine", "bridge", "sites")):
        return "FAILURE_ASSERTED_PAIR_INVALID shape"
    for scope in ("engine", "bridge"):
        missing = [pair for pair in expected[scope] if pair not in receipt[scope]]
        if missing:
            return f"FAILURE_ASSERTED_PAIR_MISSING scope={scope} pairs={missing[:3]}"
    if receipt != expected:
        return "FAILURE_ASSERTED_PAIR_INVALID unexpected-pair-or-site"
    return None


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
    pair_lines = [
        line.split("=", 1)[1] for line in combined.splitlines()
        if line.startswith("FAILURE_ASSERTED_PAIRS=")
    ]
    if len(pair_lines) != 1:
        print(f"FAILURE_ASSERTED_PAIR_MISSING receipt_count={len(pair_lines)}")
        raise SystemExit(1)
    try:
        receipt = json.loads(pair_lines[0])
        baseline = json.loads(
            (ROOT / "tests" / "failure-surface-baseline.json").read_text(
                encoding="utf-8"
            )
        )["runtime"]
        minor = f"{sys.version_info.major}.{sys.version_info.minor}"
        problem = pair_problem(receipt, baseline, minor)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        problem = f"FAILURE_ASSERTED_PAIR_INVALID {type(exc).__name__}"
    if problem:
        print(problem)
    if combined:
        print(combined.rstrip())
    if problem:
        raise SystemExit(1)
    if result.returncode != 0:
        raise SystemExit(result.returncode)
    if "FAILURE_SURFACE_RATCHET=1/1 PASS" not in combined:
        raise SystemExit("FAILURE_SURFACE_RATCHET_MARKER_MISSING")


if __name__ == "__main__":
    main()
