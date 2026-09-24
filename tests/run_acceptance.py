from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_ACCEPTANCE_STEP_COUNT = 8
EXPECTED_STEP_PATHS = {
    'functional_behaviour': 'tests/test_universal_connection.py',
    'semantic_contracts': 'tests/test_semantic_contracts.py',
    'safety_mutations': 'tests/test_safety_mutations.py',
    'contract_conformance': 'tests/test_contract_conformance.py',
    'contract_regressions': 'tests/test_contract_regressions.py',
    'otcs_bridge': 'tests/test_otcs_bridge.py',
    'failure_surface_ratchet': 'tests/check_failure_surface.py',
    'package_verifier': 'tests/verify_package.py',
}

# The four unittest steps require a bare `OK` line as well as the count. The
# count is taken from `Ran N tests`, and that line does not change when a test
# is skipped - unittest reports the skip on the verdict line instead, as
# `OK (skipped=N)`, and still exits zero. Requiring `^OK$` is what makes a
# silently skipped test visible to this runner. The other four steps print no
# such line and carry their own explicit PASS markers.
STEPS = (
    ("functional_behaviour", "tests/test_universal_connection.py", (r"Ran \d+ tests", r"(?m)^OK$"), r"Ran (?P<passed>\d+) tests"),
    ("semantic_contracts", "tests/test_semantic_contracts.py", (r"Ran \d+ tests", r"(?m)^OK$"), r"Ran (?P<passed>\d+) tests"),
    ("safety_mutations", "tests/test_safety_mutations.py", (r"SAFETY_MUTATIONS=\d+/\d+ PASS",), r"SAFETY_MUTATIONS=(?P<passed>\d+)/(?P<total>\d+) PASS"),
    ("contract_conformance", "tests/test_contract_conformance.py", (r"CONTRACT_CONFORMANCE=\d+/\d+ PASS",), r"CONTRACT_CONFORMANCE=(?P<passed>\d+)/(?P<total>\d+) PASS"),
    ("contract_regressions", "tests/test_contract_regressions.py", (r"Ran \d+ tests", r"(?m)^OK$"), r"Ran (?P<passed>\d+) tests"),
    # Run the bridge separately so its failures keep their own step name
    # and its tests are counted once.
    ("otcs_bridge", "tests/test_otcs_bridge.py", (r"Ran \d+ tests", r"(?m)^OK$"), r"Ran (?P<passed>\d+) tests"),
    ("failure_surface_ratchet", "tests/check_failure_surface.py", (r"FAILURE_SURFACE_RATCHET=1/1 PASS",), r"FAILURE_SURFACE_RATCHET=(?P<passed>\d+)/(?P<total>\d+) PASS"),
    ("package_verifier", "tests/verify_package.py", (r"PACKAGE_CHECKS=\d+/\d+ PASS",), r"PACKAGE_CHECKS=(?P<passed>\d+)/(?P<total>\d+) PASS"),
)


def extract_step_count(step_id: str, combined: str, pattern: str) -> tuple[int, int]:
    matches = list(re.finditer(pattern, combined))
    if len(matches) != 1:
        raise SystemExit(f"ACCEPTANCE_COUNT_INVALID {step_id} matches={len(matches)}")
    match = matches[0]
    passed = int(match.group("passed"))
    total_text = match.groupdict().get("total")
    total = int(total_text) if total_text is not None else passed
    if passed != total:
        raise SystemExit(
            f"ACCEPTANCE_COUNT_NOT_PASS {step_id} passed={passed} total={total}"
        )
    return passed, total


def require_external_output(path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return resolved
    raise SystemExit("ACCEPTANCE_JSON_MUST_BE_OUTSIDE_PACKAGE")


def validate_step_manifest(steps) -> None:
    """Bind each reported step to its intended executable before any suite runs.

    Checking names alone allows one suite to run twice under two different
    names. The independent manifest binds both names and paths; changing the
    executed topology therefore requires an explicit manifest change too.
    """
    if len(EXPECTED_STEP_PATHS) != REQUIRED_ACCEPTANCE_STEP_COUNT:
        raise AssertionError("ACCEPTANCE_STEP_COUNT_MANIFEST")
    actual = tuple((step_id, path) for step_id, path, _, _ in steps)
    expected = tuple(EXPECTED_STEP_PATHS.items())
    if actual != expected:
        raise AssertionError(f"ACCEPTANCE_STEP_MANIFEST expected={expected} actual={actual}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    validate_step_manifest(STEPS)
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed: list[dict[str, object]] = []
    external_core: dict[str, str] = {"source_mode": "", "external_source_checks": ""}
    for step_id, relative_path, required_markers, count_pattern in STEPS:
        command = [sys.executable, "-B", str(ROOT / relative_path)]
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
        combined = "\n".join(
            part for part in (result.stdout, result.stderr) if part
        )
        if combined:
            print(combined.rstrip())
        if result.returncode != 0:
            raise SystemExit(
                f"ACCEPTANCE_STEP_FAIL {step_id} exit={result.returncode}"
            )
        missing = [
            marker for marker in required_markers
            if re.search(marker, combined) is None
        ]
        if missing:
            raise SystemExit(
                f"ACCEPTANCE_MARKER_MISSING {step_id} patterns={missing}"
            )
        passed, total = extract_step_count(step_id, combined, count_pattern)
        completed.append(
            {"id": step_id, "status": "PASS", "passed": passed, "total": total}
        )
        if step_id == "package_verifier":
            # The package verifier prints its external NC2.5-core binding status.
            # A release-grade acceptance record must carry it verbatim so the
            # acceptance report can disclose (and require) that the core was bound.
            mode = re.search(r"^SOURCE_MODE=(\S+)$", combined, re.MULTILINE)
            status = re.search(
                r"^EXTERNAL_SOURCE_CHECKS=(\S+)$", combined, re.MULTILINE
            )
            if mode is None or status is None:
                raise SystemExit("ACCEPTANCE_EXTERNAL_CORE_MARKER_MISSING")
            external_core = {
                "source_mode": mode.group(1),
                "external_source_checks": status.group(1),
            }
        print(f"PASS ACCEPTANCE_STEP {step_id}")
    print(
        f"ACCEPTANCE_STEPS={len(completed)}/"
        f"{REQUIRED_ACCEPTANCE_STEP_COUNT} PASS"
    )
    if args.json_output is not None:
        output = require_external_output(args.json_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        # The bytes this run certifies, named: a digest of every manifest
        # entry except the acceptance report (the report's own regeneration
        # changes its entry, so binding it would bind nothing) and the digest
        # of the specification document. The report carries both, and the
        # package verifier recomputes them from the shipped bytes, so a report
        # generated for a different tree - or a document rebuilt after the
        # report was generated - is refused instead of certifying stale bytes.
        manifest = json.loads(
            (ROOT / "PACKAGE-MANIFEST.json").read_text(encoding="utf-8")
        )
        bound_manifest_digest, bound_document_sha256 = bound_bytes(manifest)
        payload = {
            "format": "nc25-acceptance-results/v1",
            "bound_manifest_digest": bound_manifest_digest,
            "bound_document_sha256": bound_document_sha256,
            "completed_utc": datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "status": "PASS",
            "acceptance_steps": {
                "passed": len(completed),
                "total": REQUIRED_ACCEPTANCE_STEP_COUNT,
            },
            "external_core": external_core,
            "steps": completed,
        }
        temporary = output.with_name(output.name + ".tmp")
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        temporary.replace(output)
        print(f"ACCEPTANCE_JSON={output}")


def bound_bytes(manifest: dict) -> tuple[str, str]:
    """The manifest-entries digest and the document digest a report binds.

    One home for the rule, imported by the verifier: the digest covers every
    entry except ACCEPTANCE-REPORT.md, as (path, sha256, byte_length) triples
    in path order, hashed as canonical JSON.
    """
    import hashlib

    entries = sorted(
        (entry["path"], entry["sha256"].upper(), int(entry["byte_length"]))
        for entry in manifest["files"]
        if entry["path"] != "ACCEPTANCE-REPORT.md"
    )
    digest = hashlib.sha256(
        json.dumps(entries, separators=(",", ":")).encode("utf-8")
    ).hexdigest().upper()
    documents = [
        entry["sha256"].upper()
        for entry in manifest["files"]
        if entry["path"].endswith(".docx")
    ]
    if len(documents) != 1:
        raise ValueError(f"BOUND_DOCUMENT_COUNT:{len(documents)}")
    return digest, documents[0]


if __name__ == "__main__":
    main()
