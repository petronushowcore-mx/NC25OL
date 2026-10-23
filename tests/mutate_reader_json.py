"""Require the reader's JSON refusals to survive benign changes and detect regressions."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "sdk" / "python" / "nc25ol_reader.py"
TEST = "ReaderTests.test_cli_json_input_boundary_is_a_stable_refusal"


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise SystemExit("MUTATION_ANCHOR_INVALID")
    return source.replace(old, new, 1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    source = SOURCE.read_text(encoding="utf-8")
    before = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    observations = []

    def run(path: Path, label: str) -> tuple[subprocess.CompletedProcess, list[str], list[str]]:
        env = os.environ.copy()
        env["NC25_READER_MUTANT"] = str(path)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "tests" / "test_reader.py"), TEST, "-f"],
            cwd=ROOT, env=env, stdin=subprocess.DEVNULL, capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=120, check=False,
        )
        failures = re.findall(r"^FAIL: .*\(case='([^']+)'\)$", result.stderr, re.MULTILINE)
        errors = re.findall(r"^ERROR: ", result.stderr, re.MULTILINE)
        observations.append({
            "case": label, "returncode": result.returncode,
            "first_red": failures[0] if failures else None,
            "failures": failures, "errors": errors,
            "stdout": result.stdout, "stderr": result.stderr,
        })
        if args.evidence is not None:
            args.evidence.write_text(json.dumps({
                "python": sys.version, "source_sha256": before,
                "observations": observations,
            }, indent=2) + "\n", encoding="utf-8")
        return result, failures, errors

    baseline, failures, errors = run(SOURCE, "baseline")
    if baseline.returncode != 0 or failures or errors:
        raise SystemExit("READER_JSON_BASELINE_FAILED: " + baseline.stderr[-1600:])

    assignment = 'GENESIS = "0" * 64\nMAX_EXPORT_BYTES = 32 * 1024 * 1024'
    cases = (
        ("integer_parser_limit", replace_once(
            source,
            "    except (UnicodeError, ValueError, RecursionError) as exc:",
            "    except (UnicodeError, json.JSONDecodeError) as exc:",
        ), "large_integer"),
        ("specific_json_codes", replace_once(
            source, "    except ReaderError:\n        raise\n", "",
        ), "duplicate_key"),
        ("SURVIVE", replace_once(
            source, assignment,
            'MAX_EXPORT_BYTES = 32 * 1024 * 1024\nGENESIS = "0" * 64',
        ), None),
        ("REACH", replace_once(
            source, "MAX_EXPORT_BYTES = 32 * 1024 * 1024", "MAX_EXPORT_BYTES = 1",
        ), "valid_export_control"),
    )
    with tempfile.TemporaryDirectory(prefix="reader-json-mutations-") as folder:
        mutant = Path(folder) / "nc25ol_reader.py"
        for label, changed, expected in cases:
            mutant.write_text(changed, encoding="utf-8")
            result, failures, errors = run(mutant, label)
            if expected is None:
                valid = result.returncode == 0 and not failures and not errors
            else:
                valid = result.returncode != 0 and failures == [expected] and not errors
            if not valid:
                raise SystemExit(
                    f"READER_JSON_MUTATION_FAILED {label}: rc={result.returncode} "
                    f"failures={failures!r} errors={errors!r} stderr={result.stderr[-1600:]!r}"
                )
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != before:
        raise SystemExit("READER_JSON_LIVE_SOURCE_CHANGED")
    print("READER_JSON_MUTATIONS=2/2 PASS; SURVIVE=PASS; REACH=PASS")


if __name__ == "__main__":
    main()
