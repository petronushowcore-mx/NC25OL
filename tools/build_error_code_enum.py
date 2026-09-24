"""Write the contract's Error.code enum from the live failure-surface scan.

The enum is the complete vocabulary a caller can receive: every engine refusal
code, every adapter wire code, and the codes the adapter's translation site
re-emits from an integrity halt. The first two come from the static scan of the
shipped source; the third is observable only at run time and is read from the
committed baseline's recorded run. The package verifier holds the written list
to the same sources (`openapi_error_codes_match_closed_world`) and reddens in
either direction, so this builder is run whenever that check names a
difference - after adding or retiring a code - and the result is committed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import failure_surface  # noqa: E402

CONTRACT = ROOT / "protocol" / "universal-connection.openapi.yaml"
BASELINE = ROOT / "tests" / "failure-surface-baseline.json"
DESCRIPTION = (
    "          description: >-\n"
    "            The complete vocabulary a caller can receive: every engine refusal\n"
    "            code, every adapter wire code, and every code the adapter re-emits\n"
    "            from an integrity halt. Generated from the shipped source by the\n"
    "            failure-surface scan and held in step with it by the package\n"
    "            verifier; adding a code to the engine or the adapter without\n"
    "            adding it here fails acceptance.\n"
)


def main() -> None:
    snapshot, problems = failure_surface.static_snapshot()
    if problems:
        for problem in problems:
            print(problem)
        raise SystemExit(1)
    recorded = json.loads(BASELINE.read_text(encoding="utf-8"))
    engine = set(snapshot["engine_refusal_codes"])
    wire = set(snapshot["wire_error_codes"])
    foreign = set(recorded["runtime"]["foreign_translated_codes"])
    if engine & wire:
        print(f"ERROR_CODE_VOCABULARIES_OVERLAP {sorted(engine & wire)}")
        raise SystemExit(1)
    codes = sorted(engine | wire | foreign)

    text = CONTRACT.read_text(encoding="utf-8")
    start = text.index("        code:\n", text.index("    Error:\n"))
    end = text.index("        message:\n", start)
    block = (
        "        code:\n"
        + DESCRIPTION
        + "          type: string\n"
        + "          enum:\n"
        + "".join(f"            - {code}\n" for code in codes)
    )
    CONTRACT.write_bytes((text[:start] + block + text[end:]).encode("utf-8"))
    print(
        f"ERROR_CODE_ENUM={len(codes)}"
        f" engine={len(engine)} wire={len(wire)} re_emitted={len(foreign)}"
    )


if __name__ == "__main__":
    main()
