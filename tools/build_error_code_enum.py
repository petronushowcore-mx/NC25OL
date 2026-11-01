"""Write the contract's closed Error.code enum from the failure-surface scan.

The declared vocabulary is a conservative superset of codes reachable through
any one request path. Schema-first validation can pre-empt domain guards;
authoritative resolver details become a recorded generic refusal. Engine and
wire codes come from the static scan. The recorded run's foreign translated
codes are NOT in the list: by the baseline's own definition such a code was
injected from outside production, typically by a test replacing an engine
method, so no production path emits it, and a test-only name that reached the
published enum became part of the public contract (LEDGER_TAMPERED did). They
stay in the baseline as a visible ratchet. The package verifier holds the
written list to the static scan in both directions. Regenerate after adding or
retiring codes.
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
    "            The closed declared vocabulary includes engine refusal codes\n"
    "            and adapter wire codes.\n"
    "            It is a conservative superset of codes reachable through any one\n"
    "            request path: schema validation can refuse a body before a domain\n"
    "            guard, and authoritative resolver failures become recorded generic\n"
    "            non-executable refusals rather than exposing resolver details.\n"
    "            Generated from the shipped source by the failure-surface scan and\n"
    "            held in step with it by the package verifier; adding an engine or\n"
    "            adapter refusal code without adding it here fails acceptance.\n"
)


def declared_codes(snapshot: dict, recorded: dict) -> tuple[list[str], int, int, int]:
    """The enum's codes, with the three counts: engine, wire, and foreign (not published).

    One home for the rule, so a test can plant a foreign code in `recorded` and watch it
    stay out. Raises SystemExit when the engine and wire vocabularies overlap.
    """
    engine = set(snapshot["engine_refusal_codes"])
    wire = set(snapshot["wire_error_codes"])
    foreign = set(recorded["runtime"]["foreign_translated_codes"])
    if engine & wire:
        print(f"ERROR_CODE_VOCABULARIES_OVERLAP {sorted(engine & wire)}")
        raise SystemExit(1)
    return sorted(engine | wire), len(engine), len(wire), len(foreign)


def main() -> None:
    snapshot, problems = failure_surface.static_snapshot()
    if problems:
        for problem in problems:
            print(problem)
        raise SystemExit(1)
    recorded = json.loads(BASELINE.read_text(encoding="utf-8"))
    codes, engine_count, wire_count, foreign_count = declared_codes(snapshot, recorded)

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
        f" engine={engine_count} wire={wire_count} foreign_not_published={foreign_count}"
    )


if __name__ == "__main__":
    main()
