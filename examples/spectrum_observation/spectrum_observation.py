"""Local Spectrum observations associated with a Ledger context, never permits."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

ROOT = Path(os.environ.get("NC25_LEDGER_ROOT", Path(__file__).resolve().parents[2])).resolve()
sys.path.insert(0, str(ROOT / "sdk/python"))
from nc25_universal_ledger import canonical_json

MODULES = {
    "finite": "layers/XIV/harness/finite_state_harness.py",
    "bc": "layers/XIV/harness/beck_chevalley_check.py",
    "robust": "layers/XIV/robustness-companion/harness/robustness_harness.py",
    "graph": "layers/XV/harness/graph_hodge.py",
    "nest": "layers/XV/harness/nestability.py",
    "core": "layers/XV/harness/core_reduction.py",
}
SCENARIOS = {
    "SIMPLE", "SELF_LOOP", "REPEATED_EDGE", "NU_NOT_BUDGET_RESPECTING",
    "ZERO_COST_MOTION", "EXPLICIT_WINDOW_SELECTOR", "SEALED_CORE",
    "NO_ADMISSIBLE_MOTION", "SINGLETON_REJECTED", "PARALLEL_REFUSAL",
    "INFINITE_CAPACITY_REFUSAL", "PAIRING_IS_NOT_GLOBAL_CLASS",
    "TREE_GLOBAL_CLASS_ZERO", "NONZERO_EXACT_CLASS_ZERO", "NONZERO_PERIOD_CLASS",
}
CONTROL_IDS = {
    "map_missing_state", "map_foreign_state", "map_not_monic", "missing_image_edge",
    "image_outside_K", "wrong_Adm_mode", "nonpath_in_lower_Adm", "missing_admissible_window",
    "foreign_adapter_type", "extra_admissible_recombination", "negative_lower_burden",
    "nonunit_nonnegative_burden", "unused_upper_structure_survives", "extra_lower_state",
    "extra_lower_edge", "lower_does_not_exhaust", "count_distinct_edges_not_traversals",
    "upper_joint_exhaustion", "fractional_lower_capacity", "burden_evaluator_never_crosses",
    "burden_evaluator_overshoots", "upstream_m_IE_wrong_value", "upstream_ie_verdict_wrong_value",
    "foreign_cochain_edge", "inexact_cochain", "unrelated_crash_is_not_a_model_refusal",
    "shared_window_generator_omits_singleton", "positive_controls_survive_mutations",
}
MAX_OUTPUT = 1024 * 1024


class Refusal(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise Refusal(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def git(root, *args):
    try:
        result = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(root), *args],
            capture_output=True, text=True, encoding="utf-8", timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refusal("SOURCE_UNAVAILABLE") from exc
    require(result.returncode == 0, "SOURCE_GIT")
    return result.stdout.rstrip("\r\n")


def source_snapshot(root, expected_revision):
    """Check three quiescent repositories; this is not a filesystem lock."""
    root = Path(root).resolve()
    require(type(expected_revision) is str and
            re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", expected_revision), "REVISION_REQUIRED")
    revisions = {"spectrum": expected_revision}
    for name in ("XIV", "XV"):
        row = git(root, "ls-tree", "HEAD", "--", "layers/" + name).split()
        require(len(row) == 4 and row[:2] == ["160000", "commit"]
                and row[3] == "layers/" + name, "LAYER_PIN_REQUIRED")
        revisions[name] = row[2]
    for name, revision in revisions.items():
        folder = root if name == "spectrum" else root / "layers" / name
        require(Path(git(folder, "rev-parse", "--show-toplevel")).resolve() == folder,
                "SOURCE_ROOT")
        require(git(folder, "rev-parse", "HEAD") == revision, "SOURCE_REVISION")
        flags = git(folder, "ls-files", "-v", "-z").split("\0")
        require(not any(row[:1].islower() or row.startswith("S ") for row in flags if row),
                "SOURCE_HIDDEN_FLAGS")
        require(not git(folder, "status", "--porcelain=v1", "--untracked-files=all", "--ignored"),
                "SOURCE_DIRTY")
    files = {name: digest((root / path).read_bytes()) for name, path in MODULES.items()}
    files["runner"] = digest((root / "layers/XV/harness/xiv_stitch.py").read_bytes())
    return {"revisions": revisions, "source_sha256": files}


def execute(root):
    """Run the pinned stitch directly: one child, no launcher grandchild."""
    command = [sys.executable, "-B", str(root / "layers/XV/harness/xiv_stitch.py"),
               "--xiv-root", str(root / "layers/XIV"), "--teeth"]
    try:
        return subprocess.run(command, cwd=root, capture_output=True, timeout=60,
                              env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(command, 2, b"", b"RUN_UNAVAILABLE")


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "OUTPUT_DUPLICATE_KEY")
        result[key] = value
    return result


def decode(raw):
    def nonfinite(_):
        raise Refusal("OUTPUT_NUMBER")
    try:
        return json.loads(raw, object_pairs_hook=_object, parse_constant=nonfinite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, Refusal):
            raise
        raise Refusal("OUTPUT_JSON") from exc


def interpret(result, root, snapshot):
    """Interpret the supplied-fixture output contract, not a theorem certificate."""
    require(type(result.stdout) is bytes and type(result.stderr) is bytes
            and len(result.stdout) + len(result.stderr) <= MAX_OUTPUT, "OUTPUT_BYTES")
    if result.returncode != 0:
        # An arbitrary exit 1 is not a named model refusal.
        named = re.fullmatch(rb"xiv_stitch: FAIL ([A-Z0-9_]+)\r?\n?", result.stderr)
        diagnostic = re.fullmatch(
            rb"xiv_stitch: FAIL (?:(MISSING_REFUSAL): ([A-Z0-9_]+)|"
            rb"(WRONG_FIRST_MARKER): (wanted=[A-Z0-9_]+ got=[A-Z0-9_]+))\r?\n?",
            result.stderr)
        if result.returncode == 1 and diagnostic:
            return {"status": "REFUSED", "code": (diagnostic[1] or diagnostic[3]).decode("ascii"),
                    "diagnostic": (diagnostic[2] or diagnostic[4]).decode("ascii"), "facts": {}}
        return {"status": "REFUSED" if result.returncode == 1 and named else "NOT_MEASURED",
                "code": named[1].decode("ascii") if result.returncode == 1 and named else "RUN_INCOMPLETE",
                "facts": {}}
    require(not result.stderr, "OUTPUT_STDERR")
    try:
        lines = result.stdout.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise Refusal("OUTPUT_ENCODING") from exc
    require(len(lines) == 48 and lines[0].startswith("SOURCE_PROVENANCE "), "OUTPUT_SHAPE")
    provenance = decode(lines[0][len("SOURCE_PROVENANCE "):])
    require(type(provenance) is dict and set(provenance) == set(MODULES), "SOURCE_PROVENANCE")
    for name, relative in MODULES.items():
        row = provenance[name]
        require(type(row) is dict and set(row) == {"path", "sha256"}
                and type(row["path"]) is str
                and Path(row["path"]).resolve() == (root / relative).resolve()
                and row["sha256"] == snapshot["source_sha256"][name], "SOURCE_PROVENANCE")
    cases = lines[1:16]
    require(all(row.startswith("[PASS] ") for row in cases)
            and {row[len("[PASS] "):] for row in cases} == SCENARIOS
            and lines[16] == "xiv_stitch selftest: 15/15 OK", "SCENARIO_SET")
    controls = lines[17:45]
    require(all(row.startswith("[PASS] control ") for row in controls)
            and {row[len("[PASS] control "):] for row in controls} == CONTROL_IDS
            and lines[45] == "xiv_stitch mutation/control rows: 28/28 OK", "CONTROL_SET")
    require(lines[46].startswith("TRANSPORT ")
            and lines[47] == "xiv_stitch: PASS (finite supplied witnesses only)", "OUTPUT_TAIL")
    transport = decode(lines[46][len("TRANSPORT "):])
    require(type(transport) is dict and set(transport) ==
            {"pairing_verdict", "global_class_zero", "full_regime_w", "reason"}
            and transport["pairing_verdict"] == "ANNIHILATING"
            and transport["global_class_zero"] is False
            and transport["full_regime_w"] == "NOT_EVALUATED"
            and type(transport["reason"]) is str and bool(transport["reason"]), "TRANSPORT_SCOPE")
    return {"status": "VERIFIED", "code": "SUPPLIED_FIXTURES",
            "facts": {"scenario_ids": sorted(SCENARIOS), "control_rows": 28,
                      "transport": transport}}


class ObservationSession:
    """One trusted engine object, one local collection, one consumption.

    The private digest is provisioned by collect(), not read from the report.
    It protects this in-process exchange, not remote identity or durable replay.
    """
    def __init__(self, engine, connector_id, spectrum_root, expected_revision):
        self._engine = engine
        self._connector_id = connector_id
        self._root = Path(spectrum_root).resolve()
        self._revision = expected_revision
        self._registry = self._read_registry()
        self._source = source_snapshot(self._root, self._revision)
        self._nonce = secrets.token_hex(32)
        self._expected_digest = None
        self._collected = False
        self._consumed = False

    def _read_registry(self):
        return canonical_json(self._engine.registry_record(
            self._connector_id, actor_scope="nc25.architect"))

    def _unchanged(self):
        require(self._read_registry() == self._registry, "LEDGER_CONTEXT_CHANGED")
        require(source_snapshot(self._root, self._revision) == self._source, "SOURCE_CHANGED")

    def collect(self):
        require(not self._collected, "COLLECTION_ALREADY_ATTEMPTED")
        self._collected = True
        self._unchanged()
        started = datetime.now(timezone.utc).isoformat()
        result = execute(self._root)
        ended = datetime.now(timezone.utc).isoformat()
        self._unchanged()
        observation = interpret(result, self._root, self._source)
        report = {
            "format": "nc25ol-spectrum-observation/v1",
            "observation_id": self._nonce,
            "association": {"kind": "LOCAL_CONTEXT_ONLY",
                            "ledger_registry": json.loads(self._registry),
                            "measurement_to_declaration": "NOT_EVALUATED"},
            "measured_subject": "TECTONICA_XIV_XV_SUPPLIED_FINITE_FIXTURES",
            "source": self._source,
            "collection": {"started_at": started, "finished_at": ended,
                           "stdout_sha256": digest(result.stdout),
                           "stderr_sha256": digest(result.stderr),
                           "returncode": result.returncode},
            "observation": observation,
            "temporal": {"clock": "collector_wall_clock",
                         "semantic_validity": "NOT_ESTABLISHED",
                         "structural_time": "NOT_MEASURED",
                         "c1_c4_deployment": "NOT_EVALUATED"},
            "executable": False,
            "admission": "NOT_REQUESTED",
        }
        raw = canonical_json(report)
        self._expected_digest = digest(raw)
        return raw

    def receive(self, raw):
        require(self._expected_digest is not None, "LOCAL_COLLECTION_REQUIRED")
        require(not self._consumed, "OBSERVATION_REPLAY")
        require(type(raw) is bytes and 0 < len(raw) <= MAX_OUTPUT, "REPORT_BYTES")
        require(digest(raw) == self._expected_digest, "REPORT_CHANGED")
        self._unchanged()
        report = decode(raw)
        # Defense in depth behind the byte-digest check; not an independent
        # first-failure path for an externally substituted report.
        require(report["observation_id"] == self._nonce, "OBSERVATION_CONTEXT")
        require(report["executable"] is False and report["admission"] == "NOT_REQUESTED",
                "OBSERVATION_AUTHORITY")
        self._consumed = True
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spectrum-root", type=Path, required=True)
    parser.add_argument("--spectrum-revision", required=True,
                        help="Full commit selected independently by the operator")
    parser.add_argument("--output", type=Path, required=True, help="New file outside both source trees")
    args = parser.parse_args()
    output = args.output.resolve()
    require(not output.is_relative_to(ROOT) and
            not output.is_relative_to(args.spectrum_root.resolve()), "OUTPUT_OUTSIDE_SOURCES")
    # The example associates a real Spectrum run with an inactive synthetic Ledger.
    # No activation, grant, evaluation, permit, executor or network endpoint is used.
    from nc25_universal_ledger import UniversalConnectionLedger, FixedClock, bind_fixture
    fixture = json.loads((ROOT / "profiles/document-release/reference-connection.json").read_bytes())
    profile, declaration, _, _ = bind_fixture(
        *(fixture[k] for k in ("profile", "declaration", "grant", "intent")))
    engine = UniversalConnectionLedger(profile, declaration, secrets.token_bytes(32),
        clock=FixedClock(datetime(2026, 8, 1, 10, tzinfo=timezone.utc)))
    session = ObservationSession(engine, declaration["connector"]["connector_id"],
                                 args.spectrum_root, args.spectrum_revision)
    raw = session.collect()
    report = session.receive(raw)
    with output.open("xb") as stream:
        stream.write(raw)
    print(json.dumps({"report": str(output), "status": report["observation"]["status"],
                      "executable": report["executable"], "synthetic_ledger": True}))
    return 0 if report["observation"]["status"] == "VERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
