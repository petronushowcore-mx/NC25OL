"""Run bounded source mutations in temporary copies and name the first failing test."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path("sdk/python/nc25_observation.py")
TESTS = Path("examples/observation_admission/test_observation_admission.py")

# Each replacement changes the implementation, never the test's assertion.
MUTATIONS = [
    ("false becomes sufficient", "test_c_false_cannot_issue_permit", [
        ('definite = report["verdict"] == "target_true_in_declared_fibre"',
         'definite = report["verdict"] in {"target_true_in_declared_fibre", "target_false_in_declared_fibre"}', 1)]),
    ("mixed loses review", "test_d_mixed_requires_review", [
        ('if report["verdict"] in {"insufficient_basis", "outside_declared_domain"}:',
         'if report["verdict"] in {"outside_declared_domain"}:', 1)]),
    ("outside loses review", "test_e_outside_requires_review", [
        ('if report["verdict"] in {"insufficient_basis", "outside_declared_domain"}:',
         'if report["verdict"] in {"insufficient_basis"}:', 1)]),
    ("positive erases baseline refusal", "test_f_true_cannot_erase_false_baseline", [
        ('controls["prerequisite_results"][self.prerequisite_id] and definite)', 'definite)', 1)]),
    ("hard blocks erased", "test_g_other_controls_preserved", [
        ('controls = copy.deepcopy(baseline)',
         'controls = copy.deepcopy(baseline)\n        controls["hard_block_flags"] = {key: False for key in controls["hard_block_flags"]}', 1)]),
    ("callbacks share mutable intent", "test_h_callbacks_cannot_rebind_original_intent", [
        ('self.base_resolver(copy.deepcopy(snapshot), now)', 'self.base_resolver(snapshot, now)', 1)]),
    ("request query is unbound", "test_h_callbacks_cannot_rebind_original_intent", [
        ('if not isinstance(request, dict) or request.get("query") != query:',
         'if not isinstance(request, dict):', 1)]),
    ("configured target is ignored", "test_j_target_mismatch_refuses", [
        ('if request.get("target") != self.target:', 'if False:', 1)]),
    ("output schema is unchecked", "test_k_output_schema_and_binding_refuse", [
        ('type(result["schema"]) is not int or result["schema"] != 1', 'False', 1)]),
    ("output target is unchecked", "test_k_output_schema_and_binding_refuse", [
        ('if result["target"] != request["target"]:', 'if False:', 1)]),
    ("output query is unchecked", "test_k_output_schema_and_binding_refuse", [
        ('if result["query"] != request["query"]:', 'if False:', 1)]),
    ("duplicate output fields overwrite", "test_l_duplicate_and_invalid_json_refuse", [
        ('if key in result:', 'if False:', 1)]),
    ("changed binary is accepted", "test_o_native_missing_or_changed_refuses", [
        ('if _digest(self.executable) != self._binary_digest:', 'if False:', 2)]),
    ("output pipe limit is enlarged", "test_p_process_timeout_and_output_are_bounded", [
        ('MAX_OUTPUT_BYTES = 2_097_152', 'MAX_OUTPUT_BYTES = 3_145_728', 1)]),
    ("requested timeout is ignored", "test_p_process_timeout_and_output_are_bounded", [
        ('process.wait(timeout=timeout)', 'process.wait(timeout=5)', 1)]),
    ("mixed witness polarity is ignored", "test_u_mixed_witness_envelope_checked", [
        ('by_id.get(witness["true_world_id"]) is not True\n                    or by_id.get(witness["false_world_id"]) is not False',
         'False', 1)]),
    ('baseline Mapping support is removed', 'test_v_mapping_baselines_preserve_core_contract', [
        ('if isinstance(baseline, Mapping):', 'if False:', 1)]),
    ('prerequisite_results Mapping is not materialized', 'test_v_mapping_baselines_preserve_core_contract', [
        ('if isinstance(baseline.get(name), Mapping):', 'if isinstance(baseline.get(name), Mapping) and name != "prerequisite_results":', 1)]),
    ('hard_block_flags Mapping is not materialized', 'test_v_mapping_baselines_preserve_core_contract', [
        ('if isinstance(baseline.get(name), Mapping):', 'if isinstance(baseline.get(name), Mapping) and name != "hard_block_flags":', 1)]),
    ('manual_review_flags Mapping is not materialized', 'test_v_mapping_baselines_preserve_core_contract', [
        ('if isinstance(baseline.get(name), Mapping):', 'if isinstance(baseline.get(name), Mapping) and name != "manual_review_flags":', 1)]),
    ('pair sequences become valid control maps', 'test_w_invalid_mapping_controls_remain_closed', [
        ('if isinstance(baseline.get(name), Mapping):', 'if isinstance(baseline.get(name), (Mapping, list)):', 1)]),
    ("definite verdict contradicts its supplied cases", "test_x_definite_verdict_matches_supplied_premises", [
        ('if any(world["target_holds"] is not expected for world in matching):', 'if False:', 1)]),
    ("unrelated cases invalidate a definite verdict", "test_x_definite_verdict_matches_supplied_premises", [
        ('world["target_holds"] is not expected for world in matching',
         'world["target_holds"] is not expected for world in request["worlds"]', 1)]),
]


def first_failure(text):
    match = re.search(r"^(?:FAIL|ERROR): (test_[A-Za-z0-9_]+)\b", text, re.MULTILINE)
    return match.group(1) if match else None


def copy_tree(destination):
    shutil.copytree(ROOT / "sdk/python", destination / "sdk/python", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(ROOT / "profiles/document-release", destination / "profiles/document-release")
    shutil.copytree(ROOT / "examples/observation_admission", destination / "examples/observation_admission",
                    ignore=shutil.ignore_patterns("__pycache__"))


def run_suite(directory):
    env = dict(os.environ, NC25_LEDGER_ROOT=str(directory))
    result = subprocess.run([sys.executable, "-B", str(directory / TESTS), "-v", "-f"],
                            cwd=directory, env=env, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=240)
    return result, result.stdout + result.stderr


def exercise(index, mutation, scratch, original, logs):
    title, expected, replacements = mutation
    with tempfile.TemporaryDirectory(prefix=f"observation-mutation-{index:02d}-", dir=scratch) as temp:
        directory = Path(temp)
        copy_tree(directory)
        changed = original
        for old, new, count in replacements:
            actual = changed.count(old)
            if actual != count:
                raise RuntimeError(f"{title}: expected {count} source anchors, found {actual}")
            changed = changed.replace(old, new)
        if changed == original:
            raise RuntimeError(f"{title}: no changed source bytes")
        (directory / SOURCE).write_text(changed, encoding="utf-8", newline="\n")
        result, output = run_suite(directory)
        (logs / f"observation-mutation-{index:02d}.log").write_text(output, encoding="utf-8")
        observed = first_failure(output)
        if result.returncode == 0 or observed != expected:
            raise RuntimeError(f"{title}: expected first failure {expected}, got {observed}; exit={result.returncode}")
        return {"mutation": title, "expected_first_failure": expected, "observed_first_failure": observed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch", required=True, type=Path)
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=1)
    args = parser.parse_args()
    if not os.environ.get("NC25_OBSERVATION_ENGINE"):
        parser.error("NC25_OBSERVATION_ENGINE must name the real native executable")
    scratch = args.scratch.resolve(strict=True)
    if not scratch.is_dir():
        parser.error("--scratch must be an existing directory")
    source = ROOT / SOURCE
    original_bytes = source.read_bytes()
    original = original_bytes.decode("utf-8").replace("\r\n", "\n")
    with tempfile.TemporaryDirectory(prefix="observation-mutations-", dir=scratch) as work:
        directory = Path(work)
        with tempfile.TemporaryDirectory(prefix="baseline-", dir=directory) as baseline:
            copied = Path(baseline)
            copy_tree(copied)
            result, output = run_suite(copied)
            (scratch / "observation-baseline.log").write_text(output, encoding="utf-8")
            if result.returncode != 0:
                raise RuntimeError("baseline failed; see observation-baseline.log")
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futures = [pool.submit(exercise, index, mutation, directory, original, scratch)
                       for index, mutation in enumerate(MUTATIONS, 1)]
            results = []
            for index, future in enumerate(futures, 1):
                result = future.result()
                results.append(result)
                print(f"PASS {index}: {result['mutation']} -> {result['observed_first_failure']}", flush=True)
    if source.read_bytes() != original_bytes:
        raise RuntimeError("working implementation changed during mutation run")
    report = {"source_sha256": hashlib.sha256(original_bytes).hexdigest(),
              "baseline": "PASS", "mutations": results, "working_source_unchanged": True}
    (scratch / "observation-mutations.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"PASS: {len(results)} source mutations, named first failures, working source unchanged")


if __name__ == "__main__":
    main()