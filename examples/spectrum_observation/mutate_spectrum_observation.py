"""Run source mutations on copies and require their named first failing test."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
LEDGER_ROOT = Path(os.environ.get('NC25_LEDGER_ROOT', ROOT.parents[1])).resolve()
MODULE = 'spectrum_observation'
TEST = 'test_spectrum_observation'
EXPECTED_TESTS = 16
CASES = [
    ('foreign_repository_root', 1, 'Path(git(folder, "rev-parse", "--show-toplevel")).resolve() == folder', 'True'),
    ('revision_not_checked', 1, 'git(folder, "rev-parse", "HEAD") == revision', 'True'),
    ('hidden_git_flags_ignored', 1,
     'not any(row[:1].islower() or row.startswith("S ") for row in flags if row)', 'True'),
    ('dirty_source_accepted', 1,
     'not git(folder, "status", "--porcelain=v1", "--untracked-files=all", "--ignored")', 'True'),
    ('source_digest_not_measured', 1,
     'digest((root / path).read_bytes())', '"0" * 64'),
    ('provenance_path_ignored', 2,
     'Path(row["path"]).resolve() == (root / relative).resolve()', 'True'),
    ('provenance_digest_ignored', 2,
     'row["sha256"] == snapshot["source_sha256"][name]', 'True'),
    ('scenario_count_replaces_identity', 3,
     '{row[len("[PASS] "):] for row in cases} == SCENARIOS', 'len(cases) == 15'),
    ('control_count_replaces_identity', 4,
     '{row[len("[PASS] control "):] for row in controls} == CONTROL_IDS', 'len(set(controls)) == 28'),
    ('full_regime_scope_overclaimed', 5,
     'transport["full_regime_w"] == "NOT_EVALUATED"', 'True'),
    ('wrong_exit_is_named_refusal', 6,
     'result.returncode == 1 and named', 'bool(named)', 2),
    ('structured_refusal_treated_as_crash', 6,
     'if result.returncode == 1 and diagnostic:', 'if False:'),
    ('output_ceiling_removed', 7,
     'len(result.stdout) + len(result.stderr) <= MAX_OUTPUT', 'True'),
    ('duplicate_json_keys_accepted', 7,
     'require(key not in result, "OUTPUT_DUPLICATE_KEY")', 'require(True, "OUTPUT_DUPLICATE_KEY")'),
    ('stdout_digest_fabricated', 8,
     '"stdout_sha256": digest(result.stdout)', '"stdout_sha256": "0" * 64'),
    ('observation_constructed_as_executable', 8,
     '"executable": False', '"executable": True'),
    ('measurement_association_overclaimed', 8,
     '"measurement_to_declaration": "NOT_EVALUATED"', '"measurement_to_declaration": "VERIFIED"'),
    ('measurement_subject_overclaimed', 8,
     '"measured_subject": "TECTONICA_XIV_XV_SUPPLIED_FINITE_FIXTURES"',
     '"measured_subject": "ALL_DEPLOYMENTS"'),
    ('collector_time_becomes_naive', 8,
     'datetime.now(timezone.utc).isoformat()',
     'datetime.now(timezone.utc).replace(tzinfo=None).isoformat()', 2),
    ('private_report_digest_ignored', 9,
     'require(digest(raw) == self._expected_digest, "REPORT_CHANGED")', 'require(True, "REPORT_CHANGED")'),
    ('same_session_replay_accepted', 10,
     'require(not self._consumed, "OBSERVATION_REPLAY")', 'require(True, "OBSERVATION_REPLAY")'),
    ('failed_collection_retried', 11,
     'require(not self._collected, "COLLECTION_ALREADY_ATTEMPTED")', 'require(True, "COLLECTION_ALREADY_ATTEMPTED")'),
    ('registry_drift_ignored', 12,
     'require(self._read_registry() == self._registry, "LEDGER_CONTEXT_CHANGED")', 'require(True, "LEDGER_CONTEXT_CHANGED")'),
    ('source_drift_ignored', 13,
     'require(source_snapshot(self._root, self._revision) == self._source, "SOURCE_CHANGED")', 'require(True, "SOURCE_CHANGED")'),
    ('post_child_source_check_removed', 14,
     'ended = datetime.now(timezone.utc).isoformat()\n        self._unchanged()',
     'ended = datetime.now(timezone.utc).isoformat()'),
    ('receive_changes_real_engine_budget', 15,
     'self._consumed = True\n        return report',
     'self._consumed = True\n        self._engine.structural_remaining -= 1\n        return report'),
    ('collector_omits_controls', 16, ', "--teeth"]', ']'),
    ('valid_fixture_incorrectly_refused', 2,
     'transport["full_regime_w"] == "NOT_EVALUATED"', 'transport["full_regime_w"] != "NOT_EVALUATED"'),
]


def child():
    import test_spectrum_observation
    class Result(unittest.TestResult):
        def __init__(self):
            super().__init__(); self.first = None
        def addFailure(self, test, err):
            if self.first is None: self.first = test.id()
            super().addFailure(test, err)
        def addError(self, test, err):
            if self.first is None: self.first = test.id()
            super().addError(test, err)
        def addSubTest(self, test, subtest, err):
            if err is not None and self.first is None: self.first = test.id()
            super().addSubTest(test, subtest, err)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(test_spectrum_observation.Cases)
    result = Result(); result.failfast = True; suite.run(result)
    print(json.dumps({'ok': result.wasSuccessful(), 'tests': result.testsRun, 'first': result.first,
                     'details': [text for _, text in result.failures + result.errors]}))
    return 0 if result.wasSuccessful() else 1


def detected(data, first):
    return data['exit'] == 1 and data['ok'] is False and data['first'] == first


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', type=Path, required=True, help='Existing directory outside the Ledger package')
    scratch = parser.parse_args().scratch.resolve()
    if not scratch.is_dir() or scratch == LEDGER_ROOT or LEDGER_ROOT in scratch.parents:
        parser.error('--scratch must exist outside the Ledger package')
    run = Path(tempfile.mkdtemp(prefix='spectrum-mutations-', dir=scratch))
    env = dict(os.environ, NC25_LEDGER_ROOT=str(LEDGER_ROOT), TEMP=str(run), TMP=str(run), TMPDIR=str(run))
    original = (ROOT/(MODULE+'.py')).read_bytes()
    source = original.decode('utf-8-sig')
    test_bytes = (ROOT/(TEST+'.py')).read_bytes()

    def execute(name, code):
        folder = run/name; folder.mkdir()
        (folder/(MODULE+'.py')).write_text(code, encoding='utf-8', newline='\n')
        (folder/(TEST+'.py')).write_bytes(test_bytes)
        runner = folder/Path(__file__).name
        shutil.copy2(__file__, runner)
        cp = subprocess.run([sys.executable, '-B', str(runner), '--child'], cwd=folder,
                            capture_output=True, text=True, encoding='utf-8', timeout=30, env=env)
        (folder/'stdout.txt').write_text(cp.stdout, encoding='utf-8')
        (folder/'stderr.txt').write_text(cp.stderr, encoding='utf-8')
        data = json.loads(cp.stdout); data['exit'] = cp.returncode
        return data

    baseline = execute('baseline', source)
    if not (baseline['ok'] and baseline['tests'] == EXPECTED_TESTS and baseline['exit'] == 0):
        raise RuntimeError(('BASELINE', baseline))
    assert not detected(baseline, TEST+'.Cases.test_01_source_snapshot_checks_exact_git_boundaries_and_bytes')
    import ast
    case_class = next(n for n in ast.parse(test_bytes).body if isinstance(n, ast.ClassDef) and n.name == 'Cases')
    test_names = {int(n.name[5:7]): TEST+'.Cases.'+n.name for n in case_class.body
                  if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')}
    assert len(test_names) == EXPECTED_TESTS
    assert set(test_names) == {entry[1] for entry in CASES}, 'EVERY_TEST_HAS_NAMED_MUTATION'
    results = []
    for entry in CASES:
        name, number, before, after = entry[:4]
        expected_count = entry[4] if len(entry) == 5 else 1
        if source.count(before) != expected_count:
            raise RuntimeError(('ANCHOR', name, source.count(before), expected_count))
        code = source.replace(before, after)
        assert code != source, ('NO_CHANGE', name)
        data = execute(name, code)
        first = test_names[number]
        passed = detected(data, first)
        assert not detected(data, 'a.different.first.test'), 'CLASSIFIER_CONTROL'
        results.append({'mutation': name, 'expected_first': first, 'observed_first': data['first'], 'passed': passed})
        print(name, passed, flush=True)
    assert (ROOT/(MODULE+'.py')).read_bytes() == original, 'SOURCE_CHANGED_DURING_RUN'
    assert (ROOT/(TEST+'.py')).read_bytes() == test_bytes, 'TEST_CHANGED_DURING_RUN'
    report = {'baseline': baseline, 'source_sha256': hashlib.sha256(original).hexdigest(),
              'test_sha256': hashlib.sha256(test_bytes).hexdigest(), 'mutations': results,
              'scope': 'First failing test in the full ordered local suite; not every assertion independently mutated. '
                       'Git and Spectrum execution are mocked; Ledger and SQLite reads are real. '
                       'Receive identity/authority checks sit behind the private digest; no independent first-failure claim.'}
    (run/'result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    ok = all(row['passed'] for row in results)
    print(json.dumps({'ok': ok, 'mutations': len(results), 'report': str(run/'result.json')}))
    return 0 if ok else 1


if __name__ == '__main__': raise SystemExit(child() if '--child' in sys.argv else main())
