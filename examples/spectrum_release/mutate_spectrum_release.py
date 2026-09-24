"""Mutate copied release source; require the exact first failing unittest."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
LEDGER_ROOT = Path(os.environ.get('NC25_LEDGER_ROOT', HERE.parents[1])).resolve()
MODULE = 'spectrum_release'
TEST = 'test_spectrum_release'
EXPECTED_TESTS = 28
CASES = [
    ('git_exit_ignored', 1, 'result.returncode == 0', 'True'),
    ('unused_file_omitted', 2, 'members[full] = raw', 'if full != "docs/unused.md": members[full] = raw'),
    ('gitlink_pin_ignored', 3, 'and oid == snapshot["revisions"][relative.split("/")[1]]', 'and True'),
    ('blob_identity_ignored', 4, 'actual_oid == oid and kind == "blob"', 'kind == "blob"'),
    ('blob_kind_ignored', 4, 'actual_oid == oid and kind == "blob"', 'actual_oid == oid'),
    ('blob_separator_ignored', 4, r'len(raw) == int(size) and data.read(1) == b"\n"', 'len(raw) == int(size) and bool(data.read(1) or True)'),
    ('blob_trailing_ignored', 4, 'require(not data.read(), "SOURCE_BLOB_TRAILING")', 'require(True, "SOURCE_BLOB_TRAILING")'),
    ('unused_checkout_mismatch_ignored', 5, 'file.read_bytes() == raw', 'True'),
    ('source_type_ignored', 6, 'mode in {"100644", "100755"} and kind == "blob"', 'True'),
    ('source_parent_path_ignored', 6, 'all(p not in {".", "..", ".git"} and ":" not in p for p in parts)', 'True'),
    ('release_namespace_case_sensitive', 6, 'not full.casefold().startswith("release/")', 'not full.startswith("release/")'),
    ('case_collision_ignored', 6, 'full.casefold() not in folded', 'True'),
    ('file_existence_ignored', 6, 'and file.is_file()', 'and True'),
    ('post_blob_snapshot_ignored', 7, 'observation.source_snapshot(root, revision) == snapshot', 'True'),
    ('module_binding_ignored', 8,
     'all(path in members and digest(members[path]) == snapshot["source_sha256"][name]\n                for name, path in files.items())', 'True'),
    ('zip_drops_unused_file', 9, 'for name, raw in sorted(members.items()):',
     'for name, raw in sorted((k, v) for k, v in members.items() if k != "docs/unused.md"):'),
    ('zip_mode_lost', 9, 'int(modes.get(name, "100644"), 8) << 16', 'int("100644", 8) << 16'),
    ('zip_duplicate_count_ignored', 10, 'len(entries) == len(expected) and ', ''),
    ('zip_member_set_ignored', 10, ' and {e.filename for e in entries} == set(expected)', ''),
    ('zip_bytes_ignored', 11, 'entry.file_size == len(wanted) and archive.read(entry) == wanted', 'True'),
    ('zip_size_ignored', 12, 'type(raw) is bytes and 0 < len(raw) <= scenario.dr.MAX_BODY // 2', 'True'),
    ('zip_type_ignored', 12, 'and stat.S_ISREG(entry.external_attr >> 16)', 'and True'),
    ('nonverified_observation_accepted', 13, 'self.report["observation"]["status"] == "VERIFIED"', 'True'),
    ('observation_source_ignored', 14, 'self.report["source"] == self.source', 'True'),
    ('unused_records_ignored', 15, 'current == self.source and records == self.records', 'current == self.source'),
    ('post_collect_check_omitted', 15, 'self.check_sources()\n        self.manifest', 'self.manifest'),
    ('manifest_observation_hash_wrong', 16, '"observation_sha256": digest(self.report_bytes)', '"observation_sha256": "0" * 64'),
    ('registry_association_ignored', 17, 'registry == self.report["association"]["ledger_registry"]', 'True'),
    ('session_required_ignored', 18, 'self._session is not None, "RELEASE_SESSION_REQUIRED"', 'True, "RELEASE_SESSION_REQUIRED"'),
    ('second_open_allowed', 18, 'self._session is None, "RELEASE_SESSION_EXISTS"', 'True, "RELEASE_SESSION_EXISTS"'),
    ('changed_package_allowed', 19, 'type(package) is bytes and digest(package) == self._archive_digest', 'True'),
    ('changed_target_allowed', 20, 'canonical_json(self._session.op) == self._operation', 'True'),
    ('submit_source_check_omitted', 21, 'self.check_sources()\n        self._attempted = True', 'self._attempted = True'),
    ('second_attempt_allowed', 22, 'not self._attempted, "RELEASE_ALREADY_ATTEMPTED"', 'True, "RELEASE_ALREADY_ATTEMPTED"'),
    ('authority_activation_omitted', 23, 'session.activate()  # Explicit synthetic owner decision, independent of Spectrum.', 'pass  # No activation.'),
    ('full_regime_overclaimed', 23, '"full_regime_w": "NOT_EVALUATED", "live_witnesses_connected": False',
     '"full_regime_w": "VERIFIED", "live_witnesses_connected": False'),
    ('wrong_denial_allowed', 24, 'exc.code == "DECLARATION_NOT_ACTIVE"', 'True'),
    ('denial_effect_ignored', 24, 'session.target_counts() == (0, 0) and session.engine.structural_remaining == 400', 'True'),
    ('changed_target_bytes_ignored', 24, 'received == prepared.archive, "TARGET_BYTES_CHANGED"', 'True, "TARGET_BYTES_CHANGED"'),
    ('changed_recovery_ignored', 24, 'replay == first and session.target_counts() == (1, 1)', 'session.target_counts() == (1, 1)'),
    ('output_source_boundary_ignored', 25, 'not directory.is_relative_to(ROOT) and not directory.is_relative_to(Path(root).resolve())', 'True'),
    ('existing_output_allowed', 25, 'not directory.exists(), "RUN_DIRECTORY_EXISTS"', 'True, "RUN_DIRECTORY_EXISTS"'),
    ('changed_archive_open_allowed', 27, 'type(self.archive) is bytes and digest(self.archive) == self._archive_digest', 'True'),
    ('different_operation_payload_allowed', 28, 'scenario.dr.operation(self._session.op) == package', 'True'),
    ('honest_source_overrefused', 2, 'file.read_bytes() == raw', 'file.read_bytes() != raw'),
    ('honest_zip_size_overrefused', 9, '0 < len(raw) <= scenario.dr.MAX_BODY // 2', '0 < len(raw) < 10'),
    ('honest_zip_members_overrefused', 9, 'len(entries) == len(expected)', 'len(entries) != len(expected)'),
]


def child():
    import test_spectrum_release
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
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(test_spectrum_release.Cases)
    result = Result(); result.failfast = True; suite.run(result)
    print(json.dumps({'ok': result.wasSuccessful(), 'tests': result.testsRun, 'first': result.first,
                      'details': [text for _, text in result.failures + result.errors]}))
    return 0 if result.wasSuccessful() else 1


def detected(data, first):
    return (data.get('exit') == 1 and data.get('ok') is False and data.get('first') == first
            and bool(data.get('details')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', required=True, type=Path, help='Existing directory outside the package')
    scratch = parser.parse_args().scratch.resolve()
    if not scratch.is_dir() or scratch.is_relative_to(LEDGER_ROOT):
        parser.error('--scratch must exist outside the package')
    run = Path(tempfile.mkdtemp(prefix='spectrum-release-mutations-', dir=scratch))
    env = dict(os.environ, NC25_LEDGER_ROOT=str(LEDGER_ROOT), TEMP=str(run), TMP=str(run), TMPDIR=str(run),
               SPECTRUM_RELEASE_TEST_SCRATCH=str(run), PYTHONDONTWRITEBYTECODE='1')
    inputs = {HERE/(MODULE+'.py'): (HERE/(MODULE+'.py')).read_bytes(),
              HERE/(TEST+'.py'): (HERE/(TEST+'.py')).read_bytes(), Path(__file__): Path(__file__).read_bytes(),
              LEDGER_ROOT/'examples/local_release/scenario.py': (LEDGER_ROOT/'examples/local_release/scenario.py').read_bytes(),
              LEDGER_ROOT/'examples/spectrum_observation/spectrum_observation.py':
                  (LEDGER_ROOT/'examples/spectrum_observation/spectrum_observation.py').read_bytes()}
    source = inputs[HERE/(MODULE+'.py')].decode('utf-8-sig')
    tests = inputs[HERE/(TEST+'.py')]
    cls = next(n for n in ast.parse(tests).body if isinstance(n, ast.ClassDef) and n.name == 'Cases')
    names = {int(n.name[5:7]): TEST+'.Cases.'+n.name for n in cls.body
             if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')}
    assert set(names) == set(range(1, EXPECTED_TESTS+1)), 'TEST_INVENTORY'
    assert {entry[1] for entry in CASES} == set(names)-{26}, 'MUTATION_INVENTORY'
    # Case 26 independently uses real Git and actual changed-checkout/revision fixtures.
    # Its guards overlap earlier unit cases; it makes no unique first-red claim.
    results = []
    report = {'source_sha256': hashlib.sha256(inputs[HERE/(MODULE+'.py')]).hexdigest(),
              'test_sha256': hashlib.sha256(tests).hexdigest(), 'mutations': results,
              'scope': 'Exact first failure in the complete ordered local suite. Synthetic observation output. '
                       'Real local HTTP, Ledger, SQLite and three newly created Git fixtures. '
                       'Not a Spectrum model result; not every sub-assertion independently mutated.'}
    def save():
        (run/'result.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    def execute(name, code):
        folder = run/name; folder.mkdir()
        (folder/(MODULE+'.py')).write_text(code, encoding='utf-8', newline='\n')
        (folder/(TEST+'.py')).write_bytes(tests)
        runner = folder/Path(__file__).name
        runner.write_bytes(inputs[Path(__file__)])
        start = time.monotonic()
        try:
            cp = subprocess.run([sys.executable, '-B', str(runner), '--child'], cwd=folder,
                                capture_output=True, encoding='utf-8', timeout=150, env=env)
        except subprocess.TimeoutExpired as exc:
            (folder/'stdout.txt').write_bytes(exc.stdout or b'')
            (folder/'stderr.txt').write_bytes(exc.stderr or b'')
            data = {'exit': None, 'ok': False, 'first': None, 'details': ['CHILD_TIMEOUT'], 'seconds': time.monotonic()-start}
        else:
            (folder/'stdout.txt').write_text(cp.stdout, encoding='utf-8')
            (folder/'stderr.txt').write_text(cp.stderr, encoding='utf-8')
            try: data = json.loads(cp.stdout)
            except ValueError: data = {'ok': False, 'first': None, 'details': ['CHILD_OUTPUT_NOT_JSON']}
            data.update(exit=cp.returncode, seconds=time.monotonic()-start)
        (folder/'result.json').write_text(json.dumps(data, indent=2)+'\n', encoding='utf-8')
        return data
    baseline = report['baseline'] = execute('baseline', source)
    save()
    if not (baseline.get('ok') is True and baseline.get('tests') == EXPECTED_TESTS and baseline['exit'] == 0):
        raise RuntimeError(('BASELINE', baseline, str(run)))
    assert not detected(baseline, names[1]), 'POSITIVE_CLASSIFIER_CONTROL'
    for name, number, before, after in CASES:
        if source.count(before) != 1:
            report['anchor_failure'] = {'mutation': name, 'count': source.count(before)}; save()
            raise RuntimeError(('ANCHOR', name, source.count(before)))
        code = source.replace(before, after)
        assert code != source, ('UNCHANGED_MUTATION', name)
        data = execute(name, code)
        first = names[number]
        passed = detected(data, first)
        if passed:
            assert not detected(dict(data, exit=0), first), 'EXIT_CLASSIFIER_CONTROL'
            assert not detected(dict(data, first='another.test'), first), 'FIRST_CLASSIFIER_CONTROL'
            assert not detected(dict(data, ok=True), first), 'STATUS_CLASSIFIER_CONTROL'
            assert not detected(dict(data, details=[]), first), 'DETAIL_CLASSIFIER_CONTROL'
        results.append({'mutation': name, 'expected_first': first, 'observed_first': data.get('first'),
                        'passed': passed, 'native_exit': data['exit'], 'seconds': data['seconds']})
        save(); print(name, passed, flush=True)
    restored = report['restored'] = execute('restored', source)
    report['inputs_unchanged'] = all(path.read_bytes() == raw for path, raw in inputs.items())
    report['input_sha256'] = {str(path): hashlib.sha256(raw).hexdigest() for path, raw in inputs.items()}
    ok = (all(row['passed'] for row in results) and report['inputs_unchanged']
          and restored.get('ok') is True and restored.get('tests') == EXPECTED_TESTS and restored['exit'] == 0)
    report['ok'] = ok; save()
    print(json.dumps({'ok': ok, 'mutations': len(results), 'report': str(run/'result.json')}))
    return 0 if ok else 1


if __name__ == '__main__': raise SystemExit(child() if '--child' in sys.argv else main())
