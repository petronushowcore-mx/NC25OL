"""Mutate isolated document-session copies and require the named first failure."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
LEDGER_ROOT = Path(os.environ.get('NC25_LEDGER_ROOT', ROOT.parents[1])).resolve()
FILES = ('scenario.py', 'document_release.py', 'exchange.py', 'test_document_session.py')
TESTS = ('test_01_exact_binary_payload_and_identifiers_start_inactive',
         'test_02_invalid_operation_is_refused_before_storage',
         'test_03_two_mib_document_crosses_gateway_and_replays_once')
IDS = tuple('test_document_session.Cases.'+name for name in TESTS)
CASES = (
    ('document_bytes_changed', 0, 'scenario.py', 'base64.b64encode(document_bytes)', 'base64.b64encode(document_bytes + b"!")'),
    ('document_identifier_ignored', 0, 'scenario.py', "'document_id': document_id", "'document_id': 'document'"),
    ('request_identifier_ignored', 0, 'scenario.py', "'idempotency_key': idempotency_key", "'idempotency_key': 'document-release-1'"),
    ('document_implicitly_activates', 0, 'scenario.py',
     '        self.process = None\n        self.engine = self.restore_engine()',
     '        self.process = None\n        self.engine = self.restore_engine()\n        self.activate()'),
    ('mutable_bytes_accepted', 1, 'scenario.py', 'if type(document_bytes) is not bytes:', 'if False:'),
    ('operation_validation_removed', 1, 'scenario.py', 'dr.operation(self.op)', 'None'),
    ('document_ceiling_raised', 1, 'document_release.py', 'MAX_BODY = 4 * 1024 * 1024', 'MAX_BODY = 8 * 1024 * 1024'),
    ('former_document_ceiling_restored', 2, 'document_release.py', 'MAX_BODY = 4 * 1024 * 1024', 'MAX_BODY = 1048576'),
    ('exact_document_boundary_refused', 2, 'document_release.py', 'len(data) > MAX_BODY // 2', 'len(data) >= MAX_BODY // 2'),
    ('valid_binary_document_refused', 0, 'scenario.py', 'if type(document_bytes) is not bytes:', 'if type(document_bytes) is bytes:'),
)


def child():
    import test_document_session
    class Result(unittest.TestResult):
        def __init__(self):
            super().__init__(); self.first = None
        def addFailure(self, test, error):
            if self.first is None: self.first = test.id()
            super().addFailure(test, error)
        def addError(self, test, error):
            if self.first is None: self.first = test.id()
            super().addError(test, error)
        def addSubTest(self, test, subtest, error):
            if error is not None and self.first is None: self.first = test.id()
            super().addSubTest(test, subtest, error)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(test_document_session.Cases)
    inventory = [case.id() for case in suite]
    result = Result(); result.failfast = True; suite.run(result)
    print(json.dumps({'ok': result.wasSuccessful(), 'inventory': inventory, 'ran': result.testsRun,
                     'first': result.first, 'details': [text for _, text in result.failures + result.errors]}))
    return 0 if result.wasSuccessful() else 1


def detected(result, expected):
    return (result['exit'] == 1 and result['ok'] is False and result['first'] == IDS[expected]
            and result['ran'] == expected + 1 and result['inventory'] == list(IDS))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', required=True, type=Path)
    scratch = parser.parse_args().scratch.resolve()
    if not scratch.is_dir() or scratch.is_relative_to(LEDGER_ROOT):
        parser.error('--scratch must exist outside the Ledger package')
    original = {name: (ROOT/name).read_bytes() for name in FILES}
    runner = Path(__file__).read_bytes()
    for name, index, filename, before, after in CASES:
        if original[filename].decode('utf-8').count(before) != 1 or before == after:
            raise ValueError(('MUTATION_ANCHOR', name))
    if {index for _, index, *_ in CASES} != set(range(len(IDS))):
        raise ValueError('MUTATION_TEST_COVERAGE')
    run = Path(tempfile.mkdtemp(prefix='document-session-mutations-', dir=scratch))
    env = dict(os.environ, NC25_LEDGER_ROOT=str(LEDGER_ROOT), TEMP=str(run), TMP=str(run), TMPDIR=str(run))

    def execute(name, mutation=None):
        folder = run/name; folder.mkdir()
        for filename, raw in original.items():
            if mutation is not None and filename == mutation[2]:
                raw = raw.decode('utf-8').replace(mutation[3], mutation[4]).encode('utf-8')
            (folder/filename).write_bytes(raw)
        command_file = folder/Path(__file__).name
        command_file.write_bytes(runner)
        completed = subprocess.run([sys.executable, '-B', str(command_file), '--child'],
                                  cwd=folder, env=env, capture_output=True, text=True, encoding='utf-8', timeout=60)
        (folder/'stdout.txt').write_text(completed.stdout, encoding='utf-8')
        (folder/'stderr.txt').write_text(completed.stderr, encoding='utf-8')
        result = json.loads(completed.stdout); result['exit'] = completed.returncode
        return result

    baseline = execute('baseline')
    if not (baseline['exit'] == 0 and baseline['ok'] is True and baseline['ran'] == len(IDS)
            and baseline['inventory'] == list(IDS) and baseline['first'] is None):
        raise ValueError(('BASELINE', baseline))
    assert not detected(baseline, 0), 'CLEAN_CLASSIFIER_CONTROL'
    results = []
    for case in CASES:
        name, index, *_ = case
        result = execute(name, case)
        passed = detected(result, index)
        assert not detected(result, (index + 1) % len(IDS)), 'WRONG_FIRST_CLASSIFIER_CONTROL'
        results.append({'name': name, 'expected_first': IDS[index], 'observed_first': result['first'], 'passed': passed})
        print(name, passed, flush=True)
    assert all((ROOT/name).read_bytes() == raw for name, raw in original.items()), 'SOURCE_CHANGED_DURING_RUN'
    report = {'baseline': baseline, 'source_sha256': {name: hashlib.sha256(raw).hexdigest() for name, raw in original.items()},
              'mutations': results, 'scope': 'First failing test in the full ordered three-test document-session suite; '
              'real Ledger and loopback target, synthetic authority and fixed time. Not every assertion independently mutated.'}
    (run/'result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    ok = all(row['passed'] for row in results)
    print(json.dumps({'ok': ok, 'mutations': len(results), 'report': str(run/'result.json')}))
    return 0 if ok else 1


if __name__ == '__main__': raise SystemExit(child() if '--child' in sys.argv else main())
