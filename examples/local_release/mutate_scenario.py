"""Run the local scenario suite against isolated implementation mutations.

Defaults to the package above examples/local_release; NC25_LEDGER_ROOT overrides it.
An explicit --scratch directory must stay outside that package.
Every run keeps its copied sources, unittest log and machine result. No live
product bytes are changed; only the existing local loopback fixture is run.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

EXAMPLE_FILES = ('scenario.py', 'document_release.py', 'exchange.py', 'test_scenario.py')
TESTS = (
    'test_01_preview_is_not_admission',
    'test_02_preview_cannot_activate',
    'test_03_complete_flow_and_exact_bytes',
    'test_04_changed_bytes_are_not_approved',
    'test_05_version_substitution_is_refused',
    'test_06_lost_response_recovers_once',
    'test_07_revocation_before_effect',
    'test_08_expiry_after_effect_requires_reconciliation',
    'test_09_crash_after_ledger_commit',
    'test_10_objection_foreign_version_with_valid_mac',
    'test_11_observation_preserves_state_and_detection',
    'test_12_observation_remains_bound_to_engine',
    'test_13_observation_checks_engine_binding',
)
IDS = ['test_scenario.Cases.' + name for name in TESTS]
SDK = 'package/sdk/python/nc25_universal_ledger.py'
MUTATIONS = (
    ('preview-admitted-accepted', 0, 'example/scenario.py',
     "or value['admitted'] is not False):", "or False):"),
    ('preview-term-drift-accepted', 0, 'example/scenario.py',
     "or term['reference'].get('sha256') != hashlib.sha256(term['text'].encode('utf-8')).hexdigest()):", "or False):"),
    ('preview-valid-overrefusal', 0, 'example/scenario.py',
     "or value['admitted'] is not False):", "or value['admitted'] is not True):"),
    ('preview-implicitly-activates', 1, 'example/scenario.py',
     '        self.process = None\n        self.engine = self.restore_engine()',
     '        self.process = None\n        self.engine = self.restore_engine()\n        self.activate()'),
    ('stored-document-bytes-change', 2, 'example/document_release.py',
     "db.execute('INSERT INTO documents VALUES (?,?)', (op['document_id'], data))",
     "db.execute('INSERT INTO documents VALUES (?,?)', (op['document_id'], data + b'\\n'))"),
    ('content-approval-ignores-payload', 3, 'example/scenario.py',
     "'CONTENT_APPROVED': intent['payload_hash'] == self.approved_hash,", "'CONTENT_APPROVED': True,"),
    ('binding-ignores-declaration-version', 4, SDK,
     '        return normalized == self._binding()',
     '        normalized["declaration_version"] = self.declaration["declaration_version"]\n        return normalized == self._binding()'),
    ('ambiguous-cannot-recover', 5, 'example/document_release.py',
     "if state in {'PREPARED', 'CALLING', 'AMBIGUOUS'}:", "if state in {'PREPARED', 'CALLING'}:"),
    ('pre-effect-permit-not-rechecked', 6, 'example/document_release.py',
     "result = self.engine.evaluate_intent(row['intent'], row['evidence'], actor_scope='nc25.operator')",
     "result = {'permit_hash': row['permit_hash'], 'disposition': 'ALLOW'}"),
    ('expired-permit-can-finalize', 7, SDK,
     '        if now >= parse_utc(record.body["expires_at"]):\n            record.reservation_active = False\n            record.invalidated_reason = "PERMIT_EXPIRED"\n            raise ContractViolation("PERMIT_EXPIRED")',
     '        # Regression: permit expiry no longer prevents finalization.'),
    ('consumed-replay-requires-live-permit', 8, SDK,
     '        if record is not None and record.consumed:\n            replay = self.execution_replays.get(permit_hash)',
     '        if record is not None and record.consumed:\n            if self._now() >= parse_utc(record.body["expires_at"]):\n                raise ContractViolation("PERMIT_EXPIRED")\n            replay = self.execution_replays.get(permit_hash)'),
    ('objection-not-bound-to-pinned-view', 9, 'example/exchange.py',
     '    if (actual["binding"] != expected["binding"]\n            or actual["projection_hash"] != expected["projection_hash"]):\n        _fail("OBJECTION_BINDING_MISMATCH")',
     '    # Regression: attributed observations are no longer pinned to this view.'),
    ('snapshot-ignores-database-only-change', 10, 'example/scenario.py',
     'ledger_digest = hashlib.sha256(db.serialize()).hexdigest()',
     "ledger_digest = hashlib.sha256(json.dumps(self.engine.ledger.events_copy(), sort_keys=True).encode('utf-8')).hexdigest()"),
    ('observation-recomputes-pin-from-received-source', 11, 'example/scenario.py',
     "        pin = json.loads(self._projection_pin)\n        if (pin['binding']['declaration_hash'] != self.engine.declaration_hash\n                or pin['binding']['profile_hash'] != self.engine.profile_hash):\n            raise ValueError('PROJECTION_ENGINE_MISMATCH')",
     '        pin = x.export_projection(self.declaration, self.profile)'),
    ('observation-ignores-engine-binding', 12, 'example/scenario.py',
     "        if (pin['binding']['declaration_hash'] != self.engine.declaration_hash\n                or pin['binding']['profile_hash'] != self.engine.profile_hash):\n            raise ValueError('PROJECTION_ENGINE_MISMATCH')",
     '        # Regression: pinned source no longer has to belong to this engine.'),
)


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def write_json(path, value):
    with path.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(value, handle, indent=2)
        handle.write('\n')


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item.id()


def worker(source, result_path):
    sys.path.insert(0, str(source))
    spec = importlib.util.spec_from_file_location('test_scenario', source / 'test_scenario.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    inventory = list(flatten(suite))

    class RecordedResult(unittest.TextTestResult):
        def startTest(self, test):
            self.started.append(test.id())
            super().startTest(test)

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.started = []

    result = unittest.TextTestRunner(verbosity=2, failfast=True, resultclass=RecordedResult).run(suite)
    red = [{'id': test.id(), 'kind': kind, 'traceback': trace}
           for kind, entries in (('failure', result.failures), ('error', result.errors))
           for test, trace in entries]
    write_json(result_path, {
        'inventory': inventory, 'started': result.started, 'ran': result.testsRun,
        'successful': result.wasSuccessful(), 'red': red,
        'skipped': [test.id() for test, _ in result.skipped],
        'expected_failures': [test.id() for test, _ in result.expectedFailures],
        'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
    })
    return 0 if result.wasSuccessful() else 1


def admit(result, expected=None):
    if result['inventory'] != IDS:
        raise ValueError('SUITE_MEMBERSHIP')
    if result['skipped'] or result['expected_failures'] or result['unexpected_successes']:
        raise ValueError('SUITE_NOT_EXECUTED_AS_DECLARED')
    if expected is None:
        if not result['successful'] or result['red'] or result['started'] != IDS or result['ran'] != len(IDS):
            raise ValueError('BASELINE_NOT_GREEN')
    else:
        index = IDS.index(expected)
        if (result['successful'] or len(result['red']) != 1 or result['red'][0]['id'] != expected
                or result['red'][0]['kind'] not in ('failure', 'error')
                or result['started'] != IDS[:index + 1] or result['ran'] != index + 1):
            raise ValueError('MUTATION_NOT_NAMED_FIRST_RED')


def runner_controls():
    """Both acceptance and rejection of the report-admission predicate."""
    good = {'inventory': IDS, 'started': IDS, 'ran': len(IDS), 'successful': True,
            'red': [], 'skipped': [], 'expected_failures': [], 'unexpected_successes': []}
    admit(good)
    red = dict(good, started=IDS[:3], ran=3, successful=False,
               red=[{'id': IDS[2], 'kind': 'failure', 'traceback': 'synthetic admission control'}])
    admit(red, IDS[2])
    broken = (
        (dict(good, inventory=IDS[:-1]), None),
        (dict(good, skipped=[IDS[0]]), None),
        (dict(good, ran=10), None),
        (red, None),
        (good, IDS[2]),
        (red, IDS[3]),
        (dict(red, started=IDS[:2]), IDS[2]),
        (dict(red, red=[]), IDS[2]),
    )
    for value, expected in broken:
        try:
            admit(value, expected)
        except ValueError:
            continue
        raise RuntimeError('RUNNER_ACCEPTED_FALSE_EVIDENCE')
    return {'positive_controls': 2, 'negative_controls': len(broken)}


def replaced(payload, old, new):
    text = payload.decode('utf-8')
    newline = '\r\n' if '\r\n' in text else '\n'
    if '\r' in text.replace('\r\n', '') or ('\r\n' in text and '\n' in text.replace('\r\n', '')):
        raise ValueError('MUTATION_MIXED_NEWLINES')
    old, new = old.replace('\n', newline), new.replace('\n', newline)
    if text.count(old) != 1 or old == new:
        raise ValueError('MUTATION_ANCHOR_NOT_EXACTLY_ONE')
    result = text.replace(old, new)
    if result == text:
        raise ValueError('MUTATION_CHANGED_NOTHING')
    return result.encode('utf-8')


def main(source, scratch, timeout):
    controls = runner_controls()
    source = source.resolve(strict=True)
    configured_root = os.environ.get('NC25_LEDGER_ROOT')
    if configured_root and not Path(configured_root).is_absolute():
        raise ValueError('NC25_LEDGER_ROOT_MUST_BE_ABSOLUTE')
    ledger = (Path(configured_root) if configured_root else source.parents[1]).resolve(strict=True)
    if not scratch.is_absolute():
        raise ValueError('SCRATCH_MUST_BE_ABSOLUTE')
    scratch = scratch.resolve(strict=True)
    if not scratch.is_dir() or scratch.is_relative_to(ledger):
        raise ValueError('SCRATCH_MUST_BE_OUTSIDE_LEDGER')
    if any((parent / 'PACKAGE-MANIFEST.json').exists() for parent in (scratch, *scratch.parents)):
        raise ValueError('SCRATCH_MUST_BE_OUTSIDE_PACKAGE')
    # Snapshot only the named example and minimal SDK/profile dependency set.
    payloads = {'example/' + name: (source / name).read_bytes() for name in EXAMPLE_FILES}
    for path in sorted((ledger / 'sdk/python').rglob('*.py')):
        if '__pycache__' not in path.parts:
            payloads['package/' + path.relative_to(ledger).as_posix()] = path.read_bytes()
    profile = 'profiles/document-release/reference-connection.json'
    payloads['package/' + profile] = (ledger / profile).read_bytes()
    if SDK not in payloads:
        raise ValueError('SDK_SOURCE_MISSING')
    if sorted({index for _, index, *_ in MUTATIONS}) != list(range(len(IDS))):
        raise ValueError('MUTATION_TEST_COVERAGE')
    for name, _, path, old, new in MUTATIONS:
        try:
            replaced(payloads[path], old, new)  # Refuse stale anchors before running anything.
        except ValueError as exc:
            raise ValueError(name + ': ' + str(exc)) from exc
    root = Path(tempfile.mkdtemp(prefix='scenario-mutations-', dir=scratch))
    write_json(root / 'source-binding.json', {path: {'bytes': len(data), 'sha256': sha(data)} for path, data in payloads.items()})
    script = Path(__file__).resolve()

    def run_case(name, mutation=None):
        folder = root / name
        folder.mkdir()
        runtime = folder / 'runtime'
        runtime.mkdir()
        for path, payload in payloads.items():
            if mutation is not None and path == mutation[2]:
                payload = replaced(payload, mutation[3], mutation[4])
            target = folder / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        env = os.environ.copy()
        env.update(NC25_LEDGER_ROOT=str(folder / 'package'),
                   NC25_LEDGER_SDK=str(folder / 'package/sdk/python'),
                   TEMP=str(runtime), TMP=str(runtime), TMPDIR=str(runtime),
                   PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1')
        command = [sys.executable, '-B', str(script), '--worker',
                   '--source', str(folder / 'example'), '--result', str(folder / 'result.json')]
        with (folder / 'run.log').open('x', encoding='utf-8', newline='\n') as log:
            completed = subprocess.run(command, env=env, cwd=folder / 'example', stdout=log, stderr=subprocess.STDOUT,
                                       text=True, timeout=timeout, check=False)
        result = json.loads((folder / 'result.json').read_text(encoding='utf-8'))
        expected = None if mutation is None else IDS[mutation[1]]
        admit(result, expected)
        if completed.returncode != (0 if mutation is None else 1):
            raise ValueError('WORKER_EXIT_DISAGREES_WITH_UNITTEST')
        return result

    print('RUNNER_CONTROLS ' + json.dumps(controls), flush=True)
    print('EVIDENCE ' + str(root), flush=True)
    baseline = run_case('baseline')
    print('BASELINE ' + str(baseline['ran']) + '/' + str(len(IDS)), flush=True)
    results = []
    for mutation in MUTATIONS:
        name, index, path, old, new = mutation
        result = run_case(name, mutation)
        item = {'name': name, 'changed_file': path, 'first_red': result['red'][0]['id'],
                'red_kind': result['red'][0]['kind'], 'tests_run': result['ran'],
                'old': old, 'new': new, 'log': str(root / name / 'run.log')}
        results.append(item)
        write_json(root / name / 'admission.json', item)
        print('BITES_FIRST ' + name + ' -> ' + TESTS[index], flush=True)
    report = {'format': 'scenario-source-mutations/v1', 'scope': 'local synthetic scenario suite only',
              'controls': controls, 'baseline_tests': baseline['ran'], 'tests': IDS,
              'mutations': results, 'live_sources_modified': False}
    write_json(root / 'report.json', report)
    print('MUTATIONS ' + str(len(results)) + '/' + str(len(MUTATIONS)) + '; report ' + str(root / 'report.json'), flush=True)
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--scratch', type=Path)
    parser.add_argument('--timeout', type=int, default=90)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--result', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        if args.result is None:
            parser.error('--worker requires --result')
        raise SystemExit(worker(args.source.resolve(strict=True), args.result))
    if args.scratch is None or args.timeout < 1:
        parser.error('--scratch is required and --timeout must be positive')
    raise SystemExit(main(args.source, args.scratch, args.timeout))
