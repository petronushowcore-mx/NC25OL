"""Local observation boundary checks with synthetic source-process output."""
import copy
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import spectrum_observation as s
from nc25_universal_ledger import ContractViolation, FixedClock, UniversalConnectionLedger, bind_fixture

MODULE_PATHS = {
    'finite': 'layers/XIV/harness/finite_state_harness.py',
    'bc': 'layers/XIV/harness/beck_chevalley_check.py',
    'robust': 'layers/XIV/robustness-companion/harness/robustness_harness.py',
    'graph': 'layers/XV/harness/graph_hodge.py',
    'nest': 'layers/XV/harness/nestability.py',
    'core': 'layers/XV/harness/core_reduction.py',
}
SCENARIO_IDS = '''SIMPLE SELF_LOOP REPEATED_EDGE NU_NOT_BUDGET_RESPECTING ZERO_COST_MOTION
EXPLICIT_WINDOW_SELECTOR SEALED_CORE NO_ADMISSIBLE_MOTION SINGLETON_REJECTED PARALLEL_REFUSAL
INFINITE_CAPACITY_REFUSAL PAIRING_IS_NOT_GLOBAL_CLASS TREE_GLOBAL_CLASS_ZERO NONZERO_EXACT_CLASS_ZERO NONZERO_PERIOD_CLASS'''.split()
CONTROL_IDS = '''map_missing_state map_foreign_state map_not_monic missing_image_edge image_outside_K
wrong_Adm_mode nonpath_in_lower_Adm missing_admissible_window foreign_adapter_type extra_admissible_recombination
negative_lower_burden nonunit_nonnegative_burden unused_upper_structure_survives extra_lower_state extra_lower_edge
lower_does_not_exhaust count_distinct_edges_not_traversals upper_joint_exhaustion fractional_lower_capacity
burden_evaluator_never_crosses burden_evaluator_overshoots upstream_m_IE_wrong_value upstream_ie_verdict_wrong_value
foreign_cochain_edge inexact_cochain unrelated_crash_is_not_a_model_refusal shared_window_generator_omits_singleton
positive_controls_survive_mutations'''.split()


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


class Cases(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.source = (self.folder/'spectrum').resolve()
        self.source.mkdir()
        self.revisions = {'spectrum': 'a'*40, 'XIV': 'b'*40, 'XV': 'c'*40}
        files = dict(MODULE_PATHS, runner='layers/XV/harness/xiv_stitch.py')
        hashes = {}
        for name, relative in files.items():
            p = self.source/relative
            p.parent.mkdir(parents=True, exist_ok=True)
            raw = ('synthetic source '+name+'\n').encode()
            p.write_bytes(raw)
            hashes[name] = hashlib.sha256(raw).hexdigest()
        self.snapshot = {'revisions': self.revisions.copy(), 'source_sha256': hashes}
        self.provenance = {name: {'path': str(self.source/relative), 'sha256': hashes[name]}
                           for name, relative in MODULE_PATHS.items()}
        self.transport = {'pairing_verdict': 'ANNIHILATING', 'global_class_zero': False,
                          'full_regime_w': 'NOT_EVALUATED', 'reason': 'Finite supplied witnesses only.'}

    def output(self):
        return (['SOURCE_PROVENANCE '+wire(self.provenance).decode()]
                + ['[PASS] '+name for name in SCENARIO_IDS]
                + ['xiv_stitch selftest: 15/15 OK']
                + ['[PASS] control '+name for name in CONTROL_IDS]
                + ['xiv_stitch mutation/control rows: 28/28 OK',
                   'TRANSPORT '+wire(self.transport).decode(),
                   'xiv_stitch: PASS (finite supplied witnesses only)'])

    def result(self, lines=None, code=0, stderr=b''):
        return subprocess.CompletedProcess(['synthetic-stitch'], code,
            ('\n'.join(self.output() if lines is None else lines)+'\n').encode(), stderr)

    def interpret(self, result=None):
        return s.interpret(self.result() if result is None else result, self.source, self.snapshot)

    def fake_git(self, folder, *args):
        folder = Path(folder).resolve()
        if args[:1] == ('ls-tree',):
            layer = args[-1].split('/')[-1]
            return '160000 commit '+self.revisions[layer]+'\tlayers/'+layer
        name = 'spectrum' if folder == self.source else folder.name
        if args == ('rev-parse', '--show-toplevel'): return str(folder)
        if args == ('rev-parse', 'HEAD'): return self.revisions[name]
        if args == ('ls-files', '-v', '-z'): return 'H tracked.py\0'
        if args == ('status', '--porcelain=v1', '--untracked-files=all', '--ignored'): return ''
        raise AssertionError(('UNEXPECTED_GIT_COMMAND', folder, args))

    def engine(self):
        raw = json.loads((s.ROOT/'profiles/document-release/reference-connection.json').read_bytes())
        profile, declaration, _, _ = bind_fixture(*(raw[k] for k in ('profile', 'declaration', 'grant', 'intent')))
        return UniversalConnectionLedger(profile, declaration, b'synthetic-observation-key-32-bytes',
            clock=FixedClock(datetime(2026, 8, 1, 10, tzinfo=timezone.utc)),
            state_path=self.folder/'ledger.sqlite')

    def session(self, engine=None, nonce='1'*64):
        if not hasattr(self, 'snapshot_mock'):
            snapshot_patch = patch.object(s, 'source_snapshot', side_effect=lambda *a: copy.deepcopy(self.snapshot))
            self.snapshot_mock = snapshot_patch.start()
            self.addCleanup(snapshot_patch.stop)
            execute_patch = patch.object(s, 'execute', return_value=self.result())
            self.execute_mock = execute_patch.start()
            self.addCleanup(execute_patch.stop)
        engine = engine or self.engine()
        with patch.object(s.secrets, 'token_hex', return_value=nonce):
            session = s.ObservationSession(engine, engine.declaration['connector']['connector_id'],
                                           self.source, self.revisions['spectrum'])
        return session, engine

    def test_01_source_snapshot_checks_exact_git_boundaries_and_bytes(self):
        with patch.object(s, 'git', side_effect=self.fake_git):
            self.assertEqual(s.source_snapshot(self.source, 'a'*40), self.snapshot)
        rows = [
            (('ls-tree',), '100644 blob '+'b'*40+'\tlayers/XIV', 'LAYER_PIN_REQUIRED'),
            (('rev-parse', '--show-toplevel'), str(self.folder), 'SOURCE_ROOT'),
            (('rev-parse', 'HEAD'), 'd'*40, 'SOURCE_REVISION'),
            (('ls-files',), 'h tracked.py\0', 'SOURCE_HIDDEN_FLAGS'),
            (('ls-files',), 'S tracked.py\0', 'SOURCE_HIDDEN_FLAGS'),
            (('status',), ' M tracked.py', 'SOURCE_DIRTY'),
            (('status',), '!! ignored.py', 'SOURCE_DIRTY'),
        ]
        for prefix, value, code in rows:
            def changed(folder, *args):
                return value if args[:len(prefix)] == prefix else self.fake_git(folder, *args)
            with self.subTest(code=code, value=value), patch.object(s, 'git', side_effect=changed):
                with self.assertRaisesRegex(s.Refusal, '^'+code+'$'):
                    s.source_snapshot(self.source, 'a'*40)
        with patch.object(s, 'git', side_effect=self.fake_git):
            with self.assertRaisesRegex(s.Refusal, '^REVISION_REQUIRED$'):
                s.source_snapshot(self.source, 'HEAD')
            (self.source/MODULE_PATHS['finite']).write_bytes(b'new exact bytes')
            actual = s.source_snapshot(self.source, 'a'*40)
            self.assertEqual(actual['source_sha256']['finite'], hashlib.sha256(b'new exact bytes').hexdigest())
            self.assertNotEqual(actual, self.snapshot)

    def test_02_provenance_binds_exact_paths_and_hashes(self):
        self.assertEqual(self.interpret()['status'], 'VERIFIED')
        for field, value in [('path', str(self.folder/'same-name.py')), ('sha256', '0'*64)]:
            bad = copy.deepcopy(self.provenance)
            bad['finite'][field] = value
            lines = self.output(); lines[0] = 'SOURCE_PROVENANCE '+wire(bad).decode()
            with self.subTest(field=field), self.assertRaisesRegex(s.Refusal, '^SOURCE_PROVENANCE$'):
                self.interpret(self.result(lines))
        self.assertEqual(self.interpret()['code'], 'SUPPLIED_FIXTURES')

    def test_03_scenario_identity_is_not_a_pass_count(self):
        for value in ('[PASS] INVENTED_SCENARIO', '[PASS] '+SCENARIO_IDS[1]):
            lines = self.output(); lines[1] = value
            with self.assertRaisesRegex(s.Refusal, '^SCENARIO_SET$'):
                self.interpret(self.result(lines))
        self.assertEqual(self.interpret()['facts']['scenario_ids'], sorted(SCENARIO_IDS))

    def test_04_control_identity_is_not_a_pass_count(self):
        for value in ('[PASS] control invented_control', '[PASS] control '+CONTROL_IDS[1]):
            lines = self.output(); lines[17] = value
            with self.assertRaisesRegex(s.Refusal, '^CONTROL_SET$'):
                self.interpret(self.result(lines))
        self.assertEqual(self.interpret()['facts']['control_rows'], 28)

    def test_05_transport_keeps_unevaluated_scope(self):
        for field, value in [('full_regime_w', 'VERIFIED'), ('global_class_zero', True),
                             ('global_class_zero', 0), ('pairing_verdict', 'CERTIFIED')]:
            transport = {**self.transport, field: value}
            lines = self.output(); lines[46] = 'TRANSPORT '+wire(transport).decode()
            with self.subTest(field=field, value=value), self.assertRaisesRegex(s.Refusal, '^TRANSPORT_SCOPE$'):
                self.interpret(self.result(lines))
        self.assertEqual(self.interpret()['facts']['transport']['full_regime_w'], 'NOT_EVALUATED')

    def test_06_exit_status_is_not_a_named_model_refusal(self):
        rows = [(1, b'Traceback: crash\n', 'NOT_MEASURED', 'RUN_INCOMPLETE', None),
                (2, b'xiv_stitch: FAIL MAP_NOT_MONIC\n', 'NOT_MEASURED', 'RUN_INCOMPLETE', None),
                (1, b'xiv_stitch: FAIL MAP_NOT_MONIC\nextra\n', 'NOT_MEASURED', 'RUN_INCOMPLETE', None),
                (1, b'xiv_stitch: FAIL MAP_NOT_MONIC: NU_MONIC\n', 'NOT_MEASURED', 'RUN_INCOMPLETE', None),
                (1, b'xiv_stitch: FAIL MISSING_REFUSAL: arbitrary suffix\n', 'NOT_MEASURED', 'RUN_INCOMPLETE', None),
                (1, b'xiv_stitch: FAIL WRONG_FIRST_MARKER: wanted=NU_MONIC got=NU_TOTAL extra\n',
                 'NOT_MEASURED', 'RUN_INCOMPLETE', None),
                (2, b'xiv_stitch: FAIL MISSING_REFUSAL: NU_MONIC\n', 'NOT_MEASURED', 'RUN_INCOMPLETE', None),
                (1, b'xiv_stitch: FAIL MAP_NOT_MONIC\n', 'REFUSED', 'MAP_NOT_MONIC', None),
                (1, b'xiv_stitch: FAIL MISSING_REFUSAL: NU_MONIC\n', 'REFUSED', 'MISSING_REFUSAL', 'NU_MONIC'),
                (1, b'xiv_stitch: FAIL WRONG_FIRST_MARKER: wanted=NU_MONIC got=NU_TOTAL\n',
                 'REFUSED', 'WRONG_FIRST_MARKER', 'wanted=NU_MONIC got=NU_TOTAL')]
        for code, stderr, status, reason, diagnostic in rows:
            with self.subTest(code=code, stderr=stderr):
                got = self.interpret(self.result(code=code, stderr=stderr))
                expected = {'status': status, 'code': reason, 'facts': {}}
                if diagnostic is not None: expected['diagnostic'] = diagnostic
                self.assertEqual(got, expected)
        with self.assertRaisesRegex(s.Refusal, '^OUTPUT_STDERR$'):
            self.interpret(self.result(stderr=b'warning'))

    def test_07_output_shape_duplicate_keys_and_byte_limit(self):
        lines = self.output(); lines[-1] = 'xiv_stitch: PASS (all deployments)'
        with self.assertRaisesRegex(s.Refusal, '^OUTPUT_TAIL$'): self.interpret(self.result(lines))
        with self.assertRaisesRegex(s.Refusal, '^OUTPUT_SHAPE$'): self.interpret(self.result(self.output()[:-1]))
        result = self.result(); result.stdout = b'\xff'
        with self.assertRaisesRegex(s.Refusal, '^OUTPUT_ENCODING$'): self.interpret(result)
        result = self.result(); result.stdout = b'x'*1048577
        with self.assertRaisesRegex(s.Refusal, '^OUTPUT_BYTES$'): self.interpret(result)
        lines = self.output(); lines[46] = 'TRANSPORT '+wire(self.transport).decode()[:-1]+',"full_regime_w":"NOT_EVALUATED"}'
        with self.assertRaisesRegex(s.Refusal, '^OUTPUT_DUPLICATE_KEY$'): self.interpret(self.result(lines))
        with self.assertRaisesRegex(s.Refusal, '^OUTPUT_NUMBER$'): s.decode(b'{"x":NaN}')

    def test_08_collection_binds_bytes_and_declares_association_only(self):
        session, engine = self.session()
        # Wall clock can step backwards; this collector does not claim monotonic time.
        with patch.object(s, 'datetime') as wall_clock:
            wall_clock.now.side_effect = [datetime(2026, 8, 1, 10, tzinfo=timezone.utc),
                                          datetime(2026, 8, 1, 9, tzinfo=timezone.utc)]
            raw = session.collect()
        report = json.loads(raw)
        self.assertEqual(report['measured_subject'], 'TECTONICA_XIV_XV_SUPPLIED_FINITE_FIXTURES')
        self.assertEqual(report['collection']['stdout_sha256'], hashlib.sha256(self.result().stdout).hexdigest())
        self.assertEqual(report['collection']['stderr_sha256'], hashlib.sha256(b'').hexdigest())
        self.assertEqual(report['collection']['returncode'], 0)
        self.assertEqual(report['source'], self.snapshot)
        self.assertEqual(report['association'], {'kind': 'LOCAL_CONTEXT_ONLY',
            'ledger_registry': engine.registry_record(engine.declaration['connector']['connector_id'], actor_scope='nc25.architect'),
            'measurement_to_declaration': 'NOT_EVALUATED'})
        self.assertEqual(report['temporal'], {'clock': 'collector_wall_clock', 'semantic_validity': 'NOT_ESTABLISHED',
            'structural_time': 'NOT_MEASURED', 'c1_c4_deployment': 'NOT_EVALUATED'})
        self.assertIs(report['executable'], False)
        self.assertEqual(report['admission'], 'NOT_REQUESTED')
        for field in ('started_at', 'finished_at'):
            instant = datetime.fromisoformat(report['collection'][field])
            self.assertIsNotNone(instant.tzinfo)
            self.assertEqual(instant.utcoffset().total_seconds(), 0)
        self.execute_mock.assert_called_once_with(self.source)

    def test_09_receive_requires_local_bytes_and_rejects_tampering(self):
        session, _ = self.session()
        with self.assertRaisesRegex(s.Refusal, '^LOCAL_COLLECTION_REQUIRED$'): session.receive(b'{}')
        raw = session.collect(); changed = json.loads(raw)
        changed['observation']['facts']['control_rows'] = 29
        with self.assertRaisesRegex(s.Refusal, '^REPORT_CHANGED$'): session.receive(wire(changed))
        self.assertEqual(session.receive(raw), json.loads(raw))

    def test_10_replay_same_and_other_session_is_refused(self):
        first, engine = self.session(nonce='1'*64)
        second, _ = self.session(engine, nonce='2'*64)
        raw = first.collect(); second_raw = second.collect()
        with self.assertRaisesRegex(s.Refusal, '^REPORT_CHANGED$'): second.receive(raw)
        self.assertEqual(second.receive(second_raw), json.loads(second_raw))
        self.assertEqual(first.receive(raw), json.loads(raw))
        with self.assertRaisesRegex(s.Refusal, '^OBSERVATION_REPLAY$'): first.receive(raw)

    def test_11_collection_is_single_attempt_even_after_failure(self):
        session, _ = self.session()
        self.execute_mock.return_value = self.result(self.output()[:-1])
        with self.assertRaisesRegex(s.Refusal, '^OUTPUT_SHAPE$'): session.collect()
        self.execute_mock.return_value = self.result()
        with self.assertRaisesRegex(s.Refusal, '^COLLECTION_ALREADY_ATTEMPTED$'): session.collect()
        self.assertEqual(self.execute_mock.call_count, 1)

    def test_12_receive_refuses_registry_drift_and_foreign_connector(self):
        session, engine = self.session()
        raw = session.collect()
        engine.status = 'SUSPENDED'
        with self.assertRaisesRegex(s.Refusal, '^LEDGER_CONTEXT_CHANGED$'): session.receive(raw)
        engine.status = 'DRAFT'
        self.assertEqual(session.receive(raw), json.loads(raw))
        with self.assertRaisesRegex(ContractViolation, '^CONNECTOR_NOT_FOUND(:|$)'):
            s.ObservationSession(engine, 'different-connector', self.source, 'a'*40)

    def test_13_receive_refuses_source_drift(self):
        session, _ = self.session()
        raw = session.collect()
        old = self.snapshot['source_sha256']['finite']
        self.snapshot['source_sha256']['finite'] = 'd'*64
        with self.assertRaisesRegex(s.Refusal, '^SOURCE_CHANGED$'): session.receive(raw)
        self.snapshot['source_sha256']['finite'] = old
        self.assertEqual(session.receive(raw), json.loads(raw))

    def test_14_collection_rechecks_source_after_child(self):
        session, _ = self.session()
        def changed(_):
            self.snapshot['source_sha256']['finite'] = 'd'*64
            return self.result()
        self.execute_mock.side_effect = changed
        with self.assertRaisesRegex(s.Refusal, '^SOURCE_CHANGED$'): session.collect()

    def test_15_receive_preserves_full_engine_and_sqlite_state(self):
        session, engine = self.session()
        before = copy.deepcopy(engine._snapshot_state())
        def database():
            with closing(sqlite3.connect(self.folder/'ledger.sqlite')) as db:
                return db.serialize()
        before_db = database()
        with patch.object(engine, 'activate', side_effect=AssertionError('ACTIVATION_FORBIDDEN')), \
             patch.object(engine, 'issue_grant', side_effect=AssertionError('GRANT_FORBIDDEN')), \
             patch.object(engine, 'evaluate_intent', side_effect=AssertionError('PERMIT_FORBIDDEN')), \
             patch.object(engine, 'commit_execution', side_effect=AssertionError('EFFECT_FORBIDDEN')):
            raw = session.collect(); got = session.receive(raw)
        self.assertEqual(got['association']['ledger_registry']['status'], 'DRAFT')
        self.assertEqual(engine._snapshot_state(), before)
        self.assertEqual(database(), before_db)
        self.assertEqual(engine.ledger.events_copy(), [])


    def test_16_execute_runs_pinned_controls_and_classifies_unavailable_child(self):
        command = [sys.executable, '-B', str(self.source/'layers/XV/harness/xiv_stitch.py'),
                   '--xiv-root', str(self.source/'layers/XIV'), '--teeth']
        completed = self.result()
        with patch.object(s.subprocess, 'run', return_value=completed) as run:
            self.assertIs(s.execute(self.source), completed)
            run.assert_called_once_with(command, cwd=self.source, capture_output=True, timeout=60,
                env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        for failure in (subprocess.TimeoutExpired(command, 60), OSError('synthetic child unavailable')):
            with self.subTest(failure=type(failure).__name__), patch.object(s.subprocess, 'run', side_effect=failure):
                result = s.execute(self.source)
                self.assertEqual(result.args, command)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b'', b'RUN_UNAVAILABLE'))
                self.assertEqual(self.interpret(result),
                    {'status': 'NOT_MEASURED', 'code': 'RUN_INCOMPLETE', 'facts': {}})


if __name__ == '__main__': unittest.main(verbosity=2)
