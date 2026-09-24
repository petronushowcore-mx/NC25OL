"""Synthetic source-boundary tests; real local gateway and a tiny Git fixture.

The supplied observation output is synthetic, not evidence about Spectrum models.
Scratch is retained outside the package; no existing repository is modified.
"""
import base64
from contextlib import contextmanager
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import spectrum_release as s

MODULE_PATHS = {
    'finite': 'layers/XIV/harness/finite_state_harness.py',
    'bc': 'layers/XIV/harness/beck_chevalley_check.py',
    'robust': 'layers/XIV/robustness-companion/harness/robustness_harness.py',
    'graph': 'layers/XV/harness/graph_hodge.py',
    'nest': 'layers/XV/harness/nestability.py',
    'core': 'layers/XV/harness/core_reduction.py',
    'runner': 'layers/XV/harness/xiv_stitch.py',
}
SCENARIOS = '''SIMPLE SELF_LOOP REPEATED_EDGE NU_NOT_BUDGET_RESPECTING ZERO_COST_MOTION
EXPLICIT_WINDOW_SELECTOR SEALED_CORE NO_ADMISSIBLE_MOTION SINGLETON_REJECTED PARALLEL_REFUSAL
INFINITE_CAPACITY_REFUSAL PAIRING_IS_NOT_GLOBAL_CLASS TREE_GLOBAL_CLASS_ZERO NONZERO_EXACT_CLASS_ZERO NONZERO_PERIOD_CLASS'''.split()
CONTROLS = '''map_missing_state map_foreign_state map_not_monic missing_image_edge image_outside_K
wrong_Adm_mode nonpath_in_lower_Adm missing_admissible_window foreign_adapter_type extra_admissible_recombination
negative_lower_burden nonunit_nonnegative_burden unused_upper_structure_survives extra_lower_state extra_lower_edge
lower_does_not_exhaust count_distinct_edges_not_traversals upper_joint_exhaustion fractional_lower_capacity
burden_evaluator_never_crosses burden_evaluator_overshoots upstream_m_IE_wrong_value upstream_ie_verdict_wrong_value
foreign_cochain_edge inexact_cochain unrelated_crash_is_not_a_model_refusal shared_window_generator_omits_singleton
positive_controls_survive_mutations'''.split()


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def archive(entries, mode=0o100644):
    """Independent ZIP builder; accepts duplicate names for negative fixtures."""
    stream = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', UserWarning)
        with zipfile.ZipFile(stream, 'w') as z:
            for name, raw in entries:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = mode << 16
                z.writestr(info, raw)
    return stream.getvalue()


class Cases(unittest.TestCase):
    def setUp(self):
        scratch = Path(os.environ.get('SPECTRUM_RELEASE_TEST_SCRATCH', tempfile.gettempdir())).resolve()
        if not scratch.is_dir() or scratch.is_relative_to(s.ROOT):
            raise RuntimeError('TEST_SCRATCH_OUTSIDE_PACKAGE_REQUIRED')
        self.folder = Path(tempfile.mkdtemp(prefix='spectrum-release-test-', dir=scratch))
        self.root = self.folder / 'source'
        self.root.mkdir()
        self.revision = 'a' * 40
        self.members = {'README.md': b'Synthetic source fixture.\n',
                        'docs/unused.md': b'Not loaded by any observation module.\n'}
        self.members.update({path: ('synthetic ' + name + '\n').encode() for name, path in MODULE_PATHS.items()})
        self.snapshot = {'revisions': {'spectrum': self.revision, 'XIV': 'b' * 40, 'XV': 'c' * 40},
                         'source_sha256': {name: sha(self.members[path]) for name, path in MODULE_PATHS.items()}}
        self.trees = {'spectrum': [], 'XIV': [], 'XV': []}
        self.blobs = {}
        for full, raw in self.members.items():
            file = self.root / full
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(raw)
            name, relative = (full.split('/')[1], '/'.join(full.split('/')[2:])) if full.startswith('layers/') else ('spectrum', full)
            self.trees[name].append(('100644', 'blob', blob(raw), relative))
            self.blobs[blob(raw)] = raw
        self.trees['spectrum'].extend([('160000', 'commit', 'b' * 40, 'layers/XIV'),
                                       ('160000', 'commit', 'c' * 40, 'layers/XV')])
        self.batch_change = lambda raw: raw

    def git_bytes(self, root, *args, input=None):
        name = 'spectrum' if Path(root) == self.root else Path(root).name
        self.assertEqual(Path(root), self.root if name == 'spectrum' else self.root / 'layers' / name)
        if args == ('ls-tree', '-rz', '--full-tree', self.snapshot['revisions'][name]):
            self.assertIsNone(input)
            return b''.join((mode+' '+kind+' '+oid+'\t'+path+'\0').encode() for mode, kind, oid, path in self.trees[name])
        self.assertEqual(args, ('cat-file', '--batch'))
        expected = ''.join(oid+'\n' for mode, _, oid, _ in self.trees[name] if mode != '160000').encode()
        self.assertEqual(input, expected)
        result = b''.join(oid.encode()+b' blob '+str(len(self.blobs[oid])).encode()+b'\n'+self.blobs[oid]+b'\n'
                          for oid in input.decode().splitlines())
        return self.batch_change(result)

    def process_output(self):
        provenance = {name: {'path': str(self.root / path), 'sha256': self.snapshot['source_sha256'][name]}
                      for name, path in MODULE_PATHS.items() if name != 'runner'}
        transport = {'pairing_verdict': 'ANNIHILATING', 'global_class_zero': False,
                     'full_regime_w': 'NOT_EVALUATED', 'reason': 'Synthetic output contract only.'}
        lines = ['SOURCE_PROVENANCE '+wire(provenance).decode()]
        lines += ['[PASS] '+name for name in SCENARIOS] + ['xiv_stitch selftest: 15/15 OK']
        lines += ['[PASS] control '+name for name in CONTROLS]
        lines += ['xiv_stitch mutation/control rows: 28/28 OK', 'TRANSPORT '+wire(transport).decode(),
                  'xiv_stitch: PASS (finite supplied witnesses only)']
        return subprocess.CompletedProcess(['synthetic-observation'], 0, ('\n'.join(lines)+'\n').encode(), b'')

    @contextmanager
    def synthetic(self):
        with patch.object(s.observation, 'source_snapshot', side_effect=lambda *a: copy.deepcopy(self.snapshot)), \
             patch.object(s, 'git_bytes', side_effect=self.git_bytes), \
             patch.object(s.observation, 'execute', side_effect=lambda *a: self.process_output()):
            yield

    def collect(self):
        return s.PreparedRelease(self.root, self.revision)

    def refused(self, code):
        return self.assertRaisesRegex(s.observation.Refusal, '^'+code+'$')

    def test_01_git_exit_and_batch_command(self):
        good = subprocess.CompletedProcess([], 0, b'exact\0bytes', b'')
        with patch.object(s.subprocess, 'run', return_value=good) as run:
            self.assertEqual(s.git_bytes(self.root, 'cat-file', '--batch', input=b'abc\n'), b'exact\0bytes')
            run.assert_called_once_with(['git', '--no-optional-locks', '-C', str(self.root), 'cat-file', '--batch'],
                                        input=b'abc\n', capture_output=True, timeout=30)
        bad = subprocess.CompletedProcess([], 1, b'partial', b'failed')
        with patch.object(s.subprocess, 'run', return_value=bad), self.refused('SOURCE_GIT'):
            s.git_bytes(self.root, 'ls-tree', 'HEAD')

    def test_02_all_sources_include_unused_document(self):
        with self.synthetic():
            snapshot, records, members = s.source_files(self.root, self.revision)
        self.assertEqual(snapshot, self.snapshot)
        self.assertEqual(members, self.members)
        expected = [{'path': name, 'mode': '100644', 'git_blob': blob(raw), 'size': len(raw), 'sha256': sha(raw)}
                    for name, raw in sorted(self.members.items())]
        self.assertEqual(records, expected)
        self.assertIn('docs/unused.md', members)

    def test_03_gitlink_requires_exact_pinned_layer(self):
        self.trees['spectrum'][-2] = ('160000', 'commit', 'd'*40, 'layers/XIV')
        with self.synthetic(), self.refused('SOURCE_GITLINK'):
            s.source_files(self.root, self.revision)

    def test_04_batch_identity_framing_and_trailing_bytes(self):
        variants = [(lambda raw: b'0'*40+raw[40:], 'SOURCE_BLOB'),
                    (lambda raw: raw.replace(b' blob ', b' tree ', 1), 'SOURCE_BLOB'),
                    (lambda raw: raw[:-1], 'SOURCE_BLOB'),
                    (lambda raw: raw+b'extra', 'SOURCE_BLOB_TRAILING')]
        for change, code in variants:
            with self.subTest(code=code):
                self.batch_change = change
                with self.synthetic(), self.refused(code): s.source_files(self.root, self.revision)

    def test_05_checkout_bytes_include_unused_document(self):
        (self.root/'docs/unused.md').write_bytes(b'Changed without changing a loaded module.\n')
        # Snapshot is held fixed here to isolate the blob/checkout guard from Git status.
        with self.synthetic(), self.refused('SOURCE_CHECKOUT_BYTES'):
            s.source_files(self.root, self.revision)

    def test_06_source_paths_types_and_case_collisions(self):
        original = copy.deepcopy(self.trees['spectrum'])
        for mode, kind, path, code in [('120000', 'blob', 'link', 'SOURCE_FILE_TYPE'),
                                     ('100644', 'blob', '../outside', 'SOURCE_PATH'),
                                     ('100644', 'blob', '.git/config', 'SOURCE_PATH'),
                                     ('100644', 'blob', 'Release/observation.json', 'SOURCE_PATH_COLLISION'),
                                     ('100644', 'blob', 'readme.MD', 'SOURCE_PATH_COLLISION')]:
            with self.subTest(path=path):
                self.trees['spectrum'] = original + [(mode, kind, original[0][2], path)]
                with self.synthetic(), self.refused(code): s.source_files(self.root, self.revision)
        self.trees['spectrum'] = original
        (self.root/'README.md').unlink()
        with self.synthetic(), self.refused('SOURCE_FILE_PATH'): s.source_files(self.root, self.revision)

    def test_07_source_snapshot_rechecked_after_blob_read(self):
        changed = copy.deepcopy(self.snapshot); changed['revisions']['XV'] = 'd'*40
        with self.synthetic(), patch.object(s.observation, 'source_snapshot', side_effect=[self.snapshot, changed]), \
             self.refused('SOURCE_CHANGED'):
            s.source_files(self.root, self.revision)

    def test_08_observed_modules_bind_to_packaged_blobs(self):
        self.snapshot['source_sha256']['finite'] = '0'*64
        with self.synthetic(), self.refused('SOURCE_MODULE_BINDING'):
            s.source_files(self.root, self.revision)

    def test_09_zip_complete_bytes_metadata_and_repeat(self):
        raw = s.zip_bytes(self.members, {'README.md': '100755'})
        self.assertEqual(raw, s.zip_bytes(dict(reversed(list(self.members.items()))), {'README.md': '100755'}))
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            self.assertEqual(z.namelist(), sorted(self.members))
            self.assertEqual({name: z.read(name) for name in z.namelist()}, self.members)
            self.assertEqual(z.getinfo('README.md').external_attr >> 16, 0o100755)
            self.assertTrue(all(e.date_time == (1980, 1, 1, 0, 0, 0) for e in z.infolist()))
        s.verify_archive(raw, self.members)

    def test_10_archive_missing_extra_and_duplicate_members(self):
        entries = [('a', b'A'), ('b', b'B')]
        for changed in (entries[:1], entries+[('c', b'C')], entries+[entries[0]], [entries[0], entries[0]]):
            with self.subTest(entries=changed), self.refused('ARCHIVE_MEMBERS'):
                s.verify_archive(archive(changed), dict(entries))
        s.verify_archive(archive(entries), dict(entries))

    def test_11_archive_rejects_changed_member_bytes(self):
        for raw in (b'X', b'longer'):
            with self.subTest(raw=raw), self.refused('ARCHIVE_BYTES'):
                s.verify_archive(archive([('a', raw)]), {'a': b'A'})
        s.verify_archive(archive([('a', b'A')]), {'a': b'A'})

    def test_12_archive_size_format_and_regular_files(self):
        with self.refused('ARCHIVE_SIZE'): s.verify_archive(b'', {})
        with self.refused('ARCHIVE_SIZE'): s.verify_archive(bytearray(archive([('a', b'A')])), {'a': b'A'})
        with self.refused('ARCHIVE_FORMAT'): s.verify_archive(b'not a zip', {})
        with self.refused('ARCHIVE_FILE_TYPE'):
            s.verify_archive(archive([('a', b'A')], 0o120777), {'a': b'A'})

    def test_13_nonverified_observation_cannot_prepare(self):
        for code, error in ((1, b'xiv_stitch: FAIL MAP_NOT_MONIC\n'), (2, b'unavailable')):
            output = subprocess.CompletedProcess([], code, b'', error)
            with self.synthetic(), patch.object(s.observation, 'execute', return_value=output), \
                 self.refused('OBSERVATION_NOT_VERIFIED'): self.collect()

    def test_14_received_report_source_must_match_collection(self):
        receive = s.observation.ObservationSession.receive
        def changed(instance, raw):
            report = receive(instance, raw)
            report['source']['revisions']['XV'] = 'd'*40
            return report
        with self.synthetic(), patch.object(s.observation.ObservationSession, 'receive', changed), \
             self.refused('OBSERVATION_SOURCE_BINDING'): self.collect()

    def test_15_all_source_records_rechecked_after_collect(self):
        files = s.source_files
        calls = []
        def changed(*args):
            result = files(*args); calls.append(True)
            if len(calls) > 1:
                for row in result[1]:
                    if row['path'] == 'docs/unused.md': row['sha256'] = '0'*64
            return result
        with self.synthetic(), patch.object(s, 'source_files', side_effect=changed), \
             self.refused('RELEASE_SOURCE_CHANGED'): self.collect()

    def test_16_manifest_binds_complete_sources_and_report(self):
        with self.synthetic(): prepared = self.collect()
        expected = {'format': 'nc25ol-spectrum-source-release/v1',
                    'scope': 'ALL_COMMITTED_FILES_OF_SPECTRUM_AND_PINNED_XIV_XV',
                    'source': self.snapshot, 'files': prepared.records,
                    'observation_sha256': sha(prepared.report_bytes),
                    'authority': 'SEPARATE_SYNTHETIC_OWNER_DECISION_REQUIRED'}
        self.assertEqual(prepared.manifest, expected)
        self.assertEqual(prepared.members, dict(self.members, **{'release/manifest.json': wire(expected),
                                                               'release/observation.json': prepared.report_bytes}))
        self.assertEqual(json.loads(prepared.report_bytes), prepared.report)
        self.assertIs(prepared.report['executable'], False)
        self.assertEqual(prepared.report['admission'], 'NOT_REQUESTED')

    def test_17_release_registry_matches_observation_association(self):
        with self.synthetic():
            prepared = self.collect()
            prepared.report['association']['ledger_registry']['status'] = 'ACTIVE'
            with self.refused('RELEASE_CONTEXT_CHANGED'): prepared.open(self.folder/'release')

    def test_18_session_required_and_single_open(self):
        with self.synthetic():
            prepared = self.collect()
            with self.refused('RELEASE_SESSION_REQUIRED'): prepared.submit(prepared.archive)
            session = prepared.open(self.folder/'release')
            self.addCleanup(session.close)
            with self.refused('RELEASE_SESSION_EXISTS'): prepared.open(self.folder/'second')
            self.assertFalse((self.folder/'second').exists())

    def test_19_changed_package_refused_before_gateway(self):
        with self.synthetic():
            prepared = self.collect(); session = prepared.open(self.folder/'release')
            self.addCleanup(session.close)
            with patch.object(session, 'submit', return_value={'state': 'COMMITTED'}) as submit:
                for bad in (prepared.archive+b'x', bytearray(prepared.archive)):
                    with self.refused('RELEASE_PACKAGE_CHANGED'): prepared.submit(bad)
                submit.assert_not_called()
                self.assertEqual(prepared.submit(prepared.archive), {'state': 'COMMITTED'})
                submit.assert_called_once_with()

    def test_20_changed_operation_target_refused_before_gateway(self):
        with self.synthetic():
            prepared = self.collect(); session = prepared.open(self.folder/'release')
            self.addCleanup(session.close)
            session.op['target_system_id'] = 'different-target'
            with patch.object(session, 'submit') as submit, self.refused('RELEASE_OPERATION_CHANGED'):
                prepared.submit(prepared.archive)
            submit.assert_not_called()

    def test_21_all_source_records_rechecked_before_submit(self):
        with self.synthetic():
            prepared = self.collect(); session = prepared.open(self.folder/'release')
            self.addCleanup(session.close)
            current = (copy.deepcopy(self.snapshot), copy.deepcopy(prepared.records), dict(self.members))
            for row in current[1]:
                if row['path'] == 'docs/unused.md': row['sha256'] = '0'*64
            with patch.object(s, 'source_files', return_value=current), patch.object(session, 'submit') as submit, \
                 self.refused('RELEASE_SOURCE_CHANGED'): prepared.submit(prepared.archive)
            submit.assert_not_called()

    def test_22_release_attempt_is_not_reusable_after_success_or_error(self):
        with self.synthetic():
            for index, error in enumerate((None, RuntimeError('synthetic interruption'))):
                prepared = self.collect(); session = prepared.open(self.folder/('release-'+str(index)))
                self.addCleanup(session.close)
                with patch.object(session, 'submit', return_value={'state': 'COMMITTED'}, side_effect=error) as submit:
                    if error is None: prepared.submit(prepared.archive)
                    else:
                        with self.assertRaisesRegex(RuntimeError, '^synthetic interruption$'): prepared.submit(prepared.archive)
                    with self.refused('RELEASE_ALREADY_ATTEMPTED'): prepared.submit(prepared.archive)
                    self.assertEqual(submit.call_count, 1)

    def test_23_run_real_gateway_no_authority_then_recovery(self):
        sessions = []
        real = s.scenario.DocumentSession
        class Recorded(real):
            def __init__(inner, *args, **kwargs):
                super().__init__(*args, **kwargs); inner.results = []; sessions.append(inner)
            def submit(inner):
                try:
                    result = super().submit()
                except s.ContractViolation as exc:
                    inner.results.append(({'code': exc.code}, inner.target_counts()))
                    raise
                inner.results.append((copy.deepcopy(result), inner.target_counts()))
                return result
        with self.synthetic(), patch.object(s.scenario, 'DocumentSession', Recorded):
            result = s.run(self.root, self.revision, self.folder/'delivery')
        session, = sessions
        denied, committed = session.results
        self.assertEqual(denied[0]['code'], 'DECLARATION_NOT_ACTIVE')
        self.assertEqual(denied[1], (0, 0))
        self.assertEqual(committed[0]['state'], 'COMMITTED')
        self.assertEqual(committed[1], (1, 1))
        self.assertEqual(result['target_receipt'], committed[0]['downstream'])
        self.assertEqual(result['ledger_receipt'], committed[0]['ledger_receipt'])
        self.assertEqual((result['target_documents'], result['target_receipts'], result['structural_remaining']), (1, 1, 360))
        self.assertEqual(result['recovery'], 'SAME_RECEIPT_ONE_EFFECT')
        self.assertEqual(result['before_activation'], 'DECLARATION_NOT_ACTIVE')
        self.assertEqual(result['source'], self.snapshot)
        self.assertEqual(result['source_file_count'], len(self.members))
        self.assertEqual(result['full_regime_w'], 'NOT_EVALUATED')
        self.assertIs(result['publicly_published'], False)
        self.assertIs(result['live_witnesses_connected'], False)
        self.assertIsNone(session.process)
        self.assertEqual(json.loads((self.folder/'delivery/result.json').read_bytes()), result)
        raw = (self.folder/'delivery/spectrum-source-release.zip').read_bytes()
        self.assertEqual(result['archive_sha256'], sha(raw))
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            manifest = json.loads(z.read('release/manifest.json'))
            self.assertEqual({name: z.read(name) for name in self.members}, self.members)
            self.assertEqual(manifest['source'], self.snapshot)
            self.assertEqual(manifest['observation_sha256'], sha(z.read('release/observation.json')))
        with sqlite3.connect(self.folder/'delivery/target.sqlite') as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM documents').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0], 1)

    def test_24_run_refuses_false_denial_changed_target_and_recovery(self):
        real = s.scenario.DocumentSession
        for index, (fault, code) in enumerate((('denial', 'UNACTIVATED_RELEASE'),
                                             ('wrong-denial', 'UNEXPECTED_ACTIVATION_REFUSAL'),
                                             ('denial-effect', 'UNACTIVATED_EFFECT'),
                                             ('target', 'TARGET_BYTES_CHANGED'),
                                             ('recovery', 'REPLAY_CHANGED_EFFECT'))):
            class Faulty(real):
                def submit(inner):
                    try:
                        return super().submit()
                    except s.ContractViolation:
                        if fault == 'denial': return {'status': 'NOT_ADMISSIBLE'}
                        if fault == 'wrong-denial': raise s.ContractViolation('UNRELATED_REFUSAL')
                        if fault == 'denial-effect': inner.engine.structural_remaining -= 1
                        raise
                def start(inner, *args, **kwargs):
                    super().start(*args, **kwargs)
                    if fault == 'target':
                        call = inner.read_client.call
                        def altered(*a, **kw):
                            result = call(*a, **kw)
                            result['content_base64'] = base64.b64encode(b'changed bytes').decode()
                            return result
                        inner.read_client.call = altered
                def reopen(inner):
                    super().reopen()
                    if fault == 'recovery':
                        recover = inner.gateway.recover
                        def altered(*a):
                            result = recover(*a)
                            return dict(result, state='PENDING')
                        inner.gateway.recover = altered
            with self.subTest(fault=fault), self.synthetic(), patch.object(s.scenario, 'DocumentSession', Faulty), self.refused(code):
                s.run(self.root, self.revision, self.folder/('bad-'+str(index)))
            self.assertFalse((self.folder/('bad-'+str(index))/'result.json').exists())

    def test_25_run_output_boundaries_precede_collection(self):
        with patch.object(s, 'PreparedRelease') as prepare:
            for target in (s.ROOT/'synthetic-forbidden-output', self.root/'out'):
                with self.refused('OUTPUT_OUTSIDE_SOURCES'): s.run(self.root, self.revision, target)
            with self.refused('RUN_DIRECTORY_EXISTS'): s.run(self.root, self.revision, self.folder)
            prepare.assert_not_called()

    def test_26_real_git_complete_sources_revision_and_unused_checkout(self):
        # Only these three newly created fixture repositories receive Git writes.
        def git(folder, *args):
            fixture_env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
            fixture_env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
            return subprocess.check_output(['git', '-C', str(folder), *args], stderr=subprocess.PIPE,
                                           env=fixture_env).decode().strip()
        folders = [self.root/'layers/XIV', self.root/'layers/XV', self.root]
        revisions = {}
        for folder in folders:
            git(folder, 'init', '--quiet', '--object-format=sha1')
            git(folder, 'config', 'core.autocrlf', 'false')
            if folder == self.root:
                git(folder, 'add', '--', 'README.md', 'docs/unused.md')
                for name in ('XIV', 'XV'):
                    git(folder, 'update-index', '--add', '--cacheinfo', '160000,'+revisions[name]+',layers/'+name)
            else: git(folder, 'add', '--', '.')
            git(folder, '-c', 'user.name=Synthetic Fixture', '-c', 'user.email=fixture@example.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Synthetic source fixture')
            revisions['spectrum' if folder == self.root else folder.name] = git(folder, 'rev-parse', 'HEAD')
        snapshot, records, members = s.source_files(self.root, revisions['spectrum'])
        self.assertEqual(snapshot['revisions'], revisions)
        self.assertEqual(members, self.members)
        self.assertEqual({row['path']: row['git_blob'] for row in records}, {name: blob(raw) for name, raw in self.members.items()})
        with self.refused('SOURCE_REVISION'): s.source_files(self.root, '0'*40)
        (self.root/'docs/unused.md').write_bytes(b'unused but changed\n')
        with self.refused('SOURCE_DIRTY'): s.source_files(self.root, revisions['spectrum'])
        native_git = s.observation.git
        def hidden_status(folder, *args):
            return '' if args[:1] == ('status',) else native_git(folder, *args)
        with patch.object(s.observation, 'git', side_effect=hidden_status), self.refused('SOURCE_CHECKOUT_BYTES'):
            s.source_files(self.root, revisions['spectrum'])

    def test_27_changed_archive_cannot_open_session(self):
        with self.synthetic():
            prepared = self.collect()
            prepared.archive = archive([('foreign.txt', b'different valid ZIP')])
            with patch.object(s.scenario, 'DocumentSession') as create, self.refused('RELEASE_PACKAGE_CHANGED'):
                prepared.open(self.folder/'release')
            create.assert_not_called()
            self.assertFalse((self.folder/'release').exists())

    def test_28_operation_payload_is_the_submitted_package(self):
        # Model a constructor forwarding different bytes before the operation is pinned.
        # The operation pin is honest about those different bytes; no private pin is edited.
        real = s.scenario.DocumentSession
        def wrong_payload(directory, raw, **kwargs):
            return real(directory, b'different constructor payload', **kwargs)
        with self.synthetic():
            prepared = self.collect()
            with patch.object(s.scenario, 'DocumentSession', side_effect=wrong_payload):
                session = prepared.open(self.folder/'release')
            self.addCleanup(session.close)
            with patch.object(session, 'submit') as submit, self.refused('RELEASE_PAYLOAD_CHANGED'):
                prepared.submit(prepared.archive)
            submit.assert_not_called()


if __name__ == '__main__': unittest.main(verbosity=2)
