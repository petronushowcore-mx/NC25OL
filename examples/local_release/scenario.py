"""Synthetic preview release and declaration-objection composition.

Local example only: separate authority, separate databases, no live witnesses.
"""
from __future__ import annotations

import argparse
import base64
import copy
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import queue
import secrets
import sqlite3
import subprocess
import sys
import threading

ROOT = Path(os.environ.get('NC25_LEDGER_ROOT', Path(__file__).resolve().parents[2])).resolve()
sys.path.insert(0, str(ROOT / 'sdk' / 'python'))
from nc25_universal_ledger import UniversalConnectionLedger, FixedClock, bind_fixture, canonical_json
import document_release as dr
import exchange as x


def check_preview(raw):
    """Check preview markers and term-text hashes; producer identity is assumed."""
    if type(raw) is not bytes or not 0 < len(raw) <= dr.MAX_BODY // 2:
        raise ValueError('PREVIEW_BYTES')
    value = json.loads(raw)
    fields = {'format', 'synthetic', 'admitted', 'project_id', 'public_fields', 'terms'}
    if type(value) is not dict or set(value) != fields:
        raise ValueError('PREVIEW_FIELDS')
    if (value['format'] != 'otcs-registration-preview/v1' or value['synthetic'] is not True
            or value['admitted'] is not False):
        raise ValueError('PREVIEW_NOT_ADMISSION')
    if not isinstance(value['project_id'], str) or not value['project_id'] or type(value['public_fields']) is not dict:
        raise ValueError('PREVIEW_PROJECT')
    terms = value['terms']
    if (type(terms) is not list or len(terms) != 3
            or {t.get('kind') for t in terms if type(t) is dict}
            != {'grant_terms', 'consent_terms', 'platform_disclosure'}):
        raise ValueError('PREVIEW_TERMS')
    for term in terms:
        if (set(term) != {'kind', 'reference', 'version', 'text'}
                or type(term['text']) is not str or type(term['reference']) is not dict
                or term['reference'].get('sha256') != hashlib.sha256(term['text'].encode('utf-8')).hexdigest()):
            raise ValueError('PREVIEW_TERMS_BINDING')
    return value


class DocumentSession:
    """One synthetic authority and serialized gateway for exact document bytes."""
    def __init__(self, path, document_bytes, document_id='document', idempotency_key='document-release-1'):
        if type(document_bytes) is not bytes:
            raise dr.ReleaseError('OPERATION_CONTENT')
        self.op = {'document_id': document_id, 'content_base64': base64.b64encode(document_bytes).decode('ascii'),
                   'target_system_id': 'document-sandbox-repository', 'expected_head': dr.GENESIS,
                   'idempotency_key': idempotency_key}
        dr.operation(self.op)  # Validate payload and identifiers before creating stores.
        self.path = Path(path).resolve()
        if self.path.exists():
            raise ValueError('RUN_DIRECTORY_EXISTS')
        self.path.mkdir(parents=True)
        self.raw = json.loads((ROOT / 'profiles/document-release/reference-connection.json').read_text(encoding='utf-8'))
        self.profile, self.declaration, self.grant, self.intent = bind_fixture(
            *(self.raw[k] for k in ('profile', 'declaration', 'grant', 'intent')))
        self.intent.update(idempotency_key=self.op['idempotency_key'], payload_hash=dr.payload_hash(self.op),
                           state_anchor_hash=dr.GENESIS, history_summary_hash=dr.GENESIS)
        self.evidence = copy.deepcopy(self.raw['evidence'])
        self.approved_hash = dr.payload_hash(self.op)
        for item in self.evidence['items']:
            item['sha256'] = dr.digest({'evidence_type': item['evidence_type'], 'payload_hash': self.approved_hash,
                                       'target': self.op['target_system_id'], 'approved_by': 'synthetic-document-owner'})
        self.clock = FixedClock(datetime(2026, 8, 1, 10, tzinfo=timezone.utc))
        self.signing_key, self.outbox_key = secrets.token_bytes(32), secrets.token_bytes(32)
        self.reader, self.executor = secrets.token_hex(32), secrets.token_hex(32)
        self.author_keys = {'local-reader': secrets.token_bytes(32)}
        self.process = None
        self.engine = self.restore_engine()
        self._projection_pin = canonical_json(x.export_projection(self.declaration, self.profile))

    def restore_engine(self):
        def controls(intent, now):
            return {'prerequisite_results': {'CONTENT_APPROVED': intent['payload_hash'] == self.approved_hash,
                      'DESTINATION_AUTHORIZED': intent['target_system_id'] == self.op['target_system_id']},
                    'hard_block_flags': {'RETENTION_HOLD': False, 'TARGET_DELISTED': False},
                    'manual_review_flags': {'CLASSIFICATION_UNCERTAIN': False}, 'ambiguity_flags': []}
        def evidence(intent, submitted, now):
            resolved = copy.deepcopy(self.evidence)
            resolved['intent_id'] = intent['intent_id']
            return resolved
        return UniversalConnectionLedger(self.profile, self.declaration, self.signing_key, clock=self.clock,
            state_path=self.path / 'ledger.sqlite', evidence_resolver=evidence, control_resolver=controls)

    def activate(self):
        self.engine.activate(self.declaration['governance']['approval_owner_id'],
                             'evidence://synthetic/document-owner/activation', actor_scope='nc25.governance')
        self.engine.issue_grant(self.grant, actor_scope='nc25.governance')

    def start(self, drop_response=False, fault=lambda point: None):
        self.process = subprocess.Popen([sys.executable, '-B', '-u', str(Path(dr.__file__))],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
        try:
            config = {'database': str(self.path / 'target.sqlite'), 'target_id': self.op['target_system_id'],
                      'fixed_time': '2026-08-01T10:00:00Z', 'reader': self.reader, 'executor': self.executor,
                      'drop_first_response': drop_response}
            self.process.stdin.write(json.dumps(config) + '\n')
            self.process.stdin.flush()
            lines = queue.Queue()
            threading.Thread(target=lambda: lines.put(self.process.stdout.readline()), daemon=True).start()
            line = lines.get(timeout=10)
            if not line:
                raise RuntimeError('TARGET_START_FAILED')
            self.port = json.loads(line)['port']
            self.client = dr.Client(self.port, self.executor)
            self.read_client = dr.Client(self.port, self.reader, 'reader')
            self.gateway = dr.Gateway(self.engine, self.client, self.path / 'outbox.sqlite', self.outbox_key, fault)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                self.process.wait(timeout=5)
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                stream.close()
            self.process = None

    def submit(self):
        return self.gateway.submit(self.op, self.intent, self.evidence)

    def reopen(self):
        self.engine = self.restore_engine()
        self.gateway = dr.Gateway(self.engine, self.client, self.path / 'outbox.sqlite', self.outbox_key)

    def revoke(self):
        self.engine.revoke_grant({'message_type': 'authority_revocation', 'grant_id': self.grant['grant_id'],
            'declaration_hash': self.engine.declaration_hash, 'revoked_at': '2026-08-01T10:00:00Z',
            'revoked_by': self.declaration['governance']['authority_issuer_id'], 'reason_code': 'APPROVAL_WITHDRAWN',
            'evidence_ref': 'evidence://synthetic/withdrawal'}, actor_scope='nc25.governance')

    def target_counts(self):
        with dr.database(self.path / 'target.sqlite') as db:
            return tuple(db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0] for table in ('documents', 'receipts'))

    def snapshot(self):
        # Read committed SQLite state, including WAL, not only the main file.
        with closing(sqlite3.connect(self.path / 'ledger.sqlite')) as db:
            ledger_digest = hashlib.sha256(db.serialize()).hexdigest()
        return {'events': self.engine.ledger.events_copy(), 'database': ledger_digest,
                'registry': self.engine.registry_record(self.declaration['connector']['connector_id'], actor_scope='nc25.architect')}

    def observe(self):
        before = self.snapshot()
        # Pin the original local declaration, independently of later input edits.
        # This local provisioning does not establish a remote owner's identity.
        pin = json.loads(self._projection_pin)
        if (pin['binding']['declaration_hash'] != self.engine.declaration_hash
                or pin['binding']['profile_hash'] != self.engine.profile_hash):
            raise ValueError('PROJECTION_ENGINE_MISMATCH')
        wire = canonical_json(x.export_projection(self.declaration, self.profile))
        received = x.read_projection(wire, pin)
        message = x.make_objection(received, 'local-reader', 'scope-question-1', 'SCOPE_QUESTION',
                                  'Please review these declaration conditions.', self.author_keys['local-reader'])
        objection = x.read_objection(canonical_json(message), pin, self.author_keys)
        if objection['executable'] is not False:
            raise RuntimeError('OBJECTION_MUST_NOT_AUTHORISE')
        if before != self.snapshot():
            raise RuntimeError('OBSERVATION_CHANGED_LEDGER')
        return {'projection': received, 'objection': objection}


class LocalSession(DocumentSession):
    """Preview-specific validation over the same synthetic document gateway."""
    def __init__(self, path, preview_bytes):
        self.preview = check_preview(preview_bytes)
        super().__init__(path, preview_bytes, document_id='registration-preview',
                         idempotency_key='preview-release-1')


def run(preview_bytes, run_directory):
    session = LocalSession(run_directory, preview_bytes)
    try:
        session.start()
        initial = session.engine.registry_record(session.declaration['connector']['connector_id'], actor_scope='nc25.architect')
        session.activate()  # Explicit fixture authority, never inferred from preview.ok.
        first = session.submit()
        if first['state'] != 'COMMITTED':
            raise RuntimeError('RELEASE_NOT_COMMITTED')
        target = session.read_client.call('GET', '/documents/registration-preview')
        if base64.b64decode(target['content_base64']) != preview_bytes:
            raise RuntimeError('RELEASE_BYTES_CHANGED')
        session.reopen()
        replay = session.gateway.recover(session.op['idempotency_key'])
        if replay != first or session.target_counts() != (1, 1) or session.engine.structural_remaining != 360:
            raise RuntimeError('REPLAY_CHANGED_EFFECT')
        observation = session.observe()
        result = {'format': 'nc25ol-local-release-example/v1', 'synthetic': True, 'otcs_admitted': False,
                  'project_id': session.preview['project_id'], 'initial_registry': initial,
                  'document_sha256': hashlib.sha256(preview_bytes).hexdigest(),
                  'target_receipt': first['downstream'], 'ledger_receipt': first['ledger_receipt'],
                  'target_documents': 1, 'target_receipts': 1, 'structural_remaining': session.engine.structural_remaining,
                  'observation': observation, 'live_witnesses_connected': False}
        (session.path / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        return result
    finally:
        session.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preview', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path, help='New run directory outside the package')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(ROOT) or output.is_relative_to(Path(__file__).resolve().parent):
        parser.error('Output must be outside both package and example directories')
    result = run(args.preview.read_bytes(), output)
    print(json.dumps({'status': 'PASS', 'report': str(output / 'result.json'),
                      'synthetic': result['synthetic'], 'otcs_admitted': result['otcs_admitted']}))
