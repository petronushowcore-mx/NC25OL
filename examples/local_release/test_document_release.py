import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone

ROOT = Path(os.environ.get('NC25_LEDGER_ROOT', Path(__file__).resolve().parents[2])).resolve()
sys.path.insert(0, str(ROOT / 'sdk' / 'python'))
from nc25_universal_ledger import UniversalConnectionLedger, FixedClock, bind_fixture, ContractViolation
import document_release as dr


class Cases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.clock = FixedClock(datetime(2026, 8, 1, 10, tzinfo=timezone.utc))
        self.raw = json.loads((ROOT/'profiles/document-release/reference-connection.json').read_text(encoding='utf-8'))
        self.op = {'document_id': 'release-1', 'content_base64': base64.b64encode(b'Actual document bytes\n').decode(),
                   'target_system_id': 'document-sandbox-repository', 'expected_head': dr.GENESIS, 'idempotency_key': 'release-1'}
        self.profile, self.declaration, self.grant, self.intent = bind_fixture(*(self.raw[k] for k in ('profile','declaration','grant','intent')))
        self.intent.update(idempotency_key='release-1', payload_hash=dr.payload_hash(self.op),
                           state_anchor_hash=dr.GENESIS, history_summary_hash=dr.GENESIS)
        self.approved_hash = dr.payload_hash(self.op)
        self.hold = self.manual = False
        self.evidence = copy.deepcopy(self.raw['evidence'])
        # Actual authority-record digests; these remain explicit synthetic decisions.
        for item in self.evidence['items']:
            item['sha256'] = dr.digest({'evidence_type': item['evidence_type'], 'payload_hash': self.approved_hash,
                                      'target': self.op['target_system_id'], 'approved_by': 'synthetic-reviewer'})
        self.signing_key, self.outbox_key = secrets.token_bytes(32), secrets.token_bytes(32)
        self.engine = self.restore_engine()
        self.engine.activate(self.declaration['governance']['approval_owner_id'], 'evidence://synthetic/activation', actor_scope='nc25.governance')
        self.engine.issue_grant(self.grant, actor_scope='nc25.governance')
        self.reader, self.executor = secrets.token_hex(32), secrets.token_hex(32)
        self.process = None

    def restore_engine(self):
        def controls(intent, now):
            return {'prerequisite_results': {'CONTENT_APPROVED': intent['payload_hash'] == self.approved_hash,
                      'DESTINATION_AUTHORIZED': intent['target_system_id'] == self.op['target_system_id']},
                    'hard_block_flags': {'RETENTION_HOLD': self.hold, 'TARGET_DELISTED': False},
                    'manual_review_flags': {'CLASSIFICATION_UNCERTAIN': self.manual}, 'ambiguity_flags': []}
        def evidence(intent, submitted, now):
            resolved = copy.deepcopy(self.evidence)
            resolved['intent_id'] = intent['intent_id']
            return resolved
        return UniversalConnectionLedger(self.profile, self.declaration, self.signing_key, clock=self.clock,
            state_path=self.path/'ledger.sqlite', evidence_resolver=evidence, control_resolver=controls)

    def start(self, drop=False, fault=lambda p: None):
        self.process = subprocess.Popen([sys.executable, '-B', '-u', str(Path(dr.__file__))], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
        self.addCleanup(self.stop)
        self.process.stdin.write(json.dumps({'database': str(self.path/'target.sqlite'), 'target_id': self.op['target_system_id'],
            'fixed_time': '2026-08-01T10:00:00Z', 'reader': self.reader, 'executor': self.executor, 'drop_first_response': drop})+'\n')
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            self.fail(self.process.stderr.read())
        self.port = json.loads(line)['port']
        self.client = dr.Client(self.port, self.executor)
        self.read_client = dr.Client(self.port, self.reader, 'reader')
        self.gateway = dr.Gateway(self.engine, self.client, self.path/'outbox.sqlite', self.outbox_key, fault)
        return self.gateway

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=5)
        if self.process:
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                stream.close()

    def submit(self):
        return self.gateway.submit(self.op, self.intent, self.evidence)

    def counts(self):
        with dr.database(self.path/'target.sqlite') as db:
            return tuple(db.execute('SELECT COUNT(*) FROM '+name).fetchone()[0] for name in ('documents','receipts'))

    def reopen(self):
        self.engine = self.restore_engine()
        self.gateway = dr.Gateway(self.engine, self.client, self.path/'outbox.sqlite', self.outbox_key)

    def revoke(self):
        self.engine.revoke_grant({'message_type':'authority_revocation', 'grant_id':self.grant['grant_id'],
            'declaration_hash':self.engine.declaration_hash, 'revoked_at':'2026-08-01T10:00:00Z',
            'revoked_by':self.declaration['governance']['authority_issuer_id'], 'reason_code':'APPROVAL_WITHDRAWN',
            'evidence_ref':'evidence://synthetic/withdrawal'}, actor_scope='nc25.governance')

    def test_bytes_and_durable_exact_replay(self):
        self.start()
        first = self.submit()
        self.assertEqual(first['state'], 'COMMITTED', 'RELEASE_COMMITTED')
        self.assertEqual(self.read_client.call('GET','/documents/release-1')['content_base64'], self.op['content_base64'], 'EXACT_BYTES')
        self.assertEqual(self.counts(), (1,1), 'ONE_TARGET_EFFECT')
        self.assertEqual(self.engine.structural_remaining, 360, 'ONE_DEBIT')
        self.reopen()
        self.clock.advance(seconds=301)
        self.assertEqual(self.gateway.recover('release-1'), first, 'DURABLE_REPLAY')
        self.assertEqual(self.counts(), (1,1), 'REPLAY_EFFECTS')
        self.assertEqual(self.engine.structural_remaining, 360, 'REPLAY_DEBIT')

    def test_reader_and_forged_role_cannot_write(self):
        self.start()
        for credential in (self.reader, 'wrong-credential', '', 'bad-' + chr(233)):
            with self.subTest(credential=credential==self.reader):
                with self.assertRaisesRegex(dr.ReleaseError, 'TARGET_CREDENTIAL|TARGET_RESPONSE_AUTH', msg='CREDENTIAL_BOUNDARY'):
                    dr.Client(self.port, credential, 'reader' if credential == self.reader else 'executor').call('POST','/append', {'operation':self.op,'permit_hash':'A'*64,'expires_at':'2026-08-01T10:05:00Z'},
                        {'X-Workload-Scope':'nc25.executor'})
        self.assertEqual(self.counts(), (0,0), 'NO_CREDENTIAL_EFFECT')
        self.assertEqual(self.submit()['state'],'COMMITTED', 'CREDENTIAL_POSITIVE_CONTROL')

    def test_substitution_never_reaches_target(self):
        self.start()
        for field, value in [('content_base64',base64.b64encode(b'changed').decode()), ('document_id','other'),
                             ('target_system_id','other-target'), ('expected_head','B'*64), ('idempotency_key','other-key')]:
            altered = {**self.op,field:value}
            with self.assertRaisesRegex(dr.ReleaseError,'DOCUMENT_INTENT_BINDING', msg='EXACT_OPERATION_BINDING'):
                self.gateway.submit(altered,self.intent,self.evidence)
        self.assertEqual(self.counts(),(0,0),'NO_SUBSTITUTED_EFFECT')
        self.assertEqual(self.submit()['state'],'COMMITTED', 'BINDING_POSITIVE_CONTROL')

    def test_authoritative_refusal_and_manual_review(self):
        self.start()
        self.hold=True
        refused=self.submit()
        self.assertEqual(refused.get('status'),'NOT_ADMISSIBLE','HOLD_DENIES')
        self.assertEqual(refused['operator_result']['disposition'],'REFUSAL','HOLD_REASON')
        self.hold=False
        self.manual=True
        op={**self.op,'idempotency_key':'manual'}
        intent={**self.intent,'idempotency_key':'manual','intent_id':'manual'}
        evidence={**self.evidence,'intent_id':'manual'}
        reviewed=self.gateway.submit(op,intent,evidence)
        self.assertEqual(reviewed['operator_result']['disposition'],'MANUAL_REVIEW','REVIEW_NOT_PERMISSION')
        self.assertEqual(self.counts(),(0,0),'NO_NONEXECUTABLE_EFFECT')

    def test_prepared_expiry_prevents_post(self):
        self.start(fault=lambda point:self.clock.advance(seconds=301) if point=='after_prepare' else None)
        row=self.submit()
        self.assertEqual(row['state'],'NOT_EXECUTED','EXPIRED_BEFORE_POST')
        self.assertEqual(self.counts(),(0,0),'NO_EXPIRED_EFFECT')

    def test_prepared_revocation_prevents_post(self):
        self.start(fault=lambda point:self.revoke() if point=='after_prepare' else None)
        row=self.submit()
        self.assertEqual(row['state'],'NOT_EXECUTED','REVOKED_BEFORE_POST')
        self.assertEqual(row['reason'],'AUTHORITY_REVOKED','REVOCATION_REASON')
        self.assertEqual(self.counts(),(0,0),'NO_REVOKED_EFFECT')

    def test_lost_response_recovers_one_effect(self):
        self.start(drop=True)
        with self.assertRaises(Exception, msg='RESPONSE_WAS_LOST'):
            self.submit()
        self.assertEqual(self.gateway.record('release-1')['state'],'AMBIGUOUS','AMBIGUOUS_RECORDED')
        self.assertEqual(self.counts(),(1,1),'EFFECT_BEFORE_RESPONSE')
        self.reopen()
        row=self.gateway.recover('release-1')
        self.assertEqual(row['state'],'COMMITTED','LOST_RESPONSE_RECOVERED')
        self.assertEqual(self.counts(),(1,1),'NO_DUPLICATE_AFTER_LOSS')
        self.assertEqual(self.engine.structural_remaining,360,'SINGLE_RECOVERY_DEBIT')

    def test_ambiguous_expiry_never_redrives(self):
        self.start(drop=True)
        with self.assertRaises(Exception): self.submit()
        self.clock.advance(seconds=301)
        self.reopen()
        self.client.append=lambda *args: self.fail('DEAD_PERMIT_REDRIVEN')
        row=self.gateway.recover('release-1')
        self.assertEqual(row['state'],'RECONCILIATION_REQUIRED','AMBIGUOUS_NOT_ABSENCE')
        self.assertEqual(self.counts(),(1,1),'OLD_EFFECT_PRESERVED')
        self.assertEqual(self.engine.structural_remaining,400,'NO_FALSE_DEBIT')

    def test_expiry_after_effect_is_reconciliation(self):
        self.start(fault=lambda point:self.clock.advance(seconds=301) if point=='before_finalize' else None)
        row=self.submit()
        self.assertEqual(row['state'],'RECONCILIATION_REQUIRED','FINALIZATION_EXPIRED')
        self.assertEqual(self.counts(),(1,1),'EFFECT_NOT_UNDONE')
        self.assertEqual(self.engine.structural_remaining,400,'NO_FALSE_FINALIZATION')

    def test_crash_after_local_commit_replays(self):
        def fault(point):
            if point=='after_ledger': raise RuntimeError('simulated process stop')
        self.start(fault=fault)
        with self.assertRaisesRegex(RuntimeError,'simulated'):self.submit()
        self.assertEqual(self.gateway.record('release-1')['state'],'TARGET_COMMITTED','CRASH_SEAM_PRESERVED')
        self.reopen()
        self.clock.advance(seconds=301)
        row=self.gateway.recover('release-1')
        self.assertEqual(row['state'],'COMMITTED','LOCAL_REPLAY_AFTER_CRASH')
        self.assertEqual(self.counts(),(1,1),'NO_POST_AFTER_LOCAL_COMMIT')
        self.assertEqual(self.engine.structural_remaining,360,'NO_SECOND_LOCAL_DEBIT')

    def test_invalid_receipt_is_not_success(self):
        self.start()
        append=self.client.append
        def corrupt(*args):
            result=append(*args)
            result['payload_hash']='C'*64
            return result
        self.client.append=corrupt
        row=self.submit()
        self.assertEqual(row['state'],'RECONCILIATION_REQUIRED','RECEIPT_CHECKED')
        self.assertEqual(row['reason'],'TARGET_RECEIPT_BINDING','RECEIPT_REASON')
        self.assertEqual(self.engine.structural_remaining,400,'BAD_RECEIPT_NO_DEBIT')

    def test_outbox_tampering_is_refused(self):
        self.start()
        self.submit()
        with dr.database(self.path/'outbox.sqlite') as db:
            body=db.execute('SELECT body FROM outbox').fetchone()[0]
            db.execute('UPDATE outbox SET body=?',(body.replace('release-1','release-2'),))
        with self.assertRaisesRegex(dr.ReleaseError,'OUTBOX_AUTHENTICATION',msg='OUTBOX_AUTHENTICATED'):
            self.gateway.recover('release-1')

    def test_target_stale_head_and_key_conflict(self):
        self.start()
        row=self.submit()
        with self.assertRaisesRegex(dr.ReleaseError,'STALE_HEAD',msg='TARGET_CAS'):
            self.client.append({**self.op,'document_id':'second','idempotency_key':'second'},'B'*64,'2026-08-01T10:05:00Z')
        with self.assertRaisesRegex(dr.ReleaseError,'TARGET_IDEMPOTENCY_CONFLICT',msg='TARGET_KEY_BINDING'):
            self.client.append({**self.op,'content_base64':base64.b64encode(b'different').decode()},row['permit_hash'],'2026-08-01T10:05:00Z')
        with self.assertRaisesRegex(dr.ReleaseError,'TARGET_PERMIT_REUSE',msg='TARGET_PERMIT_SINGLE_USE'):
            self.client.append({**self.op,'document_id':'second','idempotency_key':'second','expected_head':row['downstream']['head']},row['permit_hash'],'2026-08-01T10:05:00Z')
        self.assertEqual(self.counts(),(1,1),'TARGET_REFUSALS_NO_EFFECT')


    def test_impostor_receipt_cannot_debit(self):
        self.start()
        self.stop()
        case = self
        class Impostor(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_POST(self):
                wire=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                op=wire['operation']
                seed={'operation_hash':dr.digest(op),'previous_head':op['expected_head'],
                      'payload_hash':dr.payload_hash(op),'effective_at':'2026-08-01T10:00:00Z',
                      'target_system_id':op['target_system_id'],'idempotency_key':op['idempotency_key'],
                      'permit_hash':wire['permit_hash']}
                body=dr.encode({**seed,'head':dr.digest(seed)}).encode('ascii')
                self.send_response(200)
                self.send_header('Content-Length',str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        fake=HTTPServer(('127.0.0.1',self.port),Impostor)
        thread=threading.Thread(target=fake.handle_request)
        thread.start()
        try:
            with self.assertRaisesRegex(dr.ReleaseError,'TARGET_RESPONSE_AUTH',msg='IMPOSTOR_REFUSED'):
                self.submit()
        finally:
            thread.join(timeout=4)
            fake.server_close()
        self.assertEqual(self.counts(),(0,0),'IMPOSTOR_NO_TARGET_EFFECT')
        self.assertEqual(self.engine.structural_remaining,400,'IMPOSTOR_NO_DEBIT')

    def test_incomplete_headers_have_read_timeout(self):
        self.start()
        stalled=socket.create_connection(('127.0.0.1',self.port),timeout=3)
        try:
            stalled.sendall(b'GET /head HTTP/1.0\r\n')
            try:
                result=self.read_client.call('GET','/head')
            except TimeoutError:
                self.fail('EARLY_HEADER_TIMEOUT')
            self.assertEqual(result['head'],dr.GENESIS,'VALID_REQUEST_AFTER_STALL')
        finally:
            stalled.close()



    def test_target_expired_request_cannot_create_first_effect(self):
        self.start()
        with self.assertRaisesRegex(dr.ReleaseError,'TARGET_REQUEST_EXPIRED',msg='TARGET_DEADLINE'):
            self.client.append(self.op,'A'*64,'2026-08-01T09:59:59Z')
        self.assertEqual(self.counts(),(0,0),'NO_DELAYED_FIRST_EFFECT')
        self.assertEqual(self.submit()['state'],'COMMITTED','DEADLINE_POSITIVE_CONTROL')

    def test_invalid_request_mac_is_refused(self):
        self.start()
        body={'operation':self.op,'permit_hash':'A'*64,'expires_at':'2026-08-01T10:05:00Z'}
        with self.assertRaisesRegex(dr.ReleaseError,'TARGET_CREDENTIAL',msg='REQUEST_MAC_REQUIRED'):
            self.client.call('POST','/append',body,{'X-Request-MAC':'0'*64})
        self.assertEqual(self.counts(),(0,0),'NO_UNAUTHENTICATED_EFFECT')
        self.assertEqual(self.submit()['state'],'COMMITTED','MAC_POSITIVE_CONTROL')


    def test_authentic_response_replay_is_refused(self):
        self.start()
        origin_port = self.port
        captured, nonces = [], []
        class Relay(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                nonces.append(self.headers['X-Nonce'])
                if len(nonces) == 2:
                    status, body, signature = captured[0]
                else:
                    conn = dr.http.client.HTTPConnection('127.0.0.1', origin_port, timeout=3)
                    try:
                        conn.request('GET', self.path, headers=dict(self.headers))
                        response = conn.getresponse()
                        status = response.status
                        body = response.read()
                        signature = response.getheader('X-Response-MAC')
                    finally:
                        conn.close()
                    captured.append((status, body, signature))
                self.send_response(status)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('X-Response-MAC', signature)
                self.end_headers()
                self.wfile.write(body)
        relay = HTTPServer(('127.0.0.1', 0), Relay)
        thread = threading.Thread(target=relay.serve_forever, kwargs={'poll_interval': 0.01})
        thread.start()
        client = dr.Client(relay.server_port, self.reader, 'reader')
        try:
            try:
                current = client.call('GET', '/head')
            except dr.ReleaseError as exc:
                self.fail('LIVE_RESPONSE_POSITIVE: ' + exc.code)
            self.assertEqual(current, {'head': dr.GENESIS}, 'LIVE_RESPONSE_BYTES')
            with self.assertRaisesRegex(dr.ReleaseError, 'TARGET_RESPONSE_AUTH', msg='CROSS_REQUEST_REPLAY'):
                client.call('GET', '/head')
            self.assertEqual(client.call('GET', '/head'), current, 'FRESH_RESPONSE_AFTER_REPLAY')
            self.assertEqual(len(set(nonces)), 3, 'DISTINCT_REQUEST_NONCES')
            self.assertEqual(captured[0][1], captured[1][1], 'UNCHANGED_RESPONSE_BODY')
        finally:
            relay.shutdown()
            relay.server_close()
            thread.join(timeout=4)
        self.assertEqual(self.counts(), (0, 0), 'REPLAY_TEST_READ_ONLY')

    def test_mac_distinguishes_each_message_field(self):
        original = ['response', 'a'*48, 'GET', '/head', 200, b'{"head":"A"}']
        fields = ['direction', 'nonce', 'method', 'path', 'status', 'body']
        alternatives = ['request', 'b'*48, 'POST', '/documents/other', 409, b'{"head":"B"}']
        signature = dr.wire_mac(self.reader, *original)
        for index, field in enumerate(fields):
            with self.subTest(field=field):
                changed = original.copy()
                changed[index] = alternatives[index]
                self.assertNotEqual(signature, dr.wire_mac(self.reader, *changed), 'MAC_BINDS_' + field)
        self.assertEqual(signature, dr.wire_mac(self.reader, *original), 'MAC_EXACT_REPLAY')


if __name__=='__main__':
    unittest.main(verbosity=2)
