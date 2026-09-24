"""Executable checks of the synthetic local release example."""
import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path
import tempfile
import unittest

import scenario as s
from nc25_universal_ledger import ContractViolation


def fixture():
    terms = []
    for kind in ('grant_terms', 'consent_terms', 'platform_disclosure'):
        text = 'Synthetic ' + kind + ' only.'
        terms.append({'kind': kind, 'version': '1.0', 'text': text,
                      'reference': {'id': kind, 'version': '1.0', 'sha256': hashlib.sha256(text.encode()).hexdigest()}})
    return json.dumps({'format': 'otcs-registration-preview/v1', 'synthetic': True, 'admitted': False,
                       'project_id': 'synthetic-project', 'public_fields': {'/project/id': 'synthetic-project'},
                       'terms': terms}).encode()


class Cases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.session = s.LocalSession(self.path / 'run', fixture())
        self.addCleanup(self.session.close)

    def test_01_preview_is_not_admission(self):
        raw = json.loads(fixture())
        raw['admitted'] = True
        with self.assertRaisesRegex(ValueError, '^PREVIEW_NOT_ADMISSION$'):
            s.check_preview(json.dumps(raw).encode())
        raw['admitted'] = False
        raw['terms'][0]['text'] += 'changed'
        with self.assertRaisesRegex(ValueError, '^PREVIEW_TERMS_BINDING$'):
            s.check_preview(json.dumps(raw).encode())
        self.assertEqual(s.check_preview(fixture())['admitted'], False)

    def test_02_preview_cannot_activate(self):
        a = self.session
        a.start()
        with self.assertRaises(ContractViolation) as found:
            a.submit()
        self.assertEqual(getattr(found.exception, 'code', None), 'DECLARATION_NOT_ACTIVE')
        self.assertEqual(a.target_counts(), (0, 0))
        a.activate()
        self.assertEqual(a.submit()['state'], 'COMMITTED')

    def test_03_complete_flow_and_exact_bytes(self):
        result = s.run(fixture(), self.path / 'complete')
        self.assertFalse(result['otcs_admitted'])
        self.assertEqual(result['initial_registry']['status'], 'DRAFT')
        self.assertEqual(result['document_sha256'], hashlib.sha256(fixture()).hexdigest())
        self.assertEqual(result['structural_remaining'], 360)
        self.assertEqual((result['target_documents'], result['target_receipts']), (1, 1))
        self.assertFalse(result['observation']['objection']['executable'])
        self.assertEqual(result['observation']['projection']['binding'], result['observation']['objection']['objection']['binding'])
        with s.dr.database(self.path / 'complete' / 'target.sqlite') as db:
            self.assertEqual(db.execute('SELECT body FROM documents').fetchone()[0], fixture())

    def test_04_changed_bytes_are_not_approved(self):
        a = self.session
        a.activate()
        a.start()
        a.op['content_base64'] = base64.b64encode(b'other document').decode()
        a.intent['payload_hash'] = s.dr.payload_hash(a.op)
        refused = a.submit()
        self.assertEqual(refused['operator_result']['disposition'], 'REFUSAL')
        self.assertEqual(a.target_counts(), (0, 0))
        self.assertEqual(a.engine.structural_remaining, 400)

    def test_05_version_substitution_is_refused(self):
        a = self.session
        a.activate()
        a.start()
        changed = copy.deepcopy(a.intent)
        changed['binding']['declaration_version'] = '9.0.0'
        refusal = a.gateway.submit(a.op, changed, a.evidence)
        self.assertEqual(refusal['status'], 'NOT_ADMISSIBLE')
        self.assertEqual(refusal['operator_result']['disposition'], 'REFUSAL')
        self.assertEqual(a.target_counts(), (0, 0))
        # The rejected request consumed its idempotency key. A distinct valid
        # request is the control; changing the old request must not reuse it.
        with self.assertRaises(ContractViolation) as found:
            a.submit()
        self.assertEqual(found.exception.code, 'IDEMPOTENCY_CONFLICT')
        a.op['idempotency_key'] = 'valid-after-version-refusal'
        a.intent['idempotency_key'] = a.op['idempotency_key']
        a.intent['intent_id'] = 'valid-after-version-refusal'
        a.evidence['intent_id'] = a.intent['intent_id']
        self.assertEqual(a.submit()['state'], 'COMMITTED')

    def test_06_lost_response_recovers_once(self):
        a = self.session
        a.activate()
        a.start(drop_response=True)
        with self.assertRaises(s.dr.http.client.RemoteDisconnected):
            a.submit()
        self.assertEqual(a.gateway.record(a.op['idempotency_key'])['state'], 'AMBIGUOUS')
        self.assertEqual(a.target_counts(), (1, 1))
        a.reopen()
        first = a.gateway.recover(a.op['idempotency_key'])
        self.assertEqual(first['state'], 'COMMITTED')
        a.reopen()
        self.assertEqual(a.gateway.recover(a.op['idempotency_key']), first)
        self.assertEqual(a.target_counts(), (1, 1))
        self.assertEqual(a.engine.structural_remaining, 360)

    def test_07_revocation_before_effect(self):
        a = self.session
        a.activate()
        a.start(fault=lambda p: a.revoke() if p == 'after_prepare' else None)
        result = a.submit()
        self.assertEqual((result['state'], result['reason']), ('NOT_EXECUTED', 'AUTHORITY_REVOKED'))
        self.assertEqual(a.target_counts(), (0, 0))
        self.assertEqual(a.engine.structural_remaining, 400)

    def test_08_expiry_after_effect_requires_reconciliation(self):
        a = self.session
        a.activate()
        a.start(fault=lambda p: a.clock.advance(seconds=301) if p == 'before_finalize' else None)
        result = a.submit()
        self.assertEqual(result['state'], 'RECONCILIATION_REQUIRED')
        self.assertEqual(a.target_counts(), (1, 1))
        self.assertEqual(a.engine.structural_remaining, 400)

    def test_09_crash_after_ledger_commit(self):
        a = self.session
        a.activate()
        def fault(point):
            if point == 'after_ledger':
                raise RuntimeError('SIMULATED_STOP')
        a.start(fault=fault)
        with self.assertRaisesRegex(RuntimeError, '^SIMULATED_STOP$'):
            a.submit()
        self.assertEqual(a.engine.structural_remaining, 360)
        a.reopen()
        a.clock.advance(seconds=301)
        self.assertEqual(a.gateway.recover(a.op['idempotency_key'])['state'], 'COMMITTED')
        self.assertEqual(a.target_counts(), (1, 1))
        self.assertEqual(a.engine.structural_remaining, 360)

    def test_10_objection_foreign_version_with_valid_mac(self):
        a = self.session
        a.activate()
        pin = s.x.export_projection(a.declaration, a.profile)
        original = s.x.make_objection(pin, 'local-reader', 'o1', 'SCOPE', 'Review conditions.', a.author_keys['local-reader'])
        for field in ('projection_hash', 'declaration_version'):
            changed = copy.deepcopy(original)
            if field == 'projection_hash':
                changed[field] = 'A' * 64
            else:
                changed['binding'][field] = '9.0.0'
            body = {k: v for k, v in changed.items() if k != 'mac'}
            changed['mac'] = hmac.new(a.author_keys['local-reader'], b'NC25OL-PROJECTION-OBJECTION-v1\x00' + s.canonical_json(body), hashlib.sha256).hexdigest().upper()
            with self.assertRaisesRegex(ValueError, '^OBJECTION_BINDING_MISMATCH$'):
                s.x.read_objection(s.canonical_json(changed), pin, a.author_keys)
        self.assertFalse(s.x.read_objection(s.canonical_json(original), pin, a.author_keys)['executable'])

    def test_11_observation_preserves_state_and_detection(self):
        a = self.session
        a.activate()
        before = a.snapshot()
        a.observe()
        self.assertEqual(a.snapshot(), before)
        original = s.x.read_objection
        def changes_database(*args):
            result = original(*args)
            with s.dr.database(a.path / 'ledger.sqlite') as db:
                db.execute('PRAGMA user_version=17')
            return result
        s.x.read_objection = changes_database
        try:
            with self.assertRaisesRegex(RuntimeError, '^OBSERVATION_CHANGED_LEDGER$'):
                a.observe()
        finally:
            s.x.read_objection = original

    def test_12_observation_remains_bound_to_engine(self):
        a = self.session
        a.activate()
        original = a.observe()
        self.assertEqual(original['projection']['binding']['declaration_hash'], a.engine.declaration_hash)
        expires = a.declaration['expires_at']
        a.declaration['expires_at'] = '2027-07-28T00:00:00Z'
        with self.assertRaisesRegex(ValueError, '^PROJECTION_PIN_MISMATCH$'):
            a.observe()
        a.declaration['expires_at'] = expires
        self.assertEqual(a.observe()['projection'], original['projection'])

    def test_13_observation_checks_engine_binding(self):
        a = self.session
        a.activate()
        self.assertFalse(a.observe()['objection']['executable'])
        original = a.engine
        changed = copy.deepcopy(a.declaration)
        changed['expires_at'] = '2027-07-28T00:00:00Z'
        # A valid other engine, not corruption that its integrity check rejects first.
        a.engine = s.UniversalConnectionLedger(a.profile, changed, a.signing_key, clock=a.clock)
        try:
            with self.assertRaisesRegex(ValueError, '^PROJECTION_ENGINE_MISMATCH$'):
                a.observe()
        finally:
            a.engine = original
        self.assertFalse(a.observe()['objection']['executable'])


if __name__ == '__main__':
    unittest.main()
