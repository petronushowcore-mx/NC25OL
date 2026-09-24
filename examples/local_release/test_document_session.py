"""Generic document sessions preserve exact bytes under synthetic local authority."""
import base64
from pathlib import Path
import tempfile
import unittest

import scenario as s
from nc25_universal_ledger import ContractViolation


class Cases(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)

    def session(self, name, body, **options):
        session = s.DocumentSession(self.path/name, body, **options)
        self.addCleanup(session.close)
        return session

    def test_01_exact_binary_payload_and_identifiers_start_inactive(self):
        body = b'PK\x03\x04\x00\xffbinary document\x00'
        session = self.session('custom', body, document_id='source.zip', idempotency_key='source-release-7')
        self.assertEqual(s.dr.operation(session.op), body)
        self.assertEqual(session.op['document_id'], 'source.zip')
        self.assertEqual(session.op['idempotency_key'], 'source-release-7')
        self.assertEqual(session.intent['idempotency_key'], 'source-release-7')
        self.assertEqual(session.intent['payload_hash'], s.dr.payload_hash(session.op))
        self.assertEqual(session.approved_hash, session.intent['payload_hash'])
        self.assertEqual(session.engine.registry_record(session.declaration['connector']['connector_id'],
                         actor_scope='nc25.architect')['status'], 'DRAFT')
        self.assertEqual(session.engine.structural_remaining, 400)
        self.assertIsNone(session.process)
        default = self.session('default', body)
        self.assertEqual(default.op['document_id'], 'document')
        self.assertEqual(default.op['idempotency_key'], 'document-release-1')

    def test_02_invalid_operation_is_refused_before_storage(self):
        # Literal published bound: importing the implementation constant would
        # let a raised limit move this negative fixture along with the defect.
        cases = [(b'x' * 2097153, {}, 'OPERATION_CONTENT'),
                 (b'', {}, 'OPERATION_CONTENT'),
                 (bytearray(b'x'), {}, 'OPERATION_CONTENT'),
                 ('not bytes', {}, 'OPERATION_CONTENT'),
                 (b'valid', {'document_id': '../outside'}, 'OPERATION_IDENTIFIER'),
                 (b'valid', {'idempotency_key': 'bad key'}, 'OPERATION_IDENTIFIER')]
        for index, (body, options, code) in enumerate(cases):
            path = self.path/str(index)
            with self.subTest(index=index), self.assertRaisesRegex(s.dr.ReleaseError, '^'+code+'$'):
                s.DocumentSession(path, body, **options)
            self.assertFalse(path.exists())

    def test_03_two_mib_document_crosses_gateway_and_replays_once(self):
        # This exact-boundary payload also exceeds the former 512 KiB ceiling.
        body = bytes(range(256)) * 8192
        session = self.session('large', body, document_id='large-source.zip', idempotency_key='large-source-1')
        session.start()
        with self.assertRaises(ContractViolation) as refusal:
            session.submit()
        self.assertEqual(refusal.exception.code, 'DECLARATION_NOT_ACTIVE')
        self.assertEqual(session.target_counts(), (0, 0))
        session.activate()
        first = session.submit()
        self.assertEqual(first['state'], 'COMMITTED')
        received = session.read_client.call('GET', '/documents/large-source.zip')
        self.assertEqual(base64.b64decode(received['content_base64'], validate=True), body)
        session.reopen()
        self.assertEqual(session.gateway.recover('large-source-1'), first)
        self.assertEqual(session.target_counts(), (1, 1))
        self.assertEqual(session.engine.structural_remaining, 360)


if __name__ == '__main__': unittest.main(verbosity=2)
