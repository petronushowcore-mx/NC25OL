"""One synthetic document release through the real local Ledger and gateway."""
from __future__ import annotations

import base64
import copy
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

ROOT = Path(os.environ.get('NC25_LEDGER_ROOT', Path(__file__).resolve().parents[2])).resolve()
sys.path.insert(0, str(ROOT / 'examples' / 'local_release'))
from scenario import DocumentSession
from nc25_universal_ledger import ContractViolation

DOCUMENT = b'Synthetic document for the local Ledger quickstart.\n'


def require(condition, marker):
    if not condition:
        raise RuntimeError(marker)


def run():
    with TemporaryDirectory() as scratch:
        session = DocumentSession(Path(scratch) / 'release', DOCUMENT,
                                  document_id='quickstart-document', idempotency_key='quickstart-1')
        try:
            session.start()
            session.activate()
            allowed = session.engine.evaluate_intent(session.intent, session.evidence,
                                                      actor_scope='nc25.operator')
            require(allowed['disposition'] == 'ALLOW' and allowed['channel'] == 'OUTPUT'
                    and allowed['message_code'] == 'EXECUTION_AUTHORIZED'
                    and isinstance(allowed['permit_hash'], str) and len(allowed['permit_hash']) == 64,
                    'QUICKSTART_ADMISSION')

            first = session.submit()
            require(first['state'] == 'COMMITTED' and first['permit_hash'] == allowed['permit_hash'],
                    'QUICKSTART_COMMIT')
            target = session.read_client.call('GET', '/documents/quickstart-document')
            require(target is not None and base64.b64decode(target['content_base64'], validate=True) == DOCUMENT
                    and session.target_counts() == (1, 1), 'QUICKSTART_TARGET_BYTES')

            receipt = copy.deepcopy(first['ledger_receipt'])
            events_before = session.engine.ledger.events_copy()
            session.reopen()
            replay = session.gateway.recover(session.op['idempotency_key'])
            require(replay['state'] == 'COMMITTED' and replay['ledger_receipt'] == receipt
                    and session.engine.ledger.events_copy() == events_before
                    and session.target_counts() == (1, 1), 'QUICKSTART_EXACT_REPLAY')

            try:
                session.engine.evaluate_intent(session.intent, session.evidence, actor_scope='nc25.operator')
            except ContractViolation as exc:
                require(exc.code == 'PERMIT_ALREADY_CONSUMED', 'QUICKSTART_CONSUMED_CODE')
                consumed_code = exc.code
            else:
                raise RuntimeError('QUICKSTART_CONSUMED_NOT_REFUSED')

            unknown_intent = copy.deepcopy(session.intent)
            unknown_intent.update(intent_id='quickstart-unknown-intent',
                                  idempotency_key='quickstart-unknown-key',
                                  authority_grant_id='quickstart-unknown-grant')
            unknown_evidence = copy.deepcopy(session.evidence)
            unknown_evidence['intent_id'] = unknown_intent['intent_id']
            events_before_unknown = len(session.engine.ledger.events_copy())
            refused = session.engine.evaluate_intent(unknown_intent, unknown_evidence,
                                                     actor_scope='nc25.operator')
            require(len(session.engine.ledger.events_copy()) == events_before_unknown + 1,
                    'UNKNOWN_AUTHORITY_DECISION_MISSING')
            decision = session.engine.architect_decision(refused['request_hash'], actor_scope='nc25.architect')
            require(refused['disposition'] == 'REFUSAL' and refused['permit_hash'] is None
                    and decision['message_code'] == 'AUTHORITY_UNKNOWN'
                    and session.target_counts() == (1, 1), 'QUICKSTART_UNKNOWN_AUTHORITY')
            require(session.engine.ledger.verify(), 'QUICKSTART_LEDGER_CHAIN')

            return [
                f"ADMISSION={allowed['disposition']} {allowed['message_code']} permit=issued",
                f"RELEASE={first['state']} bytes=exact target=1/1",
                'RECOVERY=EXACT_REPLAY events=unchanged target=1/1',
                f'REUSE={consumed_code}',
                f"UNKNOWN_AUTHORITY={refused['disposition']} {decision['message_code']}",
                'LEDGER_CHAIN=verified',
            ]
        finally:
            session.close()


if __name__ == '__main__':
    print('\n'.join(run()))
