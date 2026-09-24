"""Source mutations run on independent copies; no released source is edited."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parent
LEDGER_ROOT=Path(os.environ.get('NC25_LEDGER_ROOT', ROOT.parents[1])).resolve()
CHILD_ENV=os.environ.copy()
CHILD_ENV['NC25_LEDGER_ROOT']=str(LEDGER_ROOT)
SOURCE=ROOT/'document_release.py'
TEST=ROOT/'test_document_release.py'
# Each mutation names one focused case and its expected first refusal/assertion.
CASES=[
 ('stored bytes change', 'test_bytes_and_durable_exact_replay', 'EXACT_BYTES',
  [("(op['document_id'], data))", "(op['document_id'], data + b'changed'))")]),
 ('write credential admits reader', 'test_reader_and_forged_role_cannot_write', 'CREDENTIAL_BOUNDARY',
  [("if not self.authorized(['executor'], raw):", "if not self.authorized(['executor', 'reader'], raw):")]),
 ('exact document binding removed', 'test_substitution_never_reaches_target', 'EXACT_OPERATION_BINDING',
  [("if any(intent.get(k) != v for k, v in expected.items()) or intent.get('resource_claims') != {'document_units': 1}:","if False:")]),
 ('authoritative controls disconnected', 'test_authoritative_refusal_and_manual_review', 'HOLD_DENIES',
  [("# JSON transport values only; hold defensive copies through all later steps.","self.engine._control_resolver = None")]),
 ('preflight omitted for prepared expiry', 'test_prepared_expiry_prevents_post', 'EXPIRED_BEFORE_POST',
  [("result = self.engine.evaluate_intent(row['intent'], row['evidence'], actor_scope='nc25.operator')", "result = {'permit_hash': row['permit_hash'], 'disposition': 'ALLOW'}")]),
 ('preflight omitted for prepared revocation', 'test_prepared_revocation_prevents_post', 'REVOKED_BEFORE_POST',
  [("result = self.engine.evaluate_intent(row['intent'], row['evidence'], actor_scope='nc25.operator')", "result = {'permit_hash': row['permit_hash'], 'disposition': 'ALLOW'}")]),
 ('target exact replay ignored', 'test_lost_response_recovers_one_effect', 'TARGET_PERMIT_REUSE',
  [("if previous is not None:", "if False:")]),
 ('dead ambiguous permit reissued downstream', 'test_ambiguous_expiry_never_redrives', 'DEAD_PERMIT_REDRIVEN',
  [("result = self.engine.evaluate_intent(row['intent'], row['evidence'], actor_scope='nc25.operator')", "result = {'permit_hash': row['permit_hash'], 'disposition': 'ALLOW'}")]),
 ('finalization refusal relabelled success', 'test_expiry_after_effect_is_reconciliation', 'FINALIZATION_EXPIRED',
  [("row['state'], row['reason'] = 'RECONCILIATION_REQUIRED', exc.code", "row['state'], row['reason'] = 'COMMITTED', exc.code")]),
 ('exact local replay wrongly requests fresh permit', 'test_crash_after_local_commit_replays', 'PERMIT_ALREADY_CONSUMED',
  [("self.fault('before_finalize')", "self.engine.evaluate_intent(row['intent'], row['evidence'], actor_scope='nc25.operator')")]),
 ('receipt binding removed', 'test_invalid_receipt_is_not_success', 'RECEIPT_CHECKED',
  [("if (type(downstream) is not dict", "if False and (type(downstream) is not dict")]),
 ('outbox MAC ignored', 'test_outbox_tampering_is_refused', 'OUTBOX_AUTHENTICATED',
  [("if type(stored[0]) is not str or type(stored[1]) is not str or not hmac.compare_digest(self._mac(stored[0]), stored[1]):", "if False:")]),
 ('target head CAS ignored', 'test_target_stale_head_and_key_conflict', 'TARGET_CAS',
  [("if head != op['expected_head']:", "if False:")]),
 ('target idempotency conflict ignored', 'test_target_stale_head_and_key_conflict', 'TARGET_KEY_BINDING',
  [("if previous[0] != digest(op) or json.loads(previous[1])['permit_hash'] != permit_hash:","if False:")]),
 ('target permit reused', 'test_target_stale_head_and_key_conflict', 'TARGET_PERMIT_SINGLE_USE',
  [("permit_hash TEXT NOT NULL UNIQUE", "permit_hash TEXT NOT NULL"),
   ("if db.execute('SELECT 1 FROM receipts WHERE permit_hash=?', (permit_hash,)).fetchone():", "if False:")]),
 ('target rolls back actual publication', 'test_bytes_and_durable_exact_replay', 'NOT_FOUND',
  [("db.execute('UPDATE head SET value=? WHERE singleton=1', (receipt['head'],))", "db.rollback()")]),
 ('ledger recording skipped', 'test_bytes_and_durable_exact_replay', 'ONE_DEBIT',
  [("receipt = self.engine.commit_execution(row['execution'], actor_scope='nc25.executor', route_permit_hash=row['permit_hash'])", "receipt = {}", 2)]),
 ('peer receipt authentication removed', 'test_impostor_receipt_cannot_debit', 'IMPOSTOR_REFUSED',
  [("if (len(response_body) > MAX_BODY or not re.fullmatch(r'[a-f0-9]{64}', supplied)", "if False and (len(response_body) > MAX_BODY or not re.fullmatch(r'[a-f0-9]{64}', supplied)")]),
 ('early header timeout removed', 'test_incomplete_headers_have_read_timeout', 'EARLY_HEADER_TIMEOUT',
  [("sock.settimeout(1)", "sock.settimeout(None)")]),
 ('target deadline removed', 'test_target_expired_request_cannot_create_first_effect', 'TARGET_DEADLINE',
  [("if datetime.fromisoformat(self.clock().replace('Z', '+00:00')) >= datetime.fromisoformat(expires_at.replace('Z', '+00:00')):", "if False:")]),
 ('request MAC ignored', 'test_invalid_request_mac_is_refused', 'REQUEST_MAC_REQUIRED',
  [("return hmac.compare_digest(signature, expected)", "return True")]),
]


# Removing a field changes both real endpoints, preserving wire compatibility.
_MAC_VECTOR = '[direction, nonce, method, path, status, body.hex()]'
_MAC_PARTS = ['direction', 'nonce', 'method', 'path', 'status', 'body.hex()']
for index, field in enumerate(('direction', 'nonce', 'method', 'path', 'status', 'body')):
    changed = '[' + ', '.join(part for i, part in enumerate(_MAC_PARTS) if i != index) + ']'
    CASES.append(('MAC omits ' + field, 'test_mac_distinguishes_each_message_field',
                  'MAC_BINDS_' + field, [(_MAC_VECTOR, changed)]))
CASES.extend([
 ('cross-request response replay accepted', 'test_authentic_response_replay_is_refused', 'CROSS_REQUEST_REPLAY',
  [(_MAC_VECTOR, '[direction, method, path, status, body.hex()]')]),
 ('valid peer response incorrectly refused', 'test_authentic_response_replay_is_refused', 'LIVE_RESPONSE_POSITIVE',
  [("if (len(response_body) > MAX_BODY or not re.fullmatch(r'[a-f0-9]{64}', supplied)",
    "if (True or len(response_body) > MAX_BODY or not re.fullmatch(r'[a-f0-9]{64}', supplied)")]),
])


def outcome(result):
    lines=[line for line in result.stdout.splitlines() if line.startswith('RESULT_JSON:')]
    return json.loads(lines[-1].split(':',1)[1]) if lines else None


def is_expected(result, marker):
    value=outcome(result)
    return bool(result.returncode and value and value['failures'] and marker in value['failures'][0]['exception'])


CHILD = r"""
import json, sys, unittest
class Result(unittest.TextTestResult):
    def __init__(self,*a,**k):
        super().__init__(*a,**k)
        self.ordered=[]
    def addFailure(self,t,e):
        self.ordered.append({'test':t.id(),'exception':str(e[1])})
        super().addFailure(t,e)
    def addError(self,t,e):
        self.ordered.append({'test':t.id(),'exception':str(e[1])})
        super().addError(t,e)
    def addSubTest(self,t,sub,e):
        if e:self.ordered.append({'test':sub.id(),'exception':str(e[1])})
        super().addSubTest(t,sub,e)
suite=unittest.defaultTestLoader.loadTestsFromName(sys.argv[1])
r=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
print('RESULT_JSON:'+json.dumps({'run':r.testsRun,'failures':r.ordered}))
sys.exit(not r.wasSuccessful())
"""


def run(directory, name=None):
    return subprocess.run([sys.executable,'-B','-X','utf8','-c',CHILD,
        'test_document_release'+('.Cases.'+name if name else '')], cwd=directory,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8',timeout=90,env=CHILD_ENV)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', type=Path, required=True,
                        help='Existing output directory outside the Ledger package')
    scratch=parser.parse_args().scratch.resolve()
    if not scratch.is_dir() or scratch == LEDGER_ROOT or LEDGER_ROOT in scratch.parents:
        parser.error('--scratch must exist outside the Ledger package')
    run_root=Path(tempfile.mkdtemp(prefix='document-release-mutations-', dir=scratch))
    CHILD_ENV.update(TEMP=str(run_root), TMP=str(run_root), TMPDIR=str(run_root))
    original=SOURCE.read_bytes()
    baseline=run(ROOT)
    (run_root/'baseline.log').write_text(baseline.stdout,encoding='utf-8')
    if baseline.returncode:
        raise SystemExit('BASELINE_FAILED')
    # Runner positive/negative controls operate on real baseline and failing output below.
    assert not is_expected(baseline,'OK')
    results=[]
    logs=run_root/'mutation-logs'
    logs.mkdir(exist_ok=True)
    for index,(title,case,marker,changes) in enumerate(CASES,1):
        with tempfile.TemporaryDirectory(prefix='mutation-',dir=run_root) as name:
            directory=Path(name)
            modified=original.decode('utf-8-sig')
            for entry in changes:
                before,after=entry[:2]
                expected=entry[2] if len(entry)==3 else 1
                if modified.count(before)!=expected:
                    raise AssertionError('MUTATION_ANCHOR: '+title)
                modified=modified.replace(before,after)
            assert modified.encode('utf-8')!=original
            (directory/'document_release.py').write_text(modified,encoding='utf-8')
            shutil.copyfile(TEST,directory/TEST.name)
            result=run(directory,case)
            (logs/f'{index:02}.log').write_text(result.stdout,encoding='utf-8')
            passed=is_expected(result,marker)
            assert not is_expected(result,'A_MARKER_THAT_DOES_NOT_EXIST')
            results.append({'mutation':title,'case':case,'first_expected':marker,'detected':passed,'observation':outcome(result)})
            print(f'{index:02} {"PASS" if passed else "FAIL"} {title}',flush=True)
    assert SOURCE.read_bytes()==original,'ORIGINAL_CHANGED'
    report={'scope':'focused cases, not a global full-suite first-red claim',
            'baseline':outcome(baseline),'source_sha256':hashlib.sha256(original).hexdigest(),
            'runner_controls':'real clean output rejected; wrong failure marker rejected', 'mutations':results}
    (run_root/'mutation-results.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('REPORT: '+str(run_root/'mutation-results.json'))
    if not all(r['detected'] for r in results): raise SystemExit(1)


if __name__=='__main__':main()
