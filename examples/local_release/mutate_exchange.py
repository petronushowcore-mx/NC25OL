"""Mutate local copies; require the named first failing unittest, not just exit 1."""
from pathlib import Path
import argparse, json, os, shutil, subprocess, sys, tempfile, unittest

ROOT=Path(__file__).resolve().parent
LEDGER_ROOT=Path(os.environ.get('NC25_LEDGER_ROOT', ROOT.parents[1])).resolve()
CHILD_ENV=os.environ.copy()
CHILD_ENV['NC25_LEDGER_ROOT']=str(LEDGER_ROOT)

def child():
    import test_exchange
    class Result(unittest.TestResult):
        def __init__(self): super().__init__(); self.first=None
        def addFailure(self,test,err):
            if self.first is None:self.first=test.id()
            super().addFailure(test,err)
        def addError(self,test,err):
            if self.first is None:self.first=test.id()
            super().addError(test,err)
        def addSubTest(self,test,subtest,err):
            if err is not None and self.first is None:self.first=test.id()
            super().addSubTest(test,subtest,err)
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(test_exchange.ExchangeCases)
    result=Result(); result.failfast=True; suite.run(result)
    print(json.dumps({'ok':result.wasSuccessful(),'tests':result.testsRun,'first':result.first,
                     'details':[text for _,text in result.failures+result.errors]}))
    return 0 if result.wasSuccessful() else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', type=Path, required=True,
                        help='Existing output directory outside the Ledger package')
    scratch=parser.parse_args().scratch.resolve()
    if not scratch.is_dir() or scratch == LEDGER_ROOT or LEDGER_ROOT in scratch.parents:
        parser.error('--scratch must exist outside the Ledger package')
    run=Path(tempfile.mkdtemp(prefix='exchange-mutations-',dir=scratch))
    CHILD_ENV.update(TEMP=str(run), TMP=str(run), TMPDIR=str(run))
    source=(ROOT/'exchange.py').read_text(encoding='utf-8')
    tests=(ROOT/'test_exchange.py').read_text(encoding='utf-8')
    cases=[
      ('full_source_hash','test_01_export_is_leaf_whitelist_and_hashes_full_source',[
        ('full_declaration_hash = sha256_hex(declaration)','full_declaration_hash = sha256_hex(declaration["instance_scope"])')]),
      ('leaf_disclosure','test_01_export_is_leaf_whitelist_and_hashes_full_source',[
        ('"action_target_bindings", "effective_from", "expires_at"}', '"action_target_bindings", "effective_from", "expires_at", "private_note"}'),
        ('        result["projection_hash"] = sha256_hex(result)','        result["conditions"]["private_note"] = declaration.get("private_note", "benign")\n        result["projection_hash"] = sha256_hex(result)')]),
      ('copy_alias','test_01_export_is_leaf_whitelist_and_hashes_full_source',[
        ('    return list(value)','    return value')]),
      ('pin_comparison','test_02_projection_pinning_rejects_rehash_and_old_version',[
        ('if canonical_json(actual) != canonical_json(expected):','if False:')]),
      ('mac_verification','test_03_two_reader_authentication_and_tampering',[
        ('if not hmac.compare_digest(actual["mac"], _mac(body, authors[actual["author_id"]])):', 'if False:')]),
      ('mac_domain','test_03_two_reader_authentication_and_tampering',[
        ('DOMAIN = b"NC25OL-PROJECTION-OBJECTION-v1\\x00"','DOMAIN = b""')]),
      ('foreign_projection_hash','test_04_objection_cannot_migrate_to_another_projection',[
        ('            or actual["projection_hash"] != expected["projection_hash"]','')]),
      ('foreign_binding','test_04_objection_cannot_migrate_to_another_projection',[
        ('if (actual["binding"] != expected["binding"]\n            or actual["projection_hash"] != expected["projection_hash"]):','if actual["projection_hash"] != expected["projection_hash"]:')]),
      ('unknown_fields','test_05_types_unknown_fields_and_json_rejected',[
        ('type(value) is not dict or set(value) != fields','type(value) is not dict or not fields.issubset(value)')]),
      ('executable_objection','test_06_verified_objection_stays_non_executable',[
        ('"executable": False','"executable": True')]),
      ('source_profile_mismatch','test_07_profile_binding_is_checked',[
        ('            _fail("SOURCE_PROFILE_MISMATCH")','            pass')]),
      ('numeric_diagnostic','test_08_parser_limits_have_named_failures',[
        ('                           parse_int=lambda _: _fail("JSON_TYPE"),\n','')]),
      ('duplicate_keys','test_08_parser_limits_have_named_failures',[
        ('        if key in result:','        if False:')]),
      ('byte_ceiling','test_08_parser_limits_have_named_failures',[
        ('MAX_BYTES = 65536','MAX_BYTES = 65537')]),
      ('valid_input_overrefusal','test_02_projection_pinning_rejects_rehash_and_old_version',[
        ('if canonical_json(actual) != canonical_json(expected):','if True:')]),
    ]
    def execute(name,code,test_text=tests):
        folder=run/name;folder.mkdir()
        (folder/'exchange.py').write_text(code,encoding='utf-8',newline='\n')
        (folder/'test_exchange.py').write_text(test_text,encoding='utf-8',newline='\n')
        shutil.copy2(__file__,folder/'mutate_exchange.py')
        cp=subprocess.run([sys.executable,'-B',str(folder/'mutate_exchange.py'),'--child'],cwd=folder,
                          capture_output=True,text=True,encoding='utf-8',timeout=30,env=CHILD_ENV)
        (folder/'stdout.txt').write_text(cp.stdout,encoding='utf-8');(folder/'stderr.txt').write_text(cp.stderr,encoding='utf-8')
        data=json.loads(cp.stdout);data['exit']=cp.returncode
        return data
    baseline=execute('baseline',source)
    if not (baseline['ok'] and baseline['tests']==8 and baseline['exit']==0):raise RuntimeError(baseline)
    results=[]
    for name,expected,edits in cases:
        code=source
        for old,new in edits:
            if code.count(old)!=1:raise RuntimeError(('ANCHOR',name,old,code.count(old)))
            code=code.replace(old,new)
        data=execute(name,code)
        first='test_exchange.ExchangeCases.'+expected
        passed=data['exit']==1 and data['ok'] is False and data['first']==first
        results.append({'mutation':name,'expected_first':first,'observed_first':data['first'],'passed':passed})
        print(name,passed,flush=True)
    summary={'baseline':baseline,'mutations':results,
             'scope':'first failing test in whole ordered local suite; not every assertion independently mutated'}
    (run/'result.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    ok=all(v['passed'] for v in results)
    print(json.dumps({'ok':ok,'mutations':len(results),'report':str(run/'result.json')}))
    return 0 if ok else 1

if __name__=='__main__':raise SystemExit(child() if '--child' in sys.argv else main())