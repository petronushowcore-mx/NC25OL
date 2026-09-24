"""Synthetic exchange contract tests; no live witnesses or publication."""
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(os.environ.get('NC25_LEDGER_ROOT', Path(__file__).resolve().parents[2])).resolve()
sys.path.insert(0, str(ROOT / 'sdk' / 'python'))
import exchange as x


def wire(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(wire(value)).hexdigest().upper()


class ExchangeCases(unittest.TestCase):
    def setUp(self):
        self.raw = json.loads((ROOT/'profiles/document-release/reference-connection.json').read_text(encoding='utf-8'))
        self.d = self.raw['declaration']; self.p = self.raw['profile']
        self.keys = {'reader-a': b'A' * 32, 'reader-b': b'B' * 32}
        self.view = x.export_projection(self.d, self.p)

    def objection(self, author='reader-a'):
        return x.make_objection(self.view, author, 'objection-1', 'SCOPE_QUESTION',
                                'Нужна проверка области действия.', self.keys[author])

    def test_01_export_is_leaf_whitelist_and_hashes_full_source(self):
        d = copy.deepcopy(self.d)
        d['private_note'] = 'SECRET_CANARY'
        d['instance_scope']['private_field'] = 'SECRET_CANARY'
        d['governance']['private_field'] = 'SECRET_CANARY'
        result = x.export_projection(d, self.p)
        self.assertNotIn(b'SECRET_CANARY', wire(result))
        self.assertEqual(set(result['conditions']), {'action_ids','effect_class_ids','target_system_ids',
                'action_target_bindings','effective_from','expires_at'})
        self.assertEqual(result['conditions']['action_target_bindings'], d['instance_scope']['action_target_bindings'])
        self.assertEqual(result['binding']['declaration_hash'], digest(d))
        self.assertEqual(result['binding']['profile_hash'], digest(self.p))
        body = {k:v for k,v in result.items() if k != 'projection_hash'}
        self.assertEqual(result['projection_hash'], digest(body))
        result['conditions']['action_ids'].append('NEW_ACTION')
        self.assertNotIn('NEW_ACTION',d['instance_scope']['action_ids'])

    def test_02_projection_pinning_rejects_rehash_and_old_version(self):
        self.assertEqual(x.read_projection(wire(self.view), self.view), self.view)
        reverse = json.dumps(self.view, ensure_ascii=False, indent=3).encode('utf-8')
        self.assertEqual(x.read_projection(reverse, self.view), self.view)
        for field in self.view['binding']:
            wrong = copy.deepcopy(self.view)
            old = wrong['binding'][field]
            wrong['binding'][field] = ('0' * 64 if field.endswith('_hash') else ('1.9.0' if field.endswith('_version') else old + '-new'))
            wrong['projection_hash'] = digest({k:v for k,v in wrong.items() if k != 'projection_hash'})
            with self.subTest(field=field), self.assertRaises(ValueError):
                x.read_projection(wire(wrong), self.view)
        wrong = copy.deepcopy(self.view)
        wrong['conditions']['expires_at'] = '2028-07-27T00:00:00Z'
        wrong['projection_hash'] = digest({k:v for k,v in wrong.items() if k != 'projection_hash'})
        with self.assertRaises(ValueError): x.read_projection(wire(wrong), self.view)
        invalid_pin = copy.deepcopy(self.view); invalid_pin['projection_hash'] = '0' * 64
        with self.assertRaises(ValueError): x.read_projection(wire(invalid_pin), invalid_pin)

    def test_03_two_reader_authentication_and_tampering(self):
        for author in self.keys:
            obj = self.objection(author)
            got = x.read_objection(wire(obj), self.view, self.keys)
            self.assertEqual(got['objection']['author_id'], author)
            self.assertEqual(got['objection']['text'], 'Нужна проверка области действия.')
        obj = self.objection()
        body = {k:v for k,v in obj.items() if k != 'mac'}
        # Independent writer fixes the byte-domain, not the module's constant.
        mac = hmac.new(self.keys['reader-a'], b'NC25OL-PROJECTION-OBJECTION-v1\x00'+wire(body), hashlib.sha256).hexdigest().upper()
        self.assertEqual(obj['mac'], mac)
        fixed = {**body, 'mac': mac}
        self.assertEqual(x.read_objection(wire(fixed), self.view, self.keys)['objection'], body)
        for field, value in [('author_id','reader-b'), ('text','changed'), ('code','OTHER'), ('objection_id','other')]:
            wrong = copy.deepcopy(obj); wrong[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                x.read_objection(wire(wrong), self.view, self.keys)
        with self.assertRaises(ValueError): x.read_objection(wire(obj), self.view, {'reader-a': b'C'*32})
        with self.assertRaises(ValueError): x.read_objection(wire(obj), self.view, {})
        for key in (b'', b'A'*31):
            with self.assertRaises(ValueError):
                x.make_objection(self.view,'reader-a','id','CODE','text',key)

    def test_04_objection_cannot_migrate_to_another_projection(self):
        obj = self.objection()
        newer = copy.deepcopy(self.d); newer['declaration_version'] = '1.3.0'
        changed = x.export_projection(newer, self.p)
        with self.assertRaises(ValueError): x.read_objection(wire(obj), changed, self.keys)
        for field in ('projection_hash', *self.view['binding']):
            wrong=copy.deepcopy(obj)
            target=wrong if field=='projection_hash' else wrong['binding']
            target[field]=('0'*64 if field.endswith('hash') else ('9.0.0' if field.endswith('version') else target[field]+'-changed'))
            body={k:v for k,v in wrong.items() if k!='mac'}
            wrong['mac']=hmac.new(self.keys['reader-a'],b'NC25OL-PROJECTION-OBJECTION-v1\x00'+wire(body),hashlib.sha256).hexdigest().upper()
            with self.subTest(field=field), self.assertRaisesRegex(ValueError,'^OBJECTION_BINDING_MISMATCH$'):
                x.read_objection(wire(wrong),self.view,self.keys)

    def test_05_types_unknown_fields_and_json_rejected(self):
        obj = self.objection()
        bad_views = []
        for field,value in [('message_type','execution_permit'),('schema_version','2.0.0'),('unexpected',True)]:
            wrong=copy.deepcopy(self.view); wrong[field]=value; bad_views.append(wrong)
        wrong=copy.deepcopy(self.view); wrong['conditions']['action_ids']=[True]; bad_views.append(wrong)
        wrong=copy.deepcopy(self.view); wrong['binding']['extra']='hidden'; bad_views.append(wrong)
        for value in bad_views:
            # Rehash and pin the malformed object too: a pin mismatch must not
            # stand in for the shape/type contract this case claims to test.
            value['projection_hash'] = digest({k:v for k,v in value.items() if k != 'projection_hash'})
            with self.assertRaises(ValueError): x.read_projection(wire(value), value)
        for value in (self.view, {**obj,'message_type':'execution_permit'}, {**obj,'key':'injected'}, {**obj,'text':True}):
            with self.assertRaises(ValueError): x.read_objection(wire(value), self.view, self.keys)
        with self.assertRaises(ValueError): x.read_projection(wire(obj), self.view)

    def test_06_verified_objection_stays_non_executable(self):
        obj=self.objection()
        before=wire((self.view,obj,self.raw))
        first=x.read_objection(wire(obj),self.view,self.keys)
        again=x.read_objection(wire(obj),self.view,self.keys)
        self.assertEqual(first,again)
        self.assertEqual(set(first), {'verdict','executable','objection'})
        self.assertEqual(first['verdict'],'attributed_objection')
        self.assertIs(first['executable'],False)
        self.assertNotIn('mac',first['objection'])
        self.assertEqual(wire((self.view,obj,self.raw)), before)
        first['objection']['binding']['declaration_id']='edited-result'
        self.assertEqual(wire((self.view,obj,self.raw)), before)

    def test_07_profile_binding_is_checked(self):
        for field in ('profile_id','profile_version','profile_hash'):
            wrong=copy.deepcopy(self.d)
            wrong['profile_binding'][field]='0'*64 if field.endswith('hash') else ('9.0.0' if field.endswith('version') else 'other')
            with self.subTest(field=field),self.assertRaises(ValueError): x.export_projection(wrong,self.p)

    def test_08_parser_limits_have_named_failures(self):
        valid=wire(self.view)
        duplicate=valid[:-1]+b',"message_type":"declaration_projection"}'
        cases=[(duplicate,'JSON_DUPLICATE_KEY'),
               (b'{"x":NaN}','JSON_NONFINITE'),
               (b'\xff','JSON_UTF8'),
               (b'['*17+b'"leaf"'+b']'*17,'JSON_DEPTH'),
               (valid+b' '*(65537-len(valid)),'JSON_BYTES'),
               (b'{"x":"\\ud800"}','JSON_STRING'),
               (b'{"x":'+b'1'*5000+b'}','JSON_TYPE'),
               (b'{"x":1.5}','JSON_TYPE')]
        for raw,code in cases:
            with self.subTest(code=code), self.assertRaisesRegex(ValueError,'^'+code+'$'):
                x.read_projection(raw,self.view)
        # Exact byte ceiling accepts legal JSON whitespace; this is not a length
        # imported from the implementation whose regression we want to detect.
        self.assertEqual(x.read_projection(valid+b' '*(65536-len(valid)),self.view),self.view)


if __name__=='__main__': unittest.main(verbosity=2)