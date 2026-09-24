"""Local document release experiment; see README.md for the trust boundary."""
from __future__ import annotations
import base64
import copy
from contextlib import closing, contextmanager
import hashlib
import hmac
import http.client
import json
import re
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer


@contextmanager
def database(path):
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            yield connection


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(encode(value).encode('ascii')).hexdigest().upper()


GENESIS = digest({'documents': []})
MAX_BODY = 4 * 1024 * 1024  # Wire body ceiling; decoded documents are limited to half.


class ReleaseError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def operation(value):
    fields = {'document_id', 'content_base64', 'target_system_id', 'expected_head', 'idempotency_key'}
    if type(value) is not dict or set(value) != fields:
        raise ReleaseError('OPERATION_FIELDS')
    for name in ('document_id', 'target_system_id', 'idempotency_key'):
        if type(value[name]) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value[name]):
            raise ReleaseError('OPERATION_IDENTIFIER')
    if type(value['expected_head']) is not str or not re.fullmatch(r'[A-F0-9]{64}', value['expected_head']):
        raise ReleaseError('OPERATION_HEAD')
    try:
        data = base64.b64decode(value['content_base64'], validate=True)
    except (ValueError, TypeError):
        raise ReleaseError('OPERATION_CONTENT') from None
    if not data or len(data) > MAX_BODY // 2 or base64.b64encode(data).decode('ascii') != value['content_base64']:
        raise ReleaseError('OPERATION_CONTENT')
    return data


def payload_hash(op):
    # The name as well as the exact bytes is part of the released object.
    return digest({k: op[k] for k in ('document_id', 'content_base64')})


class Target:
    """One SQLite transaction owns bytes, receipt, uniqueness and target head."""
    def __init__(self, path, target_id, clock):
        self.path, self.target_id, self.clock = path, target_id, clock
        with database(path) as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS documents (
                    document_id TEXT PRIMARY KEY COLLATE BINARY, body BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS receipts (
                    request_key TEXT PRIMARY KEY COLLATE BINARY,
                    operation_hash TEXT NOT NULL, receipt TEXT NOT NULL, permit_hash TEXT NOT NULL UNIQUE);
                CREATE TABLE IF NOT EXISTS head (singleton INTEGER PRIMARY KEY CHECK(singleton=1), value TEXT NOT NULL);
            ''')
            db.execute('INSERT OR IGNORE INTO head VALUES (1,?)', (GENESIS,))

    def read(self, document_id=None):
        with database(self.path) as db:
            if document_id is None:
                return {'head': db.execute('SELECT value FROM head WHERE singleton=1').fetchone()[0]}
            row = db.execute('SELECT body FROM documents WHERE document_id=?', (document_id,)).fetchone()
            return None if row is None else {'content_base64': base64.b64encode(row[0]).decode('ascii')}

    def append(self, op, permit_hash, expires_at):
        data = operation(op)
        if type(permit_hash) is not str or not re.fullmatch(r'[A-F0-9]{64}', permit_hash):
            raise ReleaseError('TARGET_PERMIT_HASH')
        if op['target_system_id'] != self.target_id:
            raise ReleaseError('TARGET_MISMATCH')
        with database(self.path) as db:
            db.execute('BEGIN IMMEDIATE')
            previous = db.execute('SELECT operation_hash,receipt FROM receipts WHERE request_key=?', (op['idempotency_key'],)).fetchone()
            if previous is not None:
                if previous[0] != digest(op) or json.loads(previous[1])['permit_hash'] != permit_hash:
                    raise ReleaseError('TARGET_IDEMPOTENCY_CONFLICT')
                return json.loads(previous[1])
            if datetime.fromisoformat(self.clock().replace('Z', '+00:00')) >= datetime.fromisoformat(expires_at.replace('Z', '+00:00')):
                raise ReleaseError('TARGET_REQUEST_EXPIRED')
            if db.execute('SELECT 1 FROM receipts WHERE permit_hash=?', (permit_hash,)).fetchone():
                raise ReleaseError('TARGET_PERMIT_REUSE')
            head = db.execute('SELECT value FROM head WHERE singleton=1').fetchone()[0]
            if head != op['expected_head']:
                raise ReleaseError('STALE_HEAD')
            if db.execute('SELECT 1 FROM documents WHERE document_id=?', (op['document_id'],)).fetchone():
                raise ReleaseError('DOCUMENT_EXISTS')
            seed = {'operation_hash': digest(op), 'previous_head': head, 'permit_hash': permit_hash,
                    'payload_hash': payload_hash(op), 'effective_at': self.clock(),
                    'target_system_id': self.target_id, 'idempotency_key': op['idempotency_key']}
            receipt = {**seed, 'head': digest(seed)}
            db.execute('INSERT INTO documents VALUES (?,?)', (op['document_id'], data))
            db.execute('INSERT INTO receipts VALUES (?,?,?,?)', (op['idempotency_key'], digest(op), encode(receipt), permit_hash))
            db.execute('UPDATE head SET value=? WHERE singleton=1', (receipt['head'],))
            return receipt


def wire_mac(key, direction, nonce, method, path, status, body):
    message = encode([direction, nonce, method, path, status, body.hex()]).encode('ascii')
    return hmac.new(key.encode('utf-8'), message, hashlib.sha256).hexdigest()


class Client:
    def __init__(self, port, credential, identity='executor'):
        self.port, self.credential, self.identity = port, credential, identity

    def call(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=3)
        raw = b'' if body is None else encode(body).encode('ascii')
        nonce = secrets.token_hex(24)
        auth = {'X-Identity': self.identity, 'X-Nonce': nonce, 'Content-Type': 'application/json',
                'X-Request-MAC': wire_mac(self.credential, 'request', nonce, method, path, 0, raw)}
        auth.update(headers or {})
        try:
            conn.request(method, path, body=raw, headers=auth)
            response = conn.getresponse()
            response_body = response.read(MAX_BODY + 1)
            expected = wire_mac(self.credential, 'response', nonce, method, path, response.status, response_body)
            supplied = response.getheader('X-Response-MAC', '')
            if (len(response_body) > MAX_BODY or not re.fullmatch(r'[a-f0-9]{64}', supplied)
                    or not hmac.compare_digest(supplied, expected)):
                raise ReleaseError('TARGET_RESPONSE_AUTH')
            value = json.loads(response_body)
            if response.status != 200:
                raise ReleaseError(value['error'])
            return value
        finally:
            conn.close()

    def append(self, op, permit_hash, expires_at):
        return self.call('POST', '/append', {'operation': op, 'permit_hash': permit_hash, 'expires_at': expires_at})


class Gateway:
    """Serialized single-worker lab adapter, not a distributed transaction."""
    def __init__(self, engine, client, path, outbox_key, fault=lambda point: None):
        self.engine, self.client, self.path, self.key, self.fault = engine, client, path, outbox_key, fault
        self.lock = threading.RLock()
        with database(path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS outbox (request_key TEXT PRIMARY KEY COLLATE BINARY, body TEXT NOT NULL, mac TEXT NOT NULL)')

    def _mac(self, text):
        return hmac.new(self.key, text.encode('ascii'), hashlib.sha256).hexdigest()

    def _save(self, row):
        text = encode(row)
        with database(self.path) as db:
            db.execute('INSERT INTO outbox VALUES (?,?,?) ON CONFLICT(request_key) DO UPDATE SET body=excluded.body, mac=excluded.mac',
                       (row['op']['idempotency_key'], text, self._mac(text)))

    def record(self, key):
        with database(self.path) as db:
            stored = db.execute('SELECT body,mac FROM outbox WHERE request_key=?', (key,)).fetchone()
        if stored is None:
            return None
        if type(stored[0]) is not str or type(stored[1]) is not str or not hmac.compare_digest(self._mac(stored[0]), stored[1]):
            raise ReleaseError('OUTBOX_AUTHENTICATION')
        row = json.loads(stored[0])
        if row['op']['idempotency_key'] != key:
            raise ReleaseError('OUTBOX_KEY_BINDING')
        return row

    @staticmethod
    def _bind(op, intent):
        operation(op)
        expected = {'action_id': 'DOCUMENT_RELEASE', 'idempotency_key': op['idempotency_key'],
                    'target_system_id': op['target_system_id'], 'payload_hash': payload_hash(op),
                    'state_anchor_hash': op['expected_head'], 'history_summary_hash': op['expected_head']}
        if any(intent.get(k) != v for k, v in expected.items()) or intent.get('resource_claims') != {'document_units': 1}:
            raise ReleaseError('DOCUMENT_INTENT_BINDING')

    def submit(self, op, intent, evidence):
        with self.lock:
            # JSON transport values only; hold defensive copies through all later steps.
            op, intent, evidence = copy.deepcopy((op, intent, evidence))
            self._bind(op, intent)
            submitted = digest({'op': op, 'intent': intent, 'evidence': evidence})
            row = self.record(op['idempotency_key'])
            if row:
                if row['submitted'] != submitted:
                    raise ReleaseError('GATEWAY_IDEMPOTENCY_CONFLICT')
                return self._advance(row)
            result = self.engine.evaluate_intent(intent, evidence, actor_scope='nc25.operator')
            if result['disposition'] != 'ALLOW':
                return {'status': 'NOT_ADMISSIBLE', 'operator_result': result}
            row = {'op': op, 'intent': intent, 'evidence': evidence, 'submitted': submitted,
                   'permit_hash': result['permit_hash'], 'expires_at': result['expires_at'], 'state': 'PREPARED'}
            self._save(row)
            self.fault('after_prepare')
            return self._advance(row)

    def recover(self, key):
        with self.lock:
            row = self.record(key)
            if row is None:
                raise ReleaseError('OUTBOX_MISSING')
            return self._advance(row)

    def _advance(self, row):
        self._bind(row['op'], row['intent'])
        state = row['state']
        if state in {'NOT_EXECUTED', 'RECONCILIATION_REQUIRED'}:
            return row
        if state == 'COMMITTED':
            # Verify the persisted ledger's exact replay, not just the outbox label.
            receipt = self.engine.commit_execution(row['execution'], actor_scope='nc25.executor', route_permit_hash=row['permit_hash'])
            if receipt != row['ledger_receipt']:
                raise ReleaseError('LEDGER_RECEIPT_BINDING')
            return row
        if state in {'PREPARED', 'CALLING', 'AMBIGUOUS'}:
            try:
                result = self.engine.evaluate_intent(row['intent'], row['evidence'], actor_scope='nc25.operator')
                if result.get('permit_hash') != row['permit_hash'] or result.get('disposition') != 'ALLOW':
                    raise ReleaseError('PERMIT_BINDING')
            except Exception as exc:
                # No success inference. Integrity failures propagate with their original identity.
                from nc25_universal_ledger import ContractViolation, IntegrityViolation
                if isinstance(exc, IntegrityViolation) or not isinstance(exc, (ContractViolation, ReleaseError)):
                    raise
                row['state'] = 'NOT_EXECUTED' if state == 'PREPARED' else 'RECONCILIATION_REQUIRED'
                row['reason'] = exc.code
                self._save(row)
                return row
            row['state'] = 'CALLING'
            self._save(row)
            try:
                downstream = self.client.append(row['op'], row['permit_hash'], row['expires_at'])
                self.fault('after_target')
            except Exception as exc:
                # Even HTTP error responses can have an uncertain proxy origin.
                row['state'] = 'AMBIGUOUS'
                row['reason'] = getattr(exc, 'code', type(exc).__name__)
                self._save(row)
                raise
            expected = {'operation_hash': digest(row['op']), 'previous_head': row['op']['expected_head'], 'permit_hash': row['permit_hash'],
                        'payload_hash': payload_hash(row['op']), 'target_system_id': row['op']['target_system_id'],
                        'idempotency_key': row['op']['idempotency_key']}
            if (type(downstream) is not dict or set(downstream) != set(expected) | {'effective_at', 'head'}
                    or any(downstream.get(k) != v for k, v in expected.items())
                    or downstream['head'] != digest({k: v for k, v in downstream.items() if k != 'head'})):
                row['state'], row['reason'] = 'RECONCILIATION_REQUIRED', 'TARGET_RECEIPT_BINDING'
                self._save(row)
                return row
            row['downstream'] = downstream
            row['execution'] = {'message_type': 'execution_request', 'permit_hash': row['permit_hash'],
                'connector_id': row['intent']['connector_id'], 'binding': row['intent']['binding'],
                'state_anchor_hash': row['op']['expected_head'], 'outcome': 'COMMITTED',
                'downstream_receipt_hash': digest(downstream), 'committed_at': downstream['effective_at']}
            row['state'] = 'TARGET_COMMITTED'
            self._save(row)
        if row['state'] != 'TARGET_COMMITTED':
            raise ReleaseError('OUTBOX_STATE')
        self.fault('before_finalize')
        try:
            receipt = self.engine.commit_execution(row['execution'], actor_scope='nc25.executor', route_permit_hash=row['permit_hash'])
        except Exception as exc:
            from nc25_universal_ledger import ContractViolation, IntegrityViolation
            if isinstance(exc, IntegrityViolation) or not isinstance(exc, ContractViolation):
                raise
            row['state'], row['reason'] = 'RECONCILIATION_REQUIRED', exc.code
            self._save(row)
            return row
        self.fault('after_ledger')
        row['state'], row['ledger_receipt'] = 'COMMITTED', receipt
        self._save(row)
        return row


def serve(config):
    if (not all(type(config.get(k)) is str and len(config[k]) >= 32 for k in ('reader', 'executor'))
            or config['reader'] == config['executor']):
        raise ReleaseError('CREDENTIAL_CONFIGURATION')
    clock = lambda: config.get('fixed_time') or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    target = Target(config['database'], config['target_id'], clock)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def reply(self, status, value):
            body = encode(value).encode('ascii')
            key = config.get(self.headers.get('X-Identity')) if self.headers.get('X-Identity') in {'reader','executor'} else None
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            if key is not None:
                signature = wire_mac(key, 'response', self.headers.get('X-Nonce',''), self.command, self.path, status, body)
                self.send_header('X-Response-MAC', signature)
            self.end_headers()
            self.wfile.write(body)
        def authorized(self, allowed, body=b''):
            identity = self.headers.get('X-Identity')
            if identity not in allowed:
                return False
            nonce, signature = self.headers.get('X-Nonce',''), self.headers.get('X-Request-MAC','')
            if not re.fullmatch(r'[a-f0-9]{48}',nonce) or not re.fullmatch(r'[a-f0-9]{64}',signature):
                return False
            expected = wire_mac(config[identity], 'request', nonce, self.command, self.path, 0, body)
            return hmac.compare_digest(signature, expected)
        def do_GET(self):
            if not self.authorized(['reader', 'executor']):
                return self.reply(403, {'error': 'TARGET_CREDENTIAL'})
            if self.path == '/head':
                return self.reply(200, target.read())
            if self.path.startswith('/documents/'):
                value = target.read(self.path[len('/documents/'):])
                return self.reply(200 if value else 404, value or {'error': 'NOT_FOUND'})
            self.reply(404, {'error': 'NOT_FOUND'})
        def do_POST(self):
            if self.path != '/append':
                return self.reply(404, {'error': 'NOT_FOUND'})
            try:
                self.connection.settimeout(2)
                length = int(self.headers.get('Content-Length', '-1'))
                if not 0 < length <= MAX_BODY:
                    raise ReleaseError('BODY_SIZE')
                raw = self.rfile.read(length)
                if not self.authorized(['executor'], raw):
                    return self.reply(403, {'error': 'TARGET_CREDENTIAL'})
                wire = json.loads(raw)
                if type(wire) is not dict or set(wire) != {'operation', 'permit_hash', 'expires_at'}:
                    raise ReleaseError('WIRE_FIELDS')
                receipt = target.append(wire['operation'], wire['permit_hash'], wire['expires_at'])
            except (ValueError, UnicodeError):
                return self.reply(400, {'error': 'INVALID_JSON'})
            except ReleaseError as exc:
                return self.reply(409, {'error': exc.code})
            if config.get('drop_first_response'):
                config['drop_first_response'] = False
                self.close_connection = True
                return
            self.reply(200, receipt)
    class BoundedServer(HTTPServer):
        def get_request(self):
            sock, address = super().get_request()
            sock.settimeout(1)
            return sock, address
    httpd = BoundedServer(('127.0.0.1', 0), Handler)
    print(json.dumps({'port': httpd.server_port}), flush=True)
    httpd.serve_forever()


if __name__ == '__main__':
    import sys
    serve(json.loads(sys.stdin.readline()))
