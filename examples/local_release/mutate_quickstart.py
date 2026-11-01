"""Break the quickstart transcript and refusal branch in isolated copies."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
FILES = ('quickstart.py', 'quickstart-expected.txt', 'test_quickstart.py')


def replace_once(path, old, new):
    source = path.read_bytes()
    if b'\r\n' in source:
        old, new = old.replace('\n', '\r\n'), new.replace('\n', '\r\n')
    old, new = old.encode('utf-8'), new.encode('utf-8')
    if source.count(old) != 1:
        raise RuntimeError('QUICKSTART_MUTATION_ANCHOR')
    path.write_bytes(source.replace(old, new))


def run_copy(parent, change=None):
    with TemporaryDirectory(dir=parent) as scratch:
        work = Path(scratch)
        for name in FILES:
            shutil.copy2(HERE / name, work / name)
        if change == 'expected':
            replace_once(work / 'quickstart-expected.txt',
                         'UNKNOWN_AUTHORITY=REFUSAL AUTHORITY_UNKNOWN',
                         'UNKNOWN_AUTHORITY=REFUSAL AUTHORITY_ALLOWED')
        elif change == 'source':
            replace_once(work / 'quickstart.py',
                         "refused = session.engine.evaluate_intent(unknown_intent, unknown_evidence,\n"
                         "                                                     actor_scope='nc25.operator')",
                         "refused = {'disposition': 'REFUSAL', 'permit_hash': None, 'request_hash': '0' * 64}")
        env = os.environ.copy()
        env['NC25_LEDGER_ROOT'] = str(ROOT)
        return subprocess.run([sys.executable, '-B', '-m', 'unittest', 'discover',
                               '-s', str(work), '-p', 'test_quickstart.py'],
                              capture_output=True, text=True, encoding='utf-8', env=env,
                              check=False, timeout=180)


def first_error(result):
    if 'Ran 1 test in ' not in result.stderr or 'FAILED (errors=1)' not in result.stderr:
        return None
    errors = re.findall(r'^RuntimeError: ([A-Z][A-Z0-9_]+)$', result.stderr, re.MULTILINE)
    return errors[0] if len(errors) == 1 else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scratch', type=Path)
    args = parser.parse_args()
    base = run_copy(args.scratch)
    if base.returncode != 0:
        raise RuntimeError('QUICKSTART_CONTROL_FAILED\n' + base.stdout + base.stderr)
    expected = run_copy(args.scratch, 'expected')
    if expected.returncode == 0 or 'QUICKSTART_TRANSCRIPT_MISMATCH' not in expected.stdout + expected.stderr:
        raise RuntimeError('QUICKSTART_EXPECTED_MUTATION_DID_NOT_BITE\n' + expected.stdout + expected.stderr)
    source = run_copy(args.scratch, 'source')
    if source.returncode == 0 or first_error(source) != 'UNKNOWN_AUTHORITY_DECISION_MISSING':
        raise RuntimeError('QUICKSTART_SOURCE_MUTATION_DID_NOT_BITE\n' + source.stdout + source.stderr)
    print('QUICKSTART_SOURCE_FIRST_RED=' + first_error(source), flush=True)
    print('QUICKSTART_SOURCE_RAW_BEGIN\n' + source.stdout + source.stderr +
          'QUICKSTART_SOURCE_RAW_END', flush=True)
    print('QUICKSTART_MUTATIONS=2/2 PASS')


if __name__ == '__main__':
    main()
