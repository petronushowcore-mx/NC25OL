# Local preview release and declaration exchange

This example composes three local components: an OTCS registration preview,
a document-release gateway, and an exchange of declaration conditions and an
attributed objection. It uses synthetic identities and a loopback HTTP target.
It does not register a project with OTCS or connect a live witness.

## Scope and trust boundary

The preview is a document, not an admission decision. Its `admitted` field stays
false. The example separately activates a fixture declaration and issues its
fixture grant through the Ledger governance interface. Those calls model an
explicit owner decision; the preview cannot make them.

`export_preview.mjs` imports the separately supplied OTCS candidate, builds its
synthetic owner submission, verifies it, and selects public fields and the exact
referenced grant, consent and disclosure texts. The Python consumer checks the
preview markers and those text hashes. It trusts the locally chosen producer;
it does not authenticate an arbitrary file as an OTCS submission. Use synthetic
data only. OTCS originates with Chris Perkins and the Open Trust Commons project;
this composition is a separate NC25OL contribution.

`scenario.DocumentSession(path, document_bytes, document_id='document',
idempotency_key='document-release-1')` accepts exact binary document bytes and
validates the operation before creating stores. It exposes the same explicit
`activate()`, `start()`, `submit()`, `reopen()` and `close()` methods; recovery uses
`session.gateway.recover(session.op['idempotency_key'])`. It does not inspect the
document's meaning or establish approval by a real owner. `LocalSession` adds
preview validation and retains its preview-specific identifiers and `preview`
field. Both sessions use the synthetic fixture authority and fixed clock below.

The document target runs in a separate process on `127.0.0.1`. Reader and executor
credentials are distinct, freshly generated secrets sent through a pipe, not
command-line arguments. HMAC authenticates requests and replies, including the
request nonce. This is a local process boundary, not operating-system isolation
against the same account and not a production network service.

One target transaction stores the exact document bytes, receipt and head. The
Ledger and outbox have separate SQLite databases. There is no shared transaction
across these systems: an effect which cannot be finalized enters
`RECONCILIATION_REQUIRED`. Revocation is checked before the call, but a concurrent
revocation after that check is not atomically coupled to the target transaction.
The authenticated target and its receipt are trusted. The gateway serializes one
owner process; concurrent owners, rollback-resistant storage, persistent key
custody, key rotation and full process-restart recovery are not demonstrated.
The scenario reopens durable stores with keys retained in the parent process.
The example uses a fixed synthetic clock; elapsed wall time is not its clock.

The declaration projection is pinned when the local session is created and must
match the engine binding. An objection is authenticated against its configured
HMAC key and exact projection. It is an observation about declared conditions,
not a certificate of document content, truth or human identity, and it grants
no execution authority. Remote pin delivery, persistent replay handling and
independent reader implementations remain outside this example. The reader
uses the same implementation as the exporter. The unchanged-state check reads
committed SQLite state, including WAL, as well as Ledger events and registry.

The HTTP request and response body ceiling is 4 MiB; decoded document bytes are
limited to 2 MiB so their base64 representation fits inside that ceiling. The
bounded body and socket timeout do not implement an absolute request deadline
against slow input. The command is for local synthetic runs only.

## Run the Python checks

From the Ledger package root, using Python 3.11 or 3.12 with the package's pinned
dependencies installed:

```text
python -B -m unittest discover -s examples/local_release -p "test_*.py" -v
python -B examples/local_release/mutate_scenario.py --scratch /absolute/scratch
python -B examples/local_release/mutate_document_session.py --scratch /absolute/scratch
python -B examples/local_release/mutate_document_release.py --scratch /absolute/scratch
python -B examples/local_release/mutate_exchange.py --scratch /absolute/scratch
```

The first command runs both component suites, the integration scenario and the
generic document-session checks. They
cover release, credentials, authenticated replies, outbox tampering, exact bytes,
denial before activation, changed content, version substitution, lost replies,
revocation, expiry, recovery and non-executable observations. The scenario, document-session and
exchange mutation runners require the named test to fail first in their complete
ordered suite. The document-release mutation runner instead checks the first
refusal/assertion inside each selected case; it does not claim global first-failure
ordering. The scenario runner also checks its result classifier with positive and
negative controls. All mutations operate on copies. Temporary files must stay outside
the package; set `TMPDIR` on Unix or `TEMP` and `TMP` on Windows when needed.
These example checks are separate from the core eight-step acceptance suite.

## Produce a preview from the OTCS candidate

This exporter needs the separately distributed OTCS 0.2 candidate source, including
`envelope-cases.mjs`, and its installed dependencies. It does not use the normative
registry repository as a substitute. The candidate's dependency installation and
licence remain its own. Node 24.14.1 was used for this example.

Set `OTCS_TEST_SCRATCH` to an existing absolute directory outside both packages.
Set `OTCS_DEPENDENCIES` to the absolute `package.json` of that candidate's installed
dependency environment, as required by the candidate's loader. Then run:

```text
node examples/local_release/export_preview.mjs --candidate /absolute/otcs-0.2 --output /absolute/scratch/preview.json
python -B examples/local_release/scenario.py --preview /absolute/scratch/preview.json --output /absolute/scratch/new-run
```

Both output paths must be outside the packages. The preview file and run directory
must not already exist. The successful scenario writes `result.json` and local
SQLite stores under the run directory. The JSON reports receipts and the projection
exchange, keeps `otcs_admitted: false` and `live_witnesses_connected: false`, and
contains no credentials. Keys are not saved; the run directory alone cannot
restore the session's authority.

The optional producer checks require the same candidate and environment:

```text
node examples/local_release/test_export_preview.mjs --candidate /absolute/otcs-0.2
node examples/local_release/test_export_preview.mjs --candidate /absolute/otcs-0.2 --mutations
```

The test checks public-field selection, exact term text binding, rejected damaged
references, synthetic/non-admission markers and output boundaries. The producer
mutation checks run copies and preserve the candidate source.

## Files

- `scenario.py`: generic document session, preview specialization and local report.
- `document_release.py`: loopback target, authenticated client and durable outbox.
- `exchange.py`: declaration projection and non-executable objection validation.
- `export_preview.mjs`: synthetic preview producer using the OTCS candidate.
- `test_*.py`, `mutate_*.py`, `test_export_preview.mjs`: executable checks.

The package's MIT terms apply to this example directory. No NC2.5 core source,
OTCS source, runtime database, credentials or generated preview is included here.
