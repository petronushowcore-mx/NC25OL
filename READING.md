# Reading an NC25OL observer export

**Draft format, not a released interface.** `nc25ol-observer-export/v1` lets a
reader verify a *separate public projection* of a Ledger instance. The export
contains exactly the four observer fields allowed by the current full observer
profile (`channel`, `message_code`, `event_time`, `subject_ref`). A profile that
allows fewer observer fields refuses this v1 export with
`OBSERVER_EXPORT_FIELDS`. The proposed export-only message code
`EXECUTION_COMMITTED` distinguishes a committed execution from a permit without
adding a fifth field. Publishing that code is a format decision; the existing
observer response remains unchanged.

The export records permit authorizations as `EXECUTION_AUTHORIZED`, committed
executions as `EXECUTION_COMMITTED`, and refusals by the existing public codes
`EXECUTION_DENIED` and `HUMAN_REVIEW_REQUIRED`. Only a `COMMITTED` source
execution becomes `EXECUTION_COMMITTED`. The reader reports these counts and
refusal reasons. It does not display intent bodies, evidence, receipt
seeds, original ledger event hashes, or signing secrets.

Each exported event has a zero-based **projection index**, a previous projected
hash, a public record, and its own hash. Hashes are uppercase SHA-256 of UTF-8
JSON with sorted keys, no whitespace, literal Unicode and no NaN. The first
previous hash is 64 zeroes. The signed statement is canonical JSON of
`{"format": ..., "head": {"event_count": ..., "head_hash": ...},
"public_key": {"algorithm": ..., "key_id": ..., "raw_base64": ...,
"fingerprint_sha256": ...}}`. The detached Ed25519 envelope carries version
`1`, algorithm `Ed25519`, key ID and base64 signature. The fingerprint is
uppercase SHA-256 of the 32 raw public-key bytes.

The trusted-side exporter is `build_observer_export` in
`sdk/python/nc25_universal_ledger.py`. Under the engine lock, it reads the
guarded `observer_projection` and source event classes, derives each expected
four-field projection from the source event, and refuses an equal-length
reorder or substitution with `OBSERVER_EXPORT_PROJECTION_MISMATCH`. It replaces
only the committed execution's message code for this proposed export, then
builds and signs the projected chain. The original
engine chain hashes **full private payloads**, so its hashes cannot be copied
into the public projection. This draft exporter requires explicit architect
scope and an Ed25519 signer; it is not an HTTP endpoint. The existing observer
response is unchanged.

The reader is `sdk/python/nc25ol_reader.py`. It imports neither the engine nor
its secrets. To verify a saved JSON export, pin the expected fingerprint from
an independently authenticated operator channel and run:

```text
python sdk/python/nc25ol_reader.py observer-export.json --expect-fingerprint <64-hex-fingerprint>
```

Exit 0 prints verified public counts; exit 2 prints a stable refusal code.
The command-line interface requires the fingerprint. The Python
`verify_export` function also permits an unpinned call for format diagnostics;
that result has `signature_valid: true` but `verified: false`. It proves only
possession of the *included* public key, not the operator's identity. A pinned,
signed export proves post-export integrity of the
projected events up to its declared head. It does **not** prove completeness
against the private ledger, that omitted event types never happened, that
the operator published every eligible event, or that a named organization
controls the key. The signed v1 statement also contains no connector, profile
or declaration identifier: a shared operator key does not identify which
Ledger instance produced the projection. Instance attribution requires an
independently authenticated mapping from this export to its source instance.
Such claims require external evidence and key binding.

The five required causal rejection examples use different codes:

| Change to an otherwise valid export | First refusal code |
|---|---|
| Change one public record without updating its hash | `EVENT_HASH_MISMATCH` |
| Remove one event | `EVENT_COUNT_MISMATCH` |
| Reorder two events | `EVENT_ORDER_INVALID` |
| Replace with a valid export signed by a different key while retaining the expected pin | `KEY_UNEXPECTED` |
| Attach a valid signature of a different head | `HEAD_SIGNATURE_INVALID` |

Reader input is bounded to 32 MiB and 100,000 projected events. The exporter
uses the same bounds and refuses `OBSERVER_EXPORT_EVENT_LIMIT` or
`OBSERVER_EXPORT_BYTE_LIMIT` before returning an export that exceeds them.
Save the returned object with the canonical serializer so file size agrees
with the producer check:

```python
from pathlib import Path
from nc25_universal_ledger import canonical_json
Path("observer-export.json").write_bytes(canonical_json(export))
```

The byte bound applies to those canonical UTF-8 bytes; adding whitespace or
other formatting can make an otherwise accepted object exceed the file limit.
Duplicate JSON keys are rejected. The bounds describe a standalone full
projection export, not the capacity of a live Ledger database. A history beyond
the export limits requires a separately specified export or archive mechanism;
this v1 format provides no pagination. The current tests are in
`tests/test_reader.py`.
