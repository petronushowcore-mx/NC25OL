# Security policy

## Scope

This repository is a reference and conformance package. Its security-relevant
surface is the reference engine (`sdk/python/nc25_universal_ledger.py`), the
reference WSGI adapter (`sdk/python/nc25_universal_adapter.py`), the JSON
Schemas under `core/schemas/`, and the wire contract in
`protocol/universal-connection.openapi.yaml`.

The package authenticates no calling principal and provides no production
identity, transport, key custody, or distributed-state layer; those are the
responsibility of a deployment and are documented as out of scope in the
README "Boundary of the claim". A report that requires spoofing an
authenticated principal, leaking a bearer permit handle, or otherwise
substituting the production identity and transport layer is out of scope.

In scope: any input, ordering, or state under which a declared fail-closed
surface fails open; any path to a committed effect outside the granted action,
target, effect class, or scope; any single permit yielding two debits; any
recovery of gate geometry, sub-verdicts, or the authorization stage from the
coarse operator surface; and any object shape the JSON Schema layer and the
engine's semantic validation accept differently.

## Reporting a vulnerability

Report privately to research@petronus.eu. Please include the exact objects,
call order, field values, and the engine, schema, adapter, or test site your
report concerns, and a minimal reproduction against the shipped package. Do not
open a public issue for an unfixed vulnerability.

You can expect an acknowledgement within a reasonable period and a good-faith
effort to confirm, fix, and credit the report. Coordinated disclosure is
preferred.

## Verifying a release

Every shipped file except the manifest itself is bound by SHA-256 in
`PACKAGE-MANIFEST.json`; the manifest is excluded because it cannot carry its
own hash. What holds the manifest is the verifier rather than a second hash:
its coverage check compares the declared set against the files actually
present, so a file added, removed, or renamed without updating the manifest is
reported. Outside the package, the manifest is held by the revision it was
committed in. The
NC2.5 core is bound by SHA-256, byte length, and line count in
`SOURCE-MANIFEST.json`. Run `python -B tests/run_acceptance.py` to verify the
package, and point `NC25_SOURCES_ROOT` at the core to verify the external-source
binding as well.
