# Changelog

All notable changes to this package are recorded here. Versions before 1.0.0
are pre-release; the second digit is not used in these entries, and each entry
is a patch. Tags of the form `v0.N.M` that exist in the repository history
belong to a numbering this changelog does not use and are not entries here.
Every version binds an exact set of file hashes in `PACKAGE-MANIFEST.json`.

## Unreleased

- Adds a synthetic local example composing an OTCS registration preview,
  document release and declaration projection/objection exchange.
- Keeps preview generation separate from owner activation and execution
  authority; records uncertain cross-system completion as reconciliation.
- Pins the projected declaration to its initial bytes and active engine binding.
- Runs the example's component and integration checks and source mutations in CI.

## 0.0.11

- Binds every stored OTCS operation, intent and submitted evidence bundle to
  its authenticated NC2.5 admission decision before execution or recovery.
- Rechecks snapshots returned by outbox transitions before using them. Local
  admission evidence is excluded from the downstream request.
- Refuses legacy outbox rows without an admission snapshot using
  `OTCS_OUTBOX_ADMISSION`; such rows require operator reconciliation.

## 0.0.10

- Uses the project name NC25OL - Navigational Cybernetics 2.5 Open Ledger.
- Normalizes project and idempotency selectors before querying the OTCS outbox.
  SQLite primary keys must compare identifiers exactly, and outbox queries
  use binary comparison independently of the declared column collation.
- Validates every row in the acceptance table, including rows with compact
  Markdown spacing or a non-PASS result.
- Records the two material-specific licences separately in citation metadata.
  The code remains MIT; documentation and specification remain CC BY 4.0.
- Clarifies that recovery from CALLING or AMBIGUOUS requires a live permit.

## 0.0.9

- Adds an executable OTCS registry profile and a standard-library bridge inside
  NC25OL. The active NC2.5 profile and declaration
  remain the sole source of admissibility; OTCS contributes typed legal
  receipts and the expected project head, then performs only the append
  authorized by a live NC2.5 permit.
- Adds a durable SQLite outbox around the cross-system commit seam. The exact
  operation, intent, and evidence submission is idempotency-bound. A row still
  in `PREPARED` revalidates its engine binding and permit immediately before
  the first downstream call; a dead permit becomes `NOT_EXECUTED` without
  contacting OTCS. A row in `CALLING` or `AMBIGUOUS` replays the same
  project-scoped request only while its permit remains live. A dead permit
  moves the row to `RECONCILIATION_REQUIRED` without another OTCS call. A
  downstream commit that can no longer be finalized locally also enters
  explicit reconciliation instead of receiving a late authorization.
- Separates "nothing here can verify this chain" from "this chain does not
  verify" by the signer identity the envelope declares, not by the signer's
  Python type. Reopening a persisted chain under a signer whose algorithm or
  `key_id` differs now fails closed with `EVENT_SIGNER_REQUIRED`, where it
  previously reported a chain-integrity failure and so read a routine key
  rotation as a forged ledger. A signer declaring the same `key_id` with
  different key material is indistinguishable from a forger and continues to
  fail chain verification.
- Binds the opaque OTCS receipt digest into the local execution event, records a
  stale-head rejection as a failed execution without resource debit, rejects
  OTCS receipt fields that attempt to express admissibility, and exercises the
  complete state-machine suite against banking, document release, and OTCS.

## 0.0.8

- Request identity normalizes the case of the fields the schemas DECLARE as
  hashes, nested ones included, instead of every 64-hex string. Normalizing
  by shape had pulled opaque identifiers into the identity wherever a
  deployment used hex-shaped values: an idempotency key differing only in
  case produced one identity with two stored entries, so a single logical
  request could hold two reservations and be executed twice, and two
  different principals presenting one key replayed each other's permit past
  the authority check. The inventory is compared against the schemas by a
  regression case.
- A value of the wrong type stays inside the refusal vocabulary: a
  non-string timestamp is `INVALID_TIMESTAMP` and an unhashable outcome or
  evidence status is the declared code, where both escaped as bare Python
  exceptions and, over the wire, as unhandled faults.
- The wire contract declares the complete vocabulary a caller can receive as
  the `Error.code` enum, generated from the shipped source by
  `tools/build_error_code_enum.py` and held to the live scan by the package
  verifier; `503` is declared on every operation, `400` on the three
  parametric GET routes whose selector shape check answers it, and `200` on
  an exact re-issue of a grant. The conformance suite compares every status
  the adapter can emit on a route with what the route declares.
- The reference adapter answers any fault it does not classify as
  `503 INTERNAL_FAILURE` with no detail instead of raising out of the WSGI
  callable; anchors its routes so a trailing newline is no longer a second
  spelling of every path and refuses control characters before dispatch;
  no longer percent-decodes an already-decoded path, which had served the
  active connector for a `%73...` selector; bounds nesting depth before
  `json.loads` with `BODY_NESTING`; answers a missing `activated_by` as a
  body defect; and refuses unknown top-level keys in both request wrappers.
  The engine's shape helpers and its timestamp and integer checks quote a
  refused value back truncated, and the adapter bounds its own error details,
  so the length of an error response is no longer set by the request.
- Repeats are idempotent by state: revoking a revoked grant records no
  second event and a permit already invalidated keeps its first reason, an
  identical re-issue answers `200` with the same hash, and a grant whose
  `valid_until` is not after the trusted clock is refused at issue with
  `AUTHORITY_EXPIRED` while a wholly future window is still issued. A body
  without `idempotency_key` is the engine's form error rather than a header
  mismatch. An intent's binding must have the sealed binding's shape before
  anything is recorded (`INTENT_BINDING`); a well-formed binding naming
  another profile remains a refusal with an event.
- The permit's sealed `ttl_seconds` is its effective lifetime, capped by the
  grant and declaration expiries and rounded up to whole seconds, so
  `issued_at + ttl_seconds` equals `expires_at` to the second.
- `RESOURCE_LIMIT_MISSING` left the architect decision vocabulary: the
  declaration validator makes the branch unreachable, and the loss is
  acknowledged in the baseline with its reason. The baseline's regeneration
  guard now names a shrink of the architect and wire vocabularies as well as
  of the engine's.
- Every refusal code of `validate_profile`, of `validate_declaration` (two
  are unreachable from a declaration-only corruption and are named) and of
  the intent's shape guards is asserted by name - one row per code for the
  two validators, one or more rows per code for the intent's guards;
  unwitnessed codes fell from 215 to 113.
- The package verifier compares the acceptance report's full version to the
  package version, excludes the repository directory only at the root so a
  nested `.git` can no longer hide a shipped file, and holds the citation and
  changelog versions to the package version; the acceptance runner requires a
  bare `OK` from the three unittest steps so a silently skipped test is
  visible; and the failure-surface tool refuses to write a baseline with
  nothing to compare against unless the adoption is acknowledged.

## 0.0.7

- Declared the 29-code architect decision vocabulary and added a
  failure-surface ratchet whose every figure is a property of a named
  procedure over the exact bytes the baseline binds: two closed-world
  vocabularies kept apart (engine refusal codes and adapter wire codes), two
  emission-point quantities reported side by side (every site a refusal can
  leave from, and the subset whose code is a single static literal) with the
  dynamic gap enumerated site by site, refusal codes raised during an
  in-process run of the acceptance suites attributed by the constructing
  frame, and proof observed at runtime rather than parsed from test idioms: a
  code is witnessed only when a production-raised engine refusal reached test
  code that checked exactly that code, by an equality reaching the code object
  itself or by a regex matching this exception's rendering and no other code's,
  and a wire error's code never counts toward the engine's witnesses even where
  the two vocabularies overlap. Codes the adapter's translation site re-emits
  that belong to neither vocabulary are named rather than folded into the wire
  figure, with provenance taken from the constructing function rather than from
  set arithmetic. Every figure is published under the name of the procedure that
  produced it, and the step fails if a figure and a procedure entry do not pair.
  The committed baseline pins the unwitnessed set explicitly as a no-growth debt
  ratchet: regenerating it refuses to lose a witness, drop a code from the
  closed world, or grow the debt unless the reason is recorded in the baseline
  beside what was given up. The acceptance report states the figures rather than
  leaving them to be subtracted, and names them for what the procedures measure
  — codes constructed during the run, and raise sites rather than refusal sites.
- Bound the literal standalone and strict package-check totals in the README,
  acceptance report, and report generator to the verifier's declared check-ID
  sets, so a new check cannot leave a stale green count behind.
- Moved the role check out of every public method and into the two state
  decorators, so it runs before the state store is opened. It previously ran
  after the store had loaded and verified a snapshot, which meant that on a
  state-backed engine a caller supplying no role received an integrity code
  rather than a scope refusal, and could take the write lock and force a
  durable write. Each method now declares its required role on its decorator,
  and the suite reads that declaration rather than a hand-maintained map.
- Normalized SHA-256 hex case by shape when building the operator replay
  identity, matching the executor surface and the documented either-case wire
  rule; a resubmission differing only in hex case now replays instead of
  conflicting.
- Widened several checks from one member to their whole domain: the public
  surface is swept for the role requirement, for the ordering of that check
  against the integrity halt, and for the halt itself; the integrity guard is
  exercised on each of its three seals; grant revocation is asserted against
  more than one outstanding permit; permit expiry is asserted against each of
  its three bounds rather than only the one the fixtures make earliest; the
  commit-time window recomputation and the per-resource reservation rule are
  exercised on an action claiming two resources rather than one; and the wire
  scope sweep now also presents a scope that is a real role but not the
  route's, which an unknown scope cannot distinguish from no role at all.
- Bound the engine's declared roles to the roles the reference adapter mounts,
  pinned the set of operations with no mounted route, and required every route
  to reach a public engine operation.
- Pinned the dependency lock by hash and required it in CI with
  `--require-hashes`.
- Witnessed six more refusal codes: the evidence bundle's shape guards, the
  scope binding's coverage and range order, and both execution-time bounds
  of a permit.

## 0.0.6

- Halted the two permit-key custody operations on a local integrity failure,
  the last public operations that ran on an engine whose event chain no
  longer verified, and added a public-surface sweep for the halt mirroring
  the scope sweep.
- Released reserved structural capacity when a permit signing key is revoked:
  a permit signed under a revoked key can never commit, so both revocation
  surfaces now free their permits' reservations through one shared path
  instead of leaving key-revoked permits holding capacity until expiry.
- Normalized SHA-256 hex case by shape when building the execution replay
  identity, so a retry differing only in the case of the nested binding
  hashes replays instead of conflicting, matching the documented either-case
  wire rule.
- Added named safety mutations for the activation actor and for both custody
  scope checks.

## 0.0.5

- Required an explicit governance scope on the two permit-key custody
  operations (signer rotation and key revocation), closing the only two
  public operations that did not enforce the package's explicit-scope rule,
  and widened the scope test from two named methods to an introspected sweep
  of the whole public surface.
- Bound the recorded activation actor to the declaration's declared approval
  owner (`ACTIVATION_ACTOR_UNAUTHORIZED`), the same way grant issue and
  revocation pin their actors, with a regression proving a foreign activator
  is refused without appending an event.
- Stated both rules in the README, the runbook, and the specification's
  role table.

## 0.0.4

- Fixed the continuous-integration workflow to run the package's canonical
  acceptance command and the review-bundle build only, removing a step that
  required a test runner not among the pinned runtime dependencies.

## 0.0.3

Repository tooling only; no contract, engine, schema, or wire change.

- Added a continuous-integration workflow that runs the acceptance suite on
  pushes and pull requests targeting `main`.
- Added a security policy with a private reporting address and an explicit
  in-scope and out-of-scope statement.
- Added citation metadata.
- Added an opt-in adopters registry.
- Added this changelog and a repository section in the README.

## 0.0.2

- Added a required `provenance` field to the declaration's structural budget,
  coding the origin of the declared capacity with a published four-value
  instrument; validated on both the schema and engine surfaces and sealed by
  the declaration hash. The gate never reads it.
- Documented the three accounting registers and their limits, the
  single-channel committed-action budget, the fresh-budget-per-declaration
  reset, and the principal-authentication and environment-metadata boundary.
- Kept the operator-facing request hash and the architect decision on the
  submitted hash so the coarse operator surface no longer reveals the
  authorization stage, while the permit retains its resolved binding, and
  restored the architect permit-to-decision direction.
- Validated the submitted evidence bundle's shape and time before
  authorization, so a malformed or future-dated bundle no longer reveals the
  authorization stage through its error status.
- Captured and restored the process-local permit-signer registry around
  persisted operations, so a rotation or revocation whose persist fails leaves
  the active key unchanged.
- Constrained the execution-receipt resource-debit keys to identifiers,
  mirroring the intent and permit, and widened several tests from a single
  case to their defect class.

## 0.0.1

- Initial release: domain-neutral connection contract, standard-library
  reference engine and WSGI adapter, role-separated wire contract, JSON
  Schemas, two reference profiles with executable fixtures, and the acceptance
  and conformance suites.
