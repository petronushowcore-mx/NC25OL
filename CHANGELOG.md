# Changelog

All notable changes to this package are recorded here. Every version binds an
exact set of file hashes in `PACKAGE-MANIFEST.json`.

From 01.09.01 a version has three groups with leading zeros, `LL.MM.PP`.
`LL` is Ledger's coverage edition, `MM` is the Spectrum minor line used by the
recorded local example, and `PP` is this Ledger package's revision. Each entry
names the exact Spectrum release used by that example. The first two releases
happened to share `MM.PP` with Spectrum; a Ledger-only revision can advance
`PP` without implying that a new Spectrum release exists. A ready edition does
not mean that every later Spectrum layer is covered. The file name of the specification
document and its running header carry only the first two groups (`v01.09`);
the README title and every other version field carry all three.

Versions up to 0.0.11 are pre-release; in them the second digit is not used,
and each entry is a patch.

## 01.09.03

Paired with Spectrum `v00.09.02`. This Ledger-only revision retains the recorded
Spectrum source observation and adds the connection and reading paths listed
below.

Upgrading from 01.09.02: a declaration written for 01.09.02 that still carries
any of the 17 removed fields listed in `DECLARATION-FIELDS.md` is refused under
01.09.03. The packaged declaration schema no longer admits them, and
`validate_declaration` names the unknown field under the code of its section:
`DECLARATION_FIELDS` for `predecessor_declaration_hash` and `evidence_refs`,
and `CONNECTOR`, `STRUCTURAL_BUDGET`, `GOVERNANCE` or `INTERFACES` for the
others. Remove those fields before upgrading. The declaration hash, the SHA-256
of the whole declaration, then changes: grants and intents must carry the new
hash in their `binding` and revocations in their `declaration_hash`, and state
persisted under the former hash is not restored (`STATE_DECLARATION_MISMATCH`).
An evidence resolver must return plain JSON values; output that cannot be
copied or read as such yields a generic non-executable refusal.

- Adds a local document-release quickstart with expected output showing one
  committed action, exact replay, consumed-permit refusal, and refusal without
  issued authority.
- Validates adapter POST bodies against their packaged JSON schemas before
  calling the engine, with field-path refusals and a closed refusal if schema
  validation is unavailable.
- Classifies the declaration and registry fields by runtime use. Removes 17
  format-only declaration leaves and the nine corresponding refusal codes;
  the remaining limits and external responsibilities are explicit.
- Adds a separately verifiable observer export: the operator signs the chain
  head with Ed25519, and an independent reader checks the events and signature
  against an externally pinned key fingerprint without importing the engine.
- Extends the acceptance and package checks to the field census, reader,
  failure-surface records, and the exact document and manifest bytes.
- Reads evidence resolver output as plain JSON values inside the refusal
  guard, so the gate and the permit hash see one value, and records
  authoritative resolver failures, including output that cannot be copied or
  read, as generic non-executable refusals without exposing authorization
  progress or leaving the request key reusable. Evidence message types, intent
  identifiers, references and statuses, submitted or resolved, must be native
  strings.
- Requires native Python identity and role strings, and recognizes lists by
  their real type in JSON conversion and the secret and forbidden-field
  walkers; mappings there are still recognized by their interface. Arbitrary
  Python objects supplied in process remain outside the reference JSON
  boundary.
- Keeps observer exports within the independent reader's count and canonical
  byte limits; documents instance-attribution and late-report limitations.
- Evaluates resource windows with exact integer elapsed time, including very
  large positive windows and the inclusive microsecond boundary.
- Names the reading and field-inventory documents in the documentation licence
  and checks root-document coverage.
- Returns the coarse `REFUSAL`/`EXECUTION_DENIED` result for an exact replay of
  an evaluation whose permit a policy has since invalidated, where 01.09.02
  answered 400 with the reason, without a second decision or event; the
  detailed reason stays in architect permit state. A state-anchor mismatch at
  commit invalidates the permit and releases its reservation, and restoring the
  old anchor does not revive it. A consumed or expired permit still answers
  `PERMIT_ALREADY_CONSUMED` or `PERMIT_EXPIRED` after its signing key is
  revoked, and a revocation leaves a permit whose window had already closed
  expired rather than revoked.
- Checks a persisted snapshot before installing any of it. A stored state that
  fails the check is refused under an integrity code, which the HTTP adapter
  answers with 503; 01.09.02 answered a stored contract fault, such as a
  missing field or a malformed timestamp, with 400. The running engine's state
  and verifier registry stay as they were. Every stored record is held to the
  form the engine writes it in: a grant to the grant contract, less the expiry
  check that belongs to the moment of issue; a decision, a permit body, an
  idempotency result and a replay receipt to their fields, the permit body and
  the receipt under their own hashes; and an event the chain has verified to
  its fields and to the payload fields the observer projection reads. A grant
  whose permitted actions are stored as one string is refused, where it was
  read as text and every action whose identifier occurs in it passed the
  grant's action check. A value nested deeper than any record admits, and
  stored text the parser cannot read, are refused as well.
- Stops the secret-name guard from refusing identifiers the profile declares: a
  declared flag, resource or action named like a secret is evaluated, while
  undeclared keys, free-form mappings and all values keep the guard.
- Refuses a C1 control character in a request path with the same opaque 404 as
  C0 and DEL, reading the path as UTF-8 when the whole of it decodes and one
  character per byte when it does not. U+2028 and U+2029 are not control
  characters: a selector carrying them in UTF-8 is answered 400 as malformed,
  as in 01.09.02, and the error message now shows each as one character, not
  as its three bytes.
- States in the OpenAPI contract the identifier pattern of the registry
  `connector_id`, the 404 for a path that carries a control character, and that
  ambiguity flags are among the connector claims a production adapter must not
  trust. The specification, runbook and profile authoring checklist name
  ambiguity flags the same way.
- Corrects the OpenAPI contract, the specification and the runbook on what
  resolver output binds: the permit's own request hash. The request hash on the
  operator result and the architect decision covers the submitted intent and
  evidence bundle, not the resolved results.
- Corrects the specification where 01.09.02 said more or less than the code
  does: only a profile-seal, declaration-seal or event-chain failure blocks
  every later operation while the damage remains, and any other integrity
  failure refuses only the calls that meet it; commit checks grant revocation
  and expiry, permit expiry, signing-key revocation and declaration validity
  again, but not evidence status or derived controls; a permit seals its
  effective lifetime. It also names the order in which control results apply
  and more permit-state changes that append no event, states the four commit
  refusals that keep the permit invalidated instead of restoring the pre-call
  state, states secret exclusion as an integrator duty with the engine's
  key-name scan as its only check, and lists the observer-export reader in
  Appendix B.
- Aligns two entries of `core/nc25-core-crosswalk.json` with the
  specification's anti-probing duty and states there that the reference
  adapter has no rate limiter and no probe alerting.
- Fixes the host-system field in the specification document's archive, so the
  operating system that runs the builder no longer changes its bytes; a
  byte-identical rebuild still needs the locked dependencies and the same
  Python and zlib. The builder reads its core anchor from
  `SOURCE-MANIFEST.json` and lists every acceptance step, the declaration field
  census included.
- Requires `python-docx` for the acceptance suite, whose regression tests now
  import the specification builder; the README says so.
- Corrects the banking questionnaire crosswalk, which named interface services
  removed from the declaration. The banking profile and its synthetic
  declaration, grant and intent are rebound to the new bytes, so their hashes
  change. The reference profiles, declaration and crosswalk keep their versions
  through such a rebinding: the README now says the version rule binds approved
  production artefacts, not these synthetic fixtures.
- Brings the README files, runbook, security and reading guides and the SDK
  docstrings in line with the code: the local-release example's nine-step
  acceptance suite, the directories the coverage check leaves out, refusal
  counts without reasons, the export-only `EXECUTION_COMMITTED` code, the
  fixture declarations' expiry, the conformance suite's exit without optional
  libraries, the integrator's duty to keep secrets out of evidence values, the
  commit refusals that keep a permit invalidated, how long a retired signing
  key's permits stay verifiable, what a restore checks in a persisted snapshot
  and what it trusts as written, and that without resolvers the engine takes
  connector evidence statuses and declared flags as given.
- Corrects the OTCS bridge's comments on how deep a stored row nests an
  admitted document, on the eight reasons a permit is not live on recovery,
  and on where a receipt's own code runs while it is admitted.
- Scopes the acceptance report's geometry counts to the automated geometry
  audit that produces them.
- Validates every shipped profile in the conformance suite, fails it when a
  profile directory has no checks of its own, reports its HTTP adapter part as
  `NOT_RUN` instead of failing when the date-time format checker is
  unavailable, and keeps a real failure failing under pytest.
- Checks in the conformance suite that the OpenAPI contract declares exactly
  the route-path parameters and the operator route's Idempotency-Key header,
  and that each, followed through every reference, is a string with the
  engine's own validation pattern in a form ECMA-262 reads as Python does.
- Corrects the 0.0.8 entry on the conformance suite: its status check compares
  a curated table of route statuses with what each route declares, and the
  table is not derived from the statuses the adapter is observed to emit.
- Grounds the acceptance figures in checks that can fail: a unittest step's
  total is its module's declared test count, steps no longer inherit mutant
  overrides, and the mutation tools count what ran against a named inventory.
- Reads an acceptance number for the specification and the package verifier
  only from a name its module binds once, by a top-level assignment; a second
  binding of any form, an import or a definition of the same name included,
  is refused, and a counted test class must be defined once.
- Refuses an acceptance report rebound with `--rebind-only` in every run but
  the acceptance run with `--json-output`, whose results regenerate it, so its
  figures count only after that run rewrites them; the final run and CI refuse
  a report no passing run has rewritten.
- Lets the package verifier record a failing check and continue instead of
  blocking every later check, and run standalone when the source-manifest
  input list is malformed. The verifier also checks the census test count and
  the core anchor the shipped document prints against their sources
  (`PACKAGE_CHECKS=64/64`). The failure-surface acceptance step prints its
  child's output when no receipt line arrives.
- Counts a field-census source anchor only in code; a string literal or a
  docstring that quotes it no longer satisfies it.
- Tests the reader's isolation in a fresh interpreter that loads only the
  reader, without writing bytecode into the package.
- Strengthens several regression tests so that each fails when the property
  it names is broken.
- Counts and names bare re-raises in the failure-surface inventory, derives
  the invalidation-reason code set from the writes that set it, and credits a
  bridge pair table's codes only to the call that takes its code from the loop.
  The inventory also asks OTCS bridge refusals whether their code lies outside
  the bridge's vocabulary, counts a smaller recorded selection or a new foreign
  code as a regeneration loss, and hands the observed refusal code only to test
  readers. The restore path's translation of a caught refusal adds no code of
  its own.
- Charges a new dynamic emission point as a loss when the failure surface is
  regenerated and lets one become static for free; every published list
  declares whether it ratchets as coverage or as debt, and a list with no
  declared direction is refused.
- Reruns each test that fails in the recorded run alone twice, observed and
  unobserved, and blames the observation only when those two disagree; a
  disagreement with the recorded run's order is named separately. The reader
  suite, which no acceptance step runs, is rerun the same way, and the
  declaration-field census suite joins the recorded run.

## 01.09.02

Paired with Spectrum `v00.09.02`. Fixes three defects of 01.09.01 and adds
Python 3.14 to the supported versions.

- Evidence JSON read by the acceptance-report generator is refused past a depth
  bound of 64 before it reaches the parser. The parser's own limit belongs to
  the interpreter: a list nested 50 000 deep raised `RecursionError` on Python
  3.12 and parsed on Python 3.14, so the same bytes were refused under two
  different codes. They are now `EVIDENCE_JSON_INVALID` on every interpreter.
- A virtual environment made as `.venv` or `venv` in the package root is left
  out of the package manifest and of every package check, and git ignores both.
  Taken in, its files failed `no_build_artefacts` and
  `package_manifest_coverage`, and the `.docx` templates it carries stopped the
  acceptance run on `BOUND_DOCUMENT_COUNT:3`. README says where to make the
  environment.
- The runbook's optional pytest collection names its precondition: pytest is
  not in `requirements-lock.txt` and is installed separately.
- Python 3.14 is supported: the full acceptance passes on 3.14.4, the hashes in
  `requirements-lock.txt` cover its wheels, and CI runs 3.11, 3.12 and 3.14.
- The recorded source release (`examples/spectrum_release/RESULT.md` and its
  `result.json`) uses Tectonica Spectrum `v00.09.02`. Its archive packages the
  Spectrum root, whose README and CHANGELOG changed in `v00.09.02`, so the
  example was run again on that release; the new result replaces the record
  made on `v00.09.01`.
- The package verifier checks the pair with Spectrum: the pairing line of the
  current CHANGELOG section, the recorded source release's RESULT.md (its prose,
  table and reproduction commands) and its `result.json` must name one Spectrum
  release and one commit.
- The README files of the three local examples name Python 3.11, 3.12 and 3.14,
  as the package README and CI do.
- RESULT.md states that the Probe VI companion in Spectrum's `layers/ProbeVI`
  keeps its MIT licence; it had named only CC BY-NC-ND 4.0. It also says that
  the observation's `collection.stdout_sha256` depends on the absolute path of
  the Spectrum checkout.

## 01.09.01

- Adds a synthetic local example composing an OTCS registration preview,
  document release and declaration projection/objection exchange.
- Keeps preview generation separate from owner activation and execution
  authority; records uncertain cross-system completion as reconciliation.
- Pins the projected declaration to its initial bytes and active engine binding.
- Runs the example's component and integration checks and source mutations in CI.
- The local Spectrum source release example packages the committed source files
  of the pinned root and the XIV and XV layers. Files whose path ends with
  `.gif`, `.png`, `.jpg`, `.jpeg` or `.webp`, compared without regard to case, are
  recorded under `excluded_files` by path, mode, Git blob, size and SHA-256 with
  the reason `IMAGE_SUFFIX` instead of packaged. Other root gitlinks are recorded
  by path and commit under `pinned_layers_not_packaged` and are not read.
- Its manifest and result move to the formats
  `nc25ol-spectrum-source-release/v2` and
  `nc25ol-spectrum-local-release-result/v2`; the result adds
  `excluded_file_count` and `pinned_layers_not_packaged`. Records written in
  format v1 remain records of their own runs; no converter is provided.
- Adds connection tests for a fresh intent under a revoked grant, a resource
  window that slides and a closed registry field set, run for every shipped
  profile.
- The recorded source release (`examples/spectrum_release/RESULT.md`) uses
  Tectonica Spectrum `v00.09.01`: its root and its XIV and XV layers.
- The OTCS bridge commits a completed append at the ledger's own time, as it
  records a failed one; the receipt's effective time stays in the stored
  receipt. A receipt time more than five seconds ahead of the ledger clock, or
  more than five seconds before the permit was issued, no longer sends a
  completed append to reconciliation.
- A grant re-issued with a declared hash in another case replays the first
  issue, as the wire rule for hashes states, instead of failing with
  `AUTHORITY_ID_CONFLICT`.

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
