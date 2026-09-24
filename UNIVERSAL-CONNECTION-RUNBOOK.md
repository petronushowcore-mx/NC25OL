# NC25OL Connection Runbook

## Purpose

This runbook explains how to connect a domain system to the NC25OL package. The workflow has two separate onboarding objects:

1. a domain profile that defines how the domain is typed;
2. an instance declaration that binds one connector and its exact scope to that
   profile.

Neither object is an execution permit. Runtime execution requires a valid
authority grant, a complete evidence bundle, a successful binary gate, an
active reservation, and a live single-use permit.

This schema version is reusable only when the domain can be represented by a
closed action alphabet, declared effect classes, boolean control results,
non-negative integer resource claims, typed evidence, and the supplied
role-separated runtime. If that representation would erase a material domain
fact or weaken a fail-closed rule, create a new reviewed schema version rather
than force-fitting the domain.

## 1. Create or select a domain profile

Complete `core/schemas/profile.schema.json`.

The profile must define:

- a closed action alphabet;
- effect classes and whether each mutates external state;
- resources and their claim rules;
- the action-to-effect and action-to-resource mappings;
- prerequisites, hard blocks, and manual-review flags;
- evidence required for each covered action;
- a zero-cost, non-mutating fallback action;
- role visibility and forbidden operator fields;
- fail-closed dispositions;
- a mapping witness covering every action and effect class;
- the material fields whose change requires a new version.

API similarity, naming similarity, or reuse of an existing adapter is not a
mapping witness.

Validate a profile from the package root:

```text
python -B -c "import sys; sys.path.insert(0, 'sdk/python'); from nc25_universal_ledger import load_json, validate_profile; validate_profile(load_json(sys.argv[1])); print('PROFILE_VALID')" profiles/banking/bank-profile.json
```

## 2. Seal the profile

Canonicalize the JSON with sorted keys and compact separators, then calculate
SHA-256 over the exact UTF-8 bytes. Store the approved bytes and approval
evidence in an append-only local evidence store.

Any material edit creates a new profile version and hash.

## 3. Create the connection declaration

Complete `core/schemas/connection-declaration.schema.json`.

The declaration binds:

- the immutable NC2.5 core anchor;
- one exact profile identifier, version, and hash;
- one connector and workload identity issuer;
- allowed actions, effects, targets, explicit action-target bindings, and scope values;
- a structural capacity, its declared provenance coding, and a selector
  identifier;
- domain resource limits;
- governance owners and role-separated interfaces;
- the profile mapping witness;
- immutable evidence references.

Failure outcomes are fixed by the profile and runtime contract. A declaration
cannot add or override a disposition or error posture.

The declaration must narrow or preserve the profile. It cannot add an action,
effect, resource, or target that the profile does not define.

## 4. Activate the declaration

Governance approves the exact canonical declaration bytes and records:

- declaration hash;
- profile hash;
- approval evidence reference;
- activation actor and time;
- local ledger head.

The recorded activation actor must be the declaration's declared approval
owner; any other identifier is refused with `ACTIVATION_ACTOR_UNAUTHORIZED`,
the same way grant issue and revocation pin their actors.

The connector cannot activate or revise its own declaration.

The reference engine implements `DRAFT` to `ACTIVE` and blocks runtime use
outside the declaration validity interval. `SUSPENDED`, `REVOKED`, and
`EXPIRED` are production registry projection states; a production governance
adapter must define and persist their transitions. They are not implemented as
reference-engine lifecycle commands.

Activating a new declaration version starts a new accounting instance: the
structural budget begins at the declared capacity, and no burden is carried
over from the predecessor. `predecessor_declaration_hash` preserves lineage
only. A deployment that claims continuation across declaration versions must
keep that account outside this package and argue it separately.

## 5. Issue a workload authority grant

The authority issuer creates a time-bounded grant for:

- one workload subject;
- one connector;
- one profile and declaration hash;
- explicit action identifiers;
- explicit downstream targets;
- a validity interval;
- immutable issuance evidence.

Grant scope must be a subset of the active declaration.

## 6. Submit intent and evidence

The operator submits an intent containing:

- exact profile and declaration bindings;
- authority grant identifier;
- action and target, constrained by the declaration's explicit action-target binding;
- scoped dimension values;
- non-negative resource claims;
- payload, history, and current-state hashes;
- prerequisite, block, review, and ambiguity flags.

The evidence bundle is a separate object bound to the intent identifier and
contains typed references plus content hashes. It carries no reusable
credential or raw secret.

Every public SDK operation requires an explicit `actor_scope`; omission fails
closed, and no method supplies its own required role as a default. The scope is
still an adapter assertion, not authentication: production must derive it from
the verified workload identity.

These control flags and evidence statuses are claims at the connector
boundary, not authority. Supply `evidence_resolver` at untrusted ingress so the
gate uses only the resolver's authoritative bundle; resolver exceptions,
malformed output, and intent mismatch fail closed. Without a resolver, the SDK
contract remains an internal post-resolution object. Production must retrieve
records from approved systems, verify provenance and hashes, derive controls
inside the independent evaluator, and bind the results to request and state.
The idempotency key first binds a canonical hash of the connector-submitted
intent and evidence bundle. Exact replay is therefore resolved before an
external resolver is called. The authoritative resolved bundle used by the
gate is bound by a separately computed hash sealed inside the permit body
only; the request hash on the operator result and the architect decision is
computed over the submitted intent and evidence bundle, so the hash a caller
receives reveals nothing about the gate stage. Resolver wiring is
process-local runtime configuration and is not persisted: every process
sharing a `state_path` must be constructed with the same resolver
configuration, and a stored `ALLOW` is authoritative for the resolver state
at issuance, with freshness bounded by the sealed permit TTL.

For the HTTP adapter, the `Idempotency-Key` header must exactly equal
`intent.idempotency_key`. Reject a mismatch as a conflict before evaluation.
An exact replay may return an active permit or the original non-executable
result, but replay of a consumed, expired, revoked, or otherwise invalidated
permit fails closed and never reissues `ALLOW`.

Executor replay is separate: after a successful commit, an exact replay of the
same canonical execution request returns the stored receipt without a second
event or debit, including after permit, grant, or declaration expiry or
revocation. This read-only replay cannot authorize new work. A changed request
for that consumed permit fails with `EXECUTION_REPLAY_CONFLICT`. If an in-process
exception interrupts the reference commit, the engine restores the pre-call
ledger, debit, permit, receipt, and replay state before re-raising. Production
still requires one durable transaction.

Wire SHA-256 inputs use exactly 64 hexadecimal characters in either case; the engine normalizes comparisons and emits canonical uppercase values. The
executor adapter MUST compare the path `permit_hash` with
`execution_request.permit_hash` and pass the path value as
`route_permit_hash` to `commit_execution`. Any mismatch fails with
`EXECUTION_PERMIT_MISMATCH` before permit lookup, replay, consumption, or debit.

## 7. Evaluation sequence

The evaluator performs this order:

1. verify the local ledger chain;
2. verify active profile and declaration hashes;
3. reject forbidden operator inputs;
4. verify idempotency;
5. verify grant existence, scope, time, and revocation;
6. verify action, effect, target, and instance scope;
7. resolve authoritative evidence and independently derive the internal
   control results;
8. compute structural-capacity and domain-resource inputs without emitting a
   verdict;
9. engage the two-part gate, whose structural branch decides capacity and whose
   effect branch decides resource admissibility;
10. issue a permit only when both gate bits are true.

A structurally valid evidence item with `INVALID`, `REVOKED`, or `EXPIRED`
status produces a recorded pre-gate `REFUSAL`. A malformed evidence object,
reference, hash, or unknown status is a contract error and produces no business
decision. These outcomes are protocol-fixed and cannot be overridden by the
connection declaration.

The gate equation is:

```text
gate_bit = structural_gate AND effect_gate
```

`effect_gate` is the effect-conditioned domain-resource admissibility gate. It validates the declared effect's resource claim against the active domain profile; it does not execute or simulate the external effect.

Only `gate_bit = 1` produces `ALLOW`.

## 8. Operator result

The operator receives only:

- disposition;
- normalized channel;
- stable message code;
- intent identifier and request hash;
- permit hash and expiry when allowed.

The operator never receives gate geometry, margins, thresholds, sub-verdicts,
reason vectors, retained gate statistics, or architect trace.

The operator `message_code` is fixed by disposition:
`ALLOW` -> `EXECUTION_AUTHORIZED`, `REFUSAL` -> `EXECUTION_DENIED`, and
`MANUAL_REVIEW` -> `HUMAN_REVIEW_REQUIRED`. It never identifies a failed gate
or limit. The
disposition itself remains an unavoidable one-bit decision channel. A production
adapter MUST rate-limit distinct probes per connector and alert on systematic
boundary-seeking sequences.

The disposition alphabet is exactly these three values, and every one is
producible by the reference engine. Integrity failures and availability faults
halt as transport-level errors (HTTP 503 or 400); they are never surfaced as
operator results. `MANUAL_REVIEW` routes work but cannot be consumed by an
executor.

## 9. Reservation and commit

An `ALLOW` result creates a short-lived reservation for the declared
structural cost and domain resource claims. The configured TTL cannot exceed
900 seconds; `expires_at` is capped by the earlier of that TTL, the
authority-grant expiry, and the declaration expiry, and the sealed
`ttl_seconds` is that effective lifetime in whole seconds (rounded up, never
below one), so `issued_at + ttl_seconds` equals `expires_at` to the second. The
executor may consume the permit
once and must present the same connector, declaration, profile, and state
anchor.

Each resource in the profile declares `reservation_required`. When it is true,
an outstanding permit holds that resource's claimed amount against the window
limit until the permit is consumed, released, or expires. When it is false, an
outstanding permit holds nothing for that resource and only committed amounts
count against the window limit. The structural budget is always reserved and is
not affected by this field.

- `COMMITTED` consumes the permit and records structural and domain debits.
- immediately before `COMMITTED`, the engine recomputes committed usage for
  every claimed resource against the trusted current window. If competing
  unreserved permits race, the first admissible commit wins and a later permit
  is invalidated with `RESOURCE_WINDOW_LIMIT`.
- `FAILED` or `ABORTED` consumes the permit but releases the reservation without
  a debit.
- expiry, revocation, integrity failure, or state-anchor mismatch blocks a new
  commit.
- after a successful commit, an exact retry returns the stored receipt without a
  second debit even after permit, grant, or declaration expiry or revocation; a
  changed retry fails.

If a safe fallback is needed, submit it as a new intent. A refusal is never
converted into execution inside the current request.

## 10. Revocation

Governance may revoke a grant at any time. A revocation recorded before commit
invalidates every outstanding permit and reservation issued under that grant.

A new grant does not revive an old permit.

## 11. Registry projection

The optional shared registry may contain only:

- the record's schema version;
- connector, profile, and declaration identifiers, versions, and hashes;
- core anchor;
- status and activation time;
- revocation state;
- latest receipt root and local ledger head hash;
- the registry policy and its forbidden-field list.

The reference projection emits exactly that closed set of fields; a record
whose field set differs is refused as `REGISTRY_DATA_EXPANSION`.

It must not contain raw intent, raw evidence, personal data, reusable
credentials, gate geometry, sub-verdicts, reason vectors, or control-plane
configuration.

Registry lookup is selector-bound. Pass the exact path `connector_id` to
`registry_record`. A different or unknown selector fails with
`CONNECTOR_NOT_FOUND`, maps to HTTP 404, and must never return the active
connector's record under the requested route.

## 12. Reference profiles

### 12.1 Banking

`profiles/banking/bank-profile.json` translates a bank onboarding questionnaire
into the universal fields:

- business scope becomes instance scope constraints;
- permitted actions become the action alphabet;
- amount and aggregate limits become domain resource limits;
- approval prerequisites, immediate blocks, and manual-review conditions become
  typed control flags;
- system boundaries become target and interface declarations;
- audit and ownership sections become evidence and governance obligations;
- failure choices become non-executable dispositions.

Bank financial limits remain domain controls and are not the NC2.5 structural
budget.

### 12.2 Document release

`profiles/document-release/reference-connection.json` is a complete,
non-banking bundle containing a profile, declaration, authority grant, intent,
and evidence. It exercises the same evaluate-to-commit mechanics for an
approved document release with a `document_units` resource claim. This second
profile demonstrates reuse of the protocol mechanics; it does not prove that
arbitrary domains satisfy the admission contract.

### 12.3 OTCS registry

`profiles/otcs/reference-connection.json` is a complete profile, declaration,
operational authority grant, intent, evidence bundle, typed append operation,
and downstream receipt. `sdk/python/nc25_otcs_bridge.py` runs inside this
ledger and preserves the following authority split:

- NC2.5 owns the admissibility atmosphere and is the only component that may
  issue an executable permit.
- OTCS supplies opaque RFC 8785 hashes, legal receipts, and the current project
  head as typed evidence. It does not supply an admissibility result.
- The local `authority_grant_id` and the evidence receipt
  `OTCS_REGISTRY_OPERATING_GRANT` are separate objects with separate roles.
- OTCS performs one project-scoped idempotent compare-and-swap append only
  after the bridge has persisted the live NC2.5 permit-bound request.
- The exact OTCS receipt digest is stored in the local `EXECUTION_RECORDED`
  event and is therefore transitively bound by the returned ledger receipt.

Operational sequence:

1. Resolve the current OTCS head and all required legal receipts.
2. Build the intent, evidence bundle, and typed append operation from the same
   hashes; mismatched bindings fail before the downstream call.
3. Evaluate locally. `REFUSAL` and `MANUAL_REVIEW` stop with no outbox row and
   no OTCS call.
4. For `ALLOW`, persist the exact permit-bound request.
5. Before the first downstream call, verify that the outbox row still belongs
   to the current profile and declaration and that the permit is live. A dead
   permit in `PREPARED` becomes `NOT_EXECUTED`, with no OTCS call.
6. Call the OTCS append port. The production client verifies the receipt
   signature and inclusion proof before returning it; the bridge then validates
   the closed receipt shape and commits the local execution receipt.
7. On an ambiguous response, call `recover(project_id, idempotency_key)` with
   the same project-idempotent OTCS client. A row in `CALLING` or `AMBIGUOUS`
   may replay the exact request only with a live permit. Otherwise stop in
   `RECONCILIATION_REQUIRED` without another OTCS call: neither state proves
   transmission, so a retry could create a first effect after authorization
   expired or was revoked. A changed submission conflicts.
8. Treat a stale expected head as failed execution with no resource debit.
   Obtain a fresh head and submit a new intent if another attempt is required.
9. If OTCS committed but the local permit expired before finalization, stop in
   `RECONCILIATION_REQUIRED`. Do not reclassify the old effect as authorized.

## 13. Production substitutions

| Reference element | Production requirement |
|---|---|
| Reference HMAC permit signer and state HMAC | Asymmetric KMS/HSM signature with custody, rotation, and revocation evidence |
| Optional Ed25519 permit/event envelope | KMS/HSM-backed detached envelope with reviewed key policy and independent verification |
| Versioned permit signature envelope (shipped and tested; key_id-routed verification, rotation, revocation) | Managed key custody source behind the same envelope; key ceremonies and revocation evidence |
| Connector-supplied evidence status | Inject an authoritative evidence resolver; exceptions, malformed output, and intent mismatch fail closed |
| Connector-supplied control booleans | Inject an authoritative control resolver (shipped injection point): derived prerequisite, hard-block, manual-review, and ambiguity results replace the intent flags and bind into the request hash; exceptions and malformed output fail closed |
| In-memory ledger | Transactional append-only or WORM evidence store |
| In-memory idempotency | Durable unique constraint and replay-safe result store |
| Optional SQLite execution receipt replay | Externally managed or replicated result store when multi-node availability is required |
| Required local OTCS SQLite outbox | Transactional, replicated outbox or workflow store preserving exact requests, receipts, and reconciliation state |
| Project-idempotent OTCS append port | Authenticated OTCS client that enforces expected-head compare-and-swap, verifies the receipt signature and inclusion proof, and replays receipts by project plus idempotency key |
| Optional SQLite `committed_resources` history | Managed windowed aggregate with pruning or compaction, replication where required, and trusted time |
| In-process `RLock` | Database or distributed serialization covering reservation, debit, and receipt creation |
| Full-chain verification on every operation | Indexed or checkpointed integrity verification with bounded hot-path cost and independent full audits |
| Process clock | Trusted UTC source with drift monitoring |
| Process reservation | Durable reservation coordinated with downstream commit |
| Function-call roles | mTLS plus enterprise workload identity and scoped OAuth |
| Synthetic evidence URI | Immutable enterprise evidence reference with access control |
| In-process commit | Atomic or compensatable downstream transaction boundary |

## 14. Local verification

From the package root:

```text
python -m pip install --requirement requirements-lock.txt
python -B tests/run_acceptance.py
```

After any intentional package or specification change, rebuild the DOCX first
with `python -B tools/build_universal_specification.py`, regenerate its review
projection with `python -B tools/build_docx_audit_projection.py`, then run
`python -B tools/build_package_manifest.py`, and only then run the
acceptance command. If the change touched the refusal surface - a code added,
retired or newly witnessed - regenerate the failure-surface baseline with
`python -B tools/failure_surface.py --write-baseline` (it refuses to give up a
witness or a code without a stated reason) and the contract's `Error.code`
enum with `python -B tools/build_error_code_enum.py` before the manifest is
rebuilt; the acceptance report's gate rows and failure-surface figures are
then brought to the new numbers and the manifest rebuilt once more, because
the report is itself manifest-bound. The complete order is in README under
"Reproducible release evidence". `PACKAGE-MANIFEST.json` binds every shipped
file, including the normative DOCX, by byte length and SHA-256.

The runner executes the suites in the order declared by `STEPS` in
`tests/run_acceptance.py`, including the OTCS bridge as a separate step.
Before execution, it checks each step name and executable path against its
manifest. The terminal verdict counts every completed step. It launches every
Python subprocess with `-B` and `PYTHONDONTWRITEBYTECODE=1`; the package verifier
runs last and rejects bytecode, pytest caches, and other build artefacts.

Optional pytest collection, without creating cache artefacts:

```text
python -B -m pytest -p no:cacheprovider tests
```

Set `NC25_SOURCES_ROOT` to the directory holding the immutable NC2.5 core to
run strict byte-level checks of the external immutable inputs. When that
variable is absent and the source tree cannot be auto-detected, the verifier
prints `EXTERNAL_SOURCE_CHECKS=NOT_RUN` and checks only the self-contained
package. It never converts an unperformed external check into a pass.

The fixtures are synthetic and use a public test signing key. Passing them
exercises the named reference behaviours; it is not production certification.

The reference engine returns primitive hashes from activation and grant
issuance. An HTTP adapter implementing the OpenAPI contract wraps those values
with their identifiers and status fields; it must not reinterpret the engine
result.

The same adapter must not forward connector-asserted control or evidence truth
values as trusted input. Permit signatures and ledger-event signatures are both
versioned detached envelopes: the permit surface is signed by the pluggable
`permit_signer` (reference default `HmacDetachedSigner`; `Ed25519DetachedSigner`
is a drop-in through the same protocol), and the event chain is signed by the
independent `event_signer`. The SQLite state MAC stays HMAC; substituting it
still requires an explicit reviewed contract version.

When reopening a `state_path` whose persisted event chain contains Ed25519
envelopes, configure the engine with a verifier-compatible `event_signer` using
the same `key_id`. SQLite deliberately persists neither signer configuration nor
private-key material. Omitting the verifier, or supplying one that declares
both an algorithm and a `key_id` and differs from the persisted envelope in
either, fails closed with `EVENT_SIGNER_REQUIRED`. The `EventSigner` protocol
requires only `sign` and `verify`, so a signer that does not declare both cannot be
compared against the envelope at all; for such a signer the mismatch is not
distinguished and reaches the caller as a chain verdict. A signer declaring the
same `key_id` with different key material likewise cannot be told apart from a
forged chain and so fails full-chain integrity verification. The permit signer's verifier registry follows the same rule —
it is process-local runtime configuration, so a restored process must replay
its `rotate_permit_signer` sequence before permits signed under retired
non-revoked keys verify; until then they fail closed with
`PERMIT_KEY_UNKNOWN`. The revoked key set is different: it is part of the
persisted snapshot, revocation survives restart, a revoked `key_id` cannot be
rotated back in, and state restore refuses an engine whose active signer is a
revoked key (`STATE_REVOKED_ACTIVE_KEY`).

## Source-root resolution

`tests/verify_package.py` resolves the package root as `Path(__file__).resolve().parent.parent`; the root is not discovered from the caller's current working directory. The acceptance entry point inherits that fixed source root.

## Temporal causality

Treat the engine clock as authoritative. Reject intent, evidence, or revocation timestamps more than five seconds in the future, and reject an execution timestamp more than five seconds before permit issuance or more than five seconds after trusted commit time. Never derive debits or expiry from a caller-supplied timestamp.

## Resource-window boundary

Committed usage is measured over the closed interval `[now - window_seconds, now]`. A debit timestamped exactly at the lower boundary still counts; it ages out only after the boundary has passed.

## Registry revocation semantics

Registry `status` is the declaration lifecycle state. Registry `revoked` is a connector-level alert that at least one grant revocation exists; it is neither a connector shutdown bit nor an authorization source. Exact grant validity remains local and is rechecked during evaluation and commit.

