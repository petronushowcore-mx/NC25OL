# Domain Profile Authoring Checklist

Use this checklist before sealing a profile.

## Expressibility boundary

- The domain can be represented by a closed action alphabet, declared effect
  classes, boolean control results, non-negative integer resource claims,
  typed evidence, and the existing role-separated runtime contract.
- If that representation would erase a material domain fact or weaken a
  fail-closed rule, stop and design a new reviewed schema version.
- Do not infer admission from similarity to the banking or document-release
  examples.

## Domain typing

- Every action has one stable identifier.
- Every action maps to exactly one declared effect class.
- Every instance declaration maps each selected action to a non-empty subset
  of its declared target systems; no action-target pair is inferred from two
  independent allowlists.
- Every referenced effect class exists.
- Every required resource exists in the resource catalog.
- No duplicate action, effect, resource, control, or evidence identifier exists.
- The zero-cost fallback action exists, has no required resource claim, and maps
  to a non-mutating effect class.

## Controls and evidence

- Required prerequisites are complete and objectively testable.
- Control coverage holds in both directions: every admitted transition reads
  clean, and every clean reading corresponds to an admitted transition. A
  detector that cannot see a prohibited transition returns a clean reading
  that certifies nothing. This package has no distinct forbidden-effect
  declaration type: a prohibited action, effect, or target is expressed by
  omission from the declaration's admissible scope (refused as
  `ACTION_OUT_OF_SCOPE` / `EFFECT_OUT_OF_SCOPE` / `TARGET_OUT_OF_SCOPE`),
  and a prohibited condition within an admitted action is expressed by a
  hard-block or manual-review flag. Confirm every transition the domain
  forbids is caught by one of these surfaces; the distinct-type obligation of
  the NC2.5 core (crosswalk `CORE-EFFECT-SPACE`) remains with the core.
- Hard blocks are distinct from manual-review flags.
- Manual-review flags never produce `ALLOW`.
- Every action is covered by at least one evidence requirement.
- Evidence types name immutable evidence, not reusable credentials.
- `failure_posture` contains exactly `missing_required_data: REFUSAL` and
  `ambiguity: MANUAL_REVIEW`; these are protocol-fixed mirrors, not profile
  choices.
- The declaration does not carry an instance-level `failure_posture` override.
- Connector-supplied evidence status and control booleans are treated as
  untrusted claims, never as authority.
- The production evaluator resolves evidence through approved authoritative
  systems, verifies provenance and hashes, and derives prerequisite,
  hard-block, and manual-review results inside its own trust boundary.
- Resolved evidence and derived controls are bound to the exact request and
  current-state anchor before the gate runs.

## Structural budget

- The declaration codes the origin of its capacity with the published
  four-value instrument: fully stipulated, empirically calibrated, derived
  from a load model, or mixed (NC2.5 Probe II, DOI 10.17605/OSF.IO/7SQMY, R2).
- A capacity written into configuration is `fully_stipulated`. That is a
  legitimate coding, not a defect — and it leaves the relation between the
  configured threshold and the system's actual exhaustion capacity as a
  separate, undischarged obligation.
- A declaration claiming `empirically_calibrated`, `derived_from_load_model`,
  or `mixed` references its calibration or model evidence in
  `evidence_refs`.
- The reset regime is declared: a new declaration version starts a fresh
  budget, and any cross-version continuation claim names the external ledger
  that carries it.

## Mapping witness

- The witness covers every action and effect class.
- The method explains the action-to-effect and effect-to-control mapping.
- The witness cites immutable evidence references and hashes.
- Similarity to another connector is not used as proof.
- The witness hash is calculated over the canonical witness object with the
  `witness_hash` field omitted.

## Interface separation

- Governance, operator, executor, and architect scopes are distinct.
- Observer output is a non-mutating projection.
- Operator inputs and outputs exclude boundary geometry, margins, thresholds,
  sub-verdicts, reason vectors, statistics, and architect trace.
- The connector cannot write the profile, declaration, gate, or architect
  store.

## Change and registry policy

- Material changes require a new version and hash.
- Live gate override is disabled.
- The NC2.5 core obligation against unlimited micro-revision
  (crosswalk `A53-A59-REVISION`) is a governance duty outside this package:
  the reference engine bounds no revision count and, since a new declaration
  version starts a fresh accounting instance, an unbounded revision chain both
  evades that obligation and refills the structural budget. A deployment that
  relies on revision finiteness declares and enforces a revision budget or
  predecessor-chain bound in its own governance layer.
- The shared registry policy is hash-only.
- Raw intent, evidence, personal data, reusable credentials, gate internals,
  and control-plane configuration are forbidden from the registry.

## Production evidence

- Workload identity and mTLS trust chain.
- KMS/HSM custody, rotation, and revocation.
- Versioned signature envelope with algorithm, key identifier, and signature
  bytes.
- Trusted time and drift monitoring.
- Durable idempotency and reservations.
- Authoritative evidence resolvers and independently derived control results.
- Downstream atomicity or a verified compensation boundary.
- Append-only or WORM retention and restore evidence.
- Positive and negative connection tests.

## Local validation

JSON Schema validation is a mandatory ingress gate; the engine command below is
semantic validation only. The shipped conformance suite exercises both layers
and reports `NOT_RUN`, never a pass, when its schema libraries are absent.

From the package root:

```text
python -B tests/test_contract_conformance.py
python -B -c "import sys; sys.path.insert(0, 'sdk/python'); from nc25_universal_ledger import load_json, validate_profile; validate_profile(load_json(sys.argv[1])); print('PROFILE_VALID')" profiles/banking/bank-profile.json
```

## Control-class disjointness

- [ ] `required_prerequisite_ids`, `hard_block_flag_ids`, and `manual_review_flag_ids` are pairwise disjoint.
- [ ] Moving an identifier between classes is treated as a profile revision and rebinding event.
