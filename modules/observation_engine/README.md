# Observation Engine

A local Lean library and executable for deciding whether a binary target is
determined by an observation over a supplied finite set of compatible cases.

## Scope and limits

- **L1. Declared cases:** definite answers concern exactly the supplied cases.
  An omitted case can change a definite answer to `insufficient_basis`.
  A result about a larger universe requires a separate completeness argument.
- **L2. Supplied meaning:** compatibility, projection keys, and `target_holds`
  values are supplied by the caller. The engine does not establish their truth,
  extract graphs from text, or certify absence of semantic drift.
- **L3. One target:** every case in a request must describe the same binary
  predicate, named by `target`. The name is an identifier, not executable logic.
- **L4. Local computation:** this package makes no runtime authorization decision,
  connects to no external system, and has no persistence or temporal model.
- **L5. Proof boundary:** theorems cover the Lean definitions and finite classifier.
  JSON parsing, I/O, compilation, and the runtime are outside those proofs and
  are exercised separately by executable checks.

The source result is *The Double Fibre of Verification*, version 1.1,
[DOI 10.17605/OSF.IO/Z9E5N](https://doi.org/10.17605/OSF.IO/Z9E5N), sections 2-3.
This implementation transfers Theorem 3.2 statements 1 and 2, Corollary 3.3,
and Proposition 3.4. It does not transfer the entropy equivalence or the
subsequent vector/refinement results.

## Decisions

A query selects cases with exactly the same `(skeleton, observation)` pair.
The selected set is the declared fibre.

| Selected cases | Verdict |
| --- | --- |
| None | `outside_declared_domain` |
| All have target true | `target_true_in_declared_fibre` |
| All have target false | `target_false_in_declared_fibre` |
| Both target values occur | `insufficient_basis` |

Every successful result includes the matching case IDs. A mixed result also
returns one true case and one false case as a witness. Witness selection follows
input order; reordering the same cases preserves the verdict but may select a
different valid pair.

Strings are opaque keys compared as Unicode scalar sequences. JSON escapes are
decoded; Unicode normalization, graph isomorphism, and similarity matching are
not performed. Retaining the skeleton prevents identical observations from
different declared systems being combined.

## Build and run

Requires the exact Lean toolchain pinned in `lean-toolchain`. The package uses
Lean and Std; it has no Mathlib dependency.

When using the NC25OL source package, copy this directory outside the
repository before building: `.lake` output does not belong to the release
manifest. From that build copy with `lake` on PATH:

```text
lake build
lake exe observation-engine examples/mixed.json
```

The executable accepts exactly one file argument. Success is JSON on stdout
with exit code 0, including ambiguous and outside-domain results. Input or I/O
errors are JSON on stderr with exit code 2.

## Input and output

```json
{
  "schema": 1,
  "target": "declared_relation_preserved",
  "worlds": [
    {"id": "a", "skeleton": "system-a", "observation": "projection-x", "target_holds": true},
    {"id": "b", "skeleton": "system-a", "observation": "projection-x", "target_holds": false}
  ],
  "query": {"skeleton": "system-a", "observation": "projection-x"}
}
```

The answer is `insufficient_basis` with `true_world_id: "a"` and
`false_world_id: "b"`. The two cases are observationally identical for this
query and disagree on the supplied target.

Required fields and their types are checked. Unknown fields, duplicate JSON
keys, duplicate case IDs, empty or ASCII-whitespace-only strings, invalid UTF-8,
and unpaired surrogate escapes are rejected. The file limit is 1,048,576 bytes;
the parser permits at most 64 nested containers. These are input limits, not
latency guarantees.

Examples also include homogeneous cases, separated skeletons, and an
incomplete list. Compare `examples/incomplete.json` with `examples/mixed.json`
to see why a definite list result must not be promoted to a universal claim.

## Formal interface

| File | Content |
| --- | --- |
| `ObservationEngine/Observation.lean` | Compatible-world type, visible image, factorization criterion, collision obstruction, logical classifier and maximality |
| `ObservationEngine/Finite.lean` | Executable four-way classifier |
| `ObservationEngine/Correctness.lean` | Exact case characterizations, soundness, explicit completeness premise, agreement with the logical classifier |
| `Main.lean` | JSON boundary and evidence output |
| `Tests.lean` | Executable classification examples |
| `AxiomAudit.lean` | Dependency output for the named theorems |

`finite_agrees_qStar` identifies the executable result with the logical
classifier on the subtype of listed worlds and attained observations.
`toPartial` loses the distinction between unknown and outside-domain; the
agreement theorem excludes the latter by its attained-value premise. Consumers
should use the four-way `Verdict`, as the CLI does.

Classical proofs use Lean's standard foundations where required:
`propext`, `Classical.choice`, and `Quot.sound`. This is not an axiom-free
claim. No additional assumptions are admitted by the dependency check.

## Reproduce the checks

Python 3 is required only for the check runner. Choose a writable scratch
directory outside this project:

```text
python -B verify.py --scratch ../observation-engine-check --mutations
```

The runner rebuilds the library and executable, checks theorem dependencies,
exercises valid and invalid JSON inputs, and tests source mutations in temporary
copies. Logs are written to the selected scratch directory. Real project
sources are not mutated.
