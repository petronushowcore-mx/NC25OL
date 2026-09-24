# Optional observation admission

This example runs the compiled observation engine as an additional control during a new Ledger admission. The module is selected at application startup and is disabled unless explicitly enabled. It does not issue authority or execute an external operation.

## Scope

The engine classifies a binary target over the compatible cases supplied by an application. A definite positive classification can preserve an already true prerequisite. A negative classification makes that prerequisite false. Mixed cases or no matching cases request manual review. Every other prerequisite, hard block, manual-review flag and ambiguity flag remains in force.

The application owns the case provider, its target values, compatibility assumptions and completeness claims. The engine does not extract meaning or establish the truth of those premises. Its result says only what follows within the supplied cases.

The module runs when Ledger evaluates a **new intent**. Idempotent replays return their existing decision, and previously issued permits keep Ledger's normal expiry, revocation and execution rules. Turning this module on does not revoke older permits or add a check at commit time. Obtain a new admission with a new idempotency key when observations change; revoke authority separately when existing permits must stop being usable.

## Build and run

Copy `modules/observation_engine` to a build directory outside this repository, then build that copy with its pinned Lean toolchain. The release manifest covers source files and must not acquire `.lake` build products:

```sh
cd PATH_TO_EXTERNAL_ENGINE_COPY
lake build
```

Set `NC25_OBSERVATION_ENGINE` to the absolute path of `.lake/build/bin/observation-engine` (with `.exe` on Windows), then run from the repository root:

```sh
python -B examples/observation_admission/demo.py --case true
python -B examples/observation_admission/demo.py --case false
python -B examples/observation_admission/demo.py --case mixed
python -B examples/observation_admission/demo.py --case outside
python -B examples/observation_admission/demo.py --disabled
```

Alternatively pass `--engine PATH`. `--scratch DIRECTORY` selects where temporary input files and the example's working directory are created. The directory must already exist.

The positive example calls the real Ledger permit and commit methods and records a **synthetic execution receipt**. The authority, evidence and fixed time come from the document-release fixture. No document is published and no external system is changed. The other enabled cases issue no permit.

## Application wiring

Configure the resolver before constructing `UniversalConnectionLedger`:

```python
resolver = configure_observation_controls(
    enabled=True,
    executable=engine_path,
    prerequisite_id="CONTENT_APPROVED",
    target="declared_content_condition",
    request_provider=provide_cases,
    base_resolver=existing_controls,
    timeout_seconds=5.0,
    scratch_dir=existing_scratch_directory,
)
ledger = UniversalConnectionLedger(
    profile, declaration, signing_key, control_resolver=resolver,
)
```

`provide_cases(intent, now)` returns the engine's complete request object: `schema`, `target`, `worlds` and `query`. Use `observation_query(intent)` for the query. Its skeleton key hashes `intent["binding"]`, and its observation key hashes the complete intent. Every supplied case declares its own keys and a Boolean `target_holds`. The configured target must match the request's target.

When `base_resolver` is omitted, the baseline controls come from the intent, as in the ordinary Ledger path without a resolver. The observation module does not independently validate those other controls. The provider and existing resolver each receive an independent copy of the intent. The selected prerequisite combines the existing Boolean with the definite-positive result using AND. The module never changes a false existing prerequisite into true. `enabled=False` returns the existing resolver unchanged and does not load or call an executable.

## Failure and trust boundary

Enabled configuration probes the native executable before accepting work and pins its bytes for later calls. Input and both output pipes have size limits; each direct child has a timeout. Changed or missing binaries, invalid output, mismatched query/target, process failure and provider failure cannot fall back to caller-supplied flags. During admission Ledger reports resolver failure as `CONTROL_RESOLUTION_FAILED` and issues no permit.

The executable and callbacks are trusted startup configuration. Byte pinning compares the executable with its startup digest immediately before and after each call. It does not detect a replacement restored between those checks, authenticate the publisher, or sandbox a malicious program. The process helper bounds the direct child and its pipes, not an arbitrary descendant process tree. Startup configuration must not be request-controlled.

Ledger binds the resulting control maps into the permit request hash. It does **not** retain the complete case list, raw engine report or an independent observation certificate. Applications needing later reconstruction must retain their observation evidence separately. No new permission or external authority is implied by that retained evidence.

## Checks

With `NC25_OBSERVATION_ENGINE` set to the real built executable:

```sh
python -B examples/observation_admission/test_observation_admission.py -v
python -B examples/observation_admission/mutate_observation_admission.py --scratch EXISTING_DIRECTORY
```

The tests refuse to run without a native executable. They exercise the four classifications, real Ledger admission and commit, authority controls, callback isolation, request/output binding, malformed data, timeout, bounded output, binary changes, and durable replay semantics. The mutation command alters temporary source copies and requires the named test to be the first failure. It never changes the working implementation.