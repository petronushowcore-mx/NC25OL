# Local Spectrum observations

This example collects the supplied finite XIV/XV fixture checks from a locally
installed Spectrum (TECTONICA) checkout and associates the result with a chosen
Ledger registry record. `ObservationSession` accepts an existing trusted Ledger
engine object and an exact connector ID. The command-line demo creates an inactive
synthetic document-release Ledger and runs the real Spectrum checks.

## Scope and limits

The measured subject is Spectrum's supplied finite fixtures. The association is
local context only: it does **not** show that those fixtures model the selected
Ledger declaration. `measurement_to_declaration` remains `NOT_EVALUATED`.

No declaration is activated, no grant or permit is issued, and no Ledger event,
reservation, debit or receipt is created. No network transport, scheduler or live
witness is connected. The report cannot be submitted as an execution request.

A successful report preserves Spectrum's separate transport claims: the supplied
pairing is `ANNIHILATING`, the demonstrated global class is nonzero, and full
Regime W remains `NOT_EVALUATED`. Collection timestamps are wall-clock observations,
not semantic expiry times, event-order proofs or structural time. Structural time
is `NOT_MEASURED`; semantic validity and deployment conditions C1-C4 are not proven.

## Run

Use Python 3.11 or 3.12 and Git. Obtain Spectrum separately under its own licence;
this package contains no Spectrum source. Supply a full Spectrum commit chosen
independently by the operator. All three checkouts must be clean, including ignored
files, and the XIV/XV revisions must match the Spectrum commit's gitlinks. Hidden
index flags are refused. Do not run this against an untrusted repository: its
pinned Python program executes with the current user's permissions.

From the Ledger package root:

```text
python -B examples/spectrum_observation/spectrum_observation.py --spectrum-root <Spectrum checkout> --spectrum-revision <full approved commit> --output <new JSON file outside both source trees>
```

The output parent must exist. Existing files are never overwritten. The JSON is
an observation artifact, not a portable verification token. The CLI prints that
its Ledger is synthetic; an application can construct `ObservationSession` with
its own engine instead, without changing the report's finite-fixture scope.

## Collection and receipt

The collector checks the selected revision, the two layer pins and the seven
source files before and after execution. It checks the six module paths and byte
digests reported by Spectrum, the exact scenario and control-name sets, and the
limited transport verdict. A malformed successful output is refused. A named
Spectrum failure becomes `REFUSED`; an incomplete run or unclassified process
failure becomes `NOT_MEASURED`. Both remain non-executable.

The live session keeps its report digest outside the report. `receive(raw)`
accepts only the exact bytes produced by that session, once, while its source
snapshot and Ledger registry projection still match. A different session cannot
reuse the report. The session stays attached to the engine object provided by
the caller; a report cannot select another engine. An unchanged registry projection
is not a proof that every internal engine field is unchanged.

The caller must serialize session use and keep the trusted checkout quiescent.
The before/after checks are not a filesystem lock: a concurrent change followed
by restoration is outside this example's guarantee. The 60-second child timeout
bounds a single direct child. The output size check happens after capture and is
not a hostile-process memory limit. Durable replay protection, remote identity,
trusted clock attestation and a proof mapping actual deployment objects to these
fixtures require separate implementations. Saving and reopening JSON does not
repeat the live receipt checks.

## Checks

```text
python -B -m unittest discover -s examples/spectrum_observation -p "test_*.py" -v
python -B examples/spectrum_observation/mutate_spectrum_observation.py --scratch <directory outside the package>
```

The offline tests use synthetic process output and controlled source-state probes.
Source mutations run only in temporary copies and require the designated test to
fail first in the full ordered suite. A real Spectrum checkout is a separate
integration prerequisite; offline CI does not certify its presence or its results.
