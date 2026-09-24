# Spectrum and NC25OL: one local source release

On 23 September 2026, Spectrum's supplied XIV/XV fixtures were executed from
pinned source trees. NC25OL then admitted a separate operation: storing the
complete source ZIP and its observation in an authenticated local document target.
The original machine result is [result.json](result.json).

## Observed result and limits

Before a separate synthetic owner activation, the release was refused with
`DECLARATION_NOT_ACTIVE`. After activation it committed. Reading back the target
returned the exact archive bytes. Recovery returned the same receipt with one
document, one target receipt and one debit. The fixture's structural budget went
from 400 to 360.

Spectrum reported 15 supplied scenarios and 28 control rows. The pairing verdict
was `ANNIHILATING`; `global_class_zero` was false and `full_regime_w` was
`NOT_EVALUATED`. These are separate statements, preserved in the machine result.

This is a local example using synthetic authority and a fixed authority clock.
It does not certify arbitrary systems, real-system exhaustion, semantic identity,
structural time, deployment conformance or a live witness network. Source trees
and the local caller are trusted and quiescent; pre/post comparisons are not
filesystem locks. Reopening stores retains keys in the parent process rather
than recovering authority after a full process restart. Hashes bind bytes;
they are not publisher signatures. `publicly_published: false` records that the
example did not upload its source archive to a public service.

## Exact source versions

| Repository | Commit |
| --- | --- |
| [Spectrum](https://github.com/petronushowcore-mx/TECTONICA) | `c884b02a26adc188bb71ff42ce59f19322562e5a` |
| XIV submodule | `d03e16a3094996bf5d2947e3b1ee073b102573ee` |
| XV submodule | `73b6a0c25bf0a92cc64ff3357d08d9e60b398f7d` |

The observed archive contained 56 committed source files, plus its manifest and
observation. Its size was 1005288 bytes and SHA-256 was
`09bba8c533469f3a666157ca14a167756b0d16b3989892d06d3d1ebe4b927465`.
This result records that local artifact; the archive is not included here.
`result.json` records its manifest and observation hashes and both receipts.
`document_payload_hash` is the gateway's hash of document name and encoded
bytes, not the ZIP SHA-256.

## Reproduce

Use Python 3.11 or 3.12. Create a separate Spectrum checkout without newline
transformations and select the root commit above; its gitlinks select both layers:

```text
git -c core.autocrlf=false clone https://github.com/petronushowcore-mx/TECTONICA.git spectrum
git -C spectrum config core.autocrlf false
git -C spectrum checkout --detach c884b02a26adc188bb71ff42ce59f19322562e5a
git -C spectrum -c core.autocrlf=false submodule update --init --recursive
```

From the NC25OL package root, with absolute paths to that checkout and a new
output directory outside both source trees:

```text
python -m pip install --require-hashes -r requirements-lock.txt
python -B tests/verify_package.py
python -B examples/spectrum_release/spectrum_release.py --spectrum-root /absolute/spectrum --spectrum-revision c884b02a26adc188bb71ff42ce59f19322562e5a --output /absolute/new-run
python -B -m unittest discover -s examples/spectrum_release -p "test_*.py" -v
python -B examples/spectrum_release/mutate_spectrum_release.py --scratch /absolute/scratch
```

The command runs the real pinned Spectrum sources, writes a new local source ZIP
and result, and verifies admission, exact target bytes and recovery. No public
upload or OTCS registration is performed. Each fresh observation has new
timestamps and an identifier; each local session has fresh signing keys. A rerun
is expected to produce different archive and receipt hashes. Rebuilding from the
same source, observation and manifest bytes is deterministic within one
Python/zlib runtime.

The NC2.5 core is not included. Without the separately supplied core, package
verification reports external-core checks as `NOT_RUN`; it does not reproduce
the private strict-core verification.

## Licences

This result, the machine result and the example code fall under the MIT terms
for `examples/` in the root [LICENSE](../../LICENSE). The Ledger documents
listed there have separate CC BY 4.0 terms. Spectrum and its layers remain
separate works under their own CC BY-NC-ND 4.0 terms. No Spectrum source is
relicensed by this example.

Maksim Barziankou (MxBv), The Urgrund Laboratheory.
