# Spectrum and NC25OL: one local source release

On 18 October 2026, Spectrum's supplied XIV/XV fixtures were executed from the
pinned source trees of the Tectonica Spectrum release `v00.09.02`. NC25OL then
admitted a separate operation: storing the source ZIP and its observation in an
authenticated local document target. The original machine result is
[result.json](result.json).

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
| [Spectrum](https://github.com/petronushowcore-mx/TECTONICA), tag `v00.09.02` | `8fdd50badcae0bf810ef9967a64a18a7127f8d83` |
| XIV submodule | `d03e16a3094996bf5d2947e3b1ee073b102573ee` |
| XV submodule | `73b6a0c25bf0a92cc64ff3357d08d9e60b398f7d` |

The observed archive contained 86 committed source files of the root and the
XIV and XV layers, plus its manifest and observation. Its size was 624989 bytes
and its SHA-256 was
`1cb18c1ae6676bbc747bc6b4f92a8ef77fb1e59dedcc398c330a7807a7bf4ca7`.
This result records that local artifact; the archive is not included here.
`result.json` records its manifest and observation hashes and both receipts.
`document_payload_hash` is the gateway's hash of document name and encoded
bytes, not the ZIP SHA-256.

Two committed files of the root end with an image suffix. The manifest records
them instead of packaging them:

| Path | Size | Git blob | SHA-256 |
| --- | --- | --- | --- |
| `assets/layers.gif` | 3141531 | `ba161674f4ad3dcecd0393738e7d778ea8310c9a` | `95d513ea3e5a440fd40beba5df473b445b338a1023014e725bf7be5572d8f196` |
| `assets/layers.png` | 1351911 | `f959ac0041cae11720459bc5af6084fb3038c6c4` | `47aa96bae7a4ee5055ef1dd1448375276a3b09eb98ba6e8808ff455db072f58c` |

The other five root gitlinks are recorded by path and commit only; their trees
were not read, packaged or run:

| Path | Commit |
| --- | --- |
| `layers/DoubleFibre` | `fed7eed1736d29733bdee0b4b000eed2e87d37cd` |
| `layers/Identity` | `6b981f322f9b4ae5fb6181f77f27b8ef759096d5` |
| `layers/NCNC` | `f93e44c162c8143c5c45fb7c558784ce6f5ff7a5` |
| `layers/Person` | `37f6598edeb036c531b04f4b855203df8499c953` |
| `layers/PoA` | `7b46eac803cd4073e5478bb383fc9b1f384001b7` |

## Reproduce

Use Python 3.11, 3.12 or 3.14; the recorded run used Python 3.12.9 in a new
environment installed from `requirements-lock.txt`. Create a separate Spectrum
checkout without newline transformations: the root at the tag, then the two
layers at the root's gitlinks. The other gitlink directories stay empty.
`git clone --revision` needs Git 2.49 or later.

```text
git clone -c core.autocrlf=false -c core.eol=lf --branch v00.09.02 https://github.com/petronushowcore-mx/TECTONICA.git spectrum
git clone -c core.autocrlf=false -c core.eol=lf --revision=d03e16a3094996bf5d2947e3b1ee073b102573ee https://github.com/petronushowcore-mx/NC2.5-ONTOSigma-XIV-Cross-Layer-Forgetful-Separation-corpus.git spectrum/layers/XIV
git clone -c core.autocrlf=false -c core.eol=lf --revision=73b6a0c25bf0a92cc64ff3357d08d9e60b398f7d https://github.com/petronushowcore-mx/NC2.5-ONTOSigma-XV-Spin-Channel-and-Nestability-corpus.git spectrum/layers/XV
```

From the NC25OL package root, with absolute paths to that checkout and a new
output directory outside both source trees:

```text
python -m pip install --require-hashes -r requirements-lock.txt
python -B tests/verify_package.py
python -B examples/spectrum_release/spectrum_release.py --spectrum-root /absolute/spectrum --spectrum-revision 8fdd50badcae0bf810ef9967a64a18a7127f8d83 --output /absolute/new-run
python -B -m unittest discover -s examples/spectrum_release -p "test_*.py" -v
python -B examples/spectrum_release/mutate_spectrum_release.py --scratch /absolute/scratch
```

The command runs the real pinned Spectrum sources, writes a new local source ZIP
and result, and verifies admission, exact target bytes and recovery. No public
upload or OTCS registration is performed. Each fresh observation has new
timestamps and an identifier; each local session has fresh signing keys. A rerun
is expected to produce different archive and receipt hashes. The observation in
the archive also records `collection.stdout_sha256`, the hash of the Spectrum
runner's output, and that output depends on the absolute path of the Spectrum
checkout, so the same commit checked out elsewhere gives another value.
Rebuilding from the same source, observation and manifest bytes is
deterministic within one Python/zlib runtime.

The NC2.5 core is not included. Without the separately supplied core, package
verification reports external-core checks as `NOT_RUN`; it does not reproduce
the private strict-core verification.

## Licences

This result, the machine result and the example code fall under the MIT terms
for `examples/` in the root [LICENSE](../../LICENSE). The Ledger documents
listed there have separate CC BY 4.0 terms. Spectrum and its layers remain
separate works under their own terms: CC BY-NC-ND 4.0, except the Probe VI
companion in Spectrum's `layers/ProbeVI`, which keeps its MIT licence. No
Spectrum source is relicensed by this example.

Maksim Barziankou (MxBv), The Urgrund Laboratheory.
