# Local Spectrum source release

This example runs the separately supplied Spectrum XIV/XV finite-fixture checks,
packages all committed files of its root and both pinned layers, and releases
those exact ZIP bytes through the NC25OL local document gateway. The archive also
contains the original observation and a manifest. No files are selected away to
make the archive smaller.

## Scope and limits

A successful result means that these pinned source bytes produced the expected
supplied-fixture output and that the resulting ZIP reached the authenticated
local document target under a separate synthetic owner decision. It does not
establish correctness of arbitrary Spectrum inputs, real-system exhaustion,
semantic identity, structural time, full Regime W, or a deployed witness network.

The local source repositories and caller are trusted and must remain quiescent.
The inventory compares every tracked regular file to its committed blob without
newline normalization, as well as checking revisions, gitlinks and clean state.
Symlinks, extra nested gitlinks, ignored files and hidden index flags are refused.
Pre/post comparisons are observations, not filesystem locks or protection against
a hostile process changing and restoring bytes during execution. The selected
commits are operator inputs; a commit ID does not authenticate its publisher.

The observation engine is inactive. Its registry record must match the initially
inactive release engine's record exactly. This is equality of declared context,
not an assertion that the two engine instances are the same authority. The
example demonstrates denial before explicitly activating the release fixture
and issuing its grant. A green Spectrum observation grants no authority.

All boundaries of [the local gateway](../local_release/README.md) apply: synthetic
identities and a fixed clock, one serialized owner, separate SQLite stores,
trusted loopback target, and keys retained in the parent process. Reopening stores
is not a full process restart. Recovery repeats the admitted operation and must
produce one target document, one receipt and one debit. Pending operations do
not gain permission from this package. Source changes after collection require
recollection; no calendar-time validity guarantee is inferred from an unchanged
source snapshot.

The ZIP contains the complete committed source trees, not Git history or Git
administrative files. Original source texts and licences are unchanged. Their
licences remain applicable; inclusion does not relicense them under the Ledger
code licence. The source manifest and observation are inside `release/`; the
final ZIP SHA-256 is outside to avoid self-reference. A report hash is an integrity
binding, not a signature or an independent proof that the producer ran the code.

## Run

Use Python 3.11 or 3.12 with Ledger's pinned dependencies installed. Supply a
clean Spectrum checkout with both layers at the root's gitlinks and an explicitly
chosen full root commit. Its working bytes must equal committed bytes, including
line endings. A checkout whose Git filters transform bytes is refused; use a
separate checkout with those transformations disabled, rather than changing a
working research tree. Output must be a new directory outside both source trees.

```text
python -B examples/spectrum_release/spectrum_release.py --spectrum-root /absolute/spectrum --spectrum-revision FULL_COMMIT --output /absolute/new-run
```

`result.json` records the source pins, archive SHA-256 and size, manifest and
observation hashes, both receipts, the denial before activation and the successful
recovery. `spectrum-source-release.zip` is the exact document read back from the
target. The directory also holds three local SQLite stores; distribute the ZIP
and result, not the local database files. Running the command makes no public
upload and registers nothing in OTCS.

The final archive is limited to 2 MiB by the example gateway. Identical source,
manifest and observation bytes rebuild the same ZIP within one Python/zlib
runtime. A new observation has fresh timestamps and an identifier, so a new run
is expected to have a different ZIP hash. Cross-version compressor identity is
not promised.

## Checks

```text
python -B -m unittest discover -s examples/spectrum_release -p "test_*.py" -v
python -B examples/spectrum_release/mutate_spectrum_release.py --scratch /absolute/scratch
python -B -m unittest discover -s examples/local_release -p "test_*.py" -v
python -B examples/local_release/mutate_document_session.py --scratch /absolute/scratch
```

These checks are separate from Ledger's core acceptance suite. Synthetic test
sources exercise the adapter boundaries; the CLI additionally executes the real,
operator-selected Spectrum sources. Source mutations operate on copies and must
fail at their named test before any earlier test does.
