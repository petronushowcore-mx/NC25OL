# Local Spectrum source release

This example runs the separately supplied Spectrum XIV/XV finite-fixture checks,
packages the committed source files of its root and both pinned layers, and
releases those exact ZIP bytes through the NC25OL local document gateway. The
archive also contains the original observation and a manifest. One rule keeps
files out of the archive: a committed regular file of the root, XIV or XV whose
path ends with `.gif`, `.png`, `.jpg`, `.jpeg` or `.webp`, compared without regard
to case, is recorded in the manifest instead of packaged. Every other committed
regular file of those three trees is packaged, or the run is refused. A path is
read as Git lists it, without normalization: an absolute path, a backslash, a
colon, or an empty, `.`, `..` or `.git` part gives `SOURCE_PATH`. The archive path
of a root file is its path; the archive path of a layer file has the prefix
`layers/XIV/` or `layers/XV/`. Archive paths are compared without regard to case:
two equal archive paths, or an archive path beginning with `release/`, give
`SOURCE_PATH_COLLISION`. A layer's own `release/` directory is therefore packaged
under its layer prefix.

## Scope and limits

A successful result means that these pinned source bytes, read from a checkout
that stayed quiescent during the run (see below), produced the expected
supplied-fixture output and that the resulting ZIP reached the authenticated
local document target under a separate synthetic owner decision. It does not
establish correctness of arbitrary Spectrum inputs, real-system exhaustion,
semantic identity, structural time, full Regime W, or a deployed witness network.

Coverage is the root and the XIV and XV layers. Root gitlinks other than
`layers/XIV` and `layers/XV` are accepted and listed in the manifest under
`pinned_layers_not_packaged` by path and commit only. The inventory does not
list, read or package their trees, the observation does not run them, and
nothing is claimed about their content. The example does not check that the
commit of such a gitlink exists in its own repository; the commit is recorded as
the root tree declares it. XIV and XV are different: each must be checked out at
the root's gitlink (`SOURCE_REVISION`), and its tree is read from that commit.

Excluded files are read from Git and from the checkout and pass the same blob,
size, path and checkout-byte checks as packaged files, including the 16 MiB limit
on every committed blob: a larger file, excluded or not, is refused with
`SOURCE_BLOB`. The rule looks at the path suffix only, not at the content, so a
text file whose name ends with an image suffix is excluded as well. The manifest
lists each under `excluded_files` with its path, mode, Git blob, size, SHA-256 and
the reason `IMAGE_SUFFIX`. Their bytes are not in the archive; a recipient can
compare them only with a separate copy of the same commits.

The local source repositories and caller are trusted and must remain quiescent.
The inventory compares every tracked regular file to its committed blob without
newline normalization, as well as checking revisions, gitlinks and clean state.
Symlinks, gitlinks inside XIV or XV, ignored files and hidden index flags are
refused. These comparisons are observations, not filesystem locks or protection
against a hostile process changing and restoring bytes during execution. The
inventory is collected three times: when the release is prepared, again right
after the observation, and again before submission; each collection checks every
file against its blob between two snapshots of the repositories. The observation
runs the stitch from the checkout by path between the first and the second
collection: the runner and the modules it imports are read when the child process
starts. A file replaced after the first collection and restored before the second
is not detected, so a successful result is evidence about the committed bytes only
while the checkout stays quiescent.
Running the stitch from the committed Git objects instead of the checkout would
remove this assumption; this example does not do so. The selected commits are
operator inputs; a commit ID does not authenticate its publisher.

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
not gain permission from this package. Source changes after collection,
including changes to excluded files or pinned-only gitlinks, require
recollection; no calendar-time validity guarantee is inferred from an unchanged
source snapshot.

The ZIP contains the packaged committed source files, not the files excluded by
their image suffix, Git history or Git administrative files. Original source
texts and licences are
unchanged. Their licences remain applicable; inclusion does not relicense them
under the Ledger code licence. The source manifest and observation are inside
`release/`; the final ZIP SHA-256 is outside to avoid self-reference. A report
hash is an integrity binding, not a signature or an independent proof that the
producer ran the code.

## Run

Use Python 3.11, 3.12 or 3.14 with Ledger's pinned dependencies installed. Supply a
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
recovery, together with the number of excluded files and the pinned-only layers.
`spectrum-source-release.zip` is the exact document read back from the target.
The directory also holds three local SQLite stores; distribute the ZIP and
result, not the local database files. Running the command makes no public upload
and registers nothing in OTCS.

The final archive is limited to 2 MiB by the example gateway. The exclusion rule
does not change that limit; a larger archive is refused with `ARCHIVE_SIZE`.
Identical source, manifest and observation bytes rebuild the same ZIP within one
Python/zlib runtime. A new observation has fresh timestamps and an identifier, so
a new run is expected to have a different ZIP hash. Cross-version compressor
identity is not promised.

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
