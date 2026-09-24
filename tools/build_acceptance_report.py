from __future__ import annotations

import argparse
import json
import math
from datetime import datetime
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(Path(__file__).resolve().parent))
from spec_counts import acceptance_gate_rows, spec_docx_name  # noqa: E402

sys.path.pop(0)

# The rules this generator applies - the verifier's check ids and the rule for
# the two bound digests - are those of the tree the generator ships in, imported
# once here. A `root` parameter below names the tree whose DATA a report binds
# (manifests, baseline, report, document name); it never loads code from that
# tree, which would execute a data directory's scripts and, through
# `sys.modules`, silently reuse whichever tree imported them first.
sys.path.insert(0, str(ROOT / "tests"))
import verify_package  # noqa: E402
import run_acceptance  # noqa: E402
from run_acceptance import bound_bytes  # noqa: E402

sys.path.pop(0)
# `sys.path` decides where a module is FOUND, not which one is BOUND: a module of the same
# name already in `sys.modules` is handed over untouched, and the sentence above would then
# be describing another tree's rules. Measured: a planted `verify_package` with no file at
# all was what this generator bound. Each of the two is held to a file in this tree's
# `tests`, by resolved parent, so a same-named module from anywhere else is refused here
# rather than published as this tree's ids and digest rule.
if getattr(verify_package, "__file__", None) is None or Path(
    verify_package.__file__
).resolve().parent != (ROOT / "tests").resolve():
    raise SystemExit("ACCEPTANCE_VERIFIER_MODULE_FOREIGN")
if getattr(run_acceptance, "__file__", None) is None or Path(
    run_acceptance.__file__
).resolve().parent != (ROOT / "tests").resolve():
    raise SystemExit("ACCEPTANCE_RUNNER_MODULE_FOREIGN")

REPORT_PATH = ROOT / "ACCEPTANCE-REPORT.md"
GATE_ROWS = {
    "functional_behaviour": "Functional behavior across all three reference profiles",
    "semantic_contracts": "Semantic contracts",
    "safety_mutations": "Named safety mutations",
    "contract_conformance": "JSON Schema and OpenAPI conformance",
    "contract_regressions": "Contract regression cases",
    "otcs_bridge": "OTCS bridge behaviour and refusal vocabulary",
    "failure_surface_ratchet": "Failure-surface ratchet",
    "package_verifier": "Package integrity checks",
}


def plural(count: int, noun: str) -> str:
    """Agree a regular noun with its count.

    One home for the REGULAR rule, because the figures paragraph and the
    geometry sentence each carried their own and only one of them was ever
    applied. The geometry noun is irregular and is decided beside its own
    sentence by `geometry_word`; it does not pass through here, and its justification lives
    beside it rather than as a second home for this rule.

    These nouns bypass this helper, each justified where it stands: the irregular
    `geometry_word`; the emission-point noun in the figures paragraph, frozen on purpose
    for the counts that share it; and "hard findings" in the document sentence, whose count
    the gate admits only as zero. `witnessed` in the figures paragraph bypasses nothing: it
    has no noun of its own and borrows the one agreed before it. Named, not counted - a
    number in prose beside a list is a second copy of it. An earlier form of this docstring
    named the first as "the stated exception", which reads as the complete list and is not.
    """
    return noun if count == 1 else f"{noun}s"


def load_json(path: Path) -> dict[str, Any]:
    """Read one piece of evidence, answering by name whatever is wrong with it.

    Reading and parsing used to sit in one expression, and the two failures that expression
    can produce left the vocabulary: a missing or unreadable file as `OSError`, a file whose
    bytes are not JSON as `JSONDecodeError`. Both were conceded in a test comment as
    "outside that world", and a concession is disclosure rather than closure - the caller
    still met a raw exception where every neighbouring failure has a name.

    The label carries the file, because five call sites share this function: a refusal
    saying only that some evidence was unreadable sends a reader to open all five.

    Both clauses name a CLASS and not the failures that were observed, because the first
    form of this function caught the two that had been seen and let the next two out.
    Reading bytes into text fails for reasons of the file - absent, locked, denied - and
    for reasons of its ENCODING; turning text into data fails for reasons of syntax and
    for reasons of DEPTH. All four are properties of the evidence rather than of this
    program, so all four answer in the evidence's vocabulary. Measured, because the type
    hierarchy is what decided the first form: `UnicodeDecodeError` is a `ValueError` and
    NOT an `OSError`, so it passed the read clause untouched; `RecursionError` is a
    `RuntimeError`, so it passed the parse clause the same way.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise ValueError(f"EVIDENCE_FILE_UNREADABLE: {path.name}") from None
    try:
        value = json.loads(raw)
    except (ValueError, RecursionError):
        # `JSONDecodeError` is a `ValueError`, so this catch is the parser's whole class
        # rather than one of its names, and the message is ours instead of the parser's
        # position report - which named a byte offset in a file the reader cannot see.
        # `RecursionError` is beside it because nesting deeper than the interpreter's
        # limit is a property of the bytes, not a fault in this reader.
        raise ValueError(f"EVIDENCE_JSON_INVALID: {path.name}") from None
    if not isinstance(value, dict):
        raise ValueError("EVIDENCE_JSON_OBJECT_REQUIRED")
    return value


def _finite_double(value: float) -> bool:
    """Is this a finite value of the kind a page dimension is read as?

    `math.isfinite` converts to a C double and raises OverflowError on an integer wider
    than one. That overflow IS the answer - a number that cannot be a double is not a
    finite double - so it is returned rather than raised, and the caller keeps its own
    named refusal instead of meeting the parser's exception.
    """
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def require_collection(value: Any, label: str) -> int:
    """How many entries, refusing anything that merely has a length.

    The figures below were `len(baseline[key])`, and `len` is true of a string and of a
    mapping as well as of the collection the key is supposed to hold. Measured: a bare
    string published as one code, a mapping likewise, from a baseline carrying no
    collection at all. A string is excluded deliberately rather than incidentally - it is
    the shape a scalar takes when it lands under a key meant for a list.

    Each entry is a NAME, and the figure published beside it is a count of names: every
    one of the nine collections this reads is a list of code names or of emission points,
    measured off the shipped baseline. Raw `len` counted whatever the file listed, so a
    name written twice published as two codes - measured, `["X", "X"]` answered 2 - and a
    figure the report calls a count of codes would have been a count of entries. Entries
    are required to be non-empty strings and to be distinct; the scanner that writes the
    baseline builds these lists from a set, so this cannot fire on a file of ours, and it
    is the reader that publishes the number.
    """
    if not isinstance(value, (list, tuple)):
        raise ValueError(label)
    if not all(isinstance(entry, str) and entry for entry in value):
        raise ValueError(label)
    if len(set(value)) != len(value):
        raise ValueError(label)
    return len(value)


def require_non_negative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(label)
    return value


def read_report(path: Path) -> str:
    """Read the report a run is about to rewrite, answering by name for what reading can do.

    The report is an INPUT to both halves as well as their output - its sections are
    rewritten in place - and both halves read it with a bare `read_text`, beside a
    `load_json` that names every way the evidence files can fail to read. So a report that
    was missing, locked or not UTF-8 left the generator as a raw OSError or
    UnicodeDecodeError, while the sweep's comment said only `bound_bytes` remained outside.
    The same two failure classes as `load_json`'s read, under the report's own code.
    """
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise ValueError(f"REPORT_UNREADABLE: {path.name}") from None


def write_through_temporary(path: Path, text: str) -> None:
    """Write a file through a neighbouring temporary, leaving none behind on any path this
    code runs.

    Both writers in this module used to carry these two statements in line, and both
    carried the same hole: with the replace raising - a locked destination, a device
    error - the temporary written a moment earlier stayed behind, against a sentence
    promising no residue. One writer even named the hole in a comment, which is
    disclosure and not closure; the other said nothing.

    `finally` and not an `except`, because the paths that leave residue are not only
    exceptions: an interrupt between the two statements does it too. After a successful
    replace the name is released at once: the file has moved, so whatever stands at that
    name afterwards is not this call's, and the `finally` used to remove it all the same -
    a file another writer had put there in between would have gone. `missing_ok` stays
    for a temporary something else has already removed.

    The temporary's NAME belongs to this call alone. It was `<report>.tmp`, shared by every
    writer of the same report, and the `finally` above turned that from a race into a
    hazard: removing a name is not removing MY file, so one writer could delete the
    temporary another was about to replace. `mkstemp` in the report's own directory - the
    same volume, so the replace stays a rename - gives each call a file nobody else holds.
    Two writers of one report still race for which text lands last; what they no longer
    do is destroy each other's temporaries.

    Everything after `mkstemp` names its file runs inside the `try`: closing the handle and
    building the path used to stand before it, so an interrupt there left the temporary.
    The windows no statement here can close: inside `mkstemp` itself, between the file
    being created and its name being returned; and between the replace returning and the
    name being released on the line after it, where an interrupt would still remove a
    file some other writer created at that name in that instant.
    """
    name = None
    try:
        handle, name = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
        os.close(handle)
        temporary = Path(name)
        temporary.write_text(text, encoding="utf-8", newline="\n")
        temporary.replace(path)
        name = None
    finally:
        if name is not None:
            Path(name).unlink(missing_ok=True)


def replace_once(text: str, pattern: str, replacement: str, label: str,
                 count_pattern: str | None = None) -> str:
    """Replace a pattern that occurs exactly once, and refuse any other count.

    The first form counted with `re.subn(..., count=1)`, which stops after the
    first substitution and reports one, so it refused an ABSENT pattern and
    accepted a DOUBLED one - quietly rewriting the first of two. The name said
    once; the code meant at least once.
    The count now comes from `re.findall` before anything is rewritten; the
    rewrite's own count is asked as well, for the reason below.
    """
    # What must occur once is not always what gets rewritten. A caller that substitutes a
    # well-formed value can pass the CLAIM as `count_pattern`: counting the well-formed
    # occurrences alone made a duplicate carrying a malformed one invisible, and the
    # rewrite then saved a document with both copies - measured, with 64 lowercase
    # characters as the second digest.
    # And the substitution is counted too, because the two patterns can disagree. With a
    # `count_pattern` the claim is counted and the DIGEST is rewritten, so a sole
    # occurrence carrying a malformed digest satisfies the count and matches nothing to
    # replace: before `count_pattern` existed that document was refused `:0`, and after
    # it the function returned the text unchanged while `rebind_report_to_manifest`
    # reported the new digests as though they had been written. A loud refusal traded for
    # a silent no-op. `:0` is the same detail the absent case carried, and it is
    # the right one: nothing was replaced.
    occurrences = len(re.findall(count_pattern or pattern, text, flags=re.MULTILINE))
    if occurrences != 1:
        raise ValueError(f"{label}:{occurrences}")
    rewritten, substitutions = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if substitutions != 1:
        raise ValueError(f"{label}:{substitutions}")
    return rewritten


def replace_section(
    text: str, heading: str, next_heading: str, section: str, label: str
) -> str:
    """Replace the one section under `heading`, up to `next_heading`.

    Counted by its heading line, not by matches of the block: the block
    pattern is lazy, so a second copy of the heading sits inside the first
    match and a doubled section was counted as one, with `count=1` hiding the
    rest - the same "at least once" that `replace_once` above was written to
    refuse. The detail is the heading count when it is not one, and the
    number of replaceable blocks otherwise. The section text is inserted
    literally, not as a replacement template.
    """
    occurrences = len(re.findall(rf"^{re.escape(heading)}$", text, flags=re.MULTILINE))
    pattern = rf"^{re.escape(heading)}\n\n.*?(?=\n\n{re.escape(next_heading)}$)"
    blocks = len(re.findall(pattern, text, flags=re.DOTALL | re.MULTILINE))
    if occurrences != 1 or blocks != 1:
        raise ValueError(f"{label}:{occurrences if occurrences != 1 else blocks}")
    return re.sub(
        pattern, lambda _match: section, text, count=1, flags=re.DOTALL | re.MULTILINE
    )


def rebind_report_to_manifest(root: Path = ROOT) -> tuple[str, str]:
    """Point the shipped report's two digests at the tree as it stands now.

    The report names the bytes it certifies, and the verifier refuses a report
    whose digests disagree with a recompute. That is right, and it makes a
    bootstrap: after any edit, the report is stale, so the verifier fails, so
    acceptance fails, so this generator - which refuses to run on a failed
    acceptance - cannot produce the corrected report. The way through is to set
    the two digests to the truth first, run acceptance, and let the generator
    then rewrite the whole report authoritatively over them.

    The operation takes both values from `bound_bytes` rather than recomputing
    them. The rule is this generator's own; `root` names the tree whose manifest
    and report it reads and writes.

    Returns the two digests it wrote, so a caller can report them.
    """
    manifest = load_json(root / "PACKAGE-MANIFEST.json")
    digest, document = bound_bytes(manifest)
    # The manifest digest is a `hexdigest` of the entries and cannot take
    # another shape. The document digest is the manifest's own field, read
    # unchecked, and it goes into a substitution template below: a backslash
    # there is a template escape, and any other shape would be written into
    # the report as the document's name.
    if not isinstance(document, str) or not re.fullmatch(r"[A-F0-9]{64}", document):
        raise ValueError("REBIND_DOCUMENT_DIGEST_SHAPE")
    report_path = root / "ACCEPTANCE-REPORT.md"
    source = read_report(report_path)
    # `replace_once` and not a bare `sub`: a report carrying the sentence twice
    # is a defect the verifier now names, and rewriting the first of two would
    # hide it here instead.
    source = replace_once(
        source,
        r"(every entry except this report, digest to `)[A-F0-9]{64}(`)",
        rf"\g<1>{digest}\g<2>",
        "REBIND_MANIFEST_DIGEST",
        count_pattern=r"every entry except this report, digest to `",
    )
    source = replace_once(
        source,
        r"(the geometry below describes has SHA-256 `)[A-F0-9]{64}(`)",
        rf"\g<1>{document}\g<2>",
        "REBIND_DOCUMENT_DIGEST",
        count_pattern=r"the geometry below describes has SHA-256 `",
    )
    # Through a temporary and a replace, like the generation half: an
    # interrupted in-place write would leave a truncated report that this
    # bootstrap - the only way out of the stale-report deadlock - then refuses.
    # The limit named here - that no row drives a failure of the replace, and that a line
    # inserted between the write and the replace would reopen the residue uncovered - is
    # closed rather than disclosed: both statements live in write_through_temporary now,
    # under a `finally` that removes the temporary on every path out.
    write_through_temporary(report_path, source)
    return digest, document


def failure_surface_figures(root: Path = ROOT) -> dict[str, int]:
    baseline = load_json(root / "tests" / "failure-surface-baseline.json")
    runtime = baseline.get("runtime")
    if not isinstance(runtime, dict):
        raise ValueError("FAILURE_SURFACE_BASELINE_RUNTIME")
    # Every figure is read with `.get` and answered by `require_collection`, so a key that
    # is ABSENT and a key holding the wrong shape refuse with the same name. Half of these
    # were indexed - `baseline["engine_refusal_codes"]` - and an indexed read of a missing
    # key raises KeyError: not a raise site, so outside the closed world the by-name sweep
    # holds this generator to, and outside the vocabulary a caller is promised.
    # `require_collection` refuses None already, having to refuse every non-list,
    # so the change is the read and not the helper. The two `_int` figures were already
    # written this way, which is how the split arose: the shape was copied from a
    # neighbour for some lines and not for others.
    return {
        "engine": require_collection(
            baseline.get("engine_refusal_codes"), "FAILURE_SURFACE_ENGINE_CODES"),
        "wire": require_collection(
            baseline.get("wire_error_codes"), "FAILURE_SURFACE_WIRE_CODES"),
        "all": require_non_negative_int(
            baseline.get("emission_points_all"), "FAILURE_SURFACE_ALL"
        ),
        "static": require_non_negative_int(
            baseline.get("emission_points_static"), "FAILURE_SURFACE_STATIC"
        ),
        "dynamic": require_collection(
            baseline.get("dynamic_emission_points"), "FAILURE_SURFACE_DYNAMIC_POINTS"),
        "constructed": require_collection(
            runtime.get("constructed_engine_codes"), "FAILURE_SURFACE_CONSTRUCTED_CODES"),
        "foreign": require_collection(
            runtime.get("foreign_translated_codes"), "FAILURE_SURFACE_FOREIGN_CODES"),
        "witnessed": require_collection(
            runtime.get("witnessed_codes"), "FAILURE_SURFACE_WITNESSED_CODES"),
        "unwitnessed": require_collection(
            runtime.get("unwitnessed_codes"), "FAILURE_SURFACE_UNWITNESSED_CODES"),
        # Missing or malformed code collections refuse by name; neither becomes
        # an empty collection and a misleading zero in the report.
        "bridge": require_collection(
            baseline.get("bridge_refusal_codes"), "FAILURE_SURFACE_BRIDGE_CODES"),
    }


def update_report(
    report_path: Path,
    acceptance_json_path: Path,
    geometry_json_path: Path,
    root: Path = ROOT,
) -> dict[str, Any]:
    acceptance = load_json(acceptance_json_path)
    geometry = load_json(geometry_json_path)
    if acceptance.get("format") != "nc25-acceptance-results/v1":
        raise ValueError("ACCEPTANCE_RESULTS_FORMAT")
    if acceptance.get("status") != "PASS":
        raise ValueError("ACCEPTANCE_RESULTS_NOT_PASS")
    completed_utc = acceptance.get("completed_utc")
    # ASCII digits only: in a str pattern `\d` also matches other scripts'
    # digits, and the date is printed into the report as given.
    if not isinstance(completed_utc, str) or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", completed_utc, flags=re.ASCII
    ) is None:
        raise ValueError("ACCEPTANCE_COMPLETED_UTC")
    # The shape test above stays and the parse is behind it, because they answer different
    # questions: the pattern keeps other scripts' digits out, which a parse alone would
    # admit, and the parse asks whether the stamp names a moment. Without it the shape test
    # was the whole check, and `2030-99-99T25:61:61Z` passed it - measured - to be printed
    # as the report's verification date. Month ninety-nine, hour twenty-five.
    try:
        datetime.strptime(completed_utc, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise ValueError("ACCEPTANCE_COMPLETED_UTC") from None
    step_gate = acceptance.get("acceptance_steps")
    if not isinstance(step_gate, dict):
        raise ValueError("ACCEPTANCE_STEP_GATE")
    step_passed = require_non_negative_int(step_gate.get("passed"), "STEP_PASSED")
    step_total = require_non_negative_int(step_gate.get("total"), "STEP_TOTAL")
    if step_passed != step_total or step_total != len(GATE_ROWS):
        raise ValueError("ACCEPTANCE_STEP_GATE")
    raw_steps = acceptance.get("steps")
    if not isinstance(raw_steps, list):
        raise ValueError("ACCEPTANCE_STEPS")
    steps: dict[str, tuple[int, int]] = {}
    for raw in raw_steps:
        if not isinstance(raw, dict) or raw.get("status") != "PASS":
            raise ValueError("ACCEPTANCE_STEP_ENTRY")
        step_id = raw.get("id")
        passed = require_non_negative_int(raw.get("passed"), "STEP_COUNT")
        total = require_non_negative_int(raw.get("total"), "STEP_COUNT")
        # A gate that ran NO checks is not a passing gate. `passed == total` was the whole
        # test, and zero satisfies it, so eight steps of `0/0 PASS` beside the aggregate
        # `8/8` would have been published as eight gates passed. The vacuous case is
        # reachable from our own tree, not only from a forged file: the runner extracts
        # `Ran (?P<passed>\d+) tests` and requires `OK`, and a suite that ran nothing
        # prints both.
        if (not isinstance(step_id, str) or step_id in steps or passed != total
                or total < 1):
            raise ValueError("ACCEPTANCE_STEP_ENTRY")
        steps[step_id] = (passed, total)
    if set(steps) != set(GATE_ROWS):
        raise ValueError("ACCEPTANCE_STEP_SET")
    if geometry.get("status") != "GREEN":
        raise ValueError("GEOMETRY_NOT_GREEN")
    page_count = require_non_negative_int(geometry.get("page_count"), "PAGE_COUNT")
    hard_count = require_non_negative_int(
        geometry.get("hard_issue_count"), "HARD_ISSUE_COUNT"
    )
    warning_count = require_non_negative_int(
        geometry.get("warning_count"), "WARNING_COUNT"
    )
    page_sizes = geometry.get("page_sizes")
    if page_count < 1 or hard_count != 0 or not isinstance(page_sizes, list):
        raise ValueError("GEOMETRY_GATE")
    # Each count against the list it counts, where the file carries the list. The audit
    # writes both from their own lists - measured - so this cannot fire on our own
    # pipeline; it fires on a file that says zero hard findings beside a list of them,
    # which is what this report would then publish. Two spellings of one fact with
    # nothing holding them together is the seam this change set closes elsewhere.
    # Named limits: a file that OMITS the list is still read by its count alone, as the
    # fixture that pins this reader does; and `pages` is NOT held to `page_count`,
    # deliberately - the page count is the PDF's and the page reports are the rendered
    # images', and a disagreement between them is a hard issue the audit reports rather
    # than an incoherence in the file.
    for count, key in ((hard_count, "hard_issues"), (warning_count, "warnings")):
        listed = geometry.get(key)
        if listed is not None and (not isinstance(listed, list) or len(listed) != count):
            raise ValueError("GEOMETRY_GATE")
    # `page_sizes` holds the DISTINCT page geometries, not one entry per page:
    # a multi-page render may use a single geometry. So the
    # coherent range is one geometry at least and no more than there are
    # pages. Until this line the two figures were validated separately and
    # never against each other, and the report prints both in one sentence -
    # geometry with no sizes at all would have been accepted and published as
    # "N pages and uses 0 page geometries".
    if not 1 <= len(page_sizes) <= page_count:
        raise ValueError("GEOMETRY_PAGE_SIZES")
    # Each entry is one geometry, a [width, height] pair of positive finite
    # numbers. Unchecked, a string passed the distinctness test below as a
    # tuple of its characters ("A4" as ("A", "4")) and a bare number raised
    # TypeError out of it.
    for size in page_sizes:
        if (
            not isinstance(size, list)
            or len(size) != 2
            or not all(
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                # `math.isfinite` converts to a C double, and a JSON integer can be
                # wider than one: measured, `math.isfinite(10 ** 309)` raised a raw
                # OverflowError out of the guard written to name that very input,
                # while the control `math.isfinite(1024)` answered True.
                #
                # The conversion is KEPT and its failure is the answer. A first fix
                # asked finiteness only of floats, on the reasoning that an integer is
                # finite by construction - true about integers, false about this guard,
                # which asks whether the value is a finite DOUBLE, these being page
                # dimensions. Measured, that version ACCEPTED a width of three hundred
                # and ten digits: the crash was gone and so was the refusal.
                and _finite_double(value)
                and value > 0
                for value in size
            )
        ):
            raise ValueError("GEOMETRY_PAGE_SIZE_ENTRY")
    # DISTINCT is the word the sentence below prints, so it is enforced rather
    # than assumed: without this, two identical entries would be published as
    # two page geometries. The comment above claimed distinctness a day before
    # anything held it, which is the drift this line closes.
    if len({tuple(size) for size in page_sizes}) != len(page_sizes):
        raise ValueError("GEOMETRY_PAGE_SIZES_NOT_DISTINCT")
    # A release-grade acceptance report may only be built when the acceptance run
    # actually bound and verified the immutable NC2.5 core. Without it, the
    # headline PASS would silently rest on EXTERNAL_SOURCE_CHECKS=NOT_RUN.
    external_core = acceptance.get("external_core")
    if not isinstance(external_core, dict):
        raise ValueError("ACCEPTANCE_EXTERNAL_CORE_MISSING")
    if external_core.get("external_source_checks") != "PASS":
        raise ValueError("EXTERNAL_CORE_NOT_VERIFIED")
    source_mode = external_core.get("source_mode")
    if source_mode != "strict":
        raise ValueError("ACCEPTANCE_EXTERNAL_CORE_MODE")
    strict_total = len(verify_package.ALL_PACKAGE_CHECK_IDS)
    standalone_total = len(verify_package.STANDALONE_PACKAGE_CHECK_IDS)
    if steps["package_verifier"] != (strict_total, strict_total):
        raise ValueError("STRICT_PACKAGE_VERIFIER_REQUIRED")
    source_manifest = load_json(root / "SOURCE-MANIFEST.json")
    # The two fields of this manifest the rest of the function leans on, asked here by name.
    # `package_version` is read AGAIN below by `spec_docx_name`, a helper shared with the
    # verifier and the projection builder, which re-parses the file and indexes it bare: a
    # manifest without the field, or with a number in it, left this function as KeyError or
    # AttributeError from inside that helper - no raise site of this module, so outside the
    # closed world the by-name test holds it to, and invisible to the indexed-read ratchet,
    # which reads this module's source only. The helper keeps its contract for its other
    # callers; this function names the field before handing the path over. The form asked is
    # the one the helper takes major.minor from.
    # `inputs` is iterated, and a JSON number as `inputs` itself raised TypeError from the
    # `for` - a number inside the list is filtered by the dict test below - the same
    # class one line down, found by looking at every read of this object, not only the one
    # reported.
    package_version = source_manifest.get("package_version")
    if not isinstance(package_version, str) or not re.fullmatch(
        r"[0-9]+(?:\.[0-9]+)+", package_version
    ):
        raise ValueError("SOURCE_MANIFEST_PACKAGE_VERSION")
    manifest_inputs = source_manifest.get("inputs", [])
    if not isinstance(manifest_inputs, list):
        raise ValueError("SOURCE_MANIFEST_INPUTS")
    core_input = next(
        (
            item
            for item in manifest_inputs
            if isinstance(item, dict)
            and item.get("role") == "immutable_nc25_core"
        ),
        None,
    )
    if core_input is None:
        raise ValueError("ACCEPTANCE_CORE_INPUT_MISSING")
    core_file = core_input.get("file_name")
    core_sha = core_input.get("sha256")
    core_bytes = require_non_negative_int(
        core_input.get("byte_length"), "CORE_BYTES"
    )
    core_lines = require_non_negative_int(core_input.get("line_count"), "CORE_LINES")
    # `str(core_sha)` stood where `core_sha` stands now, and the conversion was the whole
    # defect: the pattern was applied to text this line manufactured, so a JSON NUMBER
    # whose decimal form is sixty-four digits - 10**63 - satisfied a HEX test and was
    # printed into the report as the core's digest. Measured, with controls: a genuine
    # uppercase digest passes, `deadbeef` fails, the integer passed. The other three
    # digest checks in this file ask the value's type and match the value itself; this one
    # asked the type of the neighbouring FILE NAME and converted its own subject. A form
    # check run on a conversion is a check on the conversion.
    if (
        not isinstance(core_file, str)
        or not isinstance(core_sha, str)
        or not re.fullmatch(r"[A-F0-9]{64}", core_sha)
    ):
        raise ValueError("ACCEPTANCE_CORE_INPUT_SHAPE")
    text = read_report(report_path)
    canonical_command = "python -B tests/run_acceptance.py"
    # Recognise literal, single-line command forms, not arbitrary shell programs.
    # Whole executable/path tokens prevent prefix and filename-suffix matches.
    # Markdown backticks delimit tokens; removing them would concatenate fragments.
    # Quotes may surround each path or a detached switch value. A detached value is read
    # after the switches that take one before the script - -X, -W and
    # --check-hash-based-pycs, which the last form of this list omitted and so let
    # `py -3 --check-hash-based-pycs always tests/run_acceptance.py` through, measured;
    # -c and -m take a value too and END the options, so Python runs no script after them -
    # but the generic switch branch below reads them like any other switch, so a line
    # putting the script path DIRECTLY after one of them is refused. That is over-refusal
    # and it stays: like the dash runs named below, it can only refuse a line, never admit
    # an invocation. `-m` takes a module name, which stands between the switch and any
    # path, so that form is not refused - the asymmetry is the scan's, not Python's, and a
    # row pins each side. The hyphen is in
    # the class a switch's own characters are read with so that the bare end-of-options
    # marker `--` reads as a switch: one dash from the prefix, the second from the class.
    # It admits other runs of dashes too - `---` reads as a switch - which can only refuse
    # a line, never admit one, and no such token is an option Python accepts.
    # Without it a switch needed some other character after its dashes, and `py -3 --
    # tests/run_acceptance.py`, which runs the script, walked past. Those three names
    # are matched in their own case while the rest of the command is not: Python reads its
    # options case-sensitively, and `-x` in lower case is a different option that takes no
    # value, so the word after it is the script and not a value. Horizontal whitespace
    # joins arguments: any whitespace that is not a line boundary as `str.splitlines`
    # counts them. A line boundary does not join separate lines - `\s` alone included
    # VT, FF, NEL, U+2028 and U+2029, measured - and narrowing the joiner to space and
    # tab dropped the rest of the class: PowerShell reads a no-break space as a separator,
    # measured, so `py<NBSP>-3<NBSP>tests\run_acceptance.py` is an invocation.
    # Aliases, expansions and shell escapes are not evaluated. A prose sentence
    # containing an exact forbidden invocation is still refused regardless of intent.
    hspace = r"[^\S\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]"
    launcher = (
        r"(?:[^\s\"'&;|()]*[\\/])?pyw?(?:\.exe)?"
        r'|"(?:[^"\r\n]*[\\/])?pyw?(?:\.exe)?"'
        r"|'(?:[^'\r\n]*[\\/])?pyw?(?:\.exe)?'"
    )
    script = (
        r"(?:[^\s\"'&;|()]*[\\/])?tests[\\/]run_acceptance\.py"
        r'|"(?:[^"\r\n]*[\\/])?tests[\\/]run_acceptance\.py"'
        r"|'(?:[^'\r\n]*[\\/])?tests[\\/]run_acceptance\.py'"
    )
    option_value = r"""(?:[\w:=.-]+|"[^"\r\n]+"|'[^'\r\n]+')"""
    options = (
        rf"(?:{hspace}+(?:(?-i:-[XW]|--check-hash-based-pycs){hspace}+{option_value}"
        rf"|-{{1,2}}[\w:=.-]+))*"
    )
    command_start = r"(?<![^\s&;|()])"
    command_end = r"(?=$|\s|[&;|()]|[.,:!?](?=\s|$))"
    canonical = (
        r"""(?<![^\s`"'&;|()])""" + re.escape(canonical_command)
        + r"""(?=$|[\s`"'&;|()]|[.,:!?](?=\s|$))"""
    )
    def command_refused(candidate: str) -> bool:
        """The canonical command present as a token, and no launcher invocation anywhere."""
        return re.search(canonical, candidate) is None or bool(re.search(
            rf"{command_start}(?:{launcher}){options}{hspace}+(?:{script}){command_end}",
            candidate.replace("`", " "),
            re.IGNORECASE,
        ))

    # Asked here so a report that already carries an invocation costs nothing further, and
    # asked AGAIN on the final text below, which is the text this run publishes. Only the
    # second one is the guard: everything between the two lines puts generated values into
    # the report, and one of them is a NAME out of the source manifest, checked to be a
    # string and nothing else. Measured on a copy of the package - a core file name reading
    # "core.md`; py -3 tests/run_acceptance.py; `x" left the template clean, passed here,
    # and stood in the written report inside the immutable-core sentence, with the run
    # reported as successful. The guard's own comment says a sentence quoting the exact
    # invocation is refused whatever the intent; the one text it never read was its own.
    if command_refused(text):
        raise ValueError("REPORT_CANONICAL_COMMAND")
    text = replace_once(
        text,
        r"^Verification date: .*?$",
        f"Verification date: {chr(96)}{completed_utc[:10]} UTC{chr(96)}",
        "REPORT_DATE",
    )
    text = replace_once(
        text, r"^Status: .*?$", f"Status: {chr(96)}PASS{chr(96)}", "REPORT_STATUS"
    )
    for step_id, label in GATE_ROWS.items():
        passed, total = steps[step_id]
        row_pattern = rf"^\| {re.escape(label)} \| .*?\|$"
        row = f"| {label} | {chr(96)}{passed}/{total} PASS{chr(96)} |"
        text = replace_once(text, row_pattern, row, f"REPORT_ROW_{step_id}")
    core_section = "\n".join(
        [
            "## Core source binding",
            "",
            f"The immutable NC2.5 core {chr(96)}{core_file}{chr(96)} was bound and verified",
            f"during this acceptance run: SHA-256 {chr(96)}{core_sha}{chr(96)}, {core_bytes} {plural(core_bytes, 'byte')},",
            f"{core_lines} {plural(core_lines, 'line')}, byte- and line-exact (source mode {chr(96)}{source_mode}{chr(96)}). A",
            "release-grade acceptance report is refused unless this external-core",
            "verification passed.",
            "",
            "The core is not shipped with this package, so a run without it reports",
            f"{chr(96)}PACKAGE_CHECKS={standalone_total}/{standalone_total}{chr(96)} and {chr(96)}EXTERNAL_SOURCE_CHECKS=NOT_RUN{chr(96)} while the",
            f"overall verdict stays {chr(96)}ACCEPTANCE_STEPS={len(GATE_ROWS)}/{len(GATE_ROWS)} PASS{chr(96)}. The package-integrity figure",
            "recorded in the table above is the release configuration, with the bound",
            f"local core file supplied through {chr(96)}NC25_SOURCES_ROOT{chr(96)}. This revision",
            "is not part of the public deposit; the DOI identifies the core line,",
            "not the availability of this exact file.",
        ]
    )
    text = replace_section(
        text, "## Core source binding", "## Failure-surface figures",
        core_section, "REPORT_CORE_SECTION",
    )
    bound_manifest_digest = acceptance.get("bound_manifest_digest")
    bound_document_sha256 = acceptance.get("bound_document_sha256")
    for label, value in (
        ("BOUND_MANIFEST_DIGEST", bound_manifest_digest),
        ("BOUND_DOCUMENT_SHA256", bound_document_sha256),
    ):
        if not isinstance(value, str) or not re.fullmatch(r"[A-F0-9]{64}", value):
            raise ValueError(f"ACCEPTANCE_{label}_SHAPE")
    # The geometry evidence and the acceptance run must name the same document.
    # Otherwise a render of an earlier document could certify a later one.
    rendered_document = geometry.get("source_docx_sha256")
    if not isinstance(rendered_document, str) or not re.fullmatch(
        r"[A-F0-9]{64}", rendered_document
    ):
        raise ValueError("GEOMETRY_DOCUMENT_SHAPE")
    if rendered_document != bound_document_sha256:
        raise ValueError("GEOMETRY_DOCUMENT_MISMATCH")
    bound_section = "\n".join(
        [
            "## Bound bytes",
            "",
            "This report was generated for one exact tree. The manifest entries it",
            f"certifies, every entry except this report, digest to {chr(96)}{bound_manifest_digest}{chr(96)}",
            "as path-ordered (path, SHA-256, byte length) triples; the specification",
            f"document the geometry below describes has SHA-256 {chr(96)}{bound_document_sha256}{chr(96)}.",
            "The package verifier recomputes both from the shipped bytes and refuses",
            "this report when either differs.",
        ]
    )
    text = replace_section(
        text, "## Bound bytes", "## Core source binding",
        bound_section, "REPORT_BOUND_SECTION",
    )
    figures = failure_surface_figures(root)
    # The counts in this paragraph that carry a noun of their own agree with it. The ones
    # that carry none of their own are the emission-point counts below, which share one
    # fixed noun, and `witnessed`, which borrows the noun of the count before it
    # ("... constructed and 1 witnessed") and so reads right at any value. Named, not
    # counted: the figures this comment gave went stale beside the list. The
    # sentence here used to claim
    # every count agreed, which the inner comment contradicted fifteen lines later - two
    # statements about one paragraph, in one function, saying opposite things. What
    # changed was the idiom already used for the geometry sentence below, applied here
    # too: without it six nouns were frozen plural and one frozen singular, and the
    # paragraph misread itself at a value of one. `all`, `static` and `dynamic` share the
    # single noun "points" and stay frozen deliberately, because a count of emission
    # points is not a count of things the sentence names one by one.
    figures_section = "\n".join(
        [
            "## Failure-surface figures",
            "",
            "The failure-surface step measured, for the exact bytes this report",
            f"certifies: {figures['engine']} engine refusal {plural(figures['engine'], 'code')}"
            f" and {figures['wire']} wire error {plural(figures['wire'], 'code')} in the",
            f"closed world; raise and helper-emission points all={figures['all']}, static={figures['static']}, dynamic={figures['dynamic']};",
            f"{figures['constructed']} engine refusal {plural(figures['constructed'], 'code')} constructed"
            f" and {figures['witnessed']} witnessed during the",
            f"recorded run; {figures['unwitnessed']} {plural(figures['unwitnessed'], 'code')} unwitnessed;"
            f" {figures['foreign']} {plural(figures['foreign'], 'code')} re-emitted by the",
            f"translation site belonging to neither vocabulary;"
            # Agreed with its count like the figures above it that carry an
            # agreed noun - engine, wire, constructed, unwitnessed, foreign;
            # the emission points share one fixed noun and `witnessed` carries
            # none. This slot
            # was the one exemption in the paragraph, frozen plural on both
            # sides with a comment on each explaining why the rule that governs
            # everything around it did not apply here. An exemption maintained
            # in two files is a rule with a hole in it; the reader now spells
            # this noun `code[s]?` like the rest, and the special case is gone
            # rather than documented.
            f" and {figures['bridge']} OTCS bridge refusal"
            f" {plural(figures['bridge'], 'code')} in a closed world"
            " of their own. Each figure is a property",
            "of the named procedure recorded in the baseline, not of the engine in the",
            "abstract, and the committed baseline is a no-growth debt ratchet, not a",
            "completeness claim.",
        ]
    )
    text = replace_section(
        text, "## Failure-surface figures", "## Document artifact",
        figures_section, "REPORT_FIGURES_SECTION",
    )
    warning_word = plural(warning_count, "warning")
    geometry_word = "geometry" if len(page_sizes) == 1 else "geometries"
    document_section = "\n".join(
        [
            "## Document artifact",
            "",
            f"{chr(96)}{spec_docx_name(root)}{chr(96)} is generated by the",
            "shipped deterministic builder. Its headless LibreOffice PDF render contains",
            f"{page_count} {plural(page_count, 'page')} and uses {len(page_sizes)} page {geometry_word}. The machine-readable",
            # The NEXT line's noun, "hard findings", does not go through `plural` and the
            # line above this comment does: the gate admits only `hard_count == 0`, so that
            # noun has one form because the value has one value, and routing a pinned count
            # through the agreement rule would dress a constant as an agreement. Said here
            # rather than above, where it read as a denial of the page count beside it.
            f"geometry gate reported {chr(96)}GREEN{chr(96)}, {hard_count} hard findings, and",
            f"{warning_count} non-blocking {warning_word}. Automated geometry evidence does not claim",
            "human visual inspection. Optional extended-property counters that could not be",
            "derived truthfully were removed from the DOCX package.",
        ]
    )
    text = replace_section(
        text, "## Document artifact", "## Security and data boundary",
        document_section, "REPORT_DOCUMENT_SECTION",
    )
    text = text.rstrip("\n") + "\n"
    # The text this run publishes, asked the two questions that were asked of its template.
    if command_refused(text):
        raise ValueError("REPORT_CANONICAL_COMMAND")
    # Read the whole table independently of its result spelling. A row whose cell is
    # FAIL, or whose pipes have no surrounding spaces, is still a row. Ordered equality
    # rejects additions, omissions, duplicates and reordered labels as well as stale
    # results. The package verifier uses the same table reader.
    rendered = acceptance_gate_rows(text)
    expected = [
        (label, f"`{steps[step_id][0]}/{steps[step_id][1]} PASS`")
        for step_id, label in GATE_ROWS.items()
    ]
    if rendered != expected:
        raise ValueError("REPORT_GATE_ROWS")
    write_through_temporary(report_path, text)
    return {
        "verification_date": completed_utc[:10],
        "page_count": page_count,
        "hard_issue_count": hard_count,
        "warning_count": warning_count,
        "acceptance_steps": step_total,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    # The bootstrap and the generation are one tool with two modes, because
    # they are two halves of one operation: the first makes the tree
    # verifiable so acceptance can run, the second writes the report from what
    # that run produced. Neither is useful alone and the second refuses to run
    # without the first having been done, so they are not two tools.
    parser.add_argument(
        "--rebind-only",
        action="store_true",
        help=(
            "point the shipped report's two digests at the current manifest and"
            " stop; the bootstrap that lets acceptance run after an edit"
        ),
    )
    parser.add_argument("--acceptance-json", type=Path)
    parser.add_argument("--geometry-json", type=Path)
    parser.add_argument("--report", type=Path, default=REPORT_PATH)
    args = parser.parse_args()
    if args.rebind_only:
        # The bootstrap rebinds the package's own report, the one the verifier
        # reads; a named other report would be ignored while the package's was
        # rewritten, so it is refused instead.
        if args.report.resolve() != REPORT_PATH:
            raise SystemExit("REBIND_ONLY_REPORT_IS_THE_PACKAGE_REPORT")
        # In the shipped program the check above has already pinned this to ROOT, so no
        # spelling of it reaches a foreign tree. The argument is not therefore idle: it is
        # the seam the by-name test drives, patching REPORT_PATH to a temporary copy so the
        # rebind acts on that copy rather than on the real package report. The generation
        # half below carries no such check and writes the report it is given - free by
        # design, not by oversight, and that asymmetry is the point of the check here.
        digest, document = rebind_report_to_manifest(args.report.resolve().parent)
        print(f"ACCEPTANCE_REPORT=REBOUND digest={digest} document={document}")
        return
    if args.acceptance_json is None or args.geometry_json is None:
        # Refused rather than defaulted: a report built from an unnamed run is
        # the one thing this generator exists to make impossible.
        raise SystemExit("ACCEPTANCE_REPORT_INPUTS_REQUIRED")
    # The reads that take a root - the source manifest, the failure-surface baseline, the
    # document name - come from the tree of the report being written, not from this file's
    # own tree. Without that, a report named in another tree was rewritten with this tree's
    # data, and the parameter had no producer outside the tests.
    result = update_report(args.report, args.acceptance_json, args.geometry_json,
                           root=args.report.resolve().parent)
    print(
        "ACCEPTANCE_REPORT=UPDATED "
        f"date={result['verification_date']} pages={result['page_count']} "
        f"hard={result['hard_issue_count']} warnings={result['warning_count']}"
    )


if __name__ == "__main__":
    main()
