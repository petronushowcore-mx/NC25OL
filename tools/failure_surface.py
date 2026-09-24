from __future__ import annotations

import argparse
import ast
import contextlib
import importlib
import io
import json
import os
import re
import sys
import unittest
import unittest.case
from pathlib import Path
from typing import Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))
import spec_counts  # noqa: E402  the one home of the sole-assignment reader
sys.path.pop(0)

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
ENGINE_PATH = ROOT / "sdk" / "python" / "nc25_universal_ledger.py"
ADAPTER_PATH = ROOT / "sdk" / "python" / "nc25_universal_adapter.py"
BRIDGE_PATH = ROOT / "sdk" / "python" / "nc25_otcs_bridge.py"
BASELINE_PATH = ROOT / "tests" / "failure-surface-baseline.json"

CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]+$")
BASELINE_FORMAT = "nc25-failure-surface/v2"

# Every published figure is named here by the procedure that produced it,
# re-derived from the sources and compared against the baseline on every
# check, never a property of "the engine" in the abstract. What is MECHANICAL
# is the pairing of names: the tool refuses if a figure has no procedure entry
# or an entry has no figure. Whether a procedure's WORDS still describe the
# code that computes it is not machine-checked and cannot be; these texts are
# maintained by hand and read as documentation, not as certified statements.
# The two emission-point quantities are always reported side by side because
# the gap between them is the finding. Fields recording WHICH suites ran are
# the run's selection rather than a measured figure, and are listed in
# SELECTION_FIELDS instead.
PROCEDURES = {
    "engine_refusal_codes": (
        "Closed world over the engine source: string constants at raise sites"
        " outside the pinned helpers, literal code arguments at pinned-helper"
        " call sites, pinned-helper code parameter defaults, and the declared"
        " code sets of the pinned dynamic raise sites."
    ),
    "wire_error_codes": (
        "Closed world over the adapter source: literal code arguments of"
        " WireError raise sites."
    ),
    "bridge_refusal_codes": (
        "Closed world over the OTCS bridge source, kept SEPARATE from the"
        " engine vocabulary because the two never meet: a bridge code is"
        " raised in-process to a Python caller and cannot travel the adapter's"
        " wire, which carries no OTCS route at all. Literal code arguments at"
        " the bridge's own pinned-helper call sites, literal codes at its own"
        " raise sites, and the codes derived from the one site that iterates a"
        " literal table of (value, code) pairs. OTCSAppendRejected is excluded"
        " on purpose: the bridge defines it and the downstream client raises"
        " it, so counting it would claim a vocabulary the bridge does not own."
    ),
    "architect_decision_codes": (
        "Codes returned by the decision gate and recorded by the"
        " non-executable path, required to equal the engine's declared"
        " ARCHITECT_DECISION_CODES vocabulary."
    ),
    "emission_points_all": (
        "Every raise statement outside the pinned helper bodies plus every"
        " pinned-helper call site, over the engine, the adapter AND the bridge."
        " Procedure coverage pairs figure names with procedure names; it does"
        " not validate the wording of this description. This counts"
        " RAISE SITES, not refusal sites: the few that raise TypeError carry no"
        " contract code and are counted here and named as dynamic, because a"
        " raise the inventory did not account for is the thing this figure"
        " exists to make impossible."
    ),
    "emission_points_static": (
        "The subset of emission points whose emitted code is a single literal"
        " knowable without running: a literal raise argument, a literal helper"
        " argument, or a helper default."
    ),
    "dynamic_emission_points": (
        "The emission points outside the static subset, each named by file,"
        " owning function, kind, and an occurrence index that distinguishes"
        " siblings sharing all three; the enumerated gap between the two"
        " emission-point counts. Indexed rather than line-numbered on purpose:"
        " a line number moves with every edit above it, so a list keyed on"
        " lines would churn without any emission path having changed."
    ),
    "constructed_engine_codes": (
        "Codes of ContractViolation instances constructed from an engine or"
        " adapter frame while the recorded suites run in this process."
    ),
    "constructed_wire_codes": (
        "Codes of WireError instances constructed from an adapter frame while"
        " the recorded suites run. The adapter's translation site re-emits the"
        " code of a refusal it caught, so this set legitimately overlaps the"
        " engine vocabulary."
    ),
    "foreign_translated_codes": (
        "Codes observed being re-emitted BY THE TRANSLATION SITE ITSELF - the"
        " adapter function that catches an engine refusal and rebuilds it as a"
        " wire error - that belong to neither published vocabulary. Such a code"
        " was injected into the engine from outside production, typically by a"
        " test replacing an engine method. Provenance is the constructing"
        " function, not membership arithmetic over the wire sink: a code that"
        " merely appears on the adapter side without crossing from the engine"
        " is not translated and is not counted here. Named rather than folded"
        " into the wire figure, so the two closed worlds keep their meaning;"
        " a new one is a baseline delta like any other."
    ),
    "witnessed_codes": (
        "Engine refusal codes observed at runtime leaving a production-raised"
        " ContractViolation into test code, through a passing equality"
        " comparison against a value that is not itself an observed code (a"
        " passing membership test counts through the equality hit on its"
        " matched member) or a passing assertRaisesRegex entered from test"
        " code whose pattern matches this exception's rendering and no other"
        " code's. Proof is observed rather than parsed out of test source, so"
        " the observed forms need no list of recognised idioms and a new test"
        " written in one of them is covered the day it is written. The forms"
        " ARE bounded: the comparison must reach the code object itself, so a"
        " check that first converts it, as assertEqual(str(exc.code), CODE)"
        " does, is not observed and not counted. Two further consequences are"
        " stated rather than implied: any passing equality in"
        " test code counts, including bookkeeping that asserts nothing, so"
        " this measures exact-value contact and not the presence of an"
        " assertion; and a pattern admitting more than one code of the closed"
        " world does not merely go uncredited, it fails this gate, because"
        " anchoring every pattern to exactly one code is a property this"
        " package holds."
    ),
    "unwitnessed_codes": (
        "engine_refusal_codes minus witnessed_codes: the committed debt. The"
        " baseline pins it as a no-growth ratchet, not a completeness claim."
    ),
    "constructed_bridge_codes": (
        "Codes of OTCSBridgeError instances constructed from a bridge frame"
        " while the recorded suites run. OTCSAppendRejected raised by a"
        " downstream client is not a bridge frame and is not counted."
    ),
    "witnessed_bridge_codes": (
        "Bridge refusal codes observed at runtime leaving a"
        " production-raised OTCSBridgeError into test code, by the same"
        " two forms and the same discriminating rule as witnessed_codes."
        " Before this existed the bridge vocabulary was witnessed by"
        " nothing: a deleted sweep row lost its witness in silence while"
        " the method count and the declared-equals-measured check both"
        " stayed green."
    ),
    "unwitnessed_bridge_codes": (
        "bridge_refusal_codes minus witnessed_bridge_codes: the bridge's"
        " own committed debt, pinned by the same no-growth ratchet."
    ),
}

# Published fields that are not measured figures: what the run selected, the
# record of any coverage a regeneration was allowed to give up, and the record
# of a baseline written with nothing to compare against.
SELECTION_FIELDS = frozenset(
    {
        "format",
        "procedures",
        "runtime",
        "unittest_modules",
        "script_suites",
        "excluded_tests",
        "unittest_test_count",
        "script_markers",
        "accepted_regression",
        "adopted_baseline",
    }
)


RUNTIME_PROCEDURE_NAMES = frozenset(
    {
        "constructed_engine_codes",
        "constructed_wire_codes",
        "constructed_bridge_codes",
        "foreign_translated_codes",
        "witnessed_codes",
        "unwitnessed_codes",
        "witnessed_bridge_codes",
        "unwitnessed_bridge_codes",
    }
)


def _procedure_coverage_problems(snapshot: dict[str, object]) -> list[str]:
    """Every published figure must map to a procedure by its own name.

    A static-only snapshot publishes no runtime figures, so the runtime
    procedures are expected to be idle rather than orphaned there.
    """
    runtime = snapshot.get("runtime")
    published = set(snapshot) | set(runtime or {})
    figures = published - SELECTION_FIELDS
    expected = set(PROCEDURES)
    if runtime is None:
        expected -= RUNTIME_PROCEDURE_NAMES
    problems: list[str] = []
    missing = sorted(figures - set(PROCEDURES))
    extra = sorted(expected - figures)
    if missing:
        problems.append(f"FAILURE_SURFACE_FIGURE_WITHOUT_PROCEDURE {missing}")
    if extra:
        problems.append(f"FAILURE_SURFACE_PROCEDURE_WITHOUT_FIGURE {extra}")
    return problems


# These helpers turn a caller-supplied literal code into ContractViolation.
# Their bodies are intentionally replaced by their call sites in the emission
# inventory: one helper body is not one failure path.
PINNED_EXCEPTION_HELPERS = frozenset(
    {
        "_require_mapping",
        "_require_exact_keys",
        "_require_identifier",
        "_require_version",
        "_require_sha256",
        "_require_non_negative_int",
        "_unique_ids",
        "_bool_map",
        "_validate_core_anchor",
        "_validate_evidence_ref",
    }
)

# Dynamic code flows that cannot be reduced to one literal at the raise node.
# Any new dynamic raise remains unclassified until it is deliberately added.
#
# The restore helper synthesises its codes from its own argument, so its code
# set is DERIVED from the live call sites rather than declared here. A frozen
# list would be a second writer of the same fact: adding a third call would
# emit codes the closed world does not contain, and a declaration that cannot
# notice is not a declaration.
RESTORE_PAIR_HELPER = "restore_pairs"
REFUSAL_CALLEES = frozenset({"ContractViolation", "IntegrityViolation"})
# The bridge is a third closed world with its own exception classes and its
# own refusing helpers. Both are properties of the SOURCE rather than one
# flat set, because a flat set would merge two helper vocabularies: a name
# living in one source would silently pin a call site in the other.
#
# 🔴 OTCSAppendRejected is NOT here. The bridge DEFINES it and never raises
# it - the downstream client does. Counting it would pull a vocabulary the
# bridge does not own into a closed world that claims to be its own.
BRIDGE_REFUSAL_CALLEES = frozenset(
    {"OTCSBridgeError", "OTCSReconciliationRequired"}
)
BRIDGE_PINNED_HELPERS = frozenset(
    {"_mapping", "_closed", "_identifier", "_text", "_sha256", "_integer",
     "_time", "_exact", "_plain_copy"}
)
# The adapter function that re-emits a caught engine refusal on the wire.
TRANSLATION_SITE = "_dispatch"
TYPE_ERROR_OWNERS = frozenset(
    {"_scope_reader", "_state_locked", "_state_read_locked"}
)

# The recorded run: the FOUR unittest suites plus the two script suites, the
# same modules the acceptance pipeline runs, minus the FOUR cases named in
# RUNTIME_EXCLUDED_SUFFIXES - two self-referential (one re-runs this tool, one
# re-runs the verifier fleet) and two that install this tool's own observation
# machinery, which must not nest. Both counts were three and two when the
# bridge had no suite and no step of its own; neither was recounted when it
# got them.
UNITTEST_SUITE_MODULES = (
    "test_universal_connection",
    "test_semantic_contracts",
    "test_contract_regressions",
    # Added when the bridge got its own acceptance step. Until then it reached
    # the recorded run only through an import inside the regressions, so its
    # constructions were credited to a suite that does not own them.
    "test_otcs_bridge",
)
SCRIPT_SUITE_MODULES = ("test_contract_conformance", "test_safety_mutations")
# Anchored to the start of a line, and the LAST match is the one taken: an
# unanchored search returns the first hit, which is not necessarily the run's
# terminal verdict.
SCRIPT_SUITE_MARKERS = {
    "test_contract_conformance": re.compile(
        r"^CONTRACT_CONFORMANCE=(\d+/\d+) PASS$", re.M
    ),
    "test_safety_mutations": re.compile(
        r"^SAFETY_MUTATIONS=(\d+/\d+) PASS$", re.M
    ),
}
RUNTIME_EXCLUDED_SUFFIXES = (
    ".test_every_declared_check_reports_its_own_verdict",
    ".test_failure_surface_ratchet_detects_each_regression",
    ".test_wire_witness_does_not_retire_engine_debt",
    ".test_a_crashing_check_reports_blocked_rather_than_vanishing",
)
_SDK_MODULE_NAMES = frozenset(
    {"nc25_universal_ledger", "nc25_universal_adapter", "nc25_otcs_bridge"}
)


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {
        child: node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }


def _owner_name(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current.name
    return "<module>"


def _callee_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""


def _uppercase_constants(node: ast.AST) -> set[str]:
    return {
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant)
        and isinstance(child.value, str)
        and CODE_RE.fullmatch(child.value)
    }


def _unreadable_members(node: ast.AST) -> set[str]:
    """String members of a DECLARED vocabulary that the shape filter drops.

    `_uppercase_constants` is a filter, and a filter is the right instrument
    where it scans arbitrary code for things that look like refusal codes. Over
    a set whose whole purpose is to DECLARE a vocabulary it is the wrong one:
    a member the filter cannot read is silently absent from the declaration,
    so neither the declared-equals-measured comparison nor the subset rule for
    the exclusion list can see it. A lower-case entry would sit in the running
    frozenset and in no check at all.

    So the declaration readers ask for the leftovers too, and a leftover is a
    snapshot problem rather than a shrug.
    """
    return {
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant)
        and isinstance(child.value, str)
        and not CODE_RE.fullmatch(child.value)
    }


def _assignment_value(tree: ast.AST, name: str) -> ast.AST | None:
    """One reader for a sole module-level declaration, not two.

    The implementation lives in the shared AST reader. This name delegates to
    that reader so declaration validation has one implementation.
    """
    return spec_counts.sole_assignment(tree, name, where="the scanned module")


def _helper_code_specs(
    tree: ast.AST, pinned: frozenset[str] = PINNED_EXCEPTION_HELPERS
) -> dict[str, tuple[int, str | None]]:
    specs: dict[str, tuple[int, str | None]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name not in pinned:
            continue
        names = [argument.arg for argument in node.args.args]
        if "code" not in names:
            raise AssertionError(f"PINNED_HELPER_CODE_PARAMETER:{node.name}")
        position = names.index("code")
        first_default = len(names) - len(node.args.defaults)
        default_code: str | None = None
        if position >= first_default:
            default_code = _literal_code(node.args.defaults[position - first_default])
        specs[node.name] = (position, default_code)
    missing = pinned - set(specs)
    if missing:
        raise AssertionError(f"PINNED_HELPERS_MISSING:{sorted(missing)}")
    return specs


def _call_argument(call: ast.Call, position: int, keyword: str) -> ast.AST | None:
    for item in call.keywords:
        if item.arg == keyword:
            return item.value
    return call.args[position] if len(call.args) > position else None


def _literal_code(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value if CODE_RE.fullmatch(node.value) else None
    return None


def _restore_pair_codes(tree: ast.AST) -> tuple[set[str], list[str]]:
    """The codes the restore helper can synthesise, read off its call sites.

    The helper raises `STATE_{name.upper()}` and `STATE_{name.upper()}_PAIR`
    for the name it was given, so its world is exactly the set of names it is
    actually called with. A call with a non-literal name is unreadable and
    says so rather than being passed over.
    """
    codes: set[str] = set()
    unreadable: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _callee_name(node) != RESTORE_PAIR_HELPER or not node.args:
            continue
        argument = node.args[0]
        if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
            stem = f"STATE_{argument.value.upper()}"
            codes.update({stem, f"{stem}_PAIR"})
        else:
            unreadable.append(f"{RESTORE_PAIR_HELPER}:{node.lineno}:non-literal-name")
    return codes, unreadable


def _bridge_pair_table_codes(tree: ast.AST) -> tuple[set[str], list[str]]:
    """Codes a pinned bridge helper receives from a loop over (value, code) pairs.

    One site in the bridge iterates a literal tuple of pairs and calls
    `_identifier(value, code)` with the loop variable. The scanner is right to
    refuse it: a helper call whose code is a name is not readable as a literal.
    It is resolved the way the engine resolved `restore_pairs` - the codes are
    DERIVED from the live site rather than declared beside it, because a
    declared list is a second writer of one fact and goes quiet the moment a
    pair is added.

    A pair whose second element is not a literal string is UNREADABLE and says
    so; it does not silently shrink the world.
    """
    codes: set[str] = set()
    unreadable: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.For):
            continue
        if not isinstance(node.iter, (ast.Tuple, ast.List)):
            continue
        calls = [
            inner
            for inner in ast.walk(node)
            if isinstance(inner, ast.Call)
            and _callee_name(inner) in BRIDGE_PINNED_HELPERS
        ]
        if not calls:
            continue
        for element in node.iter.elts:
            if not isinstance(element, ast.Tuple) or len(element.elts) != 2:
                unreadable.append(f"bridge-pair-table:{node.lineno}:not-a-pair")
                continue
            code = _literal_code(element.elts[1])
            if code is None:
                unreadable.append(
                    f"bridge-pair-table:{getattr(element, 'lineno', node.lineno)}"
                    ":non-literal-code"
                )
            else:
                codes.add(code)
    return codes, unreadable


def _dynamic_refusal_kind(
    owner: str,
    call: ast.Call,
    grant_codes: set[str],
    restore_codes: set[str],
    is_engine: bool,
) -> tuple[str, set[str]] | None:
    """Classify a known dynamic refusal raise; None means unclassified."""
    if not is_engine or not call.args:
        # The pinned dynamic kinds are engine flows; an adapter function that
        # happened to share an owner name must not inherit their declaration.
        return None
    first = call.args[0]
    if owner == RESTORE_PAIR_HELPER and isinstance(first, ast.JoinedStr):
        return "restore-pairs-interpolation", set(restore_codes)
    if owner in {"evaluate_intent", "commit_execution"}:
        if isinstance(first, ast.Name) and first.id == "authority_failure":
            return "grant-validity-variable", set(grant_codes)
        if (
            isinstance(first, ast.Attribute)
            and isinstance(first.value, ast.Name)
            and first.value.id == "record"
            and first.attr == "invalidated_reason"
        ):
            return "state-invalidated-reason", set()
    return None


def _decision_returns(tree: ast.AST, owner_name: str) -> set[str]:
    """Literal codes returned as the second element by one decision function."""
    parents = _parents(tree)
    codes: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Return) or not isinstance(node.value, ast.Tuple):
            continue
        if _owner_name(node, parents) != owner_name or len(node.value.elts) != 2:
            continue
        code = _literal_code(node.value.elts[1])
        if code is not None:
            codes.add(code)
    return codes


def _architect_emissions(tree: ast.AST) -> tuple[set[str], list[str]]:
    """Decision codes the engine can emit, and the sites that resist reading.

    Every code-bearing position is CLASSIFIED, never skipped. Skipping is what
    made a decision code returned through a local variable invisible: the
    extractor saw no literal, said nothing, and the declaration matched a
    silently narrower world. An unreadable position now names itself, exactly
    as an unclassifiable refusal raise does.
    """
    parents = _parents(tree)
    gate_codes = _decision_returns(tree, "_effect_gate")
    grant_codes = _decision_returns(tree, "_grant_validity")
    carriers = {"authority_failure": grant_codes, "effect_code": gate_codes}
    codes: set[str] = set(gate_codes) | set(grant_codes)
    unresolved: list[str] = []

    def enclosing_function(node: ast.AST) -> ast.AST | None:
        current = node
        while current in parents:
            current = parents[current]
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return current
        return None

    def resolve(node: ast.AST | None, where: str, scope: ast.AST | None) -> None:
        """Add whatever codes this expression can emit, or name it unreadable."""
        if node is None:
            unresolved.append(f"{where}:missing-argument")
            return
        # The declared no-code path: a decision that refuses nothing.
        if isinstance(node, ast.Constant) and node.value is None:
            return
        code = _literal_code(node)
        if code is not None:
            codes.add(code)
            return
        if isinstance(node, ast.Name):
            if node.id in carriers:
                codes.update(carriers[node.id])
                return
            # A name is local: searching the whole module finds every `code` in
            # the engine and resolves none of them.
            assignments = [
                assignment.value
                for assignment in (ast.walk(scope) if scope is not None else [])
                if isinstance(assignment, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == node.id
                    for target in assignment.targets
                )
            ]
            if len(assignments) == 1:
                resolve(assignments[0], f"{where}:via-{node.id}", scope)
                return
            unresolved.append(
                f"{where}:unresolved-name:{node.id}:{len(assignments)}-assignments"
            )
            return
        if isinstance(node, ast.IfExp):
            resolve(node.body, f"{where}:if-true", scope)
            resolve(node.orelse, f"{where}:if-false", scope)
            return
        literals = _uppercase_constants(node)
        if literals:
            codes.update(literals)
            return
        unresolved.append(f"{where}:unreadable:{type(node).__name__}")

    for node in ast.walk(tree):
        owner = _owner_name(node, parents)
        if owner in {"_grant_validity", "_effect_gate"} and isinstance(node, ast.Return):
            if isinstance(node.value, ast.Tuple) and len(node.value.elts) == 2:
                resolve(
                    node.value.elts[1],
                    f"{owner}:{node.lineno}",
                    enclosing_function(node),
                )
        if owner != "evaluate_intent" or not isinstance(node, ast.Call):
            continue
        callee = _callee_name(node)
        if callee in {"_record_non_executable", "_operator_result"}:
            resolve(
                _call_argument(node, 3, "message_code"),
                f"{callee}:{node.lineno}",
                enclosing_function(node),
            )
    return codes, unresolved


def static_snapshot() -> tuple[dict[str, object], list[str]]:
    engine_tree = ast.parse(
        ENGINE_PATH.read_text(encoding="utf-8"), filename=str(ENGINE_PATH)
    )
    adapter_tree = ast.parse(
        ADAPTER_PATH.read_text(encoding="utf-8"), filename=str(ADAPTER_PATH)
    )
    bridge_tree = ast.parse(
        BRIDGE_PATH.read_text(encoding="utf-8"), filename=str(BRIDGE_PATH)
    )
    helper_specs = _helper_code_specs(engine_tree)
    bridge_specs = _helper_code_specs(bridge_tree, BRIDGE_PINNED_HELPERS)
    bridge_pair_codes, bridge_pair_unreadable = _bridge_pair_table_codes(bridge_tree)
    # One reader for one fact: the refusal side and the architect side both
    # need what _grant_validity can return, and two extractors computing it
    # separately would be free to disagree.
    grant_codes = _decision_returns(engine_tree, "_grant_validity")
    restore_codes, restore_unreadable = _restore_pair_codes(engine_tree)
    engine_codes: set[str] = set()
    wire_codes: set[str] = set()
    bridge_codes: set[str] = set()
    all_points = 0
    static_points = 0
    dynamic_sites: list[str] = []
    unclassified: list[str] = []

    def name_dynamic_site(relative: str, owner: str, kind: str) -> str:
        """A dynamic site's stable name, unique among its own siblings."""
        stem = f"{relative}:{owner}:{kind}"
        index = sum(1 for entry in dynamic_sites if entry.rsplit("#", 1)[0] == stem)
        return f"{stem}#{index}"

    # Each source carries its OWN pinned helpers, refusal classes and code
    # bucket. Those four facts used to be global, and a third source does not
    # fit that shape without changing what the first two mean: one flat helper
    # set would let a name living in the bridge pin a call site in the engine.
    #
    # `dynamic_allowed` is the engine's privilege alone. Its dynamic refusal
    # kinds are declared and derived there; the bridge has no such declaration,
    # so a non-literal code in the bridge stays UNCLASSIFIED - fail-closed, the
    # direction that makes `--write-baseline` refuse rather than invent.
    sources = (
        (ENGINE_PATH, engine_tree, helper_specs, PINNED_EXCEPTION_HELPERS,
         REFUSAL_CALLEES, engine_codes, True),
        (ADAPTER_PATH, adapter_tree, helper_specs, PINNED_EXCEPTION_HELPERS,
         REFUSAL_CALLEES, engine_codes, True),
        (BRIDGE_PATH, bridge_tree, bridge_specs, BRIDGE_PINNED_HELPERS,
         BRIDGE_REFUSAL_CALLEES, bridge_codes, False),
    )
    for (path, tree, specs, pinned, callees, target,
         dynamic_allowed) in sources:
        relative = path.relative_to(ROOT).as_posix()
        parents = _parents(tree)
        for node in ast.walk(tree):
            owner = _owner_name(node, parents)
            if isinstance(node, ast.Raise):
                if node.exc is None or owner in pinned:
                    continue
                all_points += 1
                if not isinstance(node.exc, ast.Call):
                    unclassified.append(f"{relative}:{node.lineno}:raise-expression")
                    continue
                call = node.exc
                callee = _callee_name(call)
                if callee in callees:
                    code = _literal_code(call.args[0]) if call.args else None
                    if code is not None:
                        static_points += 1
                        target.add(code)
                        continue
                    if not dynamic_allowed:
                        unclassified.append(
                            f"{relative}:{node.lineno}:dynamic-raise:{owner}"
                        )
                        continue
                    dynamic = _dynamic_refusal_kind(
                        owner,
                        call,
                        grant_codes,
                        restore_codes,
                        path == ENGINE_PATH,
                    )
                    if dynamic is None:
                        unclassified.append(
                            f"{relative}:{node.lineno}:dynamic-raise:{owner}"
                        )
                        continue
                    kind, declared_codes = dynamic
                    dynamic_sites.append(name_dynamic_site(relative, owner, kind))
                    target.update(declared_codes)
                elif callee == "WireError":
                    code_node = call.args[1] if len(call.args) > 1 else None
                    code = _literal_code(code_node)
                    if code is not None:
                        static_points += 1
                        wire_codes.add(code)
                    elif (
                        owner == "_dispatch"
                        and isinstance(code_node, ast.Attribute)
                        and code_node.attr == "code"
                    ):
                        # The translation site: a caught engine refusal crossing
                        # to the wire with its own code. Its code set is the
                        # engine universe, owned there; re-adding it here would
                        # re-merge the two vocabularies.
                        dynamic_sites.append(
                            name_dynamic_site(
                                relative, owner, "wire-translation-of-engine-code"
                            )
                        )
                    else:
                        unclassified.append(
                            f"{relative}:{node.lineno}:dynamic-wire:{owner}"
                        )
                elif callee == "TypeError" and owner in TYPE_ERROR_OWNERS:
                    dynamic_sites.append(
                        name_dynamic_site(relative, owner, "type-error-no-code")
                    )
                else:
                    unclassified.append(
                        f"{relative}:{node.lineno}:raise-callee:{callee or '?'}"
                    )
            if not isinstance(node, ast.Call):
                continue
            helper = _callee_name(node)
            if helper not in specs or owner in pinned:
                continue
            all_points += 1
            position, default_code = specs[helper]
            argument = _call_argument(node, position, "code")
            code = _literal_code(argument) if argument is not None else default_code
            if code is None:
                if path == BRIDGE_PATH and bridge_pair_codes:
                    # The pair-table site: its codes are derived above from the
                    # literal pairs it iterates, so it is a DYNAMIC point with a
                    # declared set, not an unclassified one.
                    dynamic_sites.append(
                        name_dynamic_site(relative, owner, "bridge-pair-table")
                    )
                    target.update(bridge_pair_codes)
                else:
                    unclassified.append(
                        f"{relative}:{node.lineno}:dynamic-helper:{helper}"
                    )
            else:
                static_points += 1
                target.add(code)

    # The bridge declares its own vocabulary next to the code that raises it,
    # and the declaration is held to the measurement in BOTH directions: a code
    # raised but not declared, and a name declared but raised nowhere, are the
    # same defect seen from two sides. Reported as a snapshot problem rather
    # than a package check on purpose - a problem here makes `--write-baseline`
    # REFUSE, where a package check would let the baseline be written first and
    # redden afterwards.
    declared_bridge_node = _assignment_value(bridge_tree, "OTCS_REFUSAL_CODES")
    declared_bridge = (
        _uppercase_constants(declared_bridge_node)
        if declared_bridge_node is not None
        else set()
    )
    internal_node = _assignment_value(bridge_tree, "OTCS_INTERNAL_ONLY_CODES")
    declared_internal = (
        _uppercase_constants(internal_node) if internal_node is not None else set()
    )

    declared_node = _assignment_value(engine_tree, "ARCHITECT_DECISION_CODES")
    declared_architect = (
        _uppercase_constants(declared_node) if declared_node is not None else set()
    )
    emitted_architect, architect_unresolved = _architect_emissions(engine_tree)
    problems: list[str] = []
    for label, node in (
        ("OTCS_REFUSAL_CODES", declared_bridge_node),
        ("OTCS_INTERNAL_ONLY_CODES", internal_node),
        ("ARCHITECT_DECISION_CODES", declared_node),
    ):
        unreadable = _unreadable_members(node) if node is not None else set()
        if unreadable:
            problems.append(
                f"DECLARED_VOCABULARY_UNREADABLE:{label} {sorted(unreadable)}"
            )
    if bridge_pair_unreadable:
        problems.append(
            "FAILURE_SURFACE_UNCLASSIFIED:bridge-pair-table "
            + ",".join(sorted(bridge_pair_unreadable))
        )
    if restore_unreadable:
        problems.append(
            "FAILURE_SURFACE_UNCLASSIFIED:restore-helper "
            + ",".join(sorted(restore_unreadable))
        )
    if architect_unresolved:
        problems.append(
            "FAILURE_SURFACE_UNCLASSIFIED:architect "
            + ",".join(sorted(architect_unresolved))
        )
    if unclassified:
        problems.append(
            "FAILURE_SURFACE_UNCLASSIFIED:static " + ",".join(sorted(unclassified))
        )
    if declared_bridge != bridge_codes:
        problems.append(
            "BRIDGE_REFUSAL_VOCABULARY "
            f"declared_only={sorted(declared_bridge - bridge_codes)} "
            f"raised_only={sorted(bridge_codes - declared_bridge)}"
        )
    if not declared_internal <= declared_bridge:
        # An internal-only name that is not a bridge code at all would be a
        # silent way to withhold something from the published surface. The
        # exclusion list is held to the vocabulary, not trusted beside it.
        problems.append(
            "BRIDGE_INTERNAL_ONLY_NOT_A_SUBSET "
            f"{sorted(declared_internal - declared_bridge)}"
        )
    if declared_architect != emitted_architect:
        problems.append(
            "ARCHITECT_DECISION_VOCABULARY "
            f"declared_only={sorted(declared_architect - emitted_architect)} "
            f"emitted_only={sorted(emitted_architect - declared_architect)}"
        )
    # The enum builder rejects an engine/wire collision because those two
    # vocabularies form the published `Error.code` enum. A bridge collision
    # would leave that enum intact while contradicting the separate-vocabulary
    # contract. Check all three pairs here; this does not prove that the
    # vocabulary inventory itself is exhaustive.
    for left_name, left, right_name, right in (
        ("engine", engine_codes, "wire", wire_codes),
        ("engine", engine_codes, "bridge", bridge_codes),
        ("wire", wire_codes, "bridge", bridge_codes),
    ):
        shared = set(left) & set(right)
        if shared:
            problems.append(
                f"CLOSED_WORLDS_NOT_DISJOINT {left_name}&{right_name} "
                f"{sorted(shared)}"
            )
    accounted = static_points + len(dynamic_sites) + len(unclassified)
    if accounted != all_points:
        problems.append(
            "FAILURE_SURFACE_ACCOUNTING "
            f"all={all_points} static={static_points} "
            f"dynamic={len(dynamic_sites)} unclassified={len(unclassified)}"
        )
    snapshot: dict[str, object] = {
        "format": BASELINE_FORMAT,
        "procedures": dict(PROCEDURES),
        "engine_refusal_codes": sorted(engine_codes),
        "wire_error_codes": sorted(wire_codes),
        "bridge_refusal_codes": sorted(bridge_codes),
        "architect_decision_codes": sorted(emitted_architect),
        "emission_points_all": all_points,
        "emission_points_static": static_points,
        "dynamic_emission_points": sorted(dynamic_sites),
    }
    return snapshot, problems


class _Observation:
    """Runtime sinks for one recorded suite run."""

    def __init__(
        self,
        engine_universe: set[str],
        wire_universe: set[str],
        bridge_universe: set[str],
    ) -> None:
        self.engine_universe = set(engine_universe)
        self.wire_universe = set(wire_universe)
        self.bridge_universe = set(bridge_universe)
        self.constructed_engine: set[str] = set()
        self.constructed_wire: set[str] = set()
        self.constructed_bridge: set[str] = set()
        self.witnessed_engine_raw: set[str] = set()
        self.witnessed_wire_raw: set[str] = set()
        self.witnessed_bridge_raw: set[str] = set()
        self.translated: set[str] = set()
        self.nondiscriminating: list[str] = []


_ACTIVE: _Observation | None = None
# The trailing separator keeps a sibling like `tests_extra` from
# prefix-matching the tests directory.
_TESTS_DIR = str((ROOT / "tests").resolve()).lower() + os.sep
_FILE_SIDE_CACHE: dict[str, bool] = {}


def _is_test_file(filename: str) -> bool:
    cached = _FILE_SIDE_CACHE.get(filename)
    if cached is None:
        try:
            resolved = str(Path(filename).resolve()).lower()
        except OSError:
            resolved = filename.lower()
        cached = resolved.startswith(_TESTS_DIR)
        _FILE_SIDE_CACHE[filename] = cached
    return cached


_OWN_FILE = str(Path(__file__).resolve()).lower()


def _entered_from_tests() -> bool:
    """Did test code enter the comparison or the assertion context?

    Walks outward from the immediate caller, skipping this tool's own frames
    and unittest's internals, and asks whether the first foreign frame lives
    under tests/. Written as a walk rather than a frame depth on purpose: a
    depth is silently wrong after any refactor, and the first version of this
    gate was off by one, which cost 36 witnesses and would have pinned the
    undercount into the baseline as truth.
    """
    frame = sys._getframe(1)
    while frame is not None:
        module = frame.f_globals.get("__name__", "").split(".")[0]
        filename = frame.f_code.co_filename
        try:
            resolved = str(Path(filename).resolve()).lower()
        except OSError:
            resolved = filename.lower()
        if module != "unittest" and resolved != _OWN_FILE:
            return _is_test_file(filename)
        frame = frame.f_back
    return False


class _ObservedCode(str):
    """The code of a production-raised refusal, as test code sees it.

    A passing equality comparison performed by a frame inside tests/ records
    the pair (this refusal was raised, its exact code was checked). Python's
    subclass-priority rule routes both `exc.code == literal` and
    `literal == exc.code` through this __eq__. __ne__ must be defined too:
    str carries its own C-level __ne__, which would otherwise answer
    helper-style `exc.code != expected` without ever calling __eq__.

    Subclasses bind the sink, so a code that crossed into test code on a wire
    error is never credited to the engine's witnesses: the two published
    vocabularies overlap, and a single sink would let a wire-side check retire
    engine debt.
    """

    __slots__ = ()
    _sink_name = ""

    def _record_equal(self) -> None:
        if _ACTIVE is None:
            return
        if _entered_from_tests():
            getattr(_ACTIVE, self._sink_name).add(self[:])

    def __eq__(self, other: object) -> bool:
        result = str.__eq__(self, other)
        # Two observed codes compared to each other is production bookkeeping,
        # never a test stating an expected value.
        if result is True and not isinstance(other, _ObservedCode):
            self._record_equal()
        return result

    def __ne__(self, other: object) -> bool:
        result = str.__ne__(self, other)
        if result is False and not isinstance(other, _ObservedCode):
            self._record_equal()
        return result

    __hash__ = str.__hash__


class _EngineObservedCode(_ObservedCode):
    __slots__ = ()
    _sink_name = "witnessed_engine_raw"


class _WireObservedCode(_ObservedCode):
    __slots__ = ()
    _sink_name = "witnessed_wire_raw"


class _BridgeObservedCode(_ObservedCode):
    __slots__ = ()
    _sink_name = "witnessed_bridge_raw"


def _install_observation(
    ledger_module: object,
    adapter_module: object,
    bridge_module: object,
    observation: _Observation,
) -> list[tuple[object, str, object, bool]]:
    """Patch the refusal classes and the unittest raise context.

    Returns restoration records (owner, attribute, original, existed).
    """
    global _ACTIVE
    restores: list[tuple[object, str, object, bool]] = []

    def patch_class(
        cls: type, code_position: int, sink: set[str], observed: type
    ) -> None:
        original_init = cls.__dict__["__init__"]

        def traced_init(self, *args, __original=original_init, **kwargs):
            frame = sys._getframe(1)
            caller = frame.f_globals.get("__name__", "")
            production = caller in _SDK_MODULE_NAMES
            code = kwargs.get(
                "code",
                args[code_position] if len(args) > code_position else None,
            )
            if production:
                if issubclass(type(code), str) and CODE_RE.fullmatch(code):
                    sink.add(str.__str__(code))
                    # Provenance, not membership. Which function built it is the
                    # only evidence that a code CROSSED from the engine; deriving
                    # that from set arithmetic would publish any adapter-side
                    # construction as translated, including one that was never
                    # raised at all.
                    if frame.f_code.co_name == TRANSLATION_SITE:
                        observation.translated.add(str.__str__(code))
                self.__dict__["_fs_production"] = True
            return __original(self, *args, **kwargs)

        def code_get(self):
            raw = self.__dict__["code"]
            if self.__dict__.get("_fs_production"):
                return observed(raw)
            return raw

        # The plain copy is taken with the BASE implementation. It was `value[:]`,
        # which runs a str subclass's own `__getitem__`: the bridge suite drives a
        # downstream code that refuses to be sliced, and under observation that
        # refusal fired inside this setter, so the recorded run errored on a case
        # that passes on its own - the instrument measuring its own interference.
        # And the type is the value's REAL one, as in the bridge: `isinstance` asks
        # `__class__`, and a code that claims to be a string through it made this
        # setter raise TypeError in the recorded run - measured, on the bridge case
        # that drives exactly such a code and passes on its own.
        def code_set(self, value):
            self.__dict__["code"] = (
                str.__str__(value) if issubclass(type(value), str) else value
            )

        restores.append((cls, "__init__", original_init, True))
        cls.__init__ = traced_init
        # Capture whatever `code` was, not a placeholder: restoring None over a
        # real class attribute would corrupt the class rather than undo the
        # patch. Neither class carries one today; the record must not depend
        # on that staying true.
        restores.append(
            (cls, "code", cls.__dict__.get("code"), "code" in cls.__dict__)
        )
        setattr(cls, "code", property(code_get, code_set))

    engine_class = ledger_module.ContractViolation
    bridge_class = bridge_module.OTCSBridgeError
    # (exception class, universe attribute, witness sink attribute).
    # The regex path used to name the engine class directly, so a bridge
    # refusal asserted by an anchored pattern witnessed nothing at all.
    REGEX_TARGETS = (
        (engine_class, "engine_universe", "witnessed_engine_raw"),
        (bridge_class, "bridge_universe", "witnessed_bridge_raw"),
    )
    context = unittest.case._AssertRaisesContext
    original_exit = context.__exit__

    def traced_exit(self, exc_type, exc_value, traceback):
        outcome = original_exit(self, exc_type, exc_value, traceback)
        if (
            outcome
            and _ACTIVE is not None
            and exc_value is not None
            and isinstance(exc_value, tuple(t[0] for t in REGEX_TARGETS))
            and getattr(exc_value, "_fs_production", False)
            and getattr(self, "expected_regex", None) is not None
            # The context is patched process-wide; without this the assertion
            # need not have been written in a test at all.
            and _entered_from_tests()
        ):
            code = exc_value.__dict__.get("code")
            universe_name, sink_name = next(
                (u, s) for cls, u, s in REGEX_TARGETS
                if isinstance(exc_value, cls)
            )
            universe = getattr(_ACTIVE, universe_name)
            if isinstance(code, str) and code in universe:
                pattern = self.expected_regex
                # The question is not whether the pattern matched, but whether
                # it matched BECAUSE OF the code. Asked by substitution: swap
                # this code for each other code of the closed world in the
                # exception's own rendering, leaving the detail untouched. A
                # pattern that still matches did not discriminate on the code,
                # which is exactly how a detail-only pattern passes its
                # assertion while checking nothing about the code.
                rendering = str(exc_value)
                checks_code = bool(
                    pattern.search(code) or pattern.search(rendering)
                )
                ambiguous = sorted(
                    other
                    for other in universe
                    if other != code
                    and (
                        pattern.search(other)
                        or pattern.search(rendering.replace(code, other, 1))
                    )
                )
                if checks_code and not ambiguous:
                    getattr(_ACTIVE, sink_name).add(code[:])
                elif checks_code:
                    _ACTIVE.nondiscriminating.append(
                        f"pattern={pattern.pattern} code={code} "
                        f"also_matches={ambiguous[:3]}"
                    )
        return outcome

    try:
        patch_class(
            engine_class, 0, observation.constructed_engine, _EngineObservedCode
        )
        patch_class(
            adapter_module.WireError, 1, observation.constructed_wire,
            _WireObservedCode,
        )
        patch_class(
            bridge_class, 0, observation.constructed_bridge,
            _BridgeObservedCode,
        )
        restores.append((context, "__exit__", original_exit, True))
        context.__exit__ = traced_exit
    except BaseException:
        # A half-applied patch set has no other path back to a clean process.
        _restore_observation(restores)
        raise
    _ACTIVE = observation
    return restores


def _restore_observation(
    restores: list[tuple[object, str, object, bool]]
) -> None:
    global _ACTIVE
    _ACTIVE = None
    for owner, attribute, original, existed in reversed(restores):
        if existed:
            setattr(owner, attribute, original)
        else:
            delattr(owner, attribute)


def _iter_cases(suite: unittest.TestSuite) -> Iterable[unittest.TestCase]:
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _iter_cases(item)
        else:
            yield item


def runtime_snapshot(
    engine_universe: set[str],
    wire_universe: set[str],
    bridge_universe: set[str],
) -> tuple[dict[str, object], list[str]]:
    sdk = str(ROOT / "sdk" / "python")
    tests = str(ROOT / "tests")
    for path in (sdk, tests):
        if path not in sys.path:
            sys.path.insert(0, path)
    ledger_module = importlib.import_module("nc25_universal_ledger")
    adapter_module = importlib.import_module("nc25_universal_adapter")
    bridge_module = importlib.import_module("nc25_otcs_bridge")
    unittest_modules = [
        importlib.import_module(name) for name in UNITTEST_SUITE_MODULES
    ]
    script_modules = {
        name: importlib.import_module(name) for name in SCRIPT_SUITE_MODULES
    }
    loaded = unittest.TestSuite(
        unittest.defaultTestLoader.loadTestsFromModule(module)
        for module in unittest_modules
    )
    all_ids = [case.id() for case in _iter_cases(loaded)]
    selected = unittest.TestSuite(
        case
        for case in _iter_cases(loaded)
        if not case.id().endswith(RUNTIME_EXCLUDED_SUFFIXES)
    )
    observation = _Observation(engine_universe, wire_universe, bridge_universe)
    problems: list[str] = []
    script_markers: dict[str, str] = {}
    # The two halves of this tool identify the code differently: the static
    # inventory reads FILES, the runtime observation imports MODULES BY NAME.
    # Nothing made them the same code. A stale or shadowed entry in
    # sys.modules is enough for the published figures to describe two
    # different engines while every other check stays green.
    for module, path in (
        (ledger_module, ENGINE_PATH),
        (adapter_module, ADAPTER_PATH),
        # The bridge is imported for observation just like the other two,
        # so it is exposed to exactly the hazard described above: a stale
        # or shadowed sys.modules entry would let the static inventory and
        # the runtime observation describe two different bridges.
        (bridge_module, BRIDGE_PATH),
    ):
        imported = Path(getattr(module, "__file__", "") or "")
        try:
            same = imported.resolve() == path.resolve()
        except OSError:
            same = False
        if not same:
            problems.append(
                f"FAILURE_RUNTIME_MODULE_MISMATCH {module.__name__} "
                f"imported={imported} inventoried={path}"
            )
    # A renamed translation site would leave its sink permanently empty, and an
    # empty sink reads exactly like "nothing crossed".
    if not hasattr(adapter_module.UniversalConnectionHttpAdapter, TRANSLATION_SITE):
        problems.append(f"FAILURE_TRANSLATION_SITE_MISSING {TRANSLATION_SITE}")
    # Comparing the published exclusion list against the constant it was
    # published from proves nothing. What must hold is that each suffix still
    # names a real case: a renamed check would otherwise re-enter the recorded
    # run and re-invoke this tool from inside it.
    for suffix in RUNTIME_EXCLUDED_SUFFIXES:
        matched = [case_id for case_id in all_ids if case_id.endswith(suffix)]
        if len(matched) != 1:
            problems.append(
                f"FAILURE_RUNTIME_EXCLUSION_UNMATCHED {suffix} matched={matched}"
            )
    stream = io.StringIO()
    restores = _install_observation(
        ledger_module, adapter_module, bridge_module, observation
    )
    try:
        result = unittest.TextTestRunner(stream=stream, verbosity=0).run(selected)
        if not result.wasSuccessful():
            # Every failing case by name, then the tail. The tail alone showed the
            # LAST error only, so a run with two named one and counted two.
            failing = sorted(test.id() for test, _ in result.errors + result.failures)
            summary = " ".join(stream.getvalue().split())[-2000:]
            problems.append(
                f"FAILURE_RUNTIME_SUITE:unittest failing={failing} {summary}"
            )
        for name in SCRIPT_SUITE_MODULES:
            buffer = io.StringIO()
            failure: str | None = None
            try:
                with contextlib.redirect_stdout(buffer):
                    script_modules[name].main()
            except SystemExit as exc:
                if exc.code not in (None, 0):
                    failure = f"exit={exc.code!r}"
            except Exception as exc:  # noqa: BLE001 - reported, not hidden
                failure = f"{type(exc).__name__}: {exc}"
            output = buffer.getvalue()
            found = SCRIPT_SUITE_MARKERS[name].findall(output)
            match = found[-1] if found else None
            if failure is not None:
                tail = " ".join(output.split())[-500:]
                problems.append(f"FAILURE_RUNTIME_SUITE:{name} {failure} {tail}")
            elif match is None:
                tail = " ".join(output.split())[-500:]
                problems.append(f"FAILURE_RUNTIME_SUITE:{name} marker-missing {tail}")
            else:
                script_markers[name] = match
    finally:
        _restore_observation(restores)

    witnessed = observation.witnessed_engine_raw & observation.engine_universe
    if not observation.constructed_engine:
        problems.append("FAILURE_RUNTIME_EMPTY:constructed_engine_codes")
    if not observation.constructed_wire:
        # Guarded like the engine sink rather than left to the baseline diff:
        # an empty sink and a sink that recorded nothing because it was never
        # armed are indistinguishable to a set comparison.
        problems.append("FAILURE_RUNTIME_EMPTY:constructed_wire_codes")
    if not witnessed:
        problems.append("FAILURE_RUNTIME_EMPTY:witnessed_codes")
    # The bridge sink gets the same guard for the same reason: installed
    # and never fed is indistinguishable from fed and empty.
    if not observation.constructed_bridge:
        problems.append("FAILURE_RUNTIME_EMPTY:constructed_bridge_codes")
    if not witnessed <= observation.constructed_engine:
        problems.append(
            "FAILURE_RUNTIME_WITNESS_WITHOUT_CONSTRUCTION "
            f"{sorted(witnessed - observation.constructed_engine)}"
        )
    # An engine refusal raised with a code the closed world does not contain
    # means the static procedure missed an emission path.
    outside = observation.constructed_engine - observation.engine_universe
    if outside:
        problems.append(f"FAILURE_RUNTIME_OUT_OF_WORLD engine={sorted(outside)}")
    # The adapter's translation site re-emits the code of a refusal it caught,
    # so a wire raise legitimately carries engine codes. What it must not do
    # silently is carry a code belonging to neither published vocabulary: that
    # is a code injected from outside production, and it is named rather than
    # folded into the wire figure.
    foreign = sorted(
        observation.translated
        - observation.wire_universe
        - observation.engine_universe
    )
    for entry in observation.nondiscriminating:
        problems.append(f"FAILURE_WITNESS_NONDISCRIMINATING {entry}")
    unwitnessed = observation.engine_universe - witnessed
    witnessed_bridge = (
        observation.witnessed_bridge_raw & observation.bridge_universe
    )
    unwitnessed_bridge = observation.bridge_universe - witnessed_bridge
    runtime: dict[str, object] = {
        "unittest_modules": list(UNITTEST_SUITE_MODULES),
        "script_suites": list(SCRIPT_SUITE_MODULES),
        "excluded_tests": sorted(RUNTIME_EXCLUDED_SUFFIXES),
        "unittest_test_count": result.testsRun,
        "script_markers": script_markers,
        "constructed_engine_codes": sorted(observation.constructed_engine),
        "constructed_wire_codes": sorted(observation.constructed_wire),
        "foreign_translated_codes": foreign,
        "witnessed_codes": sorted(witnessed),
        "unwitnessed_codes": sorted(unwitnessed),
        "constructed_bridge_codes": sorted(observation.constructed_bridge),
        "witnessed_bridge_codes": sorted(witnessed_bridge),
        "unwitnessed_bridge_codes": sorted(unwitnessed_bridge),
    }
    return runtime, problems


def build_snapshot(include_runtime: bool) -> tuple[dict[str, object], list[str]]:
    snapshot, problems = static_snapshot()
    if include_runtime:
        runtime, runtime_problems = runtime_snapshot(
            set(snapshot["engine_refusal_codes"]),
            set(snapshot["wire_error_codes"]),
            set(snapshot["bridge_refusal_codes"]),
        )
        snapshot["runtime"] = runtime
        problems.extend(runtime_problems)
    problems.extend(_procedure_coverage_problems(snapshot))
    return snapshot, problems


def _set_difference_problem(
    marker: str,
    baseline: dict[str, object],
    current: dict[str, object],
    field: str,
) -> list[str]:
    old = set(baseline.get(field, []))
    new = set(current.get(field, []))
    problems: list[str] = []
    if new - old:
        problems.append(f"{marker}_ADDED {sorted(new - old)}")
    if old - new:
        problems.append(f"{marker}_REMOVED {sorted(old - new)}")
    return problems


def _scalar_problem(
    marker: str,
    baseline: dict[str, object],
    current: dict[str, object],
    field: str,
) -> list[str]:
    if baseline.get(field) != current.get(field):
        return [
            f"{marker} baseline={baseline.get(field)} current={current.get(field)}"
        ]
    return []


def check_baseline(include_runtime: bool = False) -> tuple[dict[str, object], list[str]]:
    current, problems = build_snapshot(include_runtime)
    if not BASELINE_PATH.is_file():
        return current, problems + ["FAILURE_SURFACE_BASELINE_MISSING"]
    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    if baseline.get("format") != BASELINE_FORMAT:
        problems.append("FAILURE_SURFACE_BASELINE_FORMAT")
        return current, problems
    if baseline.get("procedures") != current.get("procedures"):
        problems.append("FAILURE_SURFACE_PROCEDURES_STALE")
    # A recorded loss is only worth recording if something reads it back. These
    # print on every check so the reason a piece of coverage was given up stays
    # in front of whoever reads the verdict, instead of sitting unread in the
    # file until the next regeneration drops it.
    accepted = baseline.get("accepted_regression")
    if isinstance(accepted, dict):
        print(
            "ACCEPTED_REGRESSION_ON_RECORD"
            f" reason={accepted.get('reason')!r}"
            f" losses={accepted.get('losses')}"
        )
    adopted = baseline.get("adopted_baseline")
    if isinstance(adopted, dict):
        print(f"ADOPTED_BASELINE_ON_RECORD reason={adopted.get('reason')!r}")
    problems.extend(
        _scalar_problem(
            "FAILURE_EMISSION_POINT_COUNT", baseline, current, "emission_points_all"
        )
    )
    problems.extend(
        _scalar_problem(
            "FAILURE_EMISSION_STATIC_COUNT",
            baseline,
            current,
            "emission_points_static",
        )
    )
    if sorted(baseline.get("dynamic_emission_points", [])) != sorted(
        current.get("dynamic_emission_points", [])
    ):
        problems.append(
            "DYNAMIC_EMISSION_POINTS "
            f"baseline={sorted(baseline.get('dynamic_emission_points', []))} "
            f"current={sorted(current.get('dynamic_emission_points', []))}"
        )
    problems.extend(
        _set_difference_problem(
            "ENGINE_REFUSAL_UNIVERSE", baseline, current, "engine_refusal_codes"
        )
    )
    problems.extend(
        _set_difference_problem(
            "WIRE_ERROR_UNIVERSE", baseline, current, "wire_error_codes"
        )
    )
    problems.extend(
        _set_difference_problem(
            "BRIDGE_REFUSAL_UNIVERSE", baseline, current, "bridge_refusal_codes"
        )
    )
    problems.extend(
        _set_difference_problem(
            "ARCHITECT_DECISION_CODES", baseline, current, "architect_decision_codes"
        )
    )
    if include_runtime:
        baseline_runtime = baseline.get("runtime")
        current_runtime = current.get("runtime", {})
        if not isinstance(baseline_runtime, dict):
            problems.append("FAILURE_RUNTIME_BASELINE_MISSING")
            return current, problems
        for field in ("unittest_modules", "script_suites", "excluded_tests"):
            if baseline_runtime.get(field) != current_runtime.get(field):
                problems.append(
                    f"RUNTIME_SUITE_SELECTION:{field} "
                    f"baseline={baseline_runtime.get(field)} "
                    f"current={current_runtime.get(field)}"
                )
        problems.extend(
            _scalar_problem(
                "RUNTIME_TEST_COUNT",
                baseline_runtime,
                current_runtime,
                "unittest_test_count",
            )
        )
        problems.extend(
            _scalar_problem(
                "SCRIPT_SUITE_MARKERS",
                baseline_runtime,
                current_runtime,
                "script_markers",
            )
        )
        problems.extend(
            _set_difference_problem(
                "CONSTRUCTED_ENGINE", baseline_runtime, current_runtime,
                "constructed_engine_codes",
            )
        )
        problems.extend(
            _set_difference_problem(
                "CONSTRUCTED_WIRE", baseline_runtime, current_runtime,
                "constructed_wire_codes",
            )
        )
        problems.extend(
            _set_difference_problem(
                "FOREIGN_TRANSLATED", baseline_runtime, current_runtime,
                "foreign_translated_codes",
            )
        )
        problems.extend(
            _set_difference_problem(
                "WITNESSED", baseline_runtime, current_runtime, "witnessed_codes"
            )
        )
        problems.extend(
            _set_difference_problem(
                "UNWITNESSED", baseline_runtime, current_runtime,
                "unwitnessed_codes",
            )
        )
        # The bridge's three runtime figures, compared like the rest. Until
        # these existed the WRITE path acknowledged a lost bridge witness and
        # the CHECK path could not see one: a deleted sweep row passed --check
        # green while the vocabulary and the test count both stayed put.
        problems.extend(
            _set_difference_problem(
                "CONSTRUCTED_BRIDGE", baseline_runtime, current_runtime,
                "constructed_bridge_codes",
            )
        )
        problems.extend(
            _set_difference_problem(
                "WITNESSED_BRIDGE", baseline_runtime, current_runtime,
                "witnessed_bridge_codes",
            )
        )
        problems.extend(
            _set_difference_problem(
                "UNWITNESSED_BRIDGE", baseline_runtime, current_runtime,
                "unwitnessed_bridge_codes",
            )
        )
    return current, problems


def _print_snapshot(snapshot: dict[str, object]) -> None:
    all_points = snapshot["emission_points_all"]
    static_points = snapshot["emission_points_static"]
    dynamic_count = len(snapshot["dynamic_emission_points"])
    print(
        "FAILURE_EMISSION_POINTS "
        f"all={all_points} static={static_points} dynamic={dynamic_count}"
    )
    print(f"ENGINE_REFUSAL_CODES={len(snapshot['engine_refusal_codes'])}")
    print(f"BRIDGE_REFUSAL_CODES={len(snapshot['bridge_refusal_codes'])}")
    print(f"WIRE_ERROR_CODES={len(snapshot['wire_error_codes'])}")
    print(f"ARCHITECT_DECISION_CODES={len(snapshot['architect_decision_codes'])}")
    runtime = snapshot.get("runtime")
    if isinstance(runtime, dict):
        print(
            "CONSTRUCTED_IN_RUN "
            f"engine={len(runtime['constructed_engine_codes'])} "
            f"wire={len(runtime['constructed_wire_codes'])} "
            f"bridge={len(runtime['constructed_bridge_codes'])} "
            f"foreign_translated={len(runtime['foreign_translated_codes'])}"
        )
        print(f"WITNESSED_CODES={len(runtime['witnessed_codes'])}")
        print(f"UNWITNESSED_CODES={len(runtime['unwitnessed_codes'])}")
        # Printed beside the engine figures, not folded into them: a reader who
        # sees only two worlds in the summary will assume there are two.
        print(f"WITNESSED_BRIDGE_CODES={len(runtime['witnessed_bridge_codes'])}")
        print(
            f"UNWITNESSED_BRIDGE_CODES={len(runtime['unwitnessed_bridge_codes'])}"
        )
        print(f"RUNTIME_UNITTEST_TESTS={runtime['unittest_test_count']}")


def regeneration_regressions(
    baseline: dict[str, object], current: dict[str, object]
) -> list[str]:
    """What a regeneration would give up, if anything.

    A ratchet that any regeneration can move in either direction is a
    convention, not a ratchet: `--check` refuses the regression, and then the
    same tool writes it away without a word. These are the directions that
    must cost an explicit acknowledgement.
    """
    old_runtime = baseline.get("runtime") or {}
    new_runtime = current.get("runtime") or {}
    losses: list[str] = []
    # Every published list is watched by construction. A field escapes only
    # by being named in SELECTION_FIELDS - which is what that set is for, and
    # which is read here rather than restated - or by having inverted polarity,
    # of which there are exactly two and both are named below. A new figure
    # added to the snapshot is therefore ratcheted the moment it exists, with
    # nobody having to remember this function.
    DEBT_FIELDS = {
        "unwitnessed_codes": "REGENERATION_GROWS_DEBT",
        "unwitnessed_bridge_codes": "REGENERATION_GROWS_BRIDGE_DEBT",
    }
    for old_scope, new_scope in ((baseline, current), (old_runtime, new_runtime)):
        for field in sorted(set(old_scope) | set(new_scope)):
            if field in SELECTION_FIELDS:
                continue
            old_value = old_scope.get(field)
            new_value = new_scope.get(field)
            if not isinstance(old_value, list) or not isinstance(new_value, list):
                continue
            if field in DEBT_FIELDS:
                grown = sorted(set(new_value) - set(old_value))
                if grown:
                    losses.append(f"{DEBT_FIELDS[field]} {grown}")
                continue
            lost = sorted(set(old_value) - set(new_value))
            if lost:
                losses.append(f"REGENERATION_LOSES:{field} {lost}")
    # The scalar the recorded run also carries. `check_baseline` treats a
    # changed test count as a difference worth naming, and until this entry the
    # write path did not: a regeneration could record a smaller run - suites
    # deselected, cases deleted - and exit zero, so the evidence behind every
    # witnessed code could shrink without the reason this function exists to
    # demand. Only a DECREASE is a loss; growth is free, like every other set
    # above it.
    old_tests = old_runtime.get("unittest_test_count")
    new_tests = new_runtime.get("unittest_test_count")
    if isinstance(old_tests, int) and isinstance(new_tests, int):
        if new_tests < old_tests:
            losses.append(
                f"REGENERATION_LOSES:unittest_test_count {old_tests} -> {new_tests}"
            )
    return losses


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write-baseline", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--check-static", action="store_true")
    parser.add_argument(
        "--accept-regression",
        metavar="REASON",
        help="acknowledge, in words, coverage the regeneration gives up",
    )
    parser.add_argument(
        "--adopt-baseline",
        metavar="REASON",
        help=(
            "acknowledge writing a baseline with nothing to compare against:"
            " the file is missing, or it carries a different format"
        ),
    )
    args = parser.parse_args()
    if not args.write_baseline and (args.accept_regression or args.adopt_baseline):
        # These acknowledge something only a regeneration can give up. Accepted
        # silently beside --check they read as "I acknowledged the loss" while
        # doing nothing at all.
        print("ACKNOWLEDGEMENT_REQUIRES_WRITE_BASELINE")
        raise SystemExit(2)
    if args.write_baseline:
        snapshot, problems = build_snapshot(include_runtime=True)
        _print_snapshot(snapshot)
        if problems:
            for problem in problems:
                print(problem)
            raise SystemExit(1)
        # Two ways to reach a write with no comparison, and both used to be
        # silent: the file is absent, or it carries another format. Either one
        # turns the ratchet off for exactly one run, which is all it takes, so
        # both now cost the same explicit acknowledgement a loss costs.
        previous: dict[str, object] | None = None
        if BASELINE_PATH.is_file():
            previous = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
            if previous.get("format") != BASELINE_FORMAT:
                print(
                    "BASELINE_FORMAT_MISMATCH"
                    f" recorded={previous.get('format')!r} expected={BASELINE_FORMAT!r}"
                )
                previous = None
        else:
            print("BASELINE_ABSENT")
        if previous is None:
            if not args.adopt_baseline:
                print(
                    "BASELINE_ADOPTION_REFUSED: nothing to compare against;"
                    ' rerun with --adopt-baseline "<reason>" to record why this'
                    " baseline is written without a comparison"
                )
                raise SystemExit(1)
            snapshot["adopted_baseline"] = {"reason": args.adopt_baseline}
        else:
            losses = regeneration_regressions(previous, snapshot)
            if losses:
                for loss in losses:
                    print(loss)
                if not args.accept_regression:
                    print(
                        "REGENERATION_REFUSED: rerun with"
                        ' --accept-regression "<reason>" to record why this'
                        " coverage is given up"
                    )
                    raise SystemExit(1)
                snapshot["accepted_regression"] = {
                    "reason": args.accept_regression,
                    "losses": losses,
                }
            elif "accepted_regression" in previous:
                # A recorded loss outlives the regeneration that recorded it.
                # Dropping it here would erase the only trace of what coverage
                # was given up and why, and it would go without a word.
                snapshot["accepted_regression"] = previous["accepted_regression"]
        BASELINE_PATH.write_text(
            json.dumps(snapshot, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        print(f"FAILURE_SURFACE_BASELINE={BASELINE_PATH.relative_to(ROOT).as_posix()}")
        return
    include_runtime = not args.check_static
    snapshot, problems = check_baseline(include_runtime=include_runtime)
    _print_snapshot(snapshot)
    if problems:
        for problem in problems:
            print(problem)
        raise SystemExit(1)
    print("FAILURE_SURFACE_RATCHET=1/1 PASS")


if __name__ == "__main__":
    main()
