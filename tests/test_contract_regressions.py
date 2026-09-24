from __future__ import annotations

import ast
import base64
from contextlib import closing
from datetime import datetime, timedelta
import copy
import hashlib
import inspect
import io
import json
import os
import re
import shutil
import subprocess
import sqlite3
import sys
import tempfile
import threading
import traceback
import unittest
from unittest.mock import patch
import zipfile
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "sdk" / "python"))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "tools"))

from nc25_universal_ledger import (  # noqa: E402
    ContractViolation,
    _normalize_declared_hash_case,
    Ed25519DetachedSigner,
    HmacDetachedSigner,
    IntegrityViolation,
    PUBLIC_MESSAGE_CODES,
    ROLE_ARCHITECT,
    ROLE_EXECUTOR,
    ROLE_GOVERNANCE,
    ROLE_OPERATOR,
    SHA256_RE,
    SIGNATURE_ENVELOPE_FIELDS,
    SQLiteStateStore,
    STRUCTURAL_PROVENANCE_VALUES,
    sha256_hex,
    UniversalConnectionLedger,
    DECLARED_HASH_FIELDS,
    bind_fixture,
    canonical_json,
    load_json,
    validate_declaration,
    validate_profile,
)
import test_universal_connection as universal_tests  # noqa: E402
from build_acceptance_report import (  # noqa: E402
    GATE_ROWS,
    main as generator_main,
    rebind_report_to_manifest,
    update_report,
    write_through_temporary,
)
from verify_package import (  # noqa: E402
    ALL_PACKAGE_CHECK_IDS,
    STANDALONE_PACKAGE_CHECK_IDS,
    core_deposit_availability_claims,
)
from build_review_bundle import BASELINE_FORMAT, build_artifact  # noqa: E402
from spec_counts import sole_assignment, spec_docx_name  # noqa: E402


class RaisingAppendList(list):
    def append(self, value: object) -> None:
        raise RuntimeError("FAULT_AFTER_EVENT_APPEND")


class RaisingSetDict(dict):
    def __setitem__(self, key: object, value: object) -> None:
        raise RuntimeError("FAULT_BEFORE_REPLAY_INSTALL")


# The acceptance-report generator refuses malformed evidence with ValueError
# codes. They are published nowhere but in the generator and its tests, so no
# ratchet counts them; this reader is their closed world. Every raise in the
# generator is classified into the codes it can emit, or reported as
# unclassified. A pinned helper turns a caller's literal label into its code,
# so the helper's own raise is not a site and each call site is.
# The world's key is therefore (call site, code), and that granularity has a cost
# worth saying: a pinned helper with TWO raises of the same code - `replace_once`
# refuses a wrong count of the claim and, separately, a substitution that replaced
# nothing, both as `<label>:<n>` - is ONE entry per call site, and deleting either
# raise changes neither the world nor the observed set. What witnesses the second
# raise is not this equality but the by-name row whose exact text only it produces
# (a sole claim with a malformed digest, `REBIND_MANIFEST_DIGEST:0`); the break that
# removed it reddened exactly that row.
# The owner a module-level raise is filed under. It is not a function name, and it cannot
# collide with one: the generator's raises at import fire before any driver exists, so they
# are read and named rather than left as lines the reader could not classify.
IMPORT_TIME_OWNER = "<import>"
REPORT_GENERATOR_PINNED_HELPERS = {
    "require_non_negative_int": "label",
    "replace_once": "label",
    "replace_section": "label",
    # Added with the eight figure checks: the reader turns a pinned helper's CALLER into
    # the site, so each figure's own code is what the closed world sees. Without the pin
    # the helper's single raise would be one site carrying eight codes, and the ratchet
    # could say only that some figure refused.
    "require_collection": "label",
}
_REFUSAL_CODE_TEXT = re.compile(r"^[A-Z][A-Za-z0-9_]+$")


def generator_refusal_sites(source: str) -> tuple[dict[tuple[str, int, int], set[str]], list[str]]:
    """Return ({(owner, first_line, last_line): codes}, unclassified).

    A site is a raise statement or a pinned-helper call site inside a
    module-level function. A code is a literal, or an f-string whose text
    before its first literal colon is literal text and names bound by a
    literal loop table - a tuple of literal tuples, or the `.items()` of a
    module-level literal dict. The part after that colon is detail. Anything
    that does not resolve to literal codes is unclassified, never skipped.
    """
    tree = ast.parse(source)
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    functions = {
        node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)
    }
    unclassified: list[str] = []
    sites: dict[tuple[str, int, int], set[str]] = {}

    def label_index(helper: str) -> int | None:
        definition = functions.get(helper)
        if definition is None:
            return None
        names = [argument.arg for argument in definition.args.args]
        parameter = REPORT_GENERATOR_PINNED_HELPERS[helper]
        return names.index(parameter) if parameter in names else None

    for helper, parameter in REPORT_GENERATOR_PINNED_HELPERS.items():
        if label_index(helper) is None:
            unclassified.append(f"pinned helper {helper}({parameter}) is not defined")

    def enclosing(node: ast.AST, kind: type) -> ast.AST | None:
        cursor = parents.get(node)
        while cursor is not None and not isinstance(cursor, kind):
            cursor = parents.get(cursor)
        return cursor

    def owner_of(node: ast.AST) -> str | None:
        function = enclosing(node, ast.FunctionDef)
        if function is None or parents.get(function) is not tree:
            return None
        return function.name

    def loop_values(name: str, at: ast.AST) -> list[str] | None:
        loop = enclosing(at, ast.For)
        while loop is not None:
            target = loop.target
            if isinstance(target, ast.Name):
                names = [target.id]
            elif isinstance(target, ast.Tuple):
                names = [e.id if isinstance(e, ast.Name) else "" for e in target.elts]
            else:
                names = []
            if name in names:
                position = names.index(name)
                table = loop.iter
                if isinstance(table, (ast.Tuple, ast.List)) and all(
                    isinstance(row, ast.Tuple) and len(row.elts) == len(names)
                    for row in table.elts
                ):
                    cells = [row.elts[position] for row in table.elts]
                    if all(isinstance(c, ast.Constant) and isinstance(c.value, str) for c in cells):
                        return [c.value for c in cells]
                    return None
                if (
                    isinstance(table, ast.Call)
                    and isinstance(table.func, ast.Attribute)
                    and table.func.attr == "items"
                    and isinstance(table.func.value, ast.Name)
                    and not table.args
                    and position == 0
                ):
                    literal = sole_assignment(tree, table.func.value.id)
                    if isinstance(literal, ast.Dict) and all(
                        isinstance(k, ast.Constant) and isinstance(k.value, str)
                        for k in literal.keys
                    ):
                        return [k.value for k in literal.keys]
                return None
            loop = enclosing(loop, ast.For)
        return None

    def codes_of(expression: ast.AST, at: ast.AST) -> set[str] | None:
        if isinstance(expression, ast.Constant) and isinstance(expression.value, str):
            candidates = [expression.value.partition(":")[0]]
        elif isinstance(expression, ast.JoinedStr):
            candidates = [""]
            for piece in expression.values:
                if isinstance(piece, ast.Constant) and isinstance(piece.value, str):
                    head, colon, _detail = piece.value.partition(":")
                    candidates = [c + head for c in candidates]
                    if colon:
                        break
                elif (
                    isinstance(piece, ast.FormattedValue)
                    and isinstance(piece.value, ast.Name)
                    and piece.conversion == -1
                    and piece.format_spec is None
                ):
                    values = loop_values(piece.value.id, at)
                    if values is None:
                        return None
                    candidates = [c + v for c in candidates for v in values]
                else:
                    return None
        elif isinstance(expression, ast.Name):
            candidates = loop_values(expression.id, at) or []
        else:
            return None
        if not candidates or not all(_REFUSAL_CODE_TEXT.fullmatch(c) for c in candidates):
            return None
        return set(candidates)

    def is_helper_body(raise_node: ast.Raise, argument: ast.AST) -> bool:
        owner = owner_of(raise_node)
        if owner not in REPORT_GENERATOR_PINNED_HELPERS:
            return False
        parameter = REPORT_GENERATOR_PINNED_HELPERS[owner]
        if isinstance(argument, ast.Name):
            return argument.id == parameter
        if isinstance(argument, ast.JoinedStr) and len(argument.values) > 1:
            first, second = argument.values[0], argument.values[1]
            return (
                isinstance(first, ast.FormattedValue)
                and isinstance(first.value, ast.Name)
                and first.value.id == parameter
                and isinstance(second, ast.Constant)
                and str(second.value).startswith(":")
            )
        return False

    for node in ast.walk(tree):
        if isinstance(node, ast.Raise):
            where = f"line {node.lineno}"
            owner = owner_of(node)
            call = node.exc
            if owner is None:
                # A raise at module level fires at IMPORT, before any driver of this world
                # exists, so no data row can reach it and the world's completeness test
                # cannot ask for one. It is still a refusal and it is still read: it goes
                # in under the owner below, where the test names the set it expects, so a
                # NEW one changes that set rather than passing as an unclassified line.
                if not (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name)
                    and call.func.id in {"ValueError", "SystemExit"}
                    and len(call.args) == 1
                    and not call.keywords
                    and isinstance(call.args[0], ast.Constant)
                    and isinstance(call.args[0].value, str)
                ):
                    unclassified.append(f"{where}: raise outside a module-level function")
                    continue
                sites[(IMPORT_TIME_OWNER, node.lineno, node.end_lineno)] = {
                    call.args[0].value}
                continue
            if not (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id in {"ValueError", "SystemExit"}
                and len(call.args) == 1
                and not call.keywords
            ):
                unclassified.append(f"{where}: not ValueError or SystemExit with one argument")
                continue
            if is_helper_body(node, call.args[0]):
                continue
            codes = codes_of(call.args[0], node)
            if codes is None:
                unclassified.append(f"{where}: code does not resolve to literals")
                continue
            sites[(owner, node.lineno, node.end_lineno)] = codes
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in REPORT_GENERATOR_PINNED_HELPERS
        ):
            where = f"line {node.lineno}"
            parameter = REPORT_GENERATOR_PINNED_HELPERS[node.func.id]
            label = next((k.value for k in node.keywords if k.arg == parameter), None)
            index = label_index(node.func.id)
            if label is None and index is not None and index < len(node.args):
                label = node.args[index]
            owner = owner_of(node)
            codes = codes_of(label, node) if label is not None else None
            if owner is None or codes is None:
                unclassified.append(f"{where}: pinned-helper label does not resolve to literals")
                continue
            sites[(owner, node.lineno, node.end_lineno)] = codes
    return sites, sorted(unclassified)


# Words ending in "s" that follow a formatted value and are not a noun that value counts.
# `is` and `was` are the ones the generator's own text puts there, measured; the rest are
# function words of the same shape, kept so a sentence reworded around one is not a red.
_NOT_A_COUNTED_NOUN = frozenset({"is", "was", "has", "as", "its", "this", "thus", "us"})


def frozen_count_nouns(source: str) -> list[str]:
    """Every place an f-string prints a value and then a plural noun of its own.

    A count renders beside its noun through `plural`, which agrees the two. A frozen noun
    reads right at every size but one: the core section printed "1 bytes" and "1 lines"
    for a one-line, one-byte file, and nothing showed it, because no fixture has one. The
    shape looked for is a formatted value followed directly by literal text whose first
    word ends in `s` and is not a `key=` label; a noun that goes through the helper is a
    formatted value itself and never has that shape. The nouns the helper's docstring
    names as bypassing it on purpose do not have it either - the emission-point noun
    stands before its counts, and "hard findings" puts a word between - so the scan and
    that list do not overlap. Returned as `line: word`, so a red names the place.
    """
    found = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.JoinedStr):
            continue
        for value, following in zip(node.values, node.values[1:]):
            if not isinstance(value, ast.FormattedValue):
                continue
            if not (isinstance(following, ast.Constant) and isinstance(following.value, str)):
                continue
            match = re.match(r" ([A-Za-z]+s)\b(?!=)", following.value)
            if match and match.group(1).lower() not in _NOT_A_COUNTED_NOUN:
                found.append(f"{node.lineno}: {match.group(1)}")
    return found


def _nested_list(levels: int) -> list:
    """A list nested `levels` deep, built iteratively so the fixture cannot itself recurse."""
    value: list = []
    for _ in range(levels):
        value = [value]
    return value


class ContractRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(
            (ROOT / "core" / "schemas" / "runtime-contracts.schema.json").read_text(
                encoding="utf-8"
            )
        )
        cls.validator = Draft202012Validator(
            cls.schema,
            format_checker=FormatChecker(),
        )

    def fixture(self) -> universal_tests.BankingConnectionTests:
        fixture = universal_tests.BankingConnectionTests(methodName="runTest")
        fixture.setUp()
        return fixture

    def assert_schema_rejects(self, instance: dict) -> None:
        self.assertTrue(
            list(self.validator.iter_errors(instance)),
            "mutated instance unexpectedly remained schema-valid",
        )

    def engine_state(self, engine, record) -> dict:
        return {
            "ledger": engine.ledger.events_copy(),
            "structural_remaining": engine.structural_remaining,
            "committed_resources": copy.deepcopy(list(engine.committed_resources)),
            "consumed": record.consumed,
            "reservation_active": record.reservation_active,
            "invalidated_reason": record.invalidated_reason,
            "receipt_hashes": copy.deepcopy(list(engine.receipt_hashes)),
            "execution_replays": copy.deepcopy(dict(engine.execution_replays)),
        }

    def persistent_engine(
        self, fixture, state_path: Path, event_signer=None, permit_signer=None
    ):
        bound = bind_fixture(
            fixture.profile,
            fixture.declaration,
            fixture.grant,
            fixture.intent,
        )
        bound_profile, bound_declaration, bound_grant, bound_intent = bound
        engine = UniversalConnectionLedger(
            bound_profile,
            bound_declaration,
            signing_key=b"synthetic-reference-signing-key",
            clock=fixture.clock,
            state_path=state_path,
            event_signer=event_signer,
            permit_signer=permit_signer,
        )
        if engine.status == "DRAFT":
            engine.activate(
                fixture.fx.approval_owner,
                "evidence://synthetic/declaration-activation",
                actor_scope="nc25.governance",
            )
        if bound_grant["grant_id"] not in engine.grants:
            engine.issue_grant(bound_grant, actor_scope="nc25.governance")
        return engine, bound_profile, bound_declaration, bound_intent

    def test_canonical_json_types_and_declared_hash_case(self) -> None:
        # The engine normalises the case of DECLARED hash fields, and the
        # declaration lives in the schemas. Two homes for one fact drift in
        # silence, so the inventory is compared against the schemas here: a
        # field that becomes a hash in the schema and is not added to the
        # engine reddens, and so does the reverse.
        declared: set[str] = set()

        def collect(node) -> None:
            if isinstance(node, dict):
                for name, child in (node.get("properties") or {}).items():
                    if admits_a_hash(child):
                        declared.add(name)
                for child in node.values():
                    collect(child)
            elif isinstance(node, list):
                for child in node:
                    collect(child)

        def admits_a_hash(node) -> bool:
            if not isinstance(node, dict):
                return False
            reference = node.get("$ref")
            if isinstance(reference, str) and reference.endswith("/sha256"):
                return True
            # A union of "null or a hash" declares a hash too; the receipt
            # field is exactly that, and reading only $ref would miss it.
            for keyword in ("oneOf", "anyOf", "allOf"):
                for member in node.get(keyword) or []:
                    if admits_a_hash(member):
                        return True
            return False

        for schema_path in sorted((ROOT / "core" / "schemas").glob("*.json")):
            collect(json.loads(schema_path.read_text(encoding="utf-8")))
        self.assertEqual(
            declared,
            set(DECLARED_HASH_FIELDS),
            "the engine's hash-field inventory and the schemas disagree",
        )

        fixture = self.fixture()
        grant = copy.deepcopy(fixture.grant)
        grant["binding"]["profile_hash"] = grant["binding"]["profile_hash"].lower()
        grant["binding"]["declaration_hash"] = grant["binding"][
            "declaration_hash"
        ].lower()
        self.assertFalse(list(self.validator.iter_errors(grant)))
        self.assertIsNotNone(SHA256_RE.fullmatch(grant["binding"]["profile_hash"]))
        engine, _, _ = fixture.engine(grant=grant)
        self.assertTrue(engine._binding_matches(grant["binding"]))

        # The JSON helper is a public serialization boundary, independent of
        # the private persistence encoding. Unsupported Python values refuse.
        valid = {"z": {}, "a": [None, True, -2, 1.5, "text"]}
        self.assertEqual(canonical_json(valid), b'{"a":[null,true,-2,1.5,"text"],"z":{}}')
        for key in (None, 1, False):
            for nested in (False, True):
                with self.subTest(json_contract="JSON_OBJECT_KEY_TYPE", key=key, nested=nested):
                    value = {key: "value"}
                    if nested:
                        value = {"nested": [value]}
                    before = copy.deepcopy(value)
                    with self.assertRaisesRegex(ContractViolation, "^JSON_OBJECT_KEY_TYPE(:|$)"):
                        canonical_json(value)
                    self.assertEqual(value, before)
        for invalid in ((1, 2), {1, 2}, b"value"):
            for nested in (False, True):
                with self.subTest(json_contract="JSON_VALUE_TYPE", kind=type(invalid).__name__, nested=nested):
                    value = {"nested": [invalid]} if nested else invalid
                    before = copy.deepcopy(value)
                    with self.assertRaisesRegex(ContractViolation, "^JSON_VALUE_TYPE(:|$)"):
                        canonical_json(value)
                    self.assertEqual(value, before)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.json"
            for value in (None, False, 0, "text", [], [1]):
                with self.subTest(json_contract="JSON_OBJECT_REQUIRED", value=value):
                    path.write_text(json.dumps(value), encoding="utf-8")
                    before = path.read_bytes()
                    with self.assertRaisesRegex(ContractViolation, "^JSON_OBJECT_REQUIRED(:|$)"):
                        load_json(path)
                    self.assertEqual(path.read_bytes(), before)
            for value in ({}, valid):
                with self.subTest(json_contract="object-control", value=value):
                    path.write_text(json.dumps(value), encoding="utf-8")
                    self.assertEqual(load_json(path), value)

    def test_execution_contract_rejects_before_consumption(self) -> None:
        fixture = self.fixture()
        engine, intent, _ = fixture.engine()
        result = engine.evaluate_intent(intent, fixture.evidence, actor_scope=ROLE_OPERATOR)
        request = fixture.execution_request(engine, result, intent)
        permit_hash = result["permit_hash"]
        before = engine._snapshot_state()
        rows = (
            ("EXECUTION_FIELDS", (("foreign",), "set", "field")),
            ("EXECUTION_FIELDS", (("committed_at",), "delete", None)),
            ("EXECUTION_MESSAGE_TYPE", (("message_type",), "set", "x")),
            ("EXECUTION_PERMIT_HASH", (("permit_hash",), "set", "a" * 63)),
            ("EXECUTION_PERMIT_HASH", (("permit_hash",), "set", 0)),
            ("EXECUTION_CONNECTOR", (("connector_id",), "set", "")),
            ("EXECUTION_CONNECTOR", (("connector_id",), "set", 0)),
            ("EXECUTION_STATE_ANCHOR", (("state_anchor_hash",), "set", "g" * 64)),
            ("EXECUTION_STATE_ANCHOR", (("state_anchor_hash",), "set", None)),
            ("EXECUTION_BINDING_MISMATCH", (("binding",), "set", {})),
            ("EXECUTION_BINDING_MISMATCH", (("binding",), "set", [])),
        )
        cases = [(code, self._corrupt(request, (operation,)), permit_hash)
                 for code, operation in rows]
        cases.extend(("EXECUTION_ROUTE_PERMIT_HASH", copy.deepcopy(request), route)
                     for route in (None, 0, "a" * 63))
        cases.append(("EXECUTION_PERMIT_MISMATCH", copy.deepcopy(request), "0" * 64))
        for index, (code, submitted, route) in enumerate(cases):
            with self.subTest(execution_refusal=code, case=index):
                original = copy.deepcopy(submitted)
                with self.assertRaisesRegex(ContractViolation, rf"^{code}(:|$)"):
                    engine.commit_execution(submitted, actor_scope=ROLE_EXECUTOR,
                                            route_permit_hash=route)
                self.assertEqual(engine._snapshot_state(), before, "state changed on malformed execution")
                self.assertEqual(submitted, original, "caller execution was mutated")
        # Omitting the required route argument cannot skip the binding check.
        with self.assertRaises(TypeError):
            engine.commit_execution(request, actor_scope=ROLE_EXECUTOR)
        self.assertEqual(engine._snapshot_state(), before)
        # All refusals preserve the same permit for a valid consume and replay.
        with self.subTest(execution_control="valid"):
            receipt = engine.commit_execution(request, actor_scope=ROLE_EXECUTOR,
                                              route_permit_hash=permit_hash)
            self.assertEqual(receipt["permit_hash"], permit_hash)
            committed = engine._snapshot_state()
            replay = engine.commit_execution(request, actor_scope=ROLE_EXECUTOR,
                                             route_permit_hash=permit_hash)
            self.assertEqual(replay, receipt)
            self.assertEqual(engine._snapshot_state(), committed)

    def test_structural_budget_provenance_is_required_and_typed(self) -> None:
        # The declared capacity origin is coded with the published four-value
        # instrument; the declaration cannot omit the coding or invent a fifth
        # value, and every published value remains accepted.
        fixture = self.fixture()
        missing = copy.deepcopy(fixture.declaration)
        del missing["structural_budget"]["provenance"]
        with self.assertRaisesRegex(ContractViolation, "^STRUCTURAL_BUDGET(:|$)"):
            validate_declaration(missing, fixture.profile)
        mislabeled = copy.deepcopy(fixture.declaration)
        mislabeled["structural_budget"]["provenance"] = "vendor_asserted"
        with self.assertRaisesRegex(ContractViolation, "^STRUCTURAL_PROVENANCE(:|$)"):
            validate_declaration(mislabeled, fixture.profile)
        self.assertEqual(
            STRUCTURAL_PROVENANCE_VALUES,
            {
                "fully_stipulated",
                "empirically_calibrated",
                "derived_from_load_model",
                "mixed",
            },
        )
        for value in sorted(STRUCTURAL_PROVENANCE_VALUES):
            declared = copy.deepcopy(fixture.declaration)
            declared["structural_budget"]["provenance"] = value
            validate_declaration(declared, fixture.profile)
        # The schema surface must carry the same contract as the engine: the
        # two validation layers may not silently diverge on requiredness or on
        # the value set.
        declaration_schema = json.loads(
            (
                ROOT / "core" / "schemas" / "connection-declaration.schema.json"
            ).read_text(encoding="utf-8")
        )
        budget_schema = declaration_schema["properties"]["structural_budget"]
        self.assertIn("provenance", budget_schema["required"])
        self.assertEqual(
            set(budget_schema["properties"]["provenance"]["enum"]),
            set(STRUCTURAL_PROVENANCE_VALUES),
        )

    def test_operator_request_hash_does_not_leak_authorization_stage(self) -> None:
        # A connector can compute sha256({intent, evidence_bundle}) itself. If a
        # control-stage refusal carried a different operator request_hash than an
        # authorization-stage refusal, the connector would read the gate stage —
        # and thus the action-target and scope authorization matrix — from the
        # coarse disposition it is supposed to hide. Every operator result must
        # carry the submitted hash so the stage is indistinguishable; the
        # resolved hash stays internal to the issued permit.
        fixture = self.fixture()

        def submitted_hash(intent: dict, evidence: dict) -> str:
            return sha256_hex(
                {"intent": dict(intent), "evidence_bundle": dict(evidence)}
            )

        # Authorization stage: an unknown grant refuses before the resolvers run.
        engine, intent, _ = fixture.engine()
        auth_intent = copy.deepcopy(intent)
        auth_intent["authority_grant_id"] = "grant-unknown-stage-001"
        auth_result = engine.evaluate_intent(
            auth_intent, fixture.evidence, actor_scope=ROLE_OPERATOR
        )
        self.assertEqual(auth_result["disposition"], "REFUSAL")
        self.assertEqual(
            auth_result["request_hash"],
            submitted_hash(auth_intent, fixture.evidence),
        )

        # Control stage: a wired resolver forces a hard block after the
        # resolvers run. Its operator request_hash must match the submitted
        # hash exactly as the authorization-stage refusal does.
        def hard_block(i: dict, _now: object) -> dict:
            return {
                "prerequisite_results": dict(i["prerequisite_results"]),
                "hard_block_flags": {f: True for f in i["hard_block_flags"]},
                "manual_review_flags": dict(i["manual_review_flags"]),
                "ambiguity_flags": list(i["ambiguity_flags"]),
            }

        engine2, intent2, _ = fixture.engine(control_resolver=hard_block)
        ctrl_result = engine2.evaluate_intent(
            intent2, fixture.evidence, actor_scope=ROLE_OPERATOR
        )
        self.assertEqual(ctrl_result["disposition"], "REFUSAL")
        self.assertEqual(
            ctrl_result["request_hash"],
            submitted_hash(intent2, fixture.evidence),
        )

        # ALLOW: the operator surface carries the submitted hash, while the
        # issued permit keeps the distinct resolved binding internally, and the
        # architect decision is still reachable through the operator handle.
        engine3, intent3, _ = fixture.engine()
        allow_result = engine3.evaluate_intent(
            intent3, fixture.evidence, actor_scope=ROLE_OPERATOR
        )
        self.assertEqual(allow_result["disposition"], "ALLOW")
        self.assertEqual(
            allow_result["request_hash"],
            submitted_hash(intent3, fixture.evidence),
        )
        permit_body = engine3.permits[allow_result["permit_hash"]].body
        self.assertNotEqual(
            permit_body["request_hash"], allow_result["request_hash"]
        )
        decision = engine3.architect_decision(
            allow_result["request_hash"], actor_scope=ROLE_ARCHITECT
        )
        self.assertEqual(
            decision["request_hash"], allow_result["request_hash"]
        )
        # The split must not break the architect's permit->decision direction:
        # an architect holding only the permit reaches its decision through the
        # permit's own request hash, which is distinct from the operator handle.
        via_permit = engine3.architect_decision(
            permit_body["request_hash"], actor_scope=ROLE_ARCHITECT
        )
        self.assertEqual(via_permit["permit_hash"], allow_result["permit_hash"])

    def test_unknown_bound_object_reads_fail_with_not_found_codes(self) -> None:
        # The wire contract declares 404 on consume, architect-permit,
        # architect-decision, and revoke for an object absent in this
        # declaration. Pin each engine code the adapter maps to 404, so a
        # regression from "absent" to a contract error or a silent substitution
        # reddens here rather than shipping green.
        fixture = self.fixture()
        engine, intent, grant = fixture.engine()
        unknown = "0" * 64
        with self.assertRaisesRegex(ContractViolation, "^PERMIT_UNKNOWN(:|$)"):
            engine.architect_permit(unknown, actor_scope=ROLE_ARCHITECT)
        with self.assertRaisesRegex(ContractViolation, "^DECISION_UNKNOWN(:|$)"):
            engine.architect_decision(unknown, actor_scope=ROLE_ARCHITECT)
        with self.assertRaisesRegex(ContractViolation, "^AUTHORITY_UNKNOWN(:|$)"):
            engine.revoke_grant(
                {
                    "message_type": "authority_revocation",
                    "grant_id": "grant-never-issued-001",
                    "declaration_hash": engine.declaration_hash,
                    "revoked_at": "2026-08-01T10:00:00Z",
                    "revoked_by": fixture.fx.authority_issuer,
                    "reason_code": "SYNTHETIC_REVOCATION",
                    "evidence_ref": "evidence://synthetic/revocation/unknown",
                },
                actor_scope="nc25.governance",
            )
        result = engine.evaluate_intent(
            intent, fixture.evidence, actor_scope=ROLE_OPERATOR
        )
        request = fixture.execution_request(engine, result, intent)
        request = copy.deepcopy(request)
        request["permit_hash"] = unknown
        with self.assertRaisesRegex(ContractViolation, "^PERMIT_UNKNOWN(:|$)"):
            engine.commit_execution(
                request, actor_scope=ROLE_EXECUTOR, route_permit_hash=unknown
            )

    def test_refused_architect_decision_carries_no_permit_hash(self) -> None:
        # The architect decision advertises permit_hash only for an ALLOW. A
        # non-executable decision must not carry one, so a regression attaching
        # a permit to a refusal — a false authorization signal — reddens here.
        fixture = self.fixture()
        engine, intent, _ = fixture.engine()
        refused_intent = copy.deepcopy(intent)
        refused_intent["authority_grant_id"] = "grant-unknown-decision-001"
        result = engine.evaluate_intent(
            refused_intent, fixture.evidence, actor_scope=ROLE_OPERATOR
        )
        self.assertEqual(result["disposition"], "REFUSAL")
        decision = engine.architect_decision(
            result["request_hash"], actor_scope=ROLE_ARCHITECT
        )
        self.assertNotIn("permit_hash", decision)

    def test_declaration_lifecycle_checks_status_and_time(self) -> None:
        # activate is DRAFT-guarded; a second activation must refuse and must
        # not append a duplicate DECLARATION_ACTIVATED event to the signed
        # chain. Pin both the code and the unchanged event count.
        fixture = self.fixture()
        engine, _, _ = fixture.engine()
        before = len(engine.ledger.events_copy())
        with self.assertRaisesRegex(
            ContractViolation, "^DECLARATION_ALREADY_ACTIVATED(:|$)"
        ):
            engine.activate(
                fixture.fx.approval_owner,
                "evidence://synthetic/declaration-activation",
                actor_scope="nc25.governance",
            )
        self.assertEqual(len(engine.ledger.events_copy()), before)

        # Exercise the clock and validity guards through governance and
        # evaluation; every contract refusal preserves the complete state.
        bound_profile, bound_declaration, bound_grant, bound_intent = bind_fixture(
            fixture.profile, fixture.declaration, fixture.grant, fixture.intent
        )
        start = datetime.fromisoformat(bound_declaration["effective_from"])
        end = datetime.fromisoformat(bound_declaration["expires_at"])

        class Clock:
            value = start

            def now(self):
                return self.value

        clock = Clock()

        def draft():
            return UniversalConnectionLedger(
                bound_profile, bound_declaration,
                signing_key=b"synthetic-reference-signing-key", clock=clock,
            )

        def activate(candidate):
            return candidate.activate(
                fixture.fx.approval_owner,
                "evidence://synthetic/declaration-activation",
                actor_scope=ROLE_GOVERNANCE,
            )

        engine = draft()
        operations = (
            ("grant", lambda: engine.issue_grant(
                bound_grant, actor_scope=ROLE_GOVERNANCE)),
            ("evaluate", lambda: engine.evaluate_intent(
                bound_intent, fixture.evidence, actor_scope=ROLE_OPERATOR)),
        )
        for name, operation in operations:
            with self.subTest(lifecycle="DRAFT", operation=name):
                before = engine._snapshot_state()
                with self.assertRaisesRegex(
                    ContractViolation, "^DECLARATION_NOT_ACTIVE(:|$)"
                ):
                    operation()
                self.assertEqual(engine._snapshot_state(), before)

        for value in (None, 0, True, "2026-08-01T10:00:00Z"):
            with self.subTest(lifecycle="CLOCK_VALUE", value=value):
                clock.value = value
                before = engine._snapshot_state()
                with self.assertRaisesRegex(ContractViolation, "^CLOCK_VALUE(:|$)"):
                    activate(engine)
                self.assertEqual(engine._snapshot_state(), before)
        clock.value = start.replace(tzinfo=None)
        with self.subTest(lifecycle="TIMEZONE_REQUIRED"):
            before = engine._snapshot_state()
            with self.assertRaisesRegex(ContractViolation, "^TIMEZONE_REQUIRED(:|$)"):
                activate(engine)
            self.assertEqual(engine._snapshot_state(), before)

        for value in (start - timedelta(microseconds=1), end, end + timedelta(microseconds=1)):
            with self.subTest(lifecycle="activation-window", value=value):
                clock.value = value
                before = engine._snapshot_state()
                with self.assertRaisesRegex(
                    ContractViolation, "^DECLARATION_OUTSIDE_VALIDITY(:|$)"
                ):
                    activate(engine)
                self.assertEqual(engine._snapshot_state(), before)

        # The lower endpoint is included; the upper is excluded. A grant
        # spanning the same interval keeps its own expiry out of this check.
        for value in (start, end - timedelta(microseconds=1)):
            with self.subTest(lifecycle="valid-window", value=value):
                clock.value = value
                valid = draft()
                self.assertEqual(activate(valid), valid.declaration_hash)
                self.assertEqual(valid.status, "ACTIVE")
                grant = copy.deepcopy(bound_grant)
                grant["valid_from"] = bound_declaration["effective_from"]
                grant["valid_until"] = bound_declaration["expires_at"]
                valid.issue_grant(grant, actor_scope=ROLE_GOVERNANCE)
                self.assertIn(grant["grant_id"], valid.grants)

        clock.value = start
        activate(engine)
        for value in (start - timedelta(microseconds=1), end, end + timedelta(microseconds=1)):
            for name, operation in operations:
                with self.subTest(lifecycle="active-window", operation=name, value=value):
                    clock.value = value
                    before = engine._snapshot_state()
                    with self.assertRaisesRegex(
                        ContractViolation, "^DECLARATION_OUTSIDE_VALIDITY(:|$)"
                    ):
                        operation()
                    self.assertEqual(engine._snapshot_state(), before)

    def test_activation_actor_is_bound_to_approval_owner(self) -> None:
        # activate was the only governance write that recorded its actor
        # unchecked: issue_grant pins the issuer and revoke_grant pins the
        # revoker, but any well-formed identifier could be written into the
        # signed chain as the activator. Every shipped call site passes the
        # fixture's approval owner by convention, so the gap stayed green.
        # Pin both directions: a foreign activator refuses without appending
        # an event, and the declared approval owner still activates.
        fixture = self.fixture()
        bound = bind_fixture(
            fixture.profile,
            fixture.declaration,
            fixture.grant,
            fixture.intent,
        )
        bound_profile, bound_declaration, _grant, _intent = bound
        engine = UniversalConnectionLedger(
            bound_profile,
            bound_declaration,
            signing_key=b"synthetic-reference-signing-key",
            clock=fixture.clock,
        )
        for value in (None, 0, "", "1invalid", "with spaces"):
            with self.subTest(activation_actor=value):
                snapshot = engine._snapshot_state()
                with self.assertRaisesRegex(ContractViolation, "^ACTIVATION_ACTOR(:|$)"):
                    engine.activate(
                        value, "evidence://synthetic/declaration-activation",
                        actor_scope=ROLE_GOVERNANCE,
                    )
                self.assertEqual(engine._snapshot_state(), snapshot)
        before = len(engine.ledger.events_copy())
        with self.assertRaisesRegex(
            ContractViolation, "^ACTIVATION_ACTOR_UNAUTHORIZED(:|$)"
        ):
            engine.activate(
                "mallory-unrelated-party",
                "evidence://synthetic/declaration-activation",
                actor_scope=ROLE_GOVERNANCE,
            )
        self.assertEqual(engine.status, "DRAFT")
        self.assertEqual(len(engine.ledger.events_copy()), before)
        engine.activate(
            bound_declaration["governance"]["approval_owner_id"],
            "evidence://synthetic/declaration-activation",
            actor_scope=ROLE_GOVERNANCE,
        )
        self.assertEqual(engine.status, "ACTIVE")

    def test_revocation_paths_release_reserved_capacity(self) -> None:
        # CLASS ratchet: every revocation that permanently kills a permit must
        # return its reserved structure immediately. Grant revocation always
        # did; key revocation left the capacity held until the TTL expired,
        # so a permit that provably could never commit (its signature fails
        # closed with PERMIT_KEY_REVOKED) still reserved structure. The sweep
        # runs each revocation surface against the same invariant instead of
        # pinning one of them, so a third revocation path cannot ship holding
        # capacity for a dead permit.
        def revoke_the_grant(fixture, engine, grant):
            engine.revoke_grant(
                {
                    "message_type": "authority_revocation",
                    "grant_id": grant["grant_id"],
                    "declaration_hash": engine.declaration_hash,
                    "revoked_at": "2026-08-01T10:00:00Z",
                    "revoked_by": engine.declaration["governance"][
                        "authority_issuer_id"
                    ],
                    "reason_code": "SYNTHETIC_REVOCATION",
                    "evidence_ref": "evidence://synthetic/revocation",
                },
                actor_scope=ROLE_GOVERNANCE,
            )
            return "AUTHORITY_REVOKED"

        def revoke_the_signing_key(fixture, engine, grant):
            signing_key_id = engine._permit_signer.key_id
            engine.rotate_permit_signer(
                HmacDetachedSigner(b"successor-signing-key", "successor-key"),
                actor_scope=ROLE_GOVERNANCE,
            )
            engine.revoke_permit_key(signing_key_id, actor_scope=ROLE_GOVERNANCE)
            return "PERMIT_KEY_REVOKED"

        revocation_paths = (
            ("grant", revoke_the_grant),
            ("permit signing key", revoke_the_signing_key),
        )
        for label, revoke in revocation_paths:
            with self.subTest(revocation=label):
                fixture = self.fixture()
                engine, intent, grant = fixture.engine()
                before = engine._active_structural_reserved(engine._now())
                result = engine.evaluate_intent(
                    intent, fixture.evidence, actor_scope=ROLE_OPERATOR
                )
                self.assertEqual(result["disposition"], "ALLOW")
                record = engine.permits[result["permit_hash"]]
                self.assertTrue(record.reservation_active)
                self.assertGreater(
                    engine._active_structural_reserved(engine._now()),
                    before,
                    "the ALLOW permit did not reserve any structure",
                )

                expected_reason = revoke(fixture, engine, grant)

                self.assertFalse(
                    record.reservation_active,
                    f"{label} revocation left the dead permit holding capacity",
                )
                self.assertEqual(record.invalidated_reason, expected_reason)
                self.assertEqual(
                    engine._active_structural_reserved(engine._now()),
                    before,
                    f"{label} revocation did not return the reserved structure",
                )

    def test_scope_check_precedes_the_persisted_state_halt(self) -> None:
        # The role check must refuse before the engine touches its state store.
        # It did not: the locking decorators open the store, verify the
        # snapshot MAC and restore state BEFORE the method body where the
        # check lived, so on a state-backed engine an unscoped caller learned
        # integrity status - STATE_MAC_FAILURE instead of ROLE_SCOPE_MISMATCH.
        # The in-memory sweeps could not see it: with no store the decorator
        # is a pass-through, which is why "every public operation refuses
        # without a role" was true in the suite and false in deployment.
        fixture = self.fixture()
        with tempfile.TemporaryDirectory() as temporary_directory:
            state_path = Path(temporary_directory) / "ledger-state.sqlite3"
            engine, _profile, _declaration, _intent = self.persistent_engine(
                fixture, state_path
            )
            connection = sqlite3.connect(state_path)
            connection.execute("UPDATE ledger_state SET state_mac = ?", ("0" * 64,))
            connection.commit()
            connection.close()
            for name in universal_tests.harvested_surface_roles():
                method = getattr(UniversalConnectionLedger, name)
                positional, keyword = universal_tests.dummy_arguments(
                    inspect.signature(method)
                )
                with self.subTest(method=name):
                    with self.assertRaisesRegex(
                        ContractViolation,
                        "^ROLE_SCOPE_MISMATCH(:|$)",
                        msg=f"{name} reached the state store without a role",
                    ):
                        method(engine, *positional, **keyword)

    def test_scope_refusal_touches_no_state_store(self) -> None:
        # Sibling of the halt ordering, and a distinct claim: a refused call
        # must not open a transaction either. Before the lift an unscoped
        # caller took a BEGIN IMMEDIATE write lock and, through the
        # contract-violation branch, drove a durable save and commit - so an
        # unauthorised caller could force disk writes and block writers.
        fixture = self.fixture()
        with tempfile.TemporaryDirectory() as temporary_directory:
            state_path = Path(temporary_directory) / "ledger-state.sqlite3"
            engine, _profile, _declaration, _intent = self.persistent_engine(
                fixture, state_path
            )
            store = engine._state_store
            self.assertIsNotNone(store)

            def refuse(*args, **kwargs):
                raise AssertionError("STORE_TOUCHED")

            store.begin_immediate = refuse
            store.read = refuse
            for name in universal_tests.harvested_surface_roles():
                method = getattr(UniversalConnectionLedger, name)
                positional, keyword = universal_tests.dummy_arguments(
                    inspect.signature(method)
                )
                with self.subTest(method=name):
                    with self.assertRaisesRegex(
                        ContractViolation,
                        "^ROLE_SCOPE_MISMATCH(:|$)",
                        msg=f"{name} opened the state store without a role",
                    ):
                        method(engine, *positional, **keyword)

    def test_review_bundle_rejects_inside_output_and_stale_manifest(self) -> None:
        # The freeze tooling's two fail-closed guards — it writes only outside
        # the package it freezes, and it refuses a manifest whose bound hash no
        # longer matches the file — are asserted in prose but were unpinned.
        with self.assertRaisesRegex(ValueError, "^OUTPUT_MUST_BE_OUTSIDE_PACKAGE(:|$)"):
            build_artifact(ROOT, ROOT / "inside-bundle.md")
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "pkg"
            shutil.copytree(
                ROOT,
                pkg,
                ignore=shutil.ignore_patterns(
                    ".git", "__pycache__", "*.pyc", ".pytest_cache"
                ),
            )
            manifest_path = pkg / "PACKAGE-MANIFEST.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"][0]["sha256"] = "0" * 64
            manifest_path.write_text(
                json.dumps(manifest, indent=2), encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "^PACKAGE_MANIFEST_BINDING(:|$)"):
                build_artifact(pkg, Path(tmp) / "bundle.md")

    def _package_verdicts(self, package_root: Path) -> tuple:
        """Run the package verifier in `package_root` and read one verdict per check.

        Reads the verdict of each NAMED check rather than counting lines. A count
        cannot distinguish "nothing was silenced" from "one check was silenced
        and another fired for the first time", and it drifts for reasons that
        have nothing to do with the property — which is how the first two
        attempts at this test were both wrong in opposite directions.
        """
        import subprocess

        result = subprocess.run(
            [sys.executable, "-B", str(package_root / "tests" / "verify_package.py")],
            cwd=package_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        verdicts: dict[str, str] = {}
        for line in (result.stdout or "").splitlines():
            for kind in ("PASS", "FAIL", "BLOCKED"):
                prefix = kind + " "
                if line.startswith(prefix):
                    label = line[len(prefix):].split(":", 1)[0].strip()
                    # The terminal PACKAGE_CHECKS=... line is not a verdict.
                    if label and " " not in label:
                        verdicts[label] = kind
                    break
        return result, verdicts

    @staticmethod
    def _rebind_acceptance_report(package: Path) -> None:
        # A copy whose manifest was rebuilt after a change is a tree the
        # shipped report was not generated for, and the verifier now refuses
        # that report by its bound digests. A test that wants the copy's
        # verifier fleet green must therefore re-bind the copy's report to
        # the copy's bytes - the same two digests the generator would write,
        # computed by the same function.
        #
        # The re-binding is the generator's own bootstrap, not a copy of it: a
        # second copy here used `re.sub(count=1)`, the form the generator's
        # `replace_once` exists to refuse, and would have drifted from it.
        rebind_report_to_manifest(package)
        rebuilt = subprocess.run(
            [sys.executable, "-B", str(package / "tools" / "build_package_manifest.py")],
            cwd=package,
            capture_output=True,
            text=True,
        )
        if rebuilt.returncode != 0:
            raise AssertionError(rebuilt.stdout + rebuilt.stderr)

    def _copy_package(self, destination: Path) -> Path:
        shutil.copytree(
            ROOT,
            destination,
            ignore=shutil.ignore_patterns(
                ".git", "__pycache__", "*.pyc", ".pytest_cache"
            ),
        )
        return destination

    def test_every_declared_check_reports_its_own_verdict(self) -> None:
        # One failing check must cost exactly its own verdict. The package
        # verifier evaluates 50+ checks; while a failure aborted the sequence,
        # a single stray .pyc from an ordinary `python tests/...` run made every
        # later check vanish and the run redden under a name unrelated to the
        # developer's work. Moving that scan to the end fixed one plant and left
        # the class open: any other unlisted file still silenced the rest.
        #
        # The property asserted here is the one that can actually be closed:
        # every declared check reports exactly one verdict, whatever fails. Not
        # "nothing is silenced" - a check whose precondition an earlier failure
        # destroyed has nothing true to say - but "no check is ever missing from
        # the record".
        with tempfile.TemporaryDirectory() as temporary_directory:
            package = self._copy_package(Path(temporary_directory) / "pkg")

            # The copy is made genuinely clean before anything is planted, by
            # running the package's own manifest builder in it: editing any
            # bound file - including this one - invalidates the manifest, and a
            # test that started from a stale copy would be measuring that
            # instead of the property.
            #
            # An earlier version of this test tolerated pre-existing failures
            # instead, to avoid that coupling. Measured, that was worse: with
            # `require` restored to raising, one early failure blocks 47 checks,
            # and a tolerated baseline absorbs all 47 - so the check went GREEN
            # under the exact regression it exists to catch. The baseline must
            # therefore be all-PASS, not merely recorded.
            import subprocess

            build = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(package / "tools" / "build_package_manifest.py"),
                ],
                cwd=package,
                capture_output=True,
                text=True,
            )
            self.assertEqual(build.returncode, 0, build.stderr[-2000:])
            self._rebind_acceptance_report(package)

            clean, declared = self._package_verdicts(package)
            self.assertTrue(declared, "the verifier reported no verdicts at all")
            self.assertEqual(
                {label for label, kind in declared.items() if kind != "PASS"},
                set(),
                "the freshly built copy must report PASS for every declared check",
            )
            self.assertEqual(clean.returncode, 0, clean.stderr[-2000:])

            readme_path = package / "README.md"
            readme = readme_path.read_text(encoding="utf-8")
            counter = re.search(r"PACKAGE_CHECKS=(\d+)/\1", readme)
            self.assertIsNotNone(counter, "README carries no package-check literal")
            literal = counter.group(0)
            shifted = int(counter.group(1)) - 1
            self.assertEqual(readme.count(literal), 1)
            readme_path.write_text(
                readme.replace(literal, f"PACKAGE_CHECKS={shifted}/{shifted}"),
                encoding="utf-8",
            )
            rebuilt = subprocess.run(
                [sys.executable, "-B", str(package / "tools" / "build_package_manifest.py")],
                cwd=package,
                capture_output=True,
                text=True,
            )
            self.assertEqual(rebuilt.returncode, 0, rebuilt.stderr[-2000:])
            self._rebind_acceptance_report(package)
            stale_count, stale_verdicts = self._package_verdicts(package)
            self.assertNotEqual(stale_count.returncode, 0)
            self.assertEqual(set(stale_verdicts), set(declared))
            self.assertEqual(
                {name for name, kind in stale_verdicts.items() if kind != "PASS"},
                {"package_counter_literals_current"},
            )
            readme_path.write_text(readme, encoding="utf-8")
            rebuilt = subprocess.run(
                [sys.executable, "-B", str(package / "tools" / "build_package_manifest.py")],
                cwd=package,
                capture_output=True,
                text=True,
            )
            self.assertEqual(rebuilt.returncode, 0, rebuilt.stderr[-2000:])
            self._rebind_acceptance_report(package)

            artefact = package / "tests" / "__pycache__"
            artefact.mkdir(parents=True, exist_ok=True)
            (artefact / "planted.cpython-312.pyc").write_bytes(b"\x00planted")
            stray = package / "stray-notes.txt"

            for label, plant, expected in (
                ("artefact only", (), {"no_build_artefacts"}),
                (
                    "artefact and unlisted file",
                    (stray,),
                    {"no_build_artefacts", "package_manifest_coverage"},
                ),
            ):
                for path in plant:
                    path.write_text("planted by the regression suite\n", encoding="utf-8")
                with self.subTest(plant=label):
                    result, verdicts = self._package_verdicts(package)
                    self.assertNotEqual(
                        result.returncode, 0, "a planted defect must fail the run"
                    )
                    # The invariant: the SAME checks speak, whatever fails.
                    self.assertEqual(
                        set(verdicts),
                        set(declared),
                        "a check disappeared from the record instead of "
                        "reporting its own verdict",
                    )
                    self.assertEqual(
                        {name for name, kind in verdicts.items() if kind != "PASS"},
                        expected,
                        "the set of failing checks is not the set of planted defects",
                    )

    def test_failure_surface_ratchet_detects_each_regression(self) -> None:
        import subprocess

        def rebuild_manifest(package: Path) -> None:
            # A plant edits manifest-bound bytes; rebinding inside the copy
            # keeps the recorded suite run green so the plant's own marker is
            # the only red, not a manifest-binding failure it hides behind.
            rebuilt = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(package / "tools" / "build_package_manifest.py"),
                ],
                cwd=package,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            self.assertEqual(rebuilt.returncode, 0, rebuilt.stdout + rebuilt.stderr)

        def append_exception(package: Path) -> None:
            path = package / "sdk" / "python" / "nc25_universal_ledger.py"
            with path.open("a", encoding="utf-8") as handle:
                handle.write(
                    "\n\ndef _planted_exception():\n"
                    "    raise ContractViolation(\"PLANTED_FAILURE_CODE\")\n"
                )

        def append_dynamic_helper(package: Path) -> None:
            path = package / "sdk" / "python" / "nc25_universal_ledger.py"
            with path.open("a", encoding="utf-8") as handle:
                handle.write(
                    "\n\ndef _planted_dynamic_failure(code):\n"
                    "    raise ContractViolation(code)\n"
                )

        def replace_architect_code(package: Path) -> None:
            # Targeted by ROLE, not by textual order: the emission site is the
            # occurrence outside the ARCHITECT_DECISION_CODES declaration. An
            # earlier version took the last occurrence, which rested on an
            # incidental ordering fact of the file.
            path = package / "sdk" / "python" / "nc25_universal_ledger.py"
            source = path.read_text(encoding="utf-8")
            literal = '"BINDING_MISMATCH"'
            declaration_start = source.index("ARCHITECT_DECISION_CODES = frozenset(")
            declaration_end = source.index("\n)\n", declaration_start)
            emissions = [
                position
                for position in range(len(source))
                if source.startswith(literal, position)
                and not declaration_start <= position <= declaration_end
            ]
            self.assertEqual(
                len(emissions),
                1,
                "expected exactly one BINDING_MISMATCH emission outside the "
                "declaration",
            )
            position = emissions[0]
            path.write_text(
                source[:position]
                + '"PLANTED_ARCHITECT_GATE"'
                + source[position + len(literal):],
                encoding="utf-8",
            )

        def add_stale_debt(package: Path) -> None:
            path = package / "tests" / "failure-surface-baseline.json"
            baseline = json.loads(path.read_text(encoding="utf-8"))
            baseline["runtime"]["unwitnessed_codes"].append("PLANTED_STALE_DEBT")
            path.write_text(
                json.dumps(baseline, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            rebuild_manifest(package)

        def seed_unwitnessed_code(package: Path) -> str:
            # Own the missing witness in this copy. The shipped engine may
            # already witness every refusal code, so it supplies no fixture.
            append_exception(package)
            rebuild_manifest(package)
            recorded = subprocess.run(
                [sys.executable, "-B", str(package / "tools" / "failure_surface.py"),
                 "--write-baseline", "--accept-regression",
                 "Isolated fixture adds one synthetic uncalled refusal before testing witness admission"],
                cwd=package, capture_output=True, text=True, encoding="utf-8",
                errors="replace",
            )
            self.assertEqual(recorded.returncode, 0, recorded.stdout + recorded.stderr)
            runtime = json.loads(
                (package / "tests" / "failure-surface-baseline.json").read_text(
                    encoding="utf-8")
            )["runtime"]
            code = "PLANTED_FAILURE_CODE"
            self.assertIn(code, runtime["unwitnessed_codes"])
            self.assertNotIn(code, runtime["witnessed_codes"])
            self.assertNotIn(code, runtime["constructed_engine_codes"])
            rebuild_manifest(package)
            return code

        def append_scaffold_construction(package: Path) -> None:
            # Test-only construction must not become production evidence.
            code = seed_unwitnessed_code(package)
            path = package / "tests" / "test_semantic_contracts.py"
            with path.open("a", encoding="utf-8") as handle:
                handle.write(
                    "\n\nclass PlantedScaffoldWitness(unittest.TestCase):\n"
                    "    def test_scaffold_construction(self) -> None:\n"
                    "        from nc25_universal_ledger import ContractViolation\n"
                    "        try:\n"
                    f"            raise ContractViolation(\"{code}\")\n"
                    "        except ContractViolation as exc:\n"
                    f"            self.assertEqual(exc.code, \"{code}\")\n"
                )
            rebuild_manifest(package)

        PLANTED_WITNESS = (
            '        with self.assertRaisesRegex(\n'
            '            ContractViolation, r"^PLANTED_WITNESSED_CODE(:|$)"\n'
            '        ):\n'
            '            _planted_witnessed()\n'
        )

        def neuter_witnessing_assertion(package: Path) -> None:
            # Self-contained: the plant owns the code it neuters. It appends a
            # raise to the engine and ONE witness for it inside an existing
            # semantic test - inside, so no test count moves - regenerates the
            # copy's baseline with that witness recorded, and only then
            # neuters it. An earlier form neutered the shipped suite's single
            # witness of INTENT_SCOPE_DIMENSION, which held only as long as no
            # other suite witnessed that code; a second witness silenced the
            # loss and the plant reported nothing - measured.
            engine = package / "sdk" / "python" / "nc25_universal_ledger.py"
            with engine.open("a", encoding="utf-8") as handle:
                handle.write(
                    "\n\ndef _planted_witnessed() -> None:\n"
                    "    raise ContractViolation(\"PLANTED_WITNESSED_CODE\")\n"
                )
            suite = package / "tests" / "test_semantic_contracts.py"
            source = suite.read_text(encoding="utf-8")
            anchor = (
                '        with self.assertRaisesRegex('
                'ContractViolation, "^DUPLICATE_ACTION_ID(:|$)"):\n'
                "            validate_profile(changed)\n"
            )
            self.assertEqual(source.count(anchor), 1)
            suite.write_text(
                source.replace(
                    anchor,
                    anchor
                    + "        from nc25_universal_ledger import _planted_witnessed\n"
                    + PLANTED_WITNESS,
                ),
                encoding="utf-8",
            )
            rebuild_manifest(package)
            recorded = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(package / "tools" / "failure_surface.py"),
                    "--write-baseline",
                ],
                cwd=package,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            self.assertEqual(
                recorded.returncode, 0, (recorded.stdout + recorded.stderr)[-2000:]
            )
            self.assertIn(
                "PLANTED_WITNESSED_CODE",
                json.loads(
                    (package / "tests" / "failure-surface-baseline.json").read_text(
                        encoding="utf-8"
                    )
                )["runtime"]["witnessed_codes"],
                "the planted witness was not recorded before being neutered",
            )
            source = suite.read_text(encoding="utf-8")
            self.assertEqual(source.count(PLANTED_WITNESS), 1)
            suite.write_text(
                source.replace(
                    PLANTED_WITNESS,
                    "        try:\n"
                    "            _planted_witnessed()\n"
                    "        except ContractViolation:\n"
                    "            pass\n",
                ),
                encoding="utf-8",
            )
            rebuild_manifest(package)

        def disarm_engine_sink(package: Path) -> None:
            path = package / "tools" / "failure_surface.py"
            source = path.read_text(encoding="utf-8")
            old = (
                "        patch_class(\n"
                "            engine_class, 0, observation.constructed_engine,"
                " _EngineObservedCode\n"
                "        )\n"
            )
            self.assertEqual(source.count(old), 1)
            path.write_text(
                source.replace(
                    old, "        pass  # plant: engine sink disarmed\n"
                ),
                encoding="utf-8",
            )
            rebuild_manifest(package)

        def append_regex_witness(package: Path, pattern: str) -> None:
            seed_unwitnessed_code(package)
            path = package / "tests" / "test_semantic_contracts.py"
            with path.open("a", encoding="utf-8") as handle:
                handle.write(
                    "\n\nclass PlantedRegexWitness(unittest.TestCase):\n"
                    "    def test_regex_witness(self) -> None:\n"
                    "        from nc25_universal_ledger import (\n"
                    "            ContractViolation,\n"
                    "            _planted_exception,\n"
                    "        )\n"
                    "        with self.assertRaisesRegex(\n"
                    f"            ContractViolation, r\"{pattern}\"\n"
                    "        ):\n"
                    "            _planted_exception()\n"
                )
            rebuild_manifest(package)

        def raise_undeclared_bridge_code(package: Path) -> None:
            # A code the bridge raises and its declaration does not carry. The
            # declaration is the thing a partner reads, so the two must not be
            # free to drift; this plant is the drift.
            path = package / "sdk" / "python" / "nc25_otcs_bridge.py"
            source = path.read_text(encoding="utf-8")
            literal = (
                'raise OTCSBridgeError("OTCS_HASH_PROFILE", _stored_reason(self.hash_profile))'
            )
            self.assertEqual(source.count(literal), 1)
            path.write_text(
                source.replace(
                    literal,
                    'raise OTCSBridgeError("OTCS_NEVER_DECLARED", _stored_reason(self.hash_profile))',
                    1,
                ),
                encoding="utf-8",
            )
            rebuild_manifest(package)

        def declare_unraised_bridge_code(package: Path) -> None:
            # The mirror direction, and the one a one-sided check would miss: a
            # name in the published vocabulary that no site raises. A partner
            # coding a branch for it would wait forever.
            path = package / "sdk" / "python" / "nc25_otcs_bridge.py"
            source = path.read_text(encoding="utf-8")
            anchor = '        "OTCS_BRIDGE_JSON",\n'
            self.assertEqual(source.count(anchor), 1)
            path.write_text(
                source.replace(
                    anchor, anchor + '        "OTCS_GHOST_CODE",\n', 1
                ),
                encoding="utf-8",
            )
            rebuild_manifest(package)

        def withhold_a_name_that_is_not_a_code(package: Path) -> None:
            # The exclusion list is the escape hatch, so it is the thing most
            # worth holding: a name here that is not a bridge code at all would
            # be a silent way to keep something off the published surface.
            path = package / "sdk" / "python" / "nc25_otcs_bridge.py"
            source = path.read_text(encoding="utf-8")
            # Anchored on where the set OPENS, not on whichever member happens
            # to sit last before the brace. The earlier anchor named that last
            # member, so adding one code to the exclusion list moved the brace
            # away from it and the plant could no longer be planted. The count
            # assertion is what made that legible: without it the replace
            # would have been a no-op, the ratchet would have found nothing,
            # and the row would still have failed - but on a missing marker,
            # which names the ratchet rather than the anchor that moved.
            anchor = "OTCS_INTERNAL_ONLY_CODES = frozenset(\n    {\n"
            self.assertEqual(source.count(anchor), 1)
            path.write_text(
                source.replace(
                    anchor,
                    anchor + '        "OTCS_NOT_A_BRIDGE_CODE",\n',
                    1,
                ),
                encoding="utf-8",
            )
            rebuild_manifest(package)

        plants = (
            (
                "new exception code",
                append_exception,
                "--check-static",
                ("ENGINE_REFUSAL_UNIVERSE_ADDED",),
                (),
            ),
            (
                "unclassified dynamic helper",
                append_dynamic_helper,
                "--check-static",
                ("FAILURE_SURFACE_UNCLASSIFIED:static",),
                (),
            ),
            (
                "bridge code raised without being declared",
                raise_undeclared_bridge_code,
                "--check-static",
                ("BRIDGE_REFUSAL_VOCABULARY",),
                (),
            ),
            (
                "bridge code declared without being raised",
                declare_unraised_bridge_code,
                "--check-static",
                ("BRIDGE_REFUSAL_VOCABULARY",),
                (),
            ),
            (
                "a withheld name that is not a bridge code",
                withhold_a_name_that_is_not_a_code,
                "--check-static",
                ("BRIDGE_INTERNAL_ONLY_NOT_A_SUBSET",),
                (),
            ),
            (
                "undeclared architect code",
                replace_architect_code,
                "--check-static",
                ("ARCHITECT_DECISION_VOCABULARY",),
                (),
            ),
            (
                "stale debt baseline",
                add_stale_debt,
                "--check",
                ("UNWITNESSED_REMOVED",),
                (),
            ),
            (
                # The property lives in the absences; RUNTIME_TEST_COUNT proves
                # the plant was armed (the run saw the added test) and
                # FAILURE_RUNTIME_SUITE's absence proves it actually completed
                # its check. Without the latter this plant stayed green when
                # the scaffold crashed before comparing anything - measured,
                # not supposed.
                "scaffold construction is not credited",
                append_scaffold_construction,
                "--check",
                ("RUNTIME_TEST_COUNT",),
                (
                    "WITNESSED_ADDED",
                    "CONSTRUCTED_ENGINE_ADDED",
                    "FAILURE_RUNTIME_SUITE",
                ),
            ),
            (
                "neutered assertion drops its witness",
                neuter_witnessing_assertion,
                "--check",
                (
                    ("WITNESSED_REMOVED", "PLANTED_WITNESSED_CODE"),
                    ("UNWITNESSED_ADDED", "PLANTED_WITNESSED_CODE"),
                ),
                (),
            ),
            (
                "disarmed sink reddens by itself",
                disarm_engine_sink,
                "--check",
                (
                    "FAILURE_RUNTIME_EMPTY:constructed_engine_codes",
                    "FAILURE_RUNTIME_EMPTY:witnessed_codes",
                ),
                (),
            ),
            (
                "sloppy regex is not credited",
                lambda package: append_regex_witness(package, "."),
                "--check",
                ("FAILURE_WITNESS_NONDISCRIMINATING",),
                ("WITNESSED_ADDED",),
            ),
            (
                "anchored regex is credited",
                lambda package: append_regex_witness(
                    package, "^PLANTED_FAILURE_CODE(:|$)"
                ),
                "--check",
                (("WITNESSED_ADDED", "PLANTED_FAILURE_CODE"),),
                (),
            ),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for index, (label, plant, mode, present, absent) in enumerate(plants):
                with self.subTest(plant=label):
                    package = self._copy_package(root / f"pkg-{index}")
                    plant(package)
                    result = subprocess.run(
                        [
                            sys.executable,
                            "-B",
                            str(package / "tools" / "failure_surface.py"),
                            mode,
                        ],
                        cwd=package,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                    )
                    combined = "\n".join(
                        part for part in (result.stdout, result.stderr) if part
                    )
                    self.assertNotEqual(result.returncode, 0, combined[-2000:])
                    # Marker and payload are one fact, asserted on the carrying
                    # LINE. Two separate substring searches over the whole
                    # buffer would be satisfied by a run that named the marker
                    # about one code and mentioned the expected code somewhere
                    # else entirely - and the marker vocabulary makes that
                    # sharper still, since WITNESSED_ADDED is a substring of
                    # UNWITNESSED_ADDED.
                    lines = combined.splitlines()
                    for expectation in present:
                        if isinstance(expectation, tuple):
                            marker, payload = expectation
                        else:
                            marker, payload = expectation, None
                        carrying = [
                            line for line in lines if line.startswith(marker)
                        ]
                        self.assertTrue(
                            carrying,
                            f"no line begins with {marker}\n{combined[-2000:]}",
                        )
                        if payload is not None:
                            self.assertTrue(
                                any(payload in line for line in carrying),
                                f"{marker} named no {payload}\n"
                                f"{combined[-2000:]}",
                            )
                    for marker in absent:
                        self.assertFalse(
                            [line for line in lines if line.startswith(marker)],
                            f"{marker} was reported\n{combined[-2000:]}",
                        )

    def test_wire_witness_does_not_retire_engine_debt(self) -> None:
        # The two published vocabularies overlap: the adapter's translation
        # site re-emits the code of an engine refusal it caught. A single
        # witness sink would therefore let a wire-side check retire engine
        # debt that no engine-side check ever earned. Driven through the REAL
        # adapter, not a simulated frame, because the frame condition is what
        # the tool keys on and simulating it would test the tool against
        # itself. Excluded from the tool's own recorded run (it installs the
        # observation machinery, which must not nest).
        import failure_surface
        import nc25_otcs_bridge as bridge
        import nc25_universal_adapter as wire

        fixture = self.fixture()
        engine, _intent, _grant = fixture.engine()
        app = wire.UniversalConnectionHttpAdapter(engine)
        # Three universes since the bridge became a closed world of its own.
        # This test says nothing about the bridge, so its universe is empty -
        # but the argument is required, and passing two killed this case
        # outright: it raised TypeError before reaching a single assertion,
        # so the claim it guards went unchecked while the suite still listed
        # it. The failure was loud and still went unheard, because the tool's
        # own recorded run excludes this case by name - only a full acceptance
        # run reaches it, and one had not been run green before the commit.
        observation = failure_surface._Observation(
            {"PERMIT_UNKNOWN"}, set(), set()
        )
        restores = failure_surface._install_observation(
            sys.modules["nc25_universal_ledger"], wire, bridge, observation
        )
        try:
            # Dispatch rather than the full WSGI call: the outer call catches
            # the wire error and serialises it, so only dispatch hands test
            # code the exception object whose .code an exact check would read.
            with self.assertRaises(wire.WireError) as raised:
                app._dispatch(
                    {
                        "REQUEST_METHOD": "GET",
                        "PATH_INFO": "/v1/architect/permits/" + "0" * 64,
                        "CONTENT_LENGTH": "0",
                        "wsgi.input": io.BytesIO(b""),
                        "HTTP_X_WORKLOAD_SCOPE": ROLE_ARCHITECT,
                    }
                )
            # The exact-value check a test would write on the wire side.
            self.assertEqual(raised.exception.code, "PERMIT_UNKNOWN")
        finally:
            failure_surface._restore_observation(restores)

        self.assertIn(
            "PERMIT_UNKNOWN",
            observation.constructed_wire,
            "the adapter no longer translates this engine refusal",
        )
        self.assertNotIn(
            "PERMIT_UNKNOWN",
            observation.witnessed_engine_raw,
            "a wire-side check credited the engine witness set",
        )
        self.assertIn("PERMIT_UNKNOWN", observation.witnessed_wire_raw)

    def test_a_crashing_check_reports_blocked_rather_than_vanishing(self) -> None:
        # The verdict invariant's hard half: when a check raises instead of
        # returning a verdict, the run must still record one verdict per
        # declared id. The plants in the sibling case only produce ordinary
        # FAIL verdicts, so the crash-to-BLOCKED backfill had no case at all.
        import subprocess

        with tempfile.TemporaryDirectory() as temporary_directory:
            package = self._copy_package(Path(temporary_directory) / "pkg")
            build = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(package / "tools" / "build_package_manifest.py"),
                ],
                cwd=package,
                capture_output=True,
                text=True,
            )
            self.assertEqual(build.returncode, 0, build.stderr[-2000:])
            self._rebind_acceptance_report(package)
            _clean, declared = self._package_verdicts(package)
            self.assertEqual(
                {label for label, kind in declared.items() if kind != "PASS"},
                set(),
                "the freshly built copy must report PASS for every declared check",
            )

            # Destroy a precondition mid-run rather than fail a check: the
            # manifest is read by a check that cannot tolerate malformed JSON.
            (package / "PACKAGE-MANIFEST.json").write_text(
                "{ this is not json", encoding="utf-8"
            )
            result, verdicts = self._package_verdicts(package)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(
                set(verdicts),
                set(declared),
                "a check vanished from the record instead of reporting BLOCKED",
            )
            blocked = {
                label for label, kind in verdicts.items() if kind == "BLOCKED"
            }
            self.assertTrue(
                blocked, "no check reported BLOCKED on a mid-run crash"
            )

    def test_evidence_bundle_shape_refuses_with_its_own_code(self) -> None:
        # Submitted evidence is validated before authorization and recording.
        # Each malformed copy must report its own contract error, preserve the
        # caller's input and the full accounting state, and leave the same
        # request usable when corrected. Test both memory and durable state;
        # a reopened engine checks what SQLite actually retained.
        for durable in (False, True):
            with tempfile.TemporaryDirectory(prefix="evidence-contract-") as tmp:
                fixture = self.fixture()
                state_path = Path(tmp) / "state.sqlite"
                if durable:
                    engine, _, _, intent = self.persistent_engine(fixture, state_path)
                else:
                    engine, intent, _ = fixture.engine()
                before = engine._snapshot_state()
                original_intent = copy.deepcopy(intent)
                rows = (
                    ("EVIDENCE_BUNDLE_FIELDS", (("collected_at",), "delete", None)),
                    ("EVIDENCE_BUNDLE_FIELDS", (("collected_by",), "set", "operator")),
                    ("EVIDENCE_MESSAGE_TYPE", (("message_type",), "set", "x")),
                    ("EVIDENCE_INTENT_MISMATCH", (("intent_id",), "set", "other-intent")),
                    ("EVIDENCE_ITEM", (("items", 0), "set", "not-a-mapping")),
                    ("EVIDENCE_ITEM", (("items", 0, "foreign"), "set", "field")),
                    ("EVIDENCE_ITEMS", (("items",), "set", [])),
                    ("EVIDENCE_ITEMS", (("items",), "set", {})),
                    ("EVIDENCE_ITEMS", (("items",), "set", {"foreign": "item"})),
                    ("EVIDENCE_ITEMS", (("items",), "set", "not-a-list")),
                    ("EVIDENCE_ITEMS", (("items",), "set", None)),
                    ("EVIDENCE_TYPE", (("items", 0, "evidence_type"), "set", "")),
                    ("EVIDENCE_TYPE", (("items", 0, "evidence_type"), "set", 0)),
                    ("EVIDENCE_REFERENCE", (("items", 0, "ref"), "set", "")),
                    ("EVIDENCE_REFERENCE", (("items", 0, "ref"), "set", 0)),
                    ("EVIDENCE_HASH", (("items", 0, "sha256"), "set", "a" * 63)),
                    ("EVIDENCE_HASH", (("items", 0, "sha256"), "set", "g" * 64)),
                    ("EVIDENCE_HASH", (("items", 0, "sha256"), "set", 0)),
                    ("DUPLICATE_EVIDENCE_TYPE", (("items",), "set",
                        [copy.deepcopy(fixture.evidence["items"][0])] * 2)),
                )
                cases = [(code, (operation,)) for code, operation in rows]
                # Pin the order of these two guards as well as their coverage.
                cases.append(("EVIDENCE_MESSAGE_TYPE", (
                    (("message_type",), "set", "x"),
                    (("intent_id",), "set", "other-intent"),
                )))
                for index, (code, operations) in enumerate(cases):
                    with self.subTest(durable=durable, evidence_refusal=code, case=index):
                        bundle = self._corrupt(fixture.evidence, operations)
                        submitted = copy.deepcopy(bundle)
                        with self.assertRaisesRegex(ContractViolation, rf"^{code}(:|$)"):
                            engine.evaluate_intent(intent, bundle, actor_scope=ROLE_OPERATOR)
                        self.assertEqual(engine._snapshot_state(), before, "state changed on malformed evidence")
                        self.assertEqual(bundle, submitted, "caller evidence was mutated")
                        self.assertEqual(intent, original_intent, "caller intent was mutated")
                if durable:
                    engine, _, _, intent = self.persistent_engine(fixture, state_path)
                    self.assertEqual(engine._snapshot_state(), before, "durable state changed")
                # Honest work on the same key must survive the guards, including
                # lowercase hexadecimal digests accepted by the wire contract.
                valid = copy.deepcopy(fixture.evidence)
                for item in valid["items"]:
                    item["sha256"] = item["sha256"].lower()
                with self.subTest(durable=durable, evidence_control="valid"):
                    result = engine.evaluate_intent(intent, valid, actor_scope=ROLE_OPERATOR)
                    self.assertEqual(result["disposition"], "ALLOW")

    @staticmethod
    def _corrupt(document: dict, operations) -> dict:
        # Rows are data, not closures: (path, op, value) applied to a deep
        # copy. A path is a tuple of keys and indexes from the document root.
        changed = copy.deepcopy(document)
        for path, op, value in operations:
            cursor = changed
            for key in path[:-1]:
                cursor = cursor[key]
            if op == "delete":
                del cursor[path[-1]]
            else:
                cursor[path[-1]] = value
        return changed

    def assert_identifier_list_contracts(self, document, validate, fields) -> None:
        for code, path, allow_empty in fields:
            cursor = document
            for key in path:
                cursor = cursor[key]
            invalid = (
                ("mapping", {cursor[0]: True}),
                ("tuple", tuple(cursor)),
                ("string", cursor[0]),
                ("null", None),
                ("non_string", [0]),
                ("empty_identifier", [""]),
                ("bad_identifier", ["1invalid"]),
                ("duplicate", [cursor[0], cursor[0]]),
            )
            if not allow_empty:
                invalid += (("empty_array", []),)
            for shape, value in invalid:
                with self.subTest(identifier_list=code, shape=shape):
                    changed = self._corrupt(document, ((path, "set", value),))
                    before = copy.deepcopy(changed)
                    with self.assertRaisesRegex(ContractViolation, rf"^{code}(:|$)"):
                        validate(changed)
                    self.assertEqual(changed, before, "validator mutated caller input")
            valid_values = (cursor, []) if allow_empty else (cursor,)
            for value in valid_values:
                with self.subTest(identifier_control=code, empty=not value):
                    changed = self._corrupt(document, ((path, "set", value),))
                    before = copy.deepcopy(changed)
                    validate(changed)
                    self.assertEqual(changed, before, "validator mutated caller input")

    def test_profile_validator_refuses_each_code_by_name(self) -> None:
        # The class sweep over validate_profile: one row per refusal code the
        # function owns, each asserting THAT code and not merely "refused".
        # Validation runs top to bottom, so every row was measured before it
        # was written - a corruption caught by an earlier guard would pin the
        # wrong fact and look green doing it. Routed through the validator
        # directly: it runs first in the constructor, before any state exists.
        #
        # Identifier-list helper refusals are exercised below as well. Shared
        # core-anchor, timestamp and secret checks have separate tests.
        fixture = self.fixture()
        self.assert_identifier_list_contracts(
            fixture.profile, validate_profile,
            (
                ('ACTION_RESOURCE_IDS', ('action_alphabet', 0, 'required_resource_ids'), True),
                ('PREREQUISITE_IDS', ('controls', 'required_prerequisite_ids'), True),
                ('HARD_BLOCK_IDS', ('controls', 'hard_block_flag_ids'), True),
                ('MANUAL_REVIEW_IDS', ('controls', 'manual_review_flag_ids'), True),
                ('EVIDENCE_ACTION_IDS', ('evidence_requirements', 0, 'applies_to_action_ids'), False),
                ('REQUIRED_EVIDENCE_TYPES', ('evidence_requirements', 0, 'required_evidence_types'), False),
                ('WITNESS_ACTIONS', ('mapping_witness', 'covered_action_ids'), False),
                ('WITNESS_EFFECTS', ('mapping_witness', 'covered_effect_class_ids'), False),
                ('OBSERVER_PROJECTION_FIELDS', ('roles', 'observer_projection_fields'), False),
            ),
        )
        rows = (
            ('WITNESS_METHOD', ((('mapping_witness', 'method'), 'set', 'too short'),)),
            ('WITNESS_EVIDENCE', ((('mapping_witness', 'evidence_refs'), 'set', []),)),
            ('WITNESS_ACTION_COVERAGE', ((('mapping_witness', 'covered_action_ids', 2), 'delete', None),)),
            ('WITNESS_EFFECT_COVERAGE', ((('mapping_witness', 'covered_effect_class_ids', 2), 'delete', None),)),
            ('WITNESS_HASH', ((('mapping_witness', 'witness_hash'), 'set', 'not-a-hash'),)),
            ('WITNESS_HASH_MISMATCH', ((('mapping_witness', 'witness_hash'), 'set', '0000000000000000000000000000000000000000000000000000000000000000'),)),
            ('PROFILE_ROLES', ((('roles',), 'set', []),)),
            ('ROLE_SCOPE_DEFINITION', ((('roles', 'governance_scope'), 'set', 'nc25.operator'),)),
            ('OBSERVER_PROJECTION_EXPANSION', ((('roles', 'observer_projection_fields', 0), 'set', 'gate_margin'),)),
            ('FORBIDDEN_OPERATOR_FIELDS', ((('roles', 'forbidden_operator_fields'), 'set', []),)),
            ('FORBIDDEN_OPERATOR_COVERAGE', ((('roles', 'forbidden_operator_fields', 1), 'delete', None),)),
            ('FAILURE_POSTURE', ((('failure_posture',), 'set', 'REFUSAL'),)),
            ('FIXED_FAILURE_POSTURE', ((('failure_posture', 'ambiguity'), 'set', 'REFUSAL'),)),
            ('CHANGE_CONTROL', ((('change_control',), 'set', True),)),
            ('LIVE_GATE_OVERRIDE', ((('change_control', 'live_gate_override_allowed'), 'set', True),)),
            ('REGISTRY_POLICY', ((('registry_policy',), 'set', 'HASH_ONLY'),)),
            ('REGISTRY_NOT_HASH_ONLY', ((('registry_policy', 'mode'), 'set', 'FULL_RECORD'),)),
            ('REGISTRY_FORBIDDEN_COVERAGE', ((('registry_policy', 'forbidden_fields', 5), 'delete', None),)),
            ('PROFILE_FIELDS', ((('registry_policy',), 'delete', None),)),
            ('PROFILE_SCHEMA_VERSION', ((('schema_version',), 'set', '2.0.0'),)),
            ('PROFILE_ID', ((('profile_id',), 'set', ''),)),
            ('PROFILE_VERSION', ((('profile_version',), 'set', '1.3'),)),
            ('PROFILE_DOMAIN', ((('domain',), 'set', None),)),
            ('PROFILE_EFFECTS', ((('effect_classes',), 'set', []),)),
            ('PROFILE_EFFECT', ((('effect_classes', 0), 'set', None),)),
            ('PROFILE_EFFECT_ID', ((('effect_classes', 0, 'effect_class_id'), 'set', ''),)),
            ('DUPLICATE_EFFECT_ID', ((('effect_classes', 1, 'effect_class_id'), 'set', 'BANK_LEDGER_MUTATION'),)),
            ('PROFILE_EFFECT_DESCRIPTION', ((('effect_classes', 0, 'description'), 'set', ''),)),
            ('PROFILE_EFFECT_MUTATION_FLAG', ((('effect_classes', 0, 'mutates_external_state'), 'set', 'true'),)),
            ('PROFILE_RESOURCES', ((('resource_catalog',), 'set', None),)),
            ('PROFILE_RESOURCE', ((('resource_catalog', 0), 'set', None),)),
            ('PROFILE_RESOURCE_ID', ((('resource_catalog', 0, 'resource_id'), 'set', ''),)),
            ('DUPLICATE_RESOURCE_ID', ((('resource_catalog', 1, 'resource_id'), 'set', 'money_minor_units'),)),
            ('RESOURCE_CLAIM_RULE', ((('resource_catalog', 0, 'claim_rule'), 'set', 'NEGATIVE'),)),
            ('RESOURCE_RESERVATION_FLAG', ((('resource_catalog', 0, 'reservation_required'), 'set', 'yes'),)),
            ('RESOURCE_UNIT', ((('resource_catalog', 0, 'unit'), 'set', ''),)),
            ('PROFILE_ACTIONS', ((('action_alphabet',), 'set', []),)),
            ('PROFILE_ACTION', ((('action_alphabet', 0), 'set', None),)),
            ('PROFILE_ACTION_ID', ((('action_alphabet', 0, 'action_id'), 'set', ''),)),
            ('DUPLICATE_ACTION_ID', ((('action_alphabet', 1, 'action_id'), 'set', 'BANK_PAYMENT_POST'),)),
            ('UNKNOWN_EFFECT_CLASS', ((('action_alphabet', 0, 'effect_class_id'), 'set', 'MISSING_EFFECT'),)),
            ('UNKNOWN_RESOURCE_ID', ((('action_alphabet', 0, 'required_resource_ids', 0), 'set', 'MISSING_RESOURCE'),)),
            ('STRUCTURAL_COST', ((('action_alphabet', 0, 'structural_cost'), 'set', -1),)),
            ('ACTION_DESCRIPTION', ((('action_alphabet', 0, 'description'), 'set', ''),)),
            ('PROFILE_CONTROLS', ((('controls',), 'set', []),)),
            ('CONTROL_CLASS_OVERLAP', ((('controls', 'hard_block_flag_ids', 0), 'set', 'ACCOUNT_ACTIVE'),)),
            ('SAFE_FALLBACK_ID', ((('controls', 'safe_fallback_action_id'), 'set', ''),)),
            ('SAFE_FALLBACK_UNKNOWN', ((('controls', 'safe_fallback_action_id'), 'set', 'MISSING_ACTION'),)),
            ('SAFE_FALLBACK_NOT_ZERO_EFFECT', ((('controls', 'safe_fallback_action_id'), 'set', 'BANK_PAYMENT_STATUS_READ'),)),
            ('EVIDENCE_REQUIREMENTS', ((('evidence_requirements',), 'set', []),)),
            ('EVIDENCE_REQUIREMENT', ((('evidence_requirements', 0), 'set', []),)),
            ('EVIDENCE_REQUIREMENT_ID', ((('evidence_requirements', 0, 'requirement_id'), 'set', ''),)),
            ('DUPLICATE_EVIDENCE_REQUIREMENT', ((('evidence_requirements', 1, 'requirement_id'), 'set', 'BANK_PAYMENT_POST_EVIDENCE'),)),
            ('EVIDENCE_UNKNOWN_ACTION', ((('evidence_requirements', 0, 'applies_to_action_ids', 0), 'set', 'MISSING_ACTION'),)),
            ('EVIDENCE_ACTION_COVERAGE', ((('evidence_requirements', 2, 'applies_to_action_ids', 0), 'set', 'BANK_PAYMENT_POST'),)),
            ('MAPPING_WITNESS', ((('mapping_witness',), 'set', []),)),
            ('WITNESS_ID', ((('mapping_witness', 'witness_id'), 'set', ''),)),
        )
        self.assertEqual(len(rows), len({code for code, _ in rows}))
        for code, operations in rows:
            with self.subTest(code=code):
                with self.assertRaisesRegex(ContractViolation, rf"^{code}(:|$)"):
                    validate_profile(self._corrupt(fixture.profile, operations))
        validate_profile(fixture.profile)

    def test_declaration_validator_refuses_each_code_by_name(self) -> None:
        # The same sweep over validate_declaration, corrupting the DECLARATION
        # only and passing the untouched profile beside it.
        #
        # Not covered here, by name: PROFILE_CORE_MISMATCH, PROFILE_WITNESS_HASH.
        # PROFILE_CORE_MISMATCH is shadowed for every declaration-only
        # corruption by the core-anchor check that runs just before it, and
        # PROFILE_WITNESS_HASH is raised from the PROFILE's witness hash, which
        # this sweep does not touch.
        fixture = self.fixture()
        self.assert_identifier_list_contracts(
            fixture.declaration, lambda value: validate_declaration(value, fixture.profile),
            (
                ('ENVIRONMENT_IDS', ('connector', 'environment_ids'), False),
                ('SCOPE_ACTION_IDS', ('instance_scope', 'action_ids'), False),
                ('SCOPE_EFFECT_IDS', ('instance_scope', 'effect_class_ids'), False),
                ('SCOPE_TARGET_IDS', ('instance_scope', 'target_system_ids'), False),
                ('REVISION_AUTHORITIES', ('governance', 'revision_authority_ids'), False),
                ('OFF_LIMITS_SYSTEMS', ('interfaces', 'off_limits_system_ids'), True),
            ),
        )
        rows = (
            ('RESOURCE_MAX_WINDOW', ((('resource_limits', 0, 'max_committed_per_window'), 'set', -1),)),
            ('RESOURCE_WINDOW_SECONDS', ((('resource_limits', 0, 'window_seconds'), 'set', -1),)),
            ('RESOURCE_LIMIT_ORDER', ((('resource_limits', 0, 'window_seconds'), 'set', 0),)),
            ('RESOURCE_LIMIT_COVERAGE', ((('resource_limits', 1), 'delete', None),)),
            ('GOVERNANCE', ((('governance',), 'set', None),)),
            ('GOVERNANCE_ID', ((('governance', 'profile_owner_id'), 'set', ''),)),
            ('GOVERNANCE_CHANGE_CONTROL', ((('governance', 'no_live_gate_override'), 'set', False),)),
            ('INTERFACES', ((('interfaces',), 'set', None),)),
            ('INTERFACE_ID', ((('interfaces', 'governance_service_id'), 'set', ''),)),
            ('INTERFACE_ROLE_OVERLAP', ((('interfaces', 'operator_service_id'), 'set', 'synthetic-governance-service'),)),
            ('TARGET_OFF_LIMITS_OVERLAP', ((('interfaces', 'off_limits_system_ids', 0), 'set', 'bank-sandbox-ledger'),)),
            ('WITNESS_BINDING', ((('mapping_witness_binding',), 'set', None),)),
            ('WITNESS_ID_MISMATCH', ((('mapping_witness_binding', 'witness_id'), 'set', 'bank-questionnaire-crosswalk-v2'),)),
            ('WITNESS_HASH', ((('mapping_witness_binding', 'witness_hash'), 'set', 'not-a-sha256'),)),
            ('WITNESS_BINDING_MISMATCH', ((('mapping_witness_binding', 'witness_hash'), 'set', '0000000000000000000000000000000000000000000000000000000000000000'),)),
            ('DECLARATION_EVIDENCE', ((('evidence_refs',), 'set', []),)),
            ('SCOPE_ACTION_TARGET_COVERAGE', ((('instance_scope', 'action_target_bindings', 'NO_EFFECT_FALLBACK'), 'delete', None),)),
            ('SCOPE_ACTION_TARGET_RANGE', ((('instance_scope', 'action_target_bindings', 'NO_EFFECT_FALLBACK'), 'set', ['unbound-target']),)),
            ('SCOPE_UNKNOWN_EFFECT', ((('instance_scope', 'effect_class_ids', 2), 'set', 'UNKNOWN_EFFECT'),)),
            ('SCOPE_EFFECT_OMISSION', ((('instance_scope', 'effect_class_ids', 2), 'delete', None),)),
            ('SCOPE_CONSTRAINTS', ((('instance_scope', 'scope_constraints'), 'set', []),)),
            ('EMPTY_SCOPE_CONSTRAINTS', ((('instance_scope', 'scope_constraints'), 'set', {}),)),
            ('SCOPE_DIMENSION_ID', ((('instance_scope', 'scope_constraints', '1product'), 'set', ['synthetic-payment']),)),
            ('SCOPE_CONSTRAINT_VALUES', ((('instance_scope', 'scope_constraints', 'product'), 'set', []),)),
            ('STRUCTURAL_BUDGET', ((('structural_budget',), 'set', []),)),
            ('SELECTOR_ID', ((('structural_budget', 'selector_id'), 'set', ''),)),
            ('STRUCTURAL_CAPACITY', ((('structural_budget', 'capacity'), 'set', -1),)),
            ('STRUCTURAL_UNIT', ((('structural_budget', 'unit'), 'set', ''),)),
            ('STRUCTURAL_PROVENANCE', ((('structural_budget', 'provenance'), 'set', 'guessed'),)),
            ('RESOURCE_LIMITS', ((('resource_limits',), 'set', {}),)),
            ('RESOURCE_LIMIT', ((('resource_limits', 0), 'set', 'money_minor_units'),)),
            ('RESOURCE_LIMIT_ID', ((('resource_limits', 0, 'resource_id'), 'set', 42),)),
            ('RESOURCE_MAX_PER_INTENT', ((('resource_limits', 0, 'max_per_intent'), 'set', -1),)),
            ('DECLARATION_FIELDS', ((('evidence_refs',), 'delete', None),)),
            ('DECLARATION_SCHEMA_VERSION', ((('schema_version',), 'set', '2.0.0'),)),
            ('DECLARATION_ID', ((('declaration_id',), 'set', ''),)),
            ('DECLARATION_VERSION', ((('declaration_version',), 'set', '1.2'),)),
            ('PREDECESSOR_HASH', ((('predecessor_declaration_hash',), 'set', 'not-a-hash'),)),
            ('DECLARATION_TIME_ORDER', ((('expires_at',), 'set', '2026-07-30T00:00:00Z'),)),
            ('PROFILE_BINDING', ((('profile_binding',), 'set', None),)),
            ('PROFILE_ID_MISMATCH', ((('profile_binding', 'profile_id'), 'set', 'banking.reference.v2'),)),
            ('PROFILE_VERSION_MISMATCH', ((('profile_binding', 'profile_version'), 'set', '1.4.0'),)),
            ('PROFILE_HASH', ((('profile_binding', 'profile_hash'), 'set', 'not-a-hash'),)),
            ('PROFILE_HASH_MISMATCH', ((('profile_binding', 'profile_hash'), 'set', '81F9552562648773F84123BADD5957A3DA50A65ED47FB962AEC9E1D9518E1069'),)),
            ('CONNECTOR', ((('connector',), 'set', None),)),
            ('CONNECTOR_ID', ((('connector', 'connector_id'), 'set', ''),)),
            ('WORKLOAD_IDENTITY_ISSUER', ((('connector', 'workload_identity_issuer'), 'set', ''),)),
            ('INSTANCE_SCOPE', ((('instance_scope',), 'set', None),)),
            ('SCOPE_UNKNOWN_ACTION', ((('instance_scope', 'action_ids', 0), 'set', 'BANK_PAYMENT_REVERSE'),)),
            ('SCOPE_ACTION_TARGET_BINDINGS', ((('instance_scope', 'action_target_bindings'), 'set', None),)),
        )
        self.assertEqual(len(rows), len({code for code, _ in rows}))
        for code, operations in rows:
            with self.subTest(code=code):
                with self.assertRaisesRegex(ContractViolation, rf"^{code}(:|$)"):
                    validate_declaration(
                        self._corrupt(fixture.declaration, operations),
                        fixture.profile,
                    )
        validate_declaration(fixture.declaration, fixture.profile)

    def test_intent_validator_refuses_each_code_by_name(self) -> None:
        # The intent's own shape guards, swept by code. This is the second
        # half of the manual-review finding: a resolver row proves the control
        # SURFACE is overridden, but MANUAL_REVIEW_FLAGS itself is raised only
        # here, on an intent whose flag set disagrees with the profile's, and
        # no row anywhere asserted it. Its siblings had the same gap.
        fixture = self.fixture()
        engine, intent, _grant = fixture.engine()
        rows = (
            ("INTENT_FIELDS", ((("received_at",), "delete", None),)),
            ("INTENT_FIELDS", ((("extra",), "set", 1),)),
            ("INTENT_MESSAGE_TYPE", ((("message_type",), "set", "x"),)),
            # Form, not substance: a binding of the wrong SHAPE is refused
            # here with no event and no consumed key. A well-formed binding
            # naming another profile is a refusal with an event, decided
            # later - the resolver row in the control sweep keeps that one.
            ("INTENT_BINDING", ((("binding",), "set", "not-an-object"),)),
            ("INTENT_BINDING", ((("binding",), "set", {"profile_id": "x"}),)),
            ("INTENT_IDENTIFIER", ((("intent_id",), "set", "1bad"),)),
            ("INTENT_HASH", ((("payload_hash",), "set", "zz"),)),
            ("INTENT_SCOPE", ((("scope",), "set", "x"),)),
            ("INTENT_SCOPE", ((("scope",), "set", {}),)),
            ("INTENT_SCOPE", ((("scope",), "set", {"region": ""}),)),
            ("INTENT_SCOPE_DIMENSION", ((("scope",), "set", {"1bad": "x"}),)),
            ("RESOURCE_CLAIMS", ((("resource_claims",), "set", "x"),)),
            ("RESOURCE_CLAIM_ID", ((("resource_claims",), "set", {"1bad": 1}),)),
            ("RESOURCE_CLAIM_AMOUNT",
             ((("resource_claims",), "set", {"money_minor_units": -1}),)),
            ("RESOURCE_CLAIM_AMOUNT",
             ((("resource_claims",), "set", {"money_minor_units": True}),)),
            ("PREREQUISITE_RESULTS",
             ((("prerequisite_results",), "set", {"NOPE": True}),)),
            ("PREREQUISITE_RESULTS",
             ((("prerequisite_results", "ACCOUNT_ACTIVE"), "set", "yes"),)),
            ("HARD_BLOCK_FLAGS", ((("hard_block_flags",), "set", "x"),)),
            ("HARD_BLOCK_FLAGS", ((("hard_block_flags",), "set", {"NOPE": False}),)),
            ("MANUAL_REVIEW_FLAGS",
             ((("manual_review_flags",), "set", {"UNKNOWN_FLAG": False}),)),
            ("MANUAL_REVIEW_FLAGS",
             ((("manual_review_flags",), "set", {"IDENTITY_UNCERTAIN": False}),)),
            ("AMBIGUITY_FLAGS", ((("ambiguity_flags",), "set", ["a", "a"]),)),
            ("AMBIGUITY_FLAGS", ((("ambiguity_flags",), "set", "a"),)),
        )
        for index, (code, operations) in enumerate(rows):
            with self.subTest(code=code, row=index):
                with self.assertRaisesRegex(ContractViolation, rf"^{code}(:|$)"):
                    engine.evaluate_intent(
                        self._corrupt(intent, operations),
                        fixture.evidence,
                        actor_scope=ROLE_OPERATOR,
                    )
        # None of the refusals above touched the chain: a shape refusal is
        # answered before anything is recorded.
        self.assertEqual(engine.ledger.head()["event_count"], 2)

    def test_request_identity_normalises_declared_hashes_only(self) -> None:
        # The identity of a request is what the idempotency guard compares, so
        # what it includes decides who may replay whose result. Normalising by
        # SHAPE - any 64-hex string, whatever field it sat in - made identity
        # blind to the case of opaque identifiers, and two measured harms
        # followed: one logical payment could be authorised and executed TWICE
        # under one identity with two stored entries, and two different
        # principals sharing one key replayed each other's permit past the
        # authority check. Narrowing to the DECLARED fields closes both while
        # keeping the published rule "a hash is accepted in either case".
        fixture = self.fixture()

        with self.subTest(claim="an idempotency key is opaque and case-sensitive"):
            engine, intent, _grant = fixture.engine()
            lower = copy.deepcopy(intent)
            lower["idempotency_key"] = "a" * 64
            upper = copy.deepcopy(intent)
            upper["idempotency_key"] = "A" * 64
            first = engine.evaluate_intent(
                lower, fixture.evidence, actor_scope=ROLE_OPERATOR
            )
            second = engine.evaluate_intent(
                upper, fixture.evidence, actor_scope=ROLE_OPERATOR
            )
            self.assertNotEqual(
                first["request_hash"],
                second["request_hash"],
                "two keys collapsed into one request identity",
            )
            # And the harm that followed from the collapse: one identity, two
            # stored entries. Each identity must own at most one entry.
            identities = [
                stored_hash for stored_hash, _ in engine.idempotency.values()
            ]
            self.assertEqual(
                len(identities),
                len(set(identities)),
                "one request identity holds more than one idempotency entry",
            )

        with self.subTest(claim="an exact retry still replays"):
            engine, intent, _grant = fixture.engine()
            once = engine.evaluate_intent(
                intent, fixture.evidence, actor_scope=ROLE_OPERATOR
            )
            twice = engine.evaluate_intent(
                copy.deepcopy(intent), fixture.evidence, actor_scope=ROLE_OPERATOR
            )
            self.assertEqual(once["permit_hash"], twice["permit_hash"])

        with self.subTest(claim="declared hash fields still replay in either case"):
            engine, intent, _grant = fixture.engine()
            issued = engine.evaluate_intent(
                intent, fixture.evidence, actor_scope=ROLE_OPERATOR
            )
            lowered = copy.deepcopy(intent)
            # The NESTED binding hashes, and each one is asserted to actually
            # change when lowered. The fixture's top-level hashes are runs of
            # digits, which have no case at all: lowering them changed nothing,
            # so this row was green with normalisation removed entirely -
            # a sample outside the class it claims to test.
            for field in ("profile_hash", "declaration_hash"):
                value = lowered["binding"][field]
                self.assertNotEqual(
                    value, value.lower(), f"{field} carries no case to normalise"
                )
                lowered["binding"][field] = value.lower()
            replayed = engine.evaluate_intent(
                lowered, fixture.evidence, actor_scope=ROLE_OPERATOR
            )
            self.assertEqual(
                issued["permit_hash"],
                replayed["permit_hash"],
                "the wire rule 'a hash is accepted in either case' was lost",
            )

        with self.subTest(claim="two principals never share one replay"):
            grant = copy.deepcopy(fixture.grant)
            grant["subject_id"] = "a" * 64
            engine, intent, _grant = fixture.engine(grant=grant)
            holder = copy.deepcopy(intent)
            holder["requester_id"] = "a" * 64
            holder["idempotency_key"] = "shared-idempotency-key"
            stranger = copy.deepcopy(holder)
            stranger["requester_id"] = "A" * 64
            authorised = engine.evaluate_intent(
                holder, fixture.evidence, actor_scope=ROLE_OPERATOR
            )
            self.assertEqual(authorised["disposition"], "ALLOW")
            with self.assertRaisesRegex(
                ContractViolation, r"^IDEMPOTENCY_CONFLICT(:|$)"
            ):
                engine.evaluate_intent(
                    stranger, fixture.evidence, actor_scope=ROLE_OPERATOR
                )

        with self.subTest(claim="the executor surface narrows the same way"):
            engine, intent, _grant = fixture.engine()
            result = self.allow_permit(fixture, engine, intent)
            request = fixture.execution_request(engine, result, intent)
            request["connector_id"] = "a" * 64
            other = copy.deepcopy(request)
            other["connector_id"] = "A" * 64
            identity = sha256_hex(_normalize_declared_hash_case(request))
            self.assertNotEqual(
                identity,
                sha256_hex(_normalize_declared_hash_case(other)),
                "a hex-shaped connector_id collapsed two execution requests",
            )
            cased = copy.deepcopy(request)
            cased["permit_hash"] = cased["permit_hash"].lower()
            self.assertEqual(
                identity,
                sha256_hex(_normalize_declared_hash_case(cased)),
                "a declared hash field stopped being case-normalised",
            )

    def test_a_header_that_lies_in_comparison_authorises_nothing(self) -> None:
        """The wire reads a header's CHARACTERS, not the object a caller put in the environ.

        Everything this layer asks of the two headers that decide an authorised scope and
        an idempotency match - truthiness, `!=` - ran the value's own code. A server hands
        native strings and nothing changes for it; in process the environ is whatever the
        caller builds, and there these checks were the only gate. Measured one layer in, at
        the bridge, where an object answering every comparison with agreement passed a
        binding written exactly like these. Planted here as a `str` subclass carrying the
        wrong characters and saying it equals everything; the controls are the honest scope
        and the honest key, which must still be served.
        """
        import nc25_universal_adapter as wire

        class AgreesWithEverything(str):
            def __eq__(self, other):  # noqa: D105
                return True

            def __ne__(self, other):  # noqa: D105
                return False

            def __hash__(self):  # noqa: D105
                return str.__hash__(self)

        fixture = self.fixture()
        engine, intent, _grant = fixture.engine()
        app = wire.UniversalConnectionHttpAdapter(engine)

        def call(scope, idem):
            raw = json.dumps(
                {"intent": intent, "evidence_bundle": fixture.evidence}).encode("utf-8")
            environ = {
                "REQUEST_METHOD": "POST",
                "PATH_INFO": "/v1/operator/intents:evaluate",
                "CONTENT_LENGTH": str(len(raw)),
                "wsgi.input": io.BytesIO(raw),
                "HTTP_X_WORKLOAD_SCOPE": scope,
                "HTTP_IDEMPOTENCY_KEY": idem,
            }
            captured: dict = {}

            def start_response(status, _headers):
                captured["status"] = status

            payload = b"".join(app(environ, start_response))
            return int(captured["status"].split()[0]), (json.loads(payload) if payload else {})

        honest_key = intent["idempotency_key"]
        status, body = call(AgreesWithEverything("not-a-scope"), honest_key)
        self.assertEqual(status, 403, body)
        status, body = call(ROLE_OPERATOR, AgreesWithEverything("not-the-intents-key"))
        self.assertEqual(status, 409, body)
        status, body = call(ROLE_OPERATOR, honest_key)
        self.assertEqual(status, 200, body)

    def test_wire_refuses_path_aliases_and_unparseable_bodies(self) -> None:
        # The adapter's guards against malformed REQUESTS, swept as one class.
        # Each row here was a way past the published contract: a route had a
        # second spelling differing by a trailing newline; a path parameter was
        # percent-decoded a second time after the server had already decoded
        # it, so a caller asking for one connector was served the active one;
        # a deeply nested body raised RecursionError out of the JSON parser
        # before any engine code ran; a missing required field was echoed back
        # as the string "None"; and a refused value was quoted back in full,
        # so the response length was set by the request.
        import nc25_universal_adapter as wire

        fixture = self.fixture()
        engine, intent, _grant = fixture.engine()
        app = wire.UniversalConnectionHttpAdapter(engine)

        def call(method, path, body=None, scope=None, idem=None, raw_text=None):
            if raw_text is not None:
                raw = raw_text.encode("utf-8")
            else:
                raw = json.dumps(body).encode("utf-8") if body is not None else b""
            environ = {
                "REQUEST_METHOD": method,
                "PATH_INFO": path,
                "CONTENT_LENGTH": str(len(raw)),
                "wsgi.input": io.BytesIO(raw),
            }
            if scope is not None:
                environ["HTTP_X_WORKLOAD_SCOPE"] = scope
            if idem is not None:
                environ["HTTP_IDEMPOTENCY_KEY"] = idem
            captured: dict = {}

            def start_response(status, _headers):
                captured["status"] = status

            payload = b"".join(app(environ, start_response))
            parsed = json.loads(payload) if payload else None
            return int(captured["status"].split()[0]), (parsed or {})

        status, decision = call(
            "POST",
            "/v1/operator/intents:evaluate",
            {"intent": intent, "evidence_bundle": fixture.evidence},
            ROLE_OPERATOR,
            idem=intent["idempotency_key"],
        )
        self.assertEqual(status, 200, decision)
        permit_hash = decision["permit_hash"]
        request_hash = decision["request_hash"]

        routes = (
            ("POST", "/v1/declarations:activate", ROLE_GOVERNANCE),
            ("POST", "/v1/authority-grants", ROLE_GOVERNANCE),
            ("POST", "/v1/authority-revocations", ROLE_GOVERNANCE),
            ("POST", "/v1/operator/intents:evaluate", ROLE_OPERATOR),
            ("POST", f"/v1/executor/permits/{permit_hash}:consume", ROLE_EXECUTOR),
            ("GET", f"/v1/architect/permits/{permit_hash}", ROLE_ARCHITECT),
            ("GET", f"/v1/architect/decisions/{request_hash}", ROLE_ARCHITECT),
            ("GET", "/v1/architect/ledger/head", ROLE_ARCHITECT),
            ("GET", "/v1/registry/connectors/synthetic-bank-connector", ROLE_ARCHITECT),
        )

        # The alias rows must cover the three PARAMETRIC routes as well as the
        # six fixed ones: the anchor alone closes the fixed six, while on a
        # route ending in a capture the class [^/]+ swallows the newline and
        # the anchor still matches. A sweep that stopped at /ledger/head would
        # be green with the second guard removed.
        events_before = engine.ledger.head()["event_count"]
        for method, path, scope in routes:
            with self.subTest(route=path, spelling="trailing newline"):
                status, body = call(method, path + "\n", {}, scope)
                self.assertEqual(status, 404, f"{path} answered under an alias")
                self.assertEqual(body.get("code"), "NOT_FOUND")
        self.assertEqual(
            engine.ledger.head()["event_count"],
            events_before,
            "an aliased path reached the signed chain",
        )
        for method, path, scope in routes:
            with self.subTest(route=path, spelling="exact"):
                status, _body = call(method, path, {}, scope)
                self.assertNotEqual(
                    status, 404, f"{path} stopped resolving under its own name"
                )

        with self.subTest(guard="registry selector is not decoded twice"):
            status, body = call(
                "GET",
                "/v1/registry/connectors/%73ynthetic-bank-connector",
                None,
                ROLE_ARCHITECT,
            )
            self.assertNotEqual(status, 200, body)
            self.assertEqual(body.get("code"), "REGISTRY_CONNECTOR_ID")
        with self.subTest(guard="permit selector is not decoded twice"):
            # The selector is the real hash with its FIRST character written
            # percent-encoded, so a second decode reproduces the hash exactly
            # and answers 200. Encoding a character and then dropping another
            # one builds a 63-character selector, which the shape check refuses
            # on its own - the row would pass with the double decode restored
            # and certify nothing. Measured: an earlier form of this row did.
            encoded_first = f"%{ord(permit_hash[0]):02X}"
            status, body = call(
                "GET",
                f"/v1/architect/permits/{encoded_first}{permit_hash[1:]}",
                None,
                ROLE_ARCHITECT,
            )
            self.assertNotEqual(status, 200, body)
            self.assertEqual(body.get("code"), "PERMIT_HASH")
        with self.subTest(guard="the exact selector still resolves"):
            status, _body = call(
                "GET",
                "/v1/registry/connectors/synthetic-bank-connector",
                None,
                ROLE_ARCHITECT,
            )
            self.assertEqual(status, 200)

        # Both sides of the depth bound, and the bound is the engine's own:
        # the scan counts the enclosing object, so 63 brackets inside it is
        # depth 64 and passes, while 64 brackets is depth 65 and does not.
        with self.subTest(guard="nesting at the bound is parsed"):
            status, body = call(
                "POST", "/v1/authority-grants", None, ROLE_GOVERNANCE,
                raw_text='{"nested": ' + "[" * 63 + "]" * 63 + "}",
            )
            self.assertNotEqual(body.get("code"), "BODY_NESTING")
        with self.subTest(guard="nesting past the bound is refused"):
            status, body = call(
                "POST", "/v1/authority-grants", None, ROLE_GOVERNANCE,
                raw_text='{"nested": ' + "[" * 64 + "]" * 64 + "}",
            )
            self.assertEqual(status, 400)
            self.assertEqual(body.get("code"), "BODY_NESTING")
        with self.subTest(guard="nesting deep enough to break the parser"):
            status, body = call(
                "POST", "/v1/authority-grants", None, ROLE_GOVERNANCE,
                raw_text='{"nested": ' + "[" * 50000 + "]" * 50000 + "}",
            )
            self.assertEqual(status, 400)
            self.assertEqual(body.get("code"), "BODY_NESTING")

        with self.subTest(guard="a missing actor is a body defect"):
            status, body = call(
                "POST",
                "/v1/declarations:activate",
                {
                    "profile": engine.profile,
                    "declaration": engine.declaration,
                    "approval_evidence_ref": "evidence://synthetic/activation",
                },
                ROLE_GOVERNANCE,
            )
            self.assertEqual(status, 400)
            self.assertEqual(body.get("code"), "ACTIVATE_BODY")
            self.assertNotEqual(
                body.get("message"), "None", "the caller was shown a Python repr"
            )

        with self.subTest(guard="a refused timestamp is not echoed in full"):
            oversized = copy.deepcopy(intent)
            oversized["received_at"] = "x" * 5000
            status, body = call(
                "POST",
                "/v1/operator/intents:evaluate",
                {"intent": oversized, "evidence_bundle": fixture.evidence},
                ROLE_OPERATOR,
                idem=oversized["idempotency_key"],
            )
            self.assertEqual(body.get("code"), "INVALID_TIMESTAMP")
            self.assertLessEqual(len(body.get("message", "")), 131)

        with self.subTest(guard="a wrapper's unknown keys are not echoed in full"):
            status, body = call(
                "POST",
                "/v1/operator/intents:evaluate",
                {"intent": intent, "evidence_bundle": fixture.evidence,
                 **{f"k{index}": 1 for index in range(400)}},
                ROLE_OPERATOR,
                idem=intent["idempotency_key"],
            )
            self.assertEqual(body.get("code"), "OPERATOR_BODY")
            self.assertLessEqual(len(body.get("message", "")), 131)

        with self.subTest(guard="engine unknown keys are bounded at the wire boundary"):
            payload = {**_grant, **{f"k{index}": 1 for index in range(400)}}
            status, body = call("POST", "/v1/authority-grants", payload, ROLE_GOVERNANCE)
            self.assertEqual(status, 400)
            self.assertEqual(body.get("code"), "AUTHORITY_GRANT_FIELDS")
            self.assertLessEqual(len(body.get("message", "")), 131)
        with self.subTest(guard="short engine explanations are preserved"):
            status, body = call("POST", "/v1/authority-grants", {**_grant, "extra": 1}, ROLE_GOVERNANCE)
            self.assertEqual(body.get("message"), "unknown fields: ['extra']")

        with self.subTest(guard="a refused value is not echoed in full"):
            oversized = copy.deepcopy(intent)
            oversized["connector_id"] = "x" * 5000
            status, body = call(
                "POST",
                "/v1/operator/intents:evaluate",
                {"intent": oversized, "evidence_bundle": fixture.evidence},
                ROLE_OPERATOR,
                idem=oversized["idempotency_key"],
            )
            self.assertEqual(status, 400)
            self.assertLessEqual(
                len(body.get("message", "")),
                131,
                "the response length was set by the request",
            )

    def test_no_hostile_value_leaves_the_refusal_vocabulary(self) -> None:
        # One class: a value the caller or a tampered store controls reaches
        # a Python exception the refusal vocabulary does not contain, and the
        # wire answers it as the unclassified 503 INTERNAL_FAILURE while the
        # engine raises it raw. Its known members were an integer literal past
        # the parser's digit limit (ValueError past the decode-error catch),
        # non-ASCII text or bytes in a persisted state column
        # (UnicodeEncodeError, AttributeError and TypeError before the hash and
        # MAC comparisons), and a non-text stored event hash (TypeError out of
        # verify(), which answers False for a hash that does not match).
        #
        # The known members are pinned to the codes the contract names for
        # them. The sweep then asks the class question of every place a value
        # enters - every leaf and object of every body route, a hostile key in
        # every object, the Idempotency-Key header, every captured path
        # segment, every column of the persisted state row, every field of a
        # stored event and of its signature envelope - without naming codes:
        # whatever comes back must be a declared answer. The classification is
        # by exception type and by the wire's own unclassified-fault code, so a
        # member of a form this list has not seen fails here the day it
        # appears.
        #
        # The pinned integer row assumes the interpreter's digit limit is on,
        # as it is by default. With PYTHONINTMAXSTRDIGITS=0 no integer is past
        # a limit, the row reddens, and the red names that configuration.
        import nc25_universal_adapter as wire

        base_fixture = self.fixture()
        digit_limit = sys.get_int_max_str_digits() or 4300
        over_limit = "9" * (digit_limit + 1)
        hostile_tokens = {
            "integer past the digit limit": over_limit,
            "negative integer past the digit limit": "-" + over_limit,
            "float overflowing to infinity": "1e999",
            "NaN token": "NaN",
            "lone surrogate": '"\\ud800"',
            "non-ASCII text": '"\\u00e9"',
            "NUL character": '"\\u0000"',
            "long text": '"' + "a" * 5000 + '"',
            "fractional number": "1.5",
            "empty object": "{}",
            "empty array": "[]",
            "null": "null",
            "boolean": "true",
            "nested arrays inside the depth bound": "[" * 40 + "]" * 40,
        }
        hostile_keys = {"lone surrogate key": '"\\ud800"', "non-ASCII key": '"\\u00e9"'}
        sentinel = "__hostile_value_placeholder__"

        def bound_objects():
            return bind_fixture(
                base_fixture.profile, base_fixture.declaration,
                base_fixture.grant, base_fixture.intent,
            )

        def fresh_app(level: int):
            profile, declaration, grant, intent = bound_objects()
            engine = UniversalConnectionLedger(
                profile, declaration,
                signing_key=b"synthetic-reference-signing-key",
                clock=copy.deepcopy(base_fixture.clock),
            )
            permit_hash = None
            if level >= 1:
                engine.activate(
                    base_fixture.fx.approval_owner,
                    "evidence://synthetic/declaration-activation",
                    actor_scope=ROLE_GOVERNANCE,
                )
            if level >= 2:
                engine.issue_grant(copy.deepcopy(grant), actor_scope=ROLE_GOVERNANCE)
            if level >= 3:
                permit_hash = engine.evaluate_intent(
                    copy.deepcopy(intent), copy.deepcopy(base_fixture.evidence),
                    actor_scope=ROLE_OPERATOR,
                )["permit_hash"]
            return wire.UniversalConnectionHttpAdapter(engine), permit_hash

        def call(app, method, path, raw=b"", scope=None, idem=None):
            environ = {
                "REQUEST_METHOD": method,
                "PATH_INFO": path,
                "CONTENT_LENGTH": str(len(raw)),
                "wsgi.input": io.BytesIO(raw),
            }
            if scope is not None:
                environ["HTTP_X_WORKLOAD_SCOPE"] = scope
            if idem is not None:
                environ["HTTP_IDEMPOTENCY_KEY"] = idem
            captured: dict = {}

            def start_response(status, _headers):
                captured["status"] = status

            payload = b"".join(app(environ, start_response))
            return int(captured["status"].split()[0]), (json.loads(payload) if payload else {})

        _profile, _declaration, grant, intent = bound_objects()
        probe_app, _ = fresh_app(0)
        body_routes = (
            ("activate", 0, "/v1/declarations:activate", ROLE_GOVERNANCE, None, {
                "profile": copy.deepcopy(probe_app._engine.profile),
                "declaration": copy.deepcopy(probe_app._engine.declaration),
                "activated_by": base_fixture.fx.approval_owner,
                "approval_evidence_ref": "evidence://synthetic/declaration-activation",
            }),
            ("grant", 1, "/v1/authority-grants", ROLE_GOVERNANCE, None, copy.deepcopy(grant)),
            ("revoke", 2, "/v1/authority-revocations", ROLE_GOVERNANCE, None, {
                "message_type": "authority_revocation",
                "grant_id": grant["grant_id"],
                "declaration_hash": probe_app._engine.declaration_hash,
                "revoked_at": "2026-08-01T10:00:00Z",
                "revoked_by": grant["issued_by"],
                "reason_code": "SYNTHETIC_REVOCATION",
                "evidence_ref": "evidence://synthetic/revocation/hostile-sweep",
            }),
            ("evaluate", 2, "/v1/operator/intents:evaluate", ROLE_OPERATOR,
             intent["idempotency_key"],
             {"intent": copy.deepcopy(intent), "evidence_bundle": copy.deepcopy(base_fixture.evidence)}),
            ("consume", 3, None, ROLE_EXECUTOR, None, {
                "message_type": "execution_request",
                "permit_hash": None,
                "connector_id": intent["connector_id"],
                "binding": intent["binding"],
                "state_anchor_hash": intent["state_anchor_hash"],
                "outcome": "COMMITTED",
                "downstream_receipt_hash": "9" * 64,
                "committed_at": "2026-08-01T10:00:00Z",
            }),
        )

        def locations(value, prefix=()):
            yield prefix
            if isinstance(value, dict):
                for key, child in value.items():
                    yield from locations(child, prefix + (key,))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    yield from locations(child, prefix + (index,))

        def node(value, location):
            for step in location:
                value = value[step]
            return value

        def send(route, place):
            name, level, path, scope, idem, body = route
            app, permit_hash = fresh_app(level)
            document = copy.deepcopy(body)
            if name == "consume":
                document["permit_hash"] = permit_hash
            raw = place(document)
            status, answer = call(
                app, "POST", path or f"/v1/executor/permits/{permit_hash}:consume",
                raw, scope, idem,
            )
            return status, answer

        # A known member, pinned: the over-limit integer is a body defect on
        # every body route, not a fault.
        for route in body_routes:
            with self.subTest(member="integer past the digit limit", route=route[0]):
                status, answer = send(
                    route,
                    lambda document: json.dumps(
                        dict(document, hostile=sentinel)
                    ).replace(json.dumps(sentinel), over_limit).encode("utf-8"),
                )
                self.assertEqual((status, answer.get("code")), (400, "BODY_JSON"))

        escapes: list[str] = []
        cases = 0
        reached: set[str] = set()
        for route in body_routes:
            for location in [place for place in locations(route[5]) if place]:
                for label, token in hostile_tokens.items():
                    def place_value(document, location=location, token=token):
                        node(document, location[:-1])[location[-1]] = sentinel
                        return json.dumps(document).replace(
                            json.dumps(sentinel), token
                        ).encode("utf-8")
                    status, answer = send(route, place_value)
                    cases += 1
                    reached.add(route[0])
                    if (status, answer.get("code")) == (503, "INTERNAL_FAILURE"):
                        escapes.append(f"{route[0]} /{'/'.join(map(str, location))} <- {label}")
            for location in locations(route[5]):
                if not isinstance(node(route[5], location), dict):
                    continue
                for label, token in hostile_keys.items():
                    def place_key(document, location=location, token=token):
                        node(document, location)[sentinel] = 1
                        return json.dumps(document).replace(
                            json.dumps(sentinel), token
                        ).encode("utf-8")
                    status, answer = send(route, place_key)
                    cases += 1
                    if (status, answer.get("code")) == (503, "INTERNAL_FAILURE"):
                        escapes.append(f"{route[0]} /{'/'.join(map(str, location))} <- {label}")

        hostile_segments = {
            "non-ASCII": "é" * 64,
            "high Latin-1": "\xff" * 64,
            "long": "A" * 100000,
            "percent-encoded NUL": "%00" * 10,
            "dots": "..",
            "spaces": " " * 64,
        }
        for label, segment in hostile_segments.items():
            for method, template, scope in (
                ("GET", "/v1/architect/permits/{}", ROLE_ARCHITECT),
                ("GET", "/v1/architect/decisions/{}", ROLE_ARCHITECT),
                ("GET", "/v1/registry/connectors/{}", ROLE_ARCHITECT),
                ("POST", "/v1/executor/permits/{}:consume", ROLE_EXECUTOR),
            ):
                app, permit_hash = fresh_app(3)
                raw = json.dumps(
                    {"message_type": "execution_request", "permit_hash": permit_hash}
                ).encode("utf-8") if method == "POST" else b""
                status, answer = call(app, method, template.format(segment), raw, scope)
                cases += 1
                if (status, answer.get("code")) == (503, "INTERNAL_FAILURE"):
                    escapes.append(f"path {template} <- {label}")
            app, _ = fresh_app(2)
            raw = json.dumps(
                {"intent": intent, "evidence_bundle": base_fixture.evidence}
            ).encode("utf-8")
            status, answer = call(
                app, "POST", "/v1/operator/intents:evaluate", raw, ROLE_OPERATOR, segment
            )
            cases += 1
            if (status, answer.get("code")) == (503, "INTERNAL_FAILURE"):
                escapes.append(f"Idempotency-Key header <- {label}")

        # Persisted state row, pinned: the three columns the reader hashes and
        # MACs, with the two value forms the writer never produces. The pinned
        # codes are the ones the store already names for a hash or MAC that
        # does not match.
        with tempfile.TemporaryDirectory() as temporary:
            for column, code in (
                ("state_json", "STATE_HASH_FAILURE"),
                ("state_hash", "STATE_HASH_FAILURE"),
                ("state_mac", "STATE_MAC_FAILURE"),
            ):
                # "invalid utf-8 text" is stored through a CAST, because a bytes parameter
                # binds as a BLOB: only the CAST produces a TEXT column the driver cannot
                # decode, which is the form that used to fail inside the driver at the
                # fetch - before this guard, and outside the vocabulary altogether.
                for form in ("non-ASCII text", "bytes", "invalid utf-8 text"):
                    path = Path(temporary) / f"{column}-{form.replace(' ', '-')}.sqlite"
                    stored, stored_declaration, _grant, stored_intent = bound_objects()
                    engine = UniversalConnectionLedger(
                        stored, stored_declaration,
                        signing_key=b"synthetic-reference-signing-key",
                        clock=copy.deepcopy(base_fixture.clock),
                        state_path=path,
                    )
                    engine.activate(
                        base_fixture.fx.approval_owner,
                        "evidence://synthetic/declaration-activation",
                        actor_scope=ROLE_GOVERNANCE,
                    )
                    with closing(sqlite3.connect(path)) as connection:
                        original = connection.execute(
                            f"SELECT {column} FROM ledger_state"
                        ).fetchone()[0]
                        if form == "invalid utf-8 text":
                            # CAST, not a bytes parameter: a parameter binds as a BLOB and
                            # the type guard sees it. Only a TEXT column carrying bytes
                            # that are not UTF-8 reaches the decoding the driver does.
                            connection.execute(
                                f"UPDATE ledger_state SET {column} = CAST(? AS TEXT)",
                                (b"\xff\xfe" + original.encode("ascii"),),
                            )
                            connection.commit()
                        else:
                            if form == "bytes":
                                value = original.encode("ascii")
                            elif column == "state_json":
                                value = original.replace('"ACTIVE"', '"ACTIVé"', 1)
                            else:
                                value = "é" + original[1:]
                            self.assertNotEqual(value, original)
                            connection.execute(f"UPDATE ledger_state SET {column} = ?", (value,))
                            connection.commit()
                    reads = (
                        ("ledger head", lambda engine=engine: engine.ledger_head(ROLE_ARCHITECT)),
                        ("evaluate", lambda engine=engine, stored_intent=stored_intent: engine.evaluate_intent(
                            copy.deepcopy(stored_intent), copy.deepcopy(base_fixture.evidence),
                            actor_scope=ROLE_OPERATOR,
                        )),
                    )
                    for surface, read in reads:
                        with self.subTest(member=f"{form} in {column}", surface=surface):
                            with self.assertRaisesRegex(IntegrityViolation, rf"^{code}(:|$)"):
                                read()

            # The sweep: every column of the row and every stored form, in a
            # table carrying the store's column names without their types, so
            # each form is kept as written (the store accepts a table it did
            # not create). Opening the store and reading it must refuse or
            # answer.
            pristine_path = Path(temporary) / "pristine.sqlite"
            stored, stored_declaration, _stored_grant, stored_intent = bound_objects()
            UniversalConnectionLedger(
                stored, stored_declaration,
                signing_key=b"synthetic-reference-signing-key",
                clock=copy.deepcopy(base_fixture.clock),
                state_path=pristine_path,
            ).activate(
                base_fixture.fx.approval_owner,
                "evidence://synthetic/declaration-activation",
                actor_scope=ROLE_GOVERNANCE,
            )
            with closing(sqlite3.connect(pristine_path)) as connection:
                connection.row_factory = sqlite3.Row
                pristine = dict(connection.execute("SELECT * FROM ledger_state").fetchone())
            state_columns = list(pristine)
            self.assertGreaterEqual(len(state_columns), 5, "the sweep saw fewer columns than the store writes")
            stored_forms = {
                "non-ASCII text": "é" * 64,
                "bytes": b"\x00" * 8,
                "integer": 7,
                "null": None,
                "empty text": "",
            }
            state_refusals: set[str] = set()
            for column in state_columns:
                # `declaration_hash` is the KEY this store reads by, and a hostile value
                # in it moves the row out of the reader's reach: the load finds no row for
                # the declaration it was constructed with, so the sweep would record
                # "nothing escaped" about a row nothing read. Measured one module over, on
                # the outbox, whose key is the same question: the honest key answers None
                # while the untouched row answers with a record. The case below the loop
                # asks what happens to such a row instead.
                if column == "declaration_hash":
                    continue
                for label, value in stored_forms.items():
                    path = Path(temporary) / f"sweep-{column}-{cases}.sqlite"
                    row = dict(pristine, **{column: value})
                    with closing(sqlite3.connect(path)) as connection:
                        connection.execute(
                            "CREATE TABLE ledger_state ("
                            + ", ".join(state_columns)
                            + ", PRIMARY KEY (declaration_hash))"
                        )
                        connection.execute(
                            "INSERT INTO ledger_state ("
                            + ", ".join(state_columns)
                            + ") VALUES ("
                            + ", ".join("?" for _ in state_columns)
                            + ")",
                            [row[name] for name in state_columns],
                        )
                        connection.commit()
                    for surface in ("ledger head", "evaluate"):
                        cases += 1
                        try:
                            reader = UniversalConnectionLedger(
                                stored, stored_declaration,
                                signing_key=b"synthetic-reference-signing-key",
                                clock=copy.deepcopy(base_fixture.clock),
                                state_path=path,
                            )
                            if surface == "ledger head":
                                reader.ledger_head(ROLE_ARCHITECT)
                            else:
                                reader.evaluate_intent(
                                    copy.deepcopy(stored_intent),
                                    copy.deepcopy(base_fixture.evidence),
                                    actor_scope=ROLE_OPERATOR,
                                )
                        except ContractViolation as refusal:
                            state_refusals.add(refusal.code)
                            continue
                        except Exception as exc:  # noqa: BLE001 - the class under test
                            escapes.append(
                                f"state row {column} <- {label} ({surface}): {type(exc).__name__}"
                            )

            # The question the key column is left out of the loop for. A stored row whose
            # `declaration_hash` is not this declaration's is not this store's row for this
            # declaration: the load finds nothing and says so by name, which is the whole
            # of what can be said about it. The control is the untouched row on the same
            # construction, so "refused" cannot pass for "the reader cannot read anything".
            keyless = Path(temporary) / "hostile-key.sqlite"
            hostile = dict(pristine, declaration_hash="not-this-declaration")
            with closing(sqlite3.connect(keyless)) as connection:
                connection.execute(
                    "CREATE TABLE ledger_state (" + ", ".join(state_columns)
                    + ", PRIMARY KEY (declaration_hash))")
                connection.execute(
                    "INSERT INTO ledger_state (" + ", ".join(state_columns) + ") VALUES ("
                    + ", ".join("?" for _ in state_columns) + ")",
                    [hostile[name] for name in state_columns])
                connection.commit()
            empty = Path(temporary) / "no-row.sqlite"
            with closing(sqlite3.connect(empty)) as connection:
                connection.execute(
                    "CREATE TABLE ledger_state (" + ", ".join(state_columns)
                    + ", PRIMARY KEY (declaration_hash))")
                connection.commit()
            with self.subTest(member="a stored row whose key is another declaration's"):
                cases += 1

                def head(path):
                    return UniversalConnectionLedger(
                        stored, stored_declaration,
                        signing_key=b"synthetic-reference-signing-key",
                        clock=copy.deepcopy(base_fixture.clock),
                        state_path=path,
                    ).ledger_head(ROLE_ARCHITECT)

                # Measured rather than assumed: the reader does NOT refuse such a row, and
                # it should not - a table holding another declaration's state holds no
                # state for this one. What the case says is that the two are the SAME
                # answer, so a foreign row cannot become this declaration's head by
                # sitting in the same table.
                self.assertEqual(head(keyless), head(empty))

            # Control, two halves, each with its own claim - stated separately because an
            # earlier version credited the first with what only the second does. A store
            # raising IntegrityViolation unconditionally would satisfy "some refusal was
            # seen", since IntegrityViolation IS a ContractViolation; what it cannot do is
            # answer two different hostile inputs with two different codes, or read an
            # unmodified row. So: the sweep must have drawn MORE THAN ONE code, and the
            # untouched row must be READ on both surfaces, through the same construction.
            #
            # The first half names its two codes rather than counting to two. Measured, the
            # sweep draws four - DECLARATION_NOT_ACTIVE, STATE_HASH_FAILURE,
            # STATE_MAC_FAILURE, STATE_PROFILE_MISMATCH - so "more than one" was carried by
            # the two that are NOT the hash and the MAC, and both of those guards could die
            # with the count still satisfied. Naming them binds the control to the guards
            # the sweep exists to exercise; the set is a subset test, not equality, because
            # which other codes a hostile value reaches is not this control's claim.
            #
            # SHADOWED, and disclosed rather than dressed up. Measured on two breaks: kill
            # the MAC comparison and six pinned `state_mac` rows redden before this line;
            # drop a column from the swept set and the column-count guard above reddens
            # first instead. No realistic break reaches this assertion first. It is kept
            # because its claim is not any row's: a row says "this input refuses with this
            # code", while this says the SWEEP - every stored column against every hostile
            # form on both surfaces, which its own loops bound at len(state_columns) x
            # len(stored_forms) x 2 - actually arrived at both guards. The bound is written
            # as those loops rather than as a figure: the figure that stood here was 5132,
            # taken from a probe of mine that printed the WHOLE test's running case counter
            # at this point. The replacement said "the sweep's own share of it is fifty",
            # which is the same mistake one size smaller: `state_columns` is READ from the
            # stored row and asserted `>= 5`, an inequality on purpose, so the product is
            # fifty only while that table has exactly five columns and is sixty the day a
            # sixth is added - with the assertion still green and the sentence still
            # saying fifty. The bound is a product of a runtime read, and that is all a
            # comment can truthfully say about it.
            # A sweep whose construction went wrong could
            # leave every pinned row green and measure nothing, and that is the only thing
            # here that would say so.
            self.assertLessEqual(
                {"STATE_HASH_FAILURE", "STATE_MAC_FAILURE"}, state_refusals,
                "the state sweep did not exercise both stored-state guards: %s" % sorted(state_refusals),
            )
            # Built by the SAME statements as the hostile rows, with the pristine values,
            # not copied from the store's own file: a control made another way vouches for
            # another construction. Misspell a name in the CREATE above and every hostile
            # read refuses on columns while a copy-built control still reads - green, with
            # the sweep measuring nothing. This one reddens with them.
            control_path = Path(temporary) / "state-control.sqlite"
            with closing(sqlite3.connect(control_path)) as connection:
                connection.execute(
                    "CREATE TABLE ledger_state ("
                    + ", ".join(state_columns)
                    + ", PRIMARY KEY (declaration_hash))"
                )
                connection.execute(
                    "INSERT INTO ledger_state ("
                    + ", ".join(state_columns)
                    + ") VALUES ("
                    + ", ".join("?" for _ in state_columns)
                    + ")",
                    [pristine[name] for name in state_columns],
                )
                connection.commit()
            control = UniversalConnectionLedger(
                stored, stored_declaration,
                signing_key=b"synthetic-reference-signing-key",
                clock=copy.deepcopy(base_fixture.clock),
                state_path=control_path,
            )
            self.assertIn("head_hash", control.ledger_head(ROLE_ARCHITECT))
            control.evaluate_intent(
                copy.deepcopy(stored_intent),
                copy.deepcopy(base_fixture.evidence),
                actor_scope=ROLE_OPERATOR,
            )

            # The table itself, pinned: a table the store did not create may lack a column
            # the store reads. Each is dropped in turn. Construction is what refuses now -
            # the store takes one checked connection as it opens - so the public read kept
            # below is never reached; it stays in the case to say that no public path sees
            # such a table either.
            for missing in state_columns:
                kept = [name for name in state_columns if name != missing]
                path = Path(temporary) / f"without-{missing}.sqlite"
                primary = ", PRIMARY KEY (declaration_hash)" if "declaration_hash" in kept else ""
                with closing(sqlite3.connect(path)) as connection:
                    connection.execute("CREATE TABLE ledger_state (" + ", ".join(kept) + primary + ")")
                    connection.execute(
                        "INSERT INTO ledger_state (" + ", ".join(kept) + ") VALUES ("
                        + ", ".join("?" for _ in kept) + ")",
                        [pristine[name] for name in kept],
                    )
                    connection.commit()
                with self.subTest(member=f"state table without {missing}"):
                    cases += 1
                    with self.assertRaisesRegex(IntegrityViolation, r"^STATE_COLUMNS(:|$)"):
                        UniversalConnectionLedger(
                            stored, stored_declaration,
                            signing_key=b"synthetic-reference-signing-key",
                            clock=copy.deepcopy(base_fixture.clock),
                            state_path=path,
                        ).ledger_head(ROLE_ARCHITECT)

            # The five columns and no KEY, which the names alone did not ask for. A create
            # does nothing when a table of the name is already there and retrofits no
            # constraint, so such a table passed the column guard and was written into -
            # and this store's key is the table itself, being WITHOUT ROWID. Measured on
            # the outbox, the same question one module over: without its key two rows
            # sharing the identifiers lived in the table and the reader answered with
            # whichever came first.
            keyless = Path(temporary) / "without-key.sqlite"
            with closing(sqlite3.connect(keyless)) as connection:
                connection.execute(
                    "CREATE TABLE ledger_state (" + ", ".join(state_columns) + ")")
                connection.commit()
            with self.subTest(member="state table without its primary key"):
                cases += 1
                with self.assertRaisesRegex(
                        IntegrityViolation, r"^STATE_COLUMNS: primary key absent$"):
                    UniversalConnectionLedger(
                        stored, stored_declaration,
                        signing_key=b"synthetic-reference-signing-key",
                        clock=copy.deepcopy(base_fixture.clock),
                        state_path=keyless,
                    ).ledger_head(ROLE_ARCHITECT)

            # The table gone entirely, which is a third fact under the same code. The store
            # opens a connection per operation - `read` and `begin_immediate` both do - so a
            # database deleted between calls is recreated empty by the driver and its table
            # is simply not there. `PRAGMA table_xinfo` answers that with no rows, which used
            # to read as every declared column missing: a detail describing a malformed
            # table where there was none.
            vanishing_path = Path(temporary) / "vanishing.sqlite"
            shutil.copyfile(pristine_path, vanishing_path)
            vanished_reader = UniversalConnectionLedger(
                stored, stored_declaration,
                signing_key=b"synthetic-reference-signing-key",
                clock=copy.deepcopy(base_fixture.clock),
                state_path=vanishing_path,
            )
            vanishing_path.unlink()
            with self.subTest(member="state database lost its table"):
                cases += 1
                with self.assertRaisesRegex(IntegrityViolation, r"^STATE_COLUMNS: table absent$"):
                    vanished_reader.ledger_head(ROLE_ARCHITECT)

            # The other direction of the same class: a table carrying every column the store
            # names plus one it does not. Nothing is missing, so the one-directional check
            # passed. The outbox's reason does not apply here - that decoder builds its record
            # from `SELECT *`, while this store names its four columns and never returns an
            # undeclared one. What the refusal buys is that a table this store did not create
            # is refused as such, instead of being written into.
            widened_path = Path(temporary) / "with-undeclared-column.sqlite"
            widened = list(state_columns) + ["undeclared_column"]
            with closing(sqlite3.connect(widened_path)) as connection:
                connection.execute(
                    "CREATE TABLE ledger_state (" + ", ".join(widened)
                    + ", PRIMARY KEY (declaration_hash))"
                )
                connection.execute(
                    "INSERT INTO ledger_state (" + ", ".join(widened) + ") VALUES ("
                    + ", ".join("?" for _ in widened) + ")",
                    [pristine[name] for name in state_columns] + ["carried"],
                )
                connection.commit()
            with self.subTest(member="state table with a column the store does not declare"):
                cases += 1
                with self.assertRaisesRegex(IntegrityViolation, r"^STATE_COLUMNS(:|$)"):
                    UniversalConnectionLedger(
                        stored, stored_declaration,
                        signing_key=b"synthetic-reference-signing-key",
                        clock=copy.deepcopy(base_fixture.clock),
                        state_path=widened_path,
                    ).ledger_head(ROLE_ARCHITECT)

            # The file itself, which is the same class one layer below the table: a stored
            # artefact that is not this store's, refused by name when the store is opened
            # rather than escaping as a driver error. Two forms, because the driver
            # distinguishes them and the refusal must not collapse them into one word.
            #
            # Which statement refuses each was measured rather than assumed, and it is not
            # the one the shape suggests: the foreign bytes raise at `PRAGMA
            # schema_version`, the corrupt schema page at `PRAGMA synchronous=FULL`, both
            # inside the four-statement prologue of `_connect`. Neither reaches the guard
            # on the create, which on this store is shadowed by that prologue and says so
            # where it stands. So what this pair pins is the prologue, and that no public
            # path takes such a file - not the construction guard.
            #
            # The three cases above are about a TABLE the store did not create; these two
            # are about a FILE that is not a database at all, which is why they are here
            # and not covered by them.
            foreign_path = Path(temporary) / "foreign-bytes.sqlite"
            foreign_path.write_bytes(b"this is not a database at all" * 40)
            with self.subTest(member="state path holding foreign bytes"):
                cases += 1
                with self.assertRaisesRegex(
                        IntegrityViolation, r"^STATE_COLUMNS: not a database$"):
                    UniversalConnectionLedger(
                        stored, stored_declaration,
                        signing_key=b"synthetic-reference-signing-key",
                        clock=copy.deepcopy(base_fixture.clock),
                        state_path=foreign_path,
                    )

            corrupt_schema_path = Path(temporary) / "corrupt-schema-page.sqlite"
            with closing(sqlite3.connect(corrupt_schema_path)) as connection:
                connection.execute("CREATE TABLE unrelated (a TEXT, b TEXT, c TEXT)")
                connection.execute("INSERT INTO unrelated VALUES ('x', 'y', 'z')")
                connection.commit()
            raw = bytearray(corrupt_schema_path.read_bytes())
            # The first hundred bytes are the header the read checks; everything after it
            # to the end of the first page is the schema. Overwriting only the latter is
            # what makes the header pass and the schema statement fail.
            for offset in range(100, min(len(raw), 512)):
                raw[offset] = 0xFF
            corrupt_schema_path.write_bytes(bytes(raw))
            with self.subTest(member="state path with a valid header over a corrupt schema page"):
                cases += 1
                with self.assertRaisesRegex(
                        IntegrityViolation, r"^STATE_COLUMNS: malformed database$"):
                    UniversalConnectionLedger(
                        stored, stored_declaration,
                        signing_key=b"synthetic-reference-signing-key",
                        clock=copy.deepcopy(base_fixture.clock),
                        state_path=corrupt_schema_path,
                    )

            # The control the pair needs: an untouched path still constructs. Without it
            # the two above are satisfied by a guard that refuses every file it is given.
            intact_path = Path(temporary) / "intact-new-state.sqlite"
            with self.subTest(member="an intact state path still constructs"):
                cases += 1
                UniversalConnectionLedger(
                    stored, stored_declaration,
                    signing_key=b"synthetic-reference-signing-key",
                    clock=copy.deepcopy(base_fixture.clock),
                    state_path=intact_path,
                )

            # Past the schema, into the rows. Both statements that read a stored table's
            # SHAPE are guarded - the header read and the column read - and a file can be
            # whole in both and broken where the rows are. Measured: overwriting the
            # SECOND page leaves `PRAGMA schema_version` and `PRAGMA table_xinfo` passing
            # and the row read raising `database disk image is malformed`, which left the
            # ENGINE raw until its row guard existed - this file is where that is pinned,
            # not where it happened.
            rows_path = Path(temporary) / "corrupt-row-page.sqlite"
            with closing(sqlite3.connect(rows_path)) as connection:
                connection.execute(
                    "CREATE TABLE ledger_state ("
                    + ", ".join(state_columns)
                    + ", PRIMARY KEY (declaration_hash))"
                )
                connection.execute(
                    "INSERT INTO ledger_state (" + ", ".join(state_columns) + ") VALUES ("
                    + ", ".join("?" for _ in state_columns) + ")",
                    [pristine[name] for name in state_columns],
                )
                connection.commit()
            raw_pages = bytearray(rows_path.read_bytes())
            page_size = int.from_bytes(raw_pages[16:18], "big") or 65536
            self.assertGreaterEqual(
                len(raw_pages), 2 * page_size,
                "the fixture has no second page, so there is no row page to corrupt")
            for offset in range(page_size + 8, min(len(raw_pages), 2 * page_size)):
                raw_pages[offset] = 0xFF
            rows_path.write_bytes(bytes(raw_pages))
            with closing(sqlite3.connect(rows_path)) as probe:
                probe.execute("PRAGMA schema_version").fetchone()
                probe.execute("PRAGMA table_xinfo(ledger_state)").fetchall()
            with self.subTest(member="state database with a corrupt row page"):
                cases += 1
                with self.assertRaisesRegex(
                        IntegrityViolation, r"^STATE_COLUMNS: malformed database$"):
                    UniversalConnectionLedger(
                        stored, stored_declaration,
                        signing_key=b"synthetic-reference-signing-key",
                        clock=copy.deepcopy(base_fixture.clock),
                        state_path=rows_path,
                    ).ledger_head(ROLE_ARCHITECT)

            # The other half of the same layer: a table this store did not declare, which
            # the NAME guard admits on purpose - it compares names so the sweep above can
            # build a typeless table and drive every storage class - and which fails the
            # first WRITE. This store writes all five of its columns and upserts on its own
            # key, so it cannot violate its own declaration; a constraint that fires is one
            # the stored table carries. Driven through the store rather than the engine
            # because the engine's write path needs a whole admitted operation, while what
            # is claimed here is the store's guard; the read half is pinned above.
            constrained_path = Path(temporary) / "state-foreign-constraint.sqlite"
            with closing(sqlite3.connect(constrained_path)) as connection:
                connection.execute(
                    "CREATE TABLE ledger_state ("
                    + ", ".join(state_columns)
                    + ", PRIMARY KEY (declaration_hash)"
                    + ", CHECK (length(state_json) < 10))"
                )
                connection.commit()
            with self.subTest(member="state table with a constraint the store did not declare"):
                cases += 1
                store = SQLiteStateStore(constrained_path)
                connection = store.begin_immediate()
                try:
                    with self.assertRaisesRegex(
                            IntegrityViolation,
                            r"^STATE_COLUMNS: constraint not declared by this store$"):
                        store.save(
                            connection,
                            pristine["declaration_hash"],
                            pristine["profile_hash"],
                            b"synthetic-reference-signing-key",
                            {"anything": "longer than ten characters"},
                        )
                finally:
                    connection.close()
            # And its control, on a table the store itself declared: the same write must
            # go through, or the case above is satisfied by a store that cannot write at all.
            with self.subTest(member="the same write on the store's own declaration"):
                cases += 1
                own_path = Path(temporary) / "state-own-declaration.sqlite"
                store = SQLiteStateStore(own_path)
                connection = store.begin_immediate()
                try:
                    store.save(
                        connection,
                        pristine["declaration_hash"],
                        pristine["profile_hash"],
                        b"synthetic-reference-signing-key",
                        {"anything": "longer than ten characters"},
                    )
                    connection.commit()
                finally:
                    connection.close()

        # Stored event fields read by verify(): every field the stored event
        # carries and every field of its signature envelope, taken from the
        # event itself rather than from a list here, with every non-text and
        # non-ASCII form. The three fields verify() compares directly are
        # pinned: it answers False, and a public read turns that into the
        # chain refusal.
        canonical_refusals = 0
        sample_engine, _intent, _grant = base_fixture.engine()
        sample_event = sample_engine.ledger._events[-1]
        event_places = [(field,) for field in sample_event] + [
            ("signature", field) for field in sample_event["signature"]
        ]
        self.assertIn(("event_hash",), event_places)
        for place in event_places:
            for label, value in (
                ("non-ASCII text", "é" * 64),
                # The loop plants this value in every field of the event and of
                # its signature envelope. Negative for the sake of one of them:
                # the pinned event_index case, where a positive integer could be
                # a legal index and this cannot. Elsewhere it is simply a
                # non-string, which is what those places are being asked about.
                ("integer", -7),
                ("null", None),
                ("bytes", b"x" * 64),
                ("list", []),
                # The third exit verify() names in its docstring - a value that
                # cannot be canonicalised at all - was claimed to be covered here
                # and was not: none of the forms above can reach it. A non-finite
                # number can, wherever the field is one canonical_json walks.
                ("non-finite number", float("nan")),
                # A mapping whose KEY is not text - the third exit the verifier's
                # docstring names, and the one this list did not have while that
                # sentence said it did. `canonical_json` re-raises a
                # ContractViolation untouched, so what leaves is the walk's own
                # JSON_OBJECT_KEY_TYPE rather than CANONICAL_JSON_INVALID; in a
                # field that is not walked it is simply a non-string, like the
                # forms above.
                ("mapping with a non-text key", {1: "x"}),
                # Deeper than the deep copy verify() used to take of every body
                # field before walking it. That copy ran ahead of the guard, so
                # this form left as a bare RecursionError - measured, through
                # verify() and through the public read - while the walk refuses a
                # structure past MAX_NESTING_DEPTH by its own code. The list held
                # `[]` and nothing deeper, so nothing in it could reach that band.
                ("structure past the recursion limit", _nested_list(600)),
            ):
                engine, _intent, _grant = base_fixture.engine()
                node(engine.ledger._events[-1], place[:-1])[place[-1]] = value
                cases += 1
                try:
                    verdict = engine.ledger.verify()
                except ContractViolation as refusal:
                    if refusal.code == "CANONICAL_JSON_INVALID":
                        canonical_refusals += 1
                    continue
                except Exception as exc:  # noqa: BLE001 - the class under test
                    escapes.append(f"verify() {'/'.join(place)} <- {label}: {type(exc).__name__}")
                    continue
                if place in (("event_hash",), ("previous_event_hash",), ("event_index",)):
                    with self.subTest(member=f"{label} in stored {place[0]}"):
                        self.assertIs(verdict, False)
                        with self.assertRaisesRegex(IntegrityViolation, r"^LEDGER_CHAIN_FAILURE(:|$)"):
                            engine.ledger_head(ROLE_ARCHITECT)

        # The three canonicalisation exits verify() names, pinned by NAME. The sweep
        # above drives all three forms and cannot tell them apart - it records what
        # ESCAPES the vocabulary, and each of these is a ContractViolation, so it is
        # green whichever code is raised. The docstring's claim is precisely that they
        # differ, so the claim needs a check that fails when they stop differing.
        for label, value, code in (
            ("non-finite number", float("nan"), "CANONICAL_JSON_INVALID"),
            ("mapping with a non-text key", {1: "x"}, "JSON_OBJECT_KEY_TYPE"),
            ("structure past the limit", _nested_list(600), "NESTING_DEPTH_EXCEEDED"),
        ):
            with self.subTest(member="verify() exit for %s" % label):
                cases += 1
                engine, _intent, _grant = base_fixture.engine()
                engine.ledger._events[-1]["payload"] = value
                with self.assertRaises(ContractViolation) as caught:
                    engine.ledger.verify()
                self.assertEqual(
                    caught.exception.code, code,
                    "%s must leave verify() under %s" % (label, code))
        # A control beside them: an untouched chain still verifies, or the three rows
        # above are satisfied by a verifier that refuses everything.
        with self.subTest(member="an untouched chain still verifies"):
            cases += 1
            engine, _intent, _grant = base_fixture.engine()
            self.assertIs(engine.ledger.verify(), True)

        # A sweep that reached nothing would report no escapes too. Every body
        # route must have been driven through leaves and objects, and the
        # total must be of the order the fixtures give (thousands of places).
        self.assertEqual(
            reached, {route[0] for route in body_routes},
            "the sweep did not reach every body route",
        )
        self.assertGreater(cases, 1000, "the sweep reached fewer places than it names")
        # The docstring of verify() says this sweep catches the canonicalisation refusal
        # beside the integrity one. It said so while no planted form could reach it; the
        # non-finite number was added for that, and this is what keeps the sentence true
        # if the form is ever dropped again.
        self.assertGreater(
            canonical_refusals, 0,
            "no planted value reached CANONICAL_JSON_INVALID - verify()'s third exit is unswept",
        )
        self.assertEqual(escapes, [], f"{len(escapes)} of {cases} values left the vocabulary")

    def test_authority_repeats_are_idempotent_and_expiry_is_refused_at_issue(
        self,
    ) -> None:
        # Repeat semantics on the authority surface, pinned on the engine.
        # A repeated revocation used to append a second AUTHORITY_REVOKED
        # event on every retry and, through the release it triggers, rewrite
        # the reason a permit had already been invalidated for. A grant whose
        # window had already closed was accepted at issue and entered the
        # chain as an authority that was never live.
        fixture = self.fixture()

        def revocation(engine, grant, revoked_at="2026-08-01T10:00:01Z"):
            return {
                "message_type": "authority_revocation",
                "grant_id": grant["grant_id"],
                "declaration_hash": engine.declaration_hash,
                "revoked_at": revoked_at,
                "revoked_by": fixture.fx.authority_issuer,
                "reason_code": "SYNTHETIC_REVOCATION",
                "evidence_ref": "evidence://synthetic/revocation/repeat",
            }

        with self.subTest(claim="a repeated revocation records nothing"):
            engine, _intent, grant = fixture.engine()
            engine.revoke_grant(revocation(engine, grant), actor_scope=ROLE_GOVERNANCE)
            after_first = engine.ledger.head()["event_count"]
            engine.revoke_grant(revocation(engine, grant), actor_scope=ROLE_GOVERNANCE)
            self.assertEqual(engine.ledger.head()["event_count"], after_first)
            self.assertIn(grant["grant_id"], engine.revoked_grants)

        with self.subTest(claim="a malformed repeat is still refused"):
            engine, _intent, grant = fixture.engine()
            engine.revoke_grant(revocation(engine, grant), actor_scope=ROLE_GOVERNANCE)
            malformed = revocation(engine, grant)
            malformed["revoked_by"] = "nobody"
            with self.assertRaisesRegex(
                ContractViolation, r"^REVOCATION_ACTOR_UNAUTHORIZED(:|$)"
            ):
                engine.revoke_grant(malformed, actor_scope=ROLE_GOVERNANCE)

        with self.subTest(claim="an expired permit keeps its own reason"):
            engine, intent, grant = fixture.engine()
            result = self.allow_permit(fixture, engine, intent)
            record = engine.permits[result["permit_hash"]]
            # Past the permit's TTL, so the purge invalidates it as expired.
            fixture.clock.advance(seconds=600)
            engine._purge_expired_reservations(engine._now())
            self.assertEqual(record.invalidated_reason, "PERMIT_EXPIRED")
            engine.revoke_grant(
                revocation(engine, grant, "2026-08-01T10:10:00Z"),
                actor_scope=ROLE_GOVERNANCE,
            )
            self.assertEqual(
                record.invalidated_reason,
                "PERMIT_EXPIRED",
                "revocation rewrote the reason of an already-invalidated permit",
            )

        with self.subTest(claim="a live permit is still killed by revocation"):
            engine, intent, grant = fixture.engine()
            result = self.allow_permit(fixture, engine, intent)
            engine.revoke_grant(revocation(engine, grant), actor_scope=ROLE_GOVERNANCE)
            self.assertEqual(
                engine.permits[result["permit_hash"]].invalidated_reason,
                "AUTHORITY_REVOKED",
            )

        with self.subTest(claim="a closed window is refused at issue"):
            engine, _intent, grant = fixture.engine()
            for label, valid_until in (
                ("closed an hour ago", "2026-08-01T09:00:00Z"),
                ("closing exactly now", "2026-08-01T10:00:00Z"),
            ):
                closed = copy.deepcopy(grant)
                closed["grant_id"] = f"synthetic-grant-{label.split()[0]}"
                closed["valid_from"] = "2026-07-01T00:00:00Z"
                closed["valid_until"] = valid_until
                with self.assertRaisesRegex(
                    ContractViolation, r"^AUTHORITY_EXPIRED(:|$)"
                ):
                    engine.issue_grant(closed, actor_scope=ROLE_GOVERNANCE)
            granted = [
                event
                for event in engine.ledger.events_copy()
                if event["event_type"] == "AUTHORITY_GRANTED"
            ]
            self.assertEqual(len(granted), 1, "a dead grant reached the chain")

        with self.subTest(claim="a future window is still issued"):
            engine, _intent, grant = fixture.engine()
            future = copy.deepcopy(grant)
            future["grant_id"] = "synthetic-grant-future"
            future["valid_from"] = "2027-01-01T00:00:00Z"
            future["valid_until"] = "2027-02-01T00:00:00Z"
            self.assertTrue(engine.issue_grant(future, actor_scope=ROLE_GOVERNANCE))

        with self.subTest(claim="an identical re-issue is a replay"):
            engine, _intent, grant = fixture.engine()
            before = engine.ledger.head()["event_count"]
            self.assertEqual(
                engine.issue_grant(copy.deepcopy(grant), actor_scope=ROLE_GOVERNANCE),
                sha256_hex(grant),
            )
            self.assertEqual(engine.ledger.head()["event_count"], before)

        # Each sample violates one public authority condition. Equality to the
        # specific code witnesses the engine refusal, not only its HTTP copy.
        grant_cases = (
            ("AUTHORITY_GRANT_FIELDS", "extra_field", True),
            ("AUTHORITY_MESSAGE_TYPE", "message_type", "not_authority_grant"),
            ("AUTHORITY_IDENTIFIER", "grant_id", []),
            ("AUTHORITY_CONNECTOR_MISMATCH", "connector_id", "synthetic-other"),
            ("AUTHORITY_BINDING_MISMATCH", "binding", {}),
            ("AUTHORITY_ACTIONS", "permitted_action_ids", []),
            ("AUTHORITY_TARGETS", "target_system_ids", []),
            ("AUTHORITY_ACTION_SCOPE", "permitted_action_ids", ["synthetic-other"]),
            ("AUTHORITY_TARGET_SCOPE", "target_system_ids", ["synthetic-other"]),
            ("AUTHORITY_ISSUER_MISMATCH", "issued_by", "synthetic-other"),
            ("AUTHORITY_TIME_ORDER", "valid_from", "2099-01-01T00:00:00Z"),
            ("AUTHORITY_ID_CONFLICT", "approval_evidence_ref", "evidence://synthetic/changed"),
        )
        revoke_cases = (
            ("REVOCATION_FIELDS", "extra_field", True),
            ("REVOCATION_MESSAGE_TYPE", "message_type", "not_authority_revocation"),
            ("REVOCATION_GRANT_ID", "grant_id", []),
            ("REVOCATION_DECLARATION_HASH", "declaration_hash", "not-a-digest"),
            ("REVOCATION_DECLARATION_MISMATCH", "declaration_hash", "F" * 64),
            ("REVOCATION_ACTOR", "revoked_by", []),
            ("REVOCATION_REASON", "reason_code", ""),
        )
        for operation, cases in (("issue", grant_cases), ("revoke", revoke_cases)):
            for code, field, value in cases:
                with self.subTest(authority_refusal=code):
                    engine, _intent, grant = fixture.engine()
                    valid = copy.deepcopy(grant) if operation == "issue" else revocation(engine, grant)
                    malformed = copy.deepcopy(valid)
                    malformed[field] = copy.deepcopy(value)
                    before = (engine.ledger.events_copy(), copy.deepcopy(engine.grants), set(engine.revoked_grants))
                    call = engine.issue_grant if operation == "issue" else engine.revoke_grant
                    with self.assertRaises(ContractViolation) as refused:
                        call(malformed, actor_scope=ROLE_GOVERNANCE)
                    self.assertEqual(refused.exception.code, code)
                    self.assertEqual(
                        (engine.ledger.events_copy(), engine.grants, engine.revoked_grants), before,
                        "an authority refusal changed the ledger or grant state",
                    )
                    # Same path with the one defect removed must still work.
                    call(valid, actor_scope=ROLE_GOVERNANCE)
                    if operation == "revoke":
                        self.assertIn(grant["grant_id"], engine.revoked_grants)
                    else:
                        self.assertEqual(engine.grants[grant["grant_id"]], grant)

        from nc25_universal_adapter import UniversalConnectionHttpAdapter

        def wire_issue(engine, grant):
            raw = json.dumps(grant).encode("utf-8")
            statuses = []
            response = b"".join(UniversalConnectionHttpAdapter(engine)({
                "REQUEST_METHOD": "POST", "PATH_INFO": "/v1/authority-grants",
                "HTTP_X_WORKLOAD_SCOPE": ROLE_GOVERNANCE,
                "CONTENT_LENGTH": str(len(raw)), "wsgi.input": io.BytesIO(raw),
            }, lambda status, headers: statuses.append(status)))
            return statuses[0], json.loads(response)

        with self.subTest(claim="malformed grant IDs are client errors, not service failures"):
            engine, _intent, grant = fixture.engine()
            for value in ([], {}, ["id"], None, True, 5):
                with self.subTest(grant_id=value):
                    malformed = copy.deepcopy(grant)
                    malformed["grant_id"] = value
                    status, response = wire_issue(engine, malformed)
                    self.assertEqual(status, "400 Bad Request")
                    self.assertEqual(response["code"], "AUTHORITY_IDENTIFIER")
            self.assertEqual(wire_issue(engine, grant)[0], "200 OK")

        with self.subTest(claim="grant replay status comes from the durable transaction"):
            profile, declaration, grant, _intent = bind_fixture(
                fixture.profile, fixture.declaration, fixture.grant, fixture.intent
            )
            with tempfile.TemporaryDirectory() as temporary:
                def build():
                    return UniversalConnectionLedger(
                        profile, declaration,
                        signing_key=b"synthetic-reference-signing-key", clock=fixture.clock,
                        state_path=Path(temporary) / "state.sqlite",
                    )
                first = build()
                first.activate(fixture.fx.approval_owner,
                    "evidence://synthetic/activation", actor_scope=ROLE_GOVERNANCE)
                second = build()
                self.assertNotIn(grant["grant_id"], second.grants)
                status, issued = wire_issue(first, grant)
                self.assertEqual(status, "201 Created")
                before = first.ledger.head()
                status, replay = wire_issue(second, grant)
                self.assertEqual(status, "200 OK")
                self.assertEqual(replay, issued)
                self.assertEqual(second.ledger.head(), before)
                self.assertEqual(second.issue_grant(grant, actor_scope=ROLE_GOVERNANCE),
                    issued["grant_hash"])

    def test_permit_ttl_seconds_is_the_effective_lifetime(self) -> None:
        # The sealed ttl_seconds used to be the CONFIGURED nominal even when
        # expires_at was capped by the grant or the declaration, so a reader
        # of one signed permit computing issued_at + ttl_seconds could land
        # three hundred seconds past the real expiry. It is now the effective
        # lifetime: issued_at + ttl_seconds == expires_at, to the second.
        fixture = self.fixture()

        def issued(grant_valid_until: str | None = None):
            grant = copy.deepcopy(fixture.grant)
            if grant_valid_until is not None:
                grant["valid_until"] = grant_valid_until
            engine, intent, _grant = fixture.engine(grant=grant)
            result = self.allow_permit(fixture, engine, intent)
            body = engine.permits[result["permit_hash"]].body
            issued_at = datetime.fromisoformat(body["issued_at"].replace("Z", "+00:00"))
            expires_at = datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00"))
            return body, issued_at, expires_at

        with self.subTest(case="capped by the grant"):
            body, issued_at, expires_at = issued("2026-08-01T10:01:00Z")
            self.assertEqual(body["ttl_seconds"], 60)
            self.assertEqual(issued_at + timedelta(seconds=body["ttl_seconds"]), expires_at)

        with self.subTest(case="not capped"):
            body, issued_at, expires_at = issued()
            self.assertEqual(body["ttl_seconds"], 300)
            self.assertEqual(issued_at + timedelta(seconds=300), expires_at)

        with self.subTest(case="sub-second remainder rounds up to one"):
            body, issued_at, expires_at = issued("2026-08-01T10:00:00.500000Z")
            self.assertEqual(body["ttl_seconds"], 1)
            # Equality holds to the second, as documented: the cap keeps its
            # fraction, the integer field cannot.
            self.assertLessEqual(expires_at, issued_at + timedelta(seconds=1))
            self.assertGreater(expires_at, issued_at)

    def test_three_refusal_worlds_are_pairwise_disjoint(self) -> None:
        import failure_surface
        from unittest.mock import patch
        # Mutate both the published name and its raise sites. A one-sided
        # edit would test declaration consistency instead of world separation.
        with tempfile.TemporaryDirectory() as temporary:
            paths = {}
            originals = {}
            for name in ("ENGINE_PATH", "ADAPTER_PATH", "BRIDGE_PATH"):
                source = getattr(failure_surface, name)
                paths[name] = Path(temporary) / "sdk" / "python" / source.name
                paths[name].parent.mkdir(parents=True, exist_ok=True)
                originals[name] = source.read_bytes()
                paths[name].write_bytes(originals[name])
            with patch.multiple(failure_surface, ROOT=Path(temporary), **paths):
                self.assertEqual(failure_surface.static_snapshot()[1], [], "WORLDS_CONTROL")
                for name, old, new, pair in (
                    ("BRIDGE_PATH", "OTCS_HASH_PROFILE", "PROFILE_SCHEMA_VERSION", "engine&bridge"),
                    ("BRIDGE_PATH", "OTCS_HASH_PROFILE", "BODY_JSON", "wire&bridge"),
                    ("ADAPTER_PATH", "BODY_JSON", "PROFILE_SCHEMA_VERSION", "engine&wire"),
                ):
                    with self.subTest(pair=pair):
                        text = originals[name].decode("utf-8")
                        self.assertIn('"' + old + '"', text)
                        try:
                            paths[name].write_text(text.replace('"' + old + '"', '"' + new + '"'), encoding="utf-8")
                            self.assertEqual(
                                failure_surface.static_snapshot()[1],
                                [f"CLOSED_WORLDS_NOT_DISJOINT {pair} ['{new}']"],
                                "WORLDS_" + pair,
                            )
                        finally:
                            paths[name].write_bytes(originals[name])
                self.assertEqual(failure_surface.static_snapshot()[1], [], "WORLDS_RESTORED")

    def test_acceptance_step_names_bind_the_executed_files(self) -> None:
        from run_acceptance import STEPS, validate_step_manifest
        validate_step_manifest(STEPS)
        for i, row in enumerate(STEPS):
            with self.subTest(step=row[0]):
                changed = list(STEPS)
                changed[i] = (row[0], STEPS[(i + 1) % len(STEPS)][1], *row[2:])
                with self.assertRaisesRegex(AssertionError, "^ACCEPTANCE_STEP_MANIFEST "):
                    validate_step_manifest(changed)
        with self.assertRaisesRegex(AssertionError, "^ACCEPTANCE_STEP_MANIFEST "):
            validate_step_manifest(STEPS[:-1])
        with self.assertRaisesRegex(AssertionError, "^ACCEPTANCE_STEP_MANIFEST "):
            validate_step_manifest(tuple(reversed(STEPS)))
        validate_step_manifest(STEPS)

    def test_regeneration_names_every_closed_world_shrink(self) -> None:
        # The guard that makes --write-baseline a ratchet rather than a
        # convention. It named a lost witness, a lost constructed code, a
        # shrunk engine vocabulary and grown debt - and let the architect
        # vocabulary shrink in silence: measured, a regeneration wrote the
        # smaller vocabulary with exit 0. Each closed world is a row here, so
        # a world the guard forgets reddens by name.
        import failure_surface

        baseline = {
            "engine_refusal_codes": ["E1", "E2"],
            "architect_decision_codes": ["A1", "A2"],
            "wire_error_codes": ["W1", "W2"],
            "bridge_refusal_codes": ["B1", "B2"],
            "runtime": {
                "witnessed_codes": ["E1"],
                "constructed_engine_codes": ["E1", "E2"],
                "unwitnessed_codes": ["E2"],
                "constructed_bridge_codes": ["B1", "B2"],
                "witnessed_bridge_codes": ["B1"],
                "unwitnessed_bridge_codes": ["B2"],
            },
        }

        def regenerated(**changes):
            current = copy.deepcopy(baseline)
            for key, value in changes.items():
                if key in current["runtime"]:
                    current["runtime"][key] = value
                else:
                    current[key] = value
            return failure_surface.regeneration_regressions(baseline, current)

        with self.subTest(world="nothing changes"):
            self.assertEqual(regenerated(), [])
        with self.subTest(world="every world grows"):
            self.assertEqual(
                regenerated(
                    engine_refusal_codes=["E1", "E2", "E3"],
                    architect_decision_codes=["A1", "A2", "A3"],
                    wire_error_codes=["W1", "W2", "W3"],
                    bridge_refusal_codes=["B1", "B2", "B3"],
                    constructed_bridge_codes=["B1", "B2", "B3"],
                    witnessed_bridge_codes=["B1", "B2"],
                    unwitnessed_bridge_codes=[],
                    witnessed_codes=["E1", "E2"],
                    unwitnessed_codes=[],
                ),
                [],
                "growth must never cost an acknowledgement",
            )
        for world, key, shrunk in (
            ("engine vocabulary", "engine_refusal_codes", ["E1"]),
            ("architect vocabulary", "architect_decision_codes", ["A1"]),
            ("wire vocabulary", "wire_error_codes", ["W1"]),
            ("bridge vocabulary", "bridge_refusal_codes", ["B1"]),
            ("bridge constructions", "constructed_bridge_codes", ["B1"]),
            ("bridge witnesses", "witnessed_bridge_codes", []),
            ("witnessed set", "witnessed_codes", []),
            ("constructed set", "constructed_engine_codes", ["E1"]),
        ):
            with self.subTest(world=world):
                losses = regenerated(**{key: shrunk})
                self.assertEqual(len(losses), 1, losses)
                self.assertTrue(losses[0].startswith(f"REGENERATION_LOSES:{key} "), losses)
        with self.subTest(world="debt grows"):
            self.assertEqual(
                regenerated(unwitnessed_codes=["E2", "E1"]),
                ["REGENERATION_GROWS_DEBT ['E1']"],
            )

        with self.subTest(world="bridge debt grows"):
            self.assertEqual(
                regenerated(unwitnessed_bridge_codes=["B2", "B1"]),
                ["REGENERATION_GROWS_BRIDGE_DEBT ['B1']"],
            )

    def test_wrong_typed_values_refuse_with_their_declared_code(self) -> None:
        # A CLASS sweep, not two tests for two fixes. The package's central
        # claim is that every refusal is a code from a published vocabulary,
        # and a value of the wrong TYPE used to leave that vocabulary
        # altogether: `.replace` on a non-string timestamp raised
        # AttributeError, and testing an unhashable value for set membership
        # raised TypeError. Both reached the caller as a bare Python exception
        # carrying no code at all - over the wire, as an unhandled fault.
        #
        # Rows are split by how the value arrives. The two validators run
        # before anything is built, so they are reachable by construction and
        # share one fixture; the rest travel a public engine call and each
        # builds its own, because several of these calls append to the chain
        # before refusing and a shared engine would let one row's state decide
        # another row's answer.
        fixture = self.fixture()
        wrong_types = (1234, None, [], {})

        # Membership checks must refuse JSON containers before hashing them.
        validate_profile(fixture.profile)
        validate_declaration(fixture.declaration, fixture.profile)
        profile_cases = (
            (("resource_catalog", 0, "claim_rule"), "RESOURCE_CLAIM_RULE"),
            (("action_alphabet", 0, "effect_class_id"), "UNKNOWN_EFFECT_CLASS"),
            (("roles", "forbidden_operator_fields", 0), "FORBIDDEN_OPERATOR_FIELDS"),
            (("registry_policy", "forbidden_fields", 0), "REGISTRY_FORBIDDEN_COVERAGE"),
        )
        for path, code in profile_cases:
            for value in ([], {}):
                with self.subTest(document="profile", path=path, value=value):
                    broken = copy.deepcopy(fixture.profile)
                    container = broken
                    for part in path[:-1]:
                        container = container[part]
                    container[path[-1]] = value
                    with self.assertRaisesRegex(ContractViolation, rf"^{code}(:|$)"):
                        validate_profile(broken)
        for value in ([], {}):
            with self.subTest(document="declaration", provenance=value):
                broken = copy.deepcopy(fixture.declaration)
                broken["structural_budget"]["provenance"] = value
                with self.assertRaisesRegex(ContractViolation, r"^STRUCTURAL_PROVENANCE(:|$)"):
                    validate_declaration(broken, fixture.profile)
            with self.subTest(document="state", status=value):
                engine, _intent, _grant = fixture.engine()
                state = engine._snapshot_state()
                state["status"] = value
                with self.assertRaisesRegex(IntegrityViolation, r"^STATE_STATUS(:|$)"):
                    engine._restore_state(state)
            with self.subTest(document="registry", status=value):
                engine, _intent, _grant = fixture.engine()
                record = engine.registry_record(engine.declaration["connector"]["connector_id"],
                    actor_scope=ROLE_ARCHITECT)
                record["status"] = value
                with self.assertRaisesRegex(IntegrityViolation, r"^REGISTRY_PROJECTION_INVALID(:|$)") as caught:
                    engine._assert_registry_projection(record)
                self.assertIsInstance(caught.exception.__cause__, ContractViolation)
                self.assertEqual(caught.exception.__cause__.code, "REGISTRY_STATUS")


        for value in wrong_types:
            with self.subTest(document="profile", value=repr(value)):
                broken = copy.deepcopy(fixture.profile)
                broken["created_at"] = value
                with self.assertRaisesRegex(
                    ContractViolation, r"^INVALID_TIMESTAMP(:|$)"
                ):
                    validate_profile(broken)

        for field, value in (
            ("created_at", []),
            ("effective_from", {}),
            ("expires_at", 1234),
        ):
            with self.subTest(document="declaration", field=field):
                broken = copy.deepcopy(fixture.declaration)
                broken[field] = value
                with self.assertRaisesRegex(
                    ContractViolation, r"^INVALID_TIMESTAMP(:|$)"
                ):
                    validate_declaration(broken, fixture.profile)

        def issue_a_grant_with(field, value):
            def run():
                local = self.fixture()
                engine, _intent, grant = local.engine()
                broken = copy.deepcopy(grant)
                broken[field] = value
                # A fresh identifier, so the row is refused for its corrupted
                # field rather than for repeating a grant already on the chain.
                broken["grant_id"] = "synthetic-grant-wrong-typed"
                engine.issue_grant(broken, actor_scope=ROLE_GOVERNANCE)

            return run

        def revoke_at(value):
            def run():
                local = self.fixture()
                engine, _intent, grant = local.engine()
                engine.revoke_grant(
                    {
                        "message_type": "authority_revocation",
                        "grant_id": grant["grant_id"],
                        "declaration_hash": engine.declaration_hash,
                        "revoked_at": value,
                        "revoked_by": local.fx.authority_issuer,
                        "reason_code": "SYNTHETIC_REVOCATION",
                        "evidence_ref": "evidence://synthetic/revocation/typed",
                    },
                    actor_scope=ROLE_GOVERNANCE,
                )

            return run

        def evaluate_with_intent_field(field, value):
            def run():
                local = self.fixture()
                engine, intent, _grant = local.engine()
                broken = copy.deepcopy(intent)
                broken[field] = value
                engine.evaluate_intent(
                    broken, local.evidence, actor_scope=ROLE_OPERATOR
                )

            return run

        def evaluate_with_evidence(corrupt):
            def run():
                local = self.fixture()
                engine, intent, _grant = local.engine()
                broken = copy.deepcopy(local.evidence)
                corrupt(broken)
                engine.evaluate_intent(
                    intent, broken, actor_scope=ROLE_OPERATOR
                )

            return run

        def commit_with(field, value):
            def run():
                local = self.fixture()
                engine, intent, _grant = local.engine()
                result = self.allow_permit(local, engine, intent)
                request = local.execution_request(engine, result, intent)
                request[field] = value
                engine.commit_execution(
                    request,
                    actor_scope=ROLE_EXECUTOR,
                    route_permit_hash=result["permit_hash"],
                )

            return run

        def set_first_item_status(value):
            def corrupt(bundle):
                bundle["items"][0]["status"] = value

            return corrupt

        def set_collected_at(value):
            def corrupt(bundle):
                bundle["collected_at"] = value

            return corrupt

        engine_rows = (
            ("grant valid_from is null", issue_a_grant_with("valid_from", None),
             "INVALID_TIMESTAMP"),
            ("grant valid_until is a list", issue_a_grant_with("valid_until", []),
             "INVALID_TIMESTAMP"),
            ("revocation time is a mapping", revoke_at({}),
             "INVALID_TIMESTAMP"),
            ("intent received_at is an int",
             evaluate_with_intent_field("received_at", 1234),
             "INVALID_TIMESTAMP"),
            ("evidence collected_at is a list",
             evaluate_with_evidence(set_collected_at([])),
             "INVALID_TIMESTAMP"),
            ("evidence item status is a list",
             evaluate_with_evidence(set_first_item_status(["VALID"])),
             "EVIDENCE_STATUS"),
            ("committed_at is null", commit_with("committed_at", None),
             "INVALID_TIMESTAMP"),
            ("outcome is a list", commit_with("outcome", ["COMMITTED"]),
             "EXECUTION_OUTCOME"),
        )
        for label, call, code in engine_rows:
            with self.subTest(corruption=label):
                with self.assertRaisesRegex(ContractViolation, rf"^{code}(:|$)"):
                    call()

    def test_scope_binding_coverage_and_range_refuse_separately(self) -> None:
        # Two guards on the same field, one after the other: the key set must
        # equal the selected actions, and every bound target must be one of the
        # declared targets. They are swept together because their ORDER is the
        # fact worth pinning - the range check reads the same mapping the
        # coverage check just accepted, so a coverage guard that admitted a
        # wrong key set would send an unrelated code to the caller.
        #
        # Routed through the validator directly rather than through the engine:
        # both fire during construction, before any state exists, so the
        # fixture-binding machinery would only add cost.
        fixture = self.fixture()

        def drop_a_binding_key(scope):
            del scope["action_target_bindings"]["NO_EFFECT_FALLBACK"]

        def add_a_foreign_binding_key(scope):
            scope["action_target_bindings"]["BANK_PAYMENT_REFUND"] = [
                "bank-sandbox-ledger"
            ]

        def bind_an_undeclared_target(scope):
            # Syntactically a valid identifier, so the id check upstream passes
            # and the range check is the one that must answer.
            scope["action_target_bindings"]["BANK_PAYMENT_POST"] = [
                "bank-sandbox-shadow"
            ]

        def break_both_at_once(scope):
            # The row that makes the ORDER observable: the key set is wrong AND
            # a target is undeclared. Each guard alone would answer; which one
            # does is decided by which runs first. Without this row the two
            # guards can be swapped and every other row still passes - measured,
            # not supposed.
            scope["action_target_bindings"]["BANK_PAYMENT_REFUND"] = [
                "bank-sandbox-shadow"
            ]

        def bind_two_targets_one_undeclared(scope):
            # A list of two, with the undeclared one SECOND: the subset check
            # must read past the first element. Reduced to a first-element
            # check, the engine accepted this and every single-target row here
            # stayed green - measured.
            scope["action_target_bindings"]["BANK_PAYMENT_POST"] = [
                "bank-sandbox-ledger",
                "bank-sandbox-shadow",
            ]

        def bind_the_same_target_twice(scope):
            scope["action_target_bindings"]["BANK_PAYMENT_POST"] = [
                "bank-sandbox-ledger",
                "bank-sandbox-ledger",
            ]

        corruptions = (
            ("binding misses a selected action", drop_a_binding_key,
             "SCOPE_ACTION_TARGET_COVERAGE"),
            ("binding names an unselected action", add_a_foreign_binding_key,
             "SCOPE_ACTION_TARGET_COVERAGE"),
            ("binding names an undeclared target", bind_an_undeclared_target,
             "SCOPE_ACTION_TARGET_RANGE"),
            ("binding lists two targets, the second undeclared",
             bind_two_targets_one_undeclared, "SCOPE_ACTION_TARGET_RANGE"),
            ("binding repeats a target", bind_the_same_target_twice,
             "SCOPE_ACTION_TARGET_IDS"),
            ("both guards violated at once", break_both_at_once,
             "SCOPE_ACTION_TARGET_COVERAGE"),
        )
        for label, corrupt, code in corruptions:
            with self.subTest(corruption=label):
                changed = copy.deepcopy(fixture.declaration)
                corrupt(changed["instance_scope"])
                with self.assertRaisesRegex(ContractViolation, rf"^{code}(:|$)"):
                    validate_declaration(changed, fixture.profile)
        # The control for the two-element rows: two DECLARED targets validate,
        # so the rows above redden on the undeclared one, not on the length.
        accepted = copy.deepcopy(fixture.declaration)
        accepted["instance_scope"]["action_target_bindings"]["BANK_PAYMENT_POST"] = [
            "bank-sandbox-ledger",
            "bank-sandbox-query",
        ]
        validate_declaration(accepted, fixture.profile)

    def test_commit_refuses_an_execution_time_on_either_side_of_the_permit(
        self,
    ) -> None:
        # The permit bounds the execution in time from both directions, and the
        # two bounds are separate guards with separate codes. Only the earlier
        # one was exercised; a regression that dropped the forward bound - or
        # widened the five-second tolerance - left no red anywhere.
        fixture = self.fixture()

        # The fixture clock stands at 10:00:00Z and the permit is issued there.
        # Each row gets its OWN engine and permit: if a break lets one row's
        # commit succeed, a shared permit would be consumed and the next row
        # would answer EXECUTION_REPLAY_CONFLICT - a red that certifies the
        # wrong fact. Measured: that is exactly what a shared engine did.
        # Each bound is pinned from BOTH sides - one second inside the
        # tolerance is accepted, one second outside is refused - because a
        # row an hour away stays green when the tolerance widens from five
        # seconds to an hour, and that mutation was measured green here.
        # The last two rows advance the clock after the permit is issued:
        # a commit at 10:00:10 is accepted only if the lower bound is anchored
        # to the permit's issued_at, and refused if it is anchored to `now`
        # (10:01:40 minus five seconds). With the clock standing still the
        # two anchors are the same instant and cannot be told apart.
        bounds = (
            ("committed far ahead of the clock", "2026-08-01T11:00:00Z", 0,
             "EXECUTION_TIME_IN_FUTURE"),
            ("committed one second past the tolerance", "2026-08-01T10:00:06Z", 0,
             "EXECUTION_TIME_IN_FUTURE"),
            ("committed exactly at the tolerance", "2026-08-01T10:00:05Z", 0,
             None),
            ("committed before the permit existed", "2026-08-01T09:00:00Z", 0,
             "EXECUTION_TIME_PRECEDES_PERMIT"),
            ("committed one second before the lower tolerance",
             "2026-08-01T09:59:54Z", 0, "EXECUTION_TIME_PRECEDES_PERMIT"),
            ("committed exactly at the lower tolerance", "2026-08-01T09:59:55Z", 0,
             None),
            ("committed after the permit, clock advanced past it",
             "2026-08-01T10:00:10Z", 100, None),
            ("committed before the permit, clock advanced past it",
             "2026-08-01T09:59:54Z", 100, "EXECUTION_TIME_PRECEDES_PERMIT"),
        )
        for label, committed_at, advance_seconds, code in bounds:
            with self.subTest(bound=label):
                engine, intent, _grant = fixture.engine()
                result = engine.evaluate_intent(
                    intent, fixture.evidence, actor_scope=ROLE_OPERATOR
                )
                self.assertEqual(result["disposition"], "ALLOW")
                if advance_seconds:
                    fixture.clock.advance(seconds=advance_seconds)
                request = fixture.execution_request(engine, result, intent)
                request["committed_at"] = committed_at
                if code is None:
                    receipt = engine.commit_execution(
                        request,
                        actor_scope=ROLE_EXECUTOR,
                        route_permit_hash=result["permit_hash"],
                    )
                    self.assertEqual(receipt["outcome"], "COMMITTED")
                    continue
                with self.assertRaisesRegex(ContractViolation, rf"^{code}(:|$)"):
                    engine.commit_execution(
                        request,
                        actor_scope=ROLE_EXECUTOR,
                        route_permit_hash=result["permit_hash"],
                    )

    def test_evidence_defects_are_authorization_stage_invariant(self) -> None:
        # CLASS ratchet, not a point: every caller-controlled evidence defect
        # must produce the SAME outcome whether authorization would pass or
        # fail, so no evidence check reveals the authorization stage through its
        # error status. A regression that defers ANY submitted-evidence
        # validation (shape, time, secret scan, identity) past authorization
        # makes one variant diverge and reddens here. Sweeping the class is the
        # point: a single-variant test would pass while a sibling channel leaks.
        fixture = self.fixture()

        def defect(mutation):
            evidence = copy.deepcopy(fixture.evidence)
            mutation(evidence)
            return evidence

        variants = [
            lambda ev: ev.__setitem__("collected_at", "2030-01-01T00:00:00Z"),
            lambda ev: ev.__setitem__("api_secret_key", "leak"),
            lambda ev: ev.pop("items"),
            lambda ev: ev.__setitem__("items", [{"evidence_type": "X"}]),
            lambda ev: ev.__setitem__("intent_id", "mismatched-intent-id"),
        ]

        def outcome(engine, the_intent, bad_evidence):
            try:
                result = engine.evaluate_intent(
                    the_intent, bad_evidence, actor_scope=ROLE_OPERATOR
                )
                return ("RESULT", result["message_code"])
            except ContractViolation as exc:
                return ("RAISE", str(exc).split(":")[0].strip())

        for index, mutation in enumerate(variants):
            bad_evidence = defect(mutation)
            engine_ok, intent_ok, _ = fixture.engine()
            engine_bad, intent_bad, _ = fixture.engine()
            unauthorized = copy.deepcopy(intent_bad)
            unauthorized["authority_grant_id"] = "grant-unknown-stageinv-001"
            authorized_outcome = outcome(engine_ok, intent_ok, bad_evidence)
            unauthorized_outcome = outcome(engine_bad, unauthorized, bad_evidence)
            self.assertEqual(
                authorized_outcome,
                unauthorized_outcome,
                f"evidence-defect variant {index} leaks the authorization stage: "
                f"authorized={authorized_outcome} unauthorized={unauthorized_outcome}",
            )
            # And the shared outcome must be a contract error raised before the
            # gate, not an authorization refusal that only one side reached.
            self.assertEqual(authorized_outcome[0], "RAISE")

    def test_exact_execution_replay_survives_declaration_expiry(self) -> None:
        fixture = self.fixture()
        engine, intent, _ = fixture.engine()
        result = engine.evaluate_intent(
            intent,
            fixture.evidence,
            actor_scope=ROLE_OPERATOR,
        )
        request = fixture.execution_request(engine, result, intent)
        # A letters-bearing receipt hash, so a case flip below is a real
        # change (the fixture default "9"*64 has no case to flip).
        request["downstream_receipt_hash"] = "ab" * 32
        receipt = engine.commit_execution(
            request,
            actor_scope=ROLE_EXECUTOR,
            route_permit_hash=request["permit_hash"],
        )
        record = engine.permits[result["permit_hash"]]
        before_replay = self.engine_state(engine, record)

        fixture.clock.advance(seconds=1_000_000_000)
        # Every SHA-256 field is case-normalized in the replay identity: a
        # retry differing only in hex case replays instead of conflicting.
        replay_request = copy.deepcopy(request)
        replay_request["permit_hash"] = replay_request["permit_hash"].lower()
        replay_request["state_anchor_hash"] = replay_request[
            "state_anchor_hash"
        ].lower()
        replay_request["downstream_receipt_hash"] = replay_request[
            "downstream_receipt_hash"
        ].upper()
        # The NESTED hashes count too. Flipping only the top-level fields left
        # the binding pair unnormalized: a retry that differed just in binding
        # hex case conflicted, though the same lowercase binding is accepted on
        # a first commit. The identity normalizes by shape, so every SHA-256 in
        # the request — at any depth — must round-trip.
        replay_request["binding"]["profile_hash"] = replay_request["binding"][
            "profile_hash"
        ].lower()
        replay_request["binding"]["declaration_hash"] = replay_request["binding"][
            "declaration_hash"
        ].lower()
        replay = engine.commit_execution(
            replay_request,
            actor_scope=ROLE_EXECUTOR,
            route_permit_hash=replay_request["permit_hash"],
        )

        self.assertEqual(replay, receipt)
        self.assertEqual(self.engine_state(engine, record), before_replay)

    def test_sqlite_path_restart_and_expired_replay(self) -> None:
        fixture = self.fixture()
        with tempfile.TemporaryDirectory() as temporary_directory:
            state_path = Path(temporary_directory) / "ledger-state.sqlite3"
            engine, profile, declaration, intent = self.persistent_engine(
                fixture,
                state_path,
            )
            result = engine.evaluate_intent(
                intent,
                fixture.evidence,
                actor_scope=ROLE_OPERATOR,
            )
            request = fixture.execution_request(engine, result, intent)
            receipt = engine.commit_execution(
                request,
                actor_scope=ROLE_EXECUTOR,
                route_permit_hash=request["permit_hash"],
            )
            committed_head = engine.ledger.head()
            committed_remaining = engine.structural_remaining

            fixture.clock.advance(seconds=1_000_000_000)
            restarted = UniversalConnectionLedger(
                profile,
                declaration,
                signing_key=b"synthetic-reference-signing-key",
                clock=fixture.clock,
                state_path=state_path,
            )
            replay = restarted.commit_execution(
                request,
                actor_scope=ROLE_EXECUTOR,
                route_permit_hash=request["permit_hash"],
            )

            self.assertEqual(replay, receipt)
            self.assertEqual(restarted.ledger.head(), committed_head)
            self.assertEqual(restarted.structural_remaining, committed_remaining)
            self.assertTrue(restarted.permits[result["permit_hash"]].consumed)
            self.assertEqual(len(restarted.receipt_hashes), 1)
            self.assertEqual(len(restarted.committed_resources), 1)

        # None selects the intentional in-memory engine. An explicitly
        # requested SQLite store must be durable and have a supported path.
        for value in (False, True, 0, [], {}, b"state.sqlite"):
            with self.subTest(state_path="invalid-type", value=value):
                with self.assertRaisesRegex(ContractViolation, "^STATE_PATH(:|$)"):
                    UniversalConnectionLedger(
                        profile, declaration,
                        signing_key=b"synthetic-reference-signing-key",
                        clock=fixture.clock, state_path=value,
                    )
        with self.subTest(state_path="memory-marker"):
            with self.assertRaisesRegex(ContractViolation, "^STATE_PATH_NOT_DURABLE(:|$)"):
                UniversalConnectionLedger(
                    profile, declaration,
                    signing_key=b"synthetic-reference-signing-key",
                    clock=fixture.clock, state_path=":memory:",
                )
        with tempfile.TemporaryDirectory() as temporary:
            for name, convert in (("path", Path), ("string", str)):
                with self.subTest(state_path="durable-control", kind=name):
                    path = Path(temporary) / (name + ".sqlite")
                    candidate = UniversalConnectionLedger(
                        profile, declaration,
                        signing_key=b"synthetic-reference-signing-key",
                        clock=fixture.clock, state_path=convert(path),
                    )
                    self.assertTrue(path.is_file())
                    self.assertEqual(candidate.status, "DRAFT")

    def test_sqlite_ed25519_restart_requires_compatible_signer(self) -> None:
        fixture = self.fixture()
        private_key = bytes(range(32))
        signer = Ed25519DetachedSigner.from_private_bytes(
            "fixture-ledger-key-v1",
            private_key,
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            state_path = Path(temporary_directory) / "ledger-state.sqlite3"
            _, profile, declaration, _ = self.persistent_engine(
                fixture,
                state_path,
                event_signer=signer,
            )
            persisted = state_path.read_bytes()
            self.assertNotIn(private_key, persisted)
            self.assertNotIn(base64.b64encode(private_key), persisted)
            self.assertNotIn(private_key.hex().encode("ascii"), persisted.lower())

            restarted = UniversalConnectionLedger(
                profile,
                declaration,
                signing_key=b"synthetic-reference-signing-key",
                clock=fixture.clock,
                state_path=state_path,
                event_signer=signer,
            )
            self.assertTrue(restarted.ledger.verify())

            with self.assertRaisesRegex(
                IntegrityViolation, "^EVENT_SIGNER_REQUIRED(:|$)"
            ):
                missing_signer = UniversalConnectionLedger(
                    profile,
                    declaration,
                    signing_key=b"synthetic-reference-signing-key",
                    clock=fixture.clock,
                    state_path=state_path,
                )
                missing_signer.observer_projection(actor_scope=ROLE_ARCHITECT)

            wrong_signer = Ed25519DetachedSigner.from_private_bytes(
                "fixture-ledger-key-v1",
                bytes(range(31, -1, -1)),
            )
            # Anchored: a bare assertRaises here passes on ANY integrity
            # code, so it certified "something refused" rather than the fact
            # this case is about.
            with self.assertRaisesRegex(
                IntegrityViolation, r"^LEDGER_CHAIN_FAILURE(:|$)"
            ):
                incompatible = UniversalConnectionLedger(
                    profile,
                    declaration,
                    signing_key=b"synthetic-reference-signing-key",
                    clock=fixture.clock,
                    state_path=state_path,
                    event_signer=wrong_signer,
                )
                incompatible.observer_projection(actor_scope=ROLE_ARCHITECT)

    def test_sqlite_concurrent_consumers_commit_and_debit_once(self) -> None:
        fixture = self.fixture()
        with tempfile.TemporaryDirectory() as temporary_directory:
            state_path = Path(temporary_directory) / "ledger-state.sqlite3"
            engine, profile, declaration, intent = self.persistent_engine(
                fixture,
                state_path,
            )
            result = engine.evaluate_intent(
                intent,
                fixture.evidence,
                actor_scope=ROLE_OPERATOR,
            )
            request = fixture.execution_request(engine, result, intent)
            event_count_before = engine.ledger.head()["event_count"]
            worker_count = 16
            workers = [
                UniversalConnectionLedger(
                    profile,
                    declaration,
                    signing_key=b"synthetic-reference-signing-key",
                    clock=fixture.clock,
                    state_path=state_path,
                )
                for _ in range(worker_count)
            ]
            barrier = threading.Barrier(worker_count)
            result_lock = threading.Lock()
            receipts: list[dict] = []
            errors: list[BaseException] = []

            def consume(worker: UniversalConnectionLedger) -> None:
                try:
                    barrier.wait(timeout=5)
                    receipt = worker.commit_execution(
                        request,
                        actor_scope=ROLE_EXECUTOR,
                        route_permit_hash=request["permit_hash"],
                    )
                    with result_lock:
                        receipts.append(receipt)
                except BaseException as exc:
                    with result_lock:
                        errors.append(exc)

            threads = [
                threading.Thread(target=consume, args=(worker,))
                for worker in workers
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)

            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])
            self.assertEqual(len(receipts), worker_count)
            self.assertEqual(
                len({receipt["receipt_hash"] for receipt in receipts}),
                1,
            )

            restarted = UniversalConnectionLedger(
                profile,
                declaration,
                signing_key=b"synthetic-reference-signing-key",
                clock=fixture.clock,
                state_path=state_path,
            )
            self.assertEqual(
                restarted.ledger.head()["event_count"],
                event_count_before + 1,
            )
            self.assertEqual(len(restarted.receipt_hashes), 1)
            self.assertEqual(len(restarted.committed_resources), 1)
            self.assertEqual(
                restarted.structural_remaining,
                fixture.fx.capacity - fixture.fx.action_cost,
            )

    def test_sqlite_persist_failure_rolls_back_memory_and_database(self) -> None:
        fixture = self.fixture()
        with tempfile.TemporaryDirectory() as temporary_directory:
            state_path = Path(temporary_directory) / "ledger-state.sqlite3"
            engine, profile, declaration, intent = self.persistent_engine(
                fixture,
                state_path,
            )
            result = engine.evaluate_intent(
                intent,
                fixture.evidence,
                actor_scope=ROLE_OPERATOR,
            )
            request = fixture.execution_request(engine, result, intent)
            event_count_before = engine.ledger.head()["event_count"]
            store = engine._state_store
            self.assertIsNotNone(store)
            original_save = store.save

            def fail_save(*args, **kwargs) -> None:
                raise RuntimeError("SYNTHETIC_SQLITE_PERSIST_FAILURE")

            store.save = fail_save
            try:
                with self.assertRaisesRegex(
                    RuntimeError,
                    "^SYNTHETIC_SQLITE_PERSIST_FAILURE(:|$)",
                ):
                    engine.commit_execution(
                        request,
                        actor_scope=ROLE_EXECUTOR,
                        route_permit_hash=request["permit_hash"],
                    )
            finally:
                store.save = original_save

            self.assertEqual(engine.ledger.head()["event_count"], event_count_before)
            self.assertFalse(engine.permits[result["permit_hash"]].consumed)
            restarted = UniversalConnectionLedger(
                profile,
                declaration,
                signing_key=b"synthetic-reference-signing-key",
                clock=fixture.clock,
                state_path=state_path,
            )
            self.assertEqual(restarted.ledger.head()["event_count"], event_count_before)
            self.assertFalse(restarted.permits[result["permit_hash"]].consumed)
            receipt = restarted.commit_execution(
                request,
                actor_scope=ROLE_EXECUTOR,
                route_permit_hash=request["permit_hash"],
            )
            self.assertEqual(receipt["permit_hash"], result["permit_hash"])

    def test_signer_rotation_rolls_back_on_persist_failure(self) -> None:
        # A signer rotation whose SQLite persist fails must not leave the new
        # signer active in memory while the database has rolled back: the
        # process-local signer registry is captured and restored with the rest
        # of the state, so the active key stays what it was before the failure.
        fixture = self.fixture()
        with tempfile.TemporaryDirectory() as temporary_directory:
            state_path = Path(temporary_directory) / "ledger-state.sqlite3"
            engine, _profile, _declaration, intent = self.persistent_engine(
                fixture,
                state_path,
            )
            original_key = engine._permit_signer.key_id
            store = engine._state_store
            self.assertIsNotNone(store)
            original_save = store.save

            def fail_save(*args, **kwargs) -> None:
                raise RuntimeError("SYNTHETIC_SQLITE_PERSIST_FAILURE")

            store.save = fail_save
            try:
                with self.assertRaisesRegex(
                    RuntimeError, "^SYNTHETIC_SQLITE_PERSIST_FAILURE(:|$)"
                ):
                    engine.rotate_permit_signer(
                        HmacDetachedSigner(b"rotated-signer-key", "rotated-key-1"),
                        actor_scope=ROLE_GOVERNANCE,
                    )
            finally:
                store.save = original_save

            self.assertEqual(engine._permit_signer.key_id, original_key)
            self.assertNotIn("rotated-key-1", engine._permit_verifiers)
            result = engine.evaluate_intent(
                intent, fixture.evidence, actor_scope=ROLE_OPERATOR
            )
            permit = engine.architect_permit(
                result["permit_hash"], actor_scope=ROLE_ARCHITECT
            )
            self.assertEqual(permit["signature"]["key_id"], original_key)

    def test_signer_revocation_rolls_back_on_persist_failure(self) -> None:
        # CLASS ratchet sibling: revocation is the second locked method that
        # mutates the process-local signer registry. A revocation whose persist
        # fails must not leave the key deleted from the verifiers or added to
        # the durable revoked set while the database rolled back.
        fixture = self.fixture()
        with tempfile.TemporaryDirectory() as temporary_directory:
            state_path = Path(temporary_directory) / "ledger-state.sqlite3"
            engine, _profile, _declaration, _intent = self.persistent_engine(
                fixture,
                state_path,
            )
            retired_key = engine._permit_signer.key_id
            engine.rotate_permit_signer(
                HmacDetachedSigner(b"active-signer-key", "active-key-1"),
                actor_scope=ROLE_GOVERNANCE,
            )
            store = engine._state_store
            self.assertIsNotNone(store)
            original_save = store.save

            def fail_save(*args, **kwargs) -> None:
                raise RuntimeError("SYNTHETIC_SQLITE_PERSIST_FAILURE")

            store.save = fail_save
            try:
                with self.assertRaisesRegex(
                    RuntimeError, "^SYNTHETIC_SQLITE_PERSIST_FAILURE(:|$)"
                ):
                    engine.revoke_permit_key(retired_key, actor_scope=ROLE_GOVERNANCE)
            finally:
                store.save = original_save

            self.assertIn(retired_key, engine._permit_verifiers)
            self.assertNotIn(retired_key, engine._revoked_permit_keys)

    def test_operator_message_code_is_bound_to_disposition(self) -> None:
        fixture = self.fixture()
        engine, intent, _ = fixture.engine()
        result = engine.evaluate_intent(
            intent,
            fixture.evidence,
            actor_scope=ROLE_OPERATOR,
        )
        result["message_code"] = "EXECUTION_DENIED"
        self.assert_schema_rejects(result)

        # Unit contract of the internal result formatter; this does not claim
        # these impossible combinations are accepted by the public evaluator.
        args = dict(intent_id=intent["intent_id"], request_hash=result["request_hash"],
                    disposition="ALLOW", architect_message_code="ALL_GATES_PASS",
                    permit_hash=result["permit_hash"], expires_at=result["expires_at"])
        for disposition, public in (("ALLOW", "EXECUTION_AUTHORIZED"),
                                    ("REFUSAL", "EXECUTION_DENIED"),
                                    ("MANUAL_REVIEW", "HUMAN_REVIEW_REQUIRED")):
            valid = dict(args, disposition=disposition)
            if disposition != "ALLOW":
                valid.update(permit_hash=None, expires_at=None)
            self.assertEqual(engine._operator_result(**valid)["message_code"], public)
        rows = [("UNKNOWN_DISPOSITION", dict(args, disposition="UNRECOGNIZED"))]
        rows += [("ALLOW_WITHOUT_PERMIT", dict(args, **{field: value}))
                 for field in ("permit_hash", "expires_at") for value in (None, "")]
        rows += [("NON_EXECUTABLE_WITH_PERMIT", dict(args, disposition=disposition,
                  permit_hash=args["permit_hash"] if field == "permit_hash" else None,
                  expires_at=args["expires_at"] if field == "expires_at" else None))
                 for disposition in ("REFUSAL", "MANUAL_REVIEW")
                 for field in ("permit_hash", "expires_at")]
        rows += [("ARCHITECT_MESSAGE_CODE", dict(args, architect_message_code=value))
                 for value in (None, "", "1invalid")]
        for code, values in rows:
            with self.subTest(formatter_contract=code, values=values):
                with self.assertRaisesRegex(ContractViolation, "^" + code + "(:|$)"):
                    engine._operator_result(**values)
        with self.subTest(formatter_contract="unknown-public-code"):
            with self.assertRaisesRegex(ContractViolation, "^UNKNOWN_DISPOSITION(:|$)"):
                engine._public_message_code("UNRECOGNIZED")

    def test_bookkeeping_refusals_and_post_append_rollback(self) -> None:
        fault_installers = {
            "resource_append": lambda engine: setattr(
                engine,
                "committed_resources",
                RaisingAppendList(engine.committed_resources),
            ),
            "replay_install": lambda engine: setattr(
                engine,
                "execution_replays",
                RaisingSetDict(engine.execution_replays),
            ),
        }
        for fault_name, install_fault in fault_installers.items():
            with self.subTest(fault=fault_name):
                fixture = self.fixture()
                engine, intent, _ = fixture.engine()
                result = engine.evaluate_intent(
                    intent,
                    fixture.evidence,
                    actor_scope=ROLE_OPERATOR,
                )
                request = fixture.execution_request(engine, result, intent)
                record = engine.permits[result["permit_hash"]]
                before = self.engine_state(engine, record)
                install_fault(engine)
                with self.assertRaises(RuntimeError):
                    engine.commit_execution(
                        request,
                        actor_scope=ROLE_EXECUTOR,
                        route_permit_hash=request["permit_hash"],
                    )
                self.assertEqual(self.engine_state(engine, record), before)
                receipt = engine.commit_execution(
                    request,
                    actor_scope=ROLE_EXECUTOR,
                    route_permit_hash=request["permit_hash"],
                )
                self.assertEqual(receipt["permit_hash"], result["permit_hash"])
                self.assertEqual(
                    len(engine.ledger.events_copy()),
                    len(before["ledger"]) + 1,
                )
                self.assertEqual(
                    engine.structural_remaining,
                    before["structural_remaining"] - record.body["structural_cost"],
                )

        # Inject internal bookkeeping loss only in an isolated in-memory
        # fixture. A guard refusal must not add an event or charge the permit.
        for code in ("IDEMPOTENCY_PERMIT_MISSING", "EXECUTION_RECEIPT_MISSING",
                     "RESERVATION_INACTIVE", "STRUCTURAL_DEBIT_UNAVAILABLE",
                     "RESOURCE_LIMIT_MISSING_AT_COMMIT"):
            with self.subTest(bookkeeping_contract=code):
                fixture = self.fixture()
                engine, intent, _ = fixture.engine()
                result = engine.evaluate_intent(intent, fixture.evidence, actor_scope=ROLE_OPERATOR)
                request = fixture.execution_request(engine, result, intent)
                record = engine.permits[result["permit_hash"]]
                def commit():
                    return engine.commit_execution(request, actor_scope=ROLE_EXECUTOR,
                                                   route_permit_hash=request["permit_hash"])
                if code == "EXECUTION_RECEIPT_MISSING":
                    original_receipt = commit()
                target, attr, damaged = {
                    "IDEMPOTENCY_PERMIT_MISSING": (engine, "permits", {}),
                    "EXECUTION_RECEIPT_MISSING": (engine, "execution_replays", {}),
                    "RESERVATION_INACTIVE": (record, "reservation_active", False),
                    "STRUCTURAL_DEBIT_UNAVAILABLE": (engine, "structural_remaining", 0),
                    "RESOURCE_LIMIT_MISSING_AT_COMMIT": (engine, "_limits", {}),
                }[code]
                with patch.object(target, attr, damaged):
                    before = engine._snapshot_state()
                    with self.assertRaisesRegex(ContractViolation, "^" + code + "(:|$)"):
                        if code == "IDEMPOTENCY_PERMIT_MISSING":
                            engine.evaluate_intent(intent, fixture.evidence, actor_scope=ROLE_OPERATOR)
                        else:
                            commit()
                    self.assertEqual(engine._snapshot_state(), before)
                    self.assertEqual(getattr(target, attr), damaged)
                receipt = commit()
                if code == "EXECUTION_RECEIPT_MISSING":
                    self.assertEqual(receipt, original_receipt)
                self.assertEqual(receipt["permit_hash"], result["permit_hash"])
                self.assertEqual(len(engine.receipt_hashes), 1)

    def test_evidence_resolver_does_not_run_before_authority_or_binding_failures(self) -> None:
        for case in ("unknown_authority", "binding_mismatch"):
            with self.subTest(case=case):
                calls: list[str] = []

                def resolver(intent, submitted, resolved_at):
                    calls.append(intent["intent_id"])
                    raise RuntimeError("resolver must not run")

                fixture = self.fixture()
                engine, intent, _ = fixture.engine(evidence_resolver=resolver)
                intent = copy.deepcopy(intent)
                if case == "unknown_authority":
                    intent["authority_grant_id"] = "grant-unknown-001"
                    expected = "AUTHORITY_UNKNOWN"
                else:
                    intent["binding"]["profile_hash"] = intent["binding"][
                        "profile_hash"
                    ][::-1]
                    expected = "BINDING_MISMATCH"
                result = engine.evaluate_intent(
                    intent,
                    fixture.evidence,
                    actor_scope=ROLE_OPERATOR,
                )
                self.assertEqual(calls, [])
                decision = engine.architect_decision(
                    result["request_hash"],
                    actor_scope=ROLE_ARCHITECT,
                )
                self.assertEqual(decision["message_code"], expected)

        fixture = self.fixture()
        grant = copy.deepcopy(fixture.grant)
        grant["valid_from"] = (fixture.clock.now() + timedelta(seconds=1)).isoformat()
        engine, intent, _ = fixture.engine(grant=grant)
        result = engine.evaluate_intent(intent, fixture.evidence, actor_scope=ROLE_OPERATOR)
        self.assertEqual(result["disposition"], "REFUSAL")
        decision = engine.architect_decision(result["request_hash"], actor_scope=ROLE_ARCHITECT)
        self.assertEqual(decision["message_code"], "AUTHORITY_NOT_YET_VALID")
        fixture.clock.advance(seconds=1)
        fresh_intent, fresh_evidence = universal_tests.unique_intent(intent, fixture.evidence, "grant-start")
        allowed = engine.evaluate_intent(fresh_intent, fresh_evidence, actor_scope=ROLE_OPERATOR)
        self.assertEqual(allowed["disposition"], "ALLOW")

        # A clock rollback after admission also reaches the execution-time
        # authority guard. Refusal invalidates the reservation without a debit.
        request = fixture.execution_request(engine, allowed, fresh_intent)
        record = engine.permits[allowed["permit_hash"]]
        before = copy.deepcopy((engine.ledger.events_copy(), engine.structural_remaining,
                                engine.receipt_hashes, engine.committed_resources, request))
        fixture.clock.advance(seconds=-1)
        with self.subTest(authority_contract="execution-before-start"):
            with self.assertRaisesRegex(ContractViolation, "^AUTHORITY_NOT_YET_VALID(:|$)"):
                engine.commit_execution(request, actor_scope=ROLE_EXECUTOR,
                                        route_permit_hash=request["permit_hash"])
            self.assertFalse(record.consumed)
            self.assertFalse(record.reservation_active)
            self.assertEqual(record.invalidated_reason, "AUTHORITY_NOT_YET_VALID")
            self.assertEqual((engine.ledger.events_copy(), engine.structural_remaining,
                              engine.receipt_hashes, engine.committed_resources, request), before)
        fixture.clock.advance(seconds=1)
        fresh_intent, fresh_evidence = universal_tests.unique_intent(
            fresh_intent, fresh_evidence, "grant-recovered")
        self.assertEqual(engine.evaluate_intent(fresh_intent, fresh_evidence,
                         actor_scope=ROLE_OPERATOR)["disposition"], "ALLOW")

        # A contradictory return from the internal authority lookup is a
        # dependency fault, not an ordinary unknown-authority input.
        fixture = self.fixture()
        engine, intent, _ = fixture.engine()
        before = engine._snapshot_state()
        with patch.object(engine, "_grant_validity", return_value=(None, None)):
            with self.assertRaisesRegex(IntegrityViolation, "^AUTHORITY_LOOKUP_FAILURE(:|$)"):
                engine.evaluate_intent(intent, fixture.evidence, actor_scope=ROLE_OPERATOR)
        self.assertEqual(engine._snapshot_state(), before)
        self.assertEqual(engine.evaluate_intent(intent, fixture.evidence,
                         actor_scope=ROLE_OPERATOR)["disposition"], "ALLOW")

    def test_evidence_resolver_exact_retry_uses_submitted_request_hash(self) -> None:
        fixture = self.fixture()
        calls: list[int] = []

        def resolver(intent, submitted, resolved_at):
            calls.append(len(calls) + 1)
            resolved = copy.deepcopy(dict(submitted))
            resolved["collected_at"] = f"2026-08-01T10:00:0{calls[-1] - 1}Z"
            return resolved

        engine, intent, _ = fixture.engine(evidence_resolver=resolver)
        first = engine.evaluate_intent(
            intent,
            fixture.evidence,
            actor_scope=ROLE_OPERATOR,
        )
        replay = engine.evaluate_intent(
            intent,
            fixture.evidence,
            actor_scope=ROLE_OPERATOR,
        )
        self.assertEqual(replay, first)
        self.assertEqual(calls, [1])

    def test_sqlite_public_reads_reload_latest_snapshot(self) -> None:
        fixture = self.fixture()
        with tempfile.TemporaryDirectory() as temporary_directory:
            state_path = Path(temporary_directory) / "ledger-state.sqlite3"
            writer, profile, declaration, intent = self.persistent_engine(
                fixture,
                state_path,
            )
            reader = UniversalConnectionLedger(
                profile,
                declaration,
                signing_key=b"synthetic-reference-signing-key",
                clock=fixture.clock,
                state_path=state_path,
            )
            result = writer.evaluate_intent(
                intent,
                fixture.evidence,
                actor_scope=ROLE_OPERATOR,
            )
            request = fixture.execution_request(writer, result, intent)
            receipt = writer.commit_execution(
                request,
                actor_scope=ROLE_EXECUTOR,
                route_permit_hash=request["permit_hash"],
            )

            # The fifth public read, and it goes FIRST. The claim is that EVERY
            # public read reloads a verified snapshot, and this sweep ran over
            # four of the five - the one left out being the only public read
            # with no mounted route, so no wire test reaches it either. Order
            # is the whole point: any sibling read below would have restored
            # the reader's state already, and a projection that never reloads
            # would then answer correctly from state someone else fetched.
            # Measured - placed last, this assertion stayed green while the
            # reload was broken for exactly this method.
            projection = reader.observer_projection(actor_scope=ROLE_ARCHITECT)
            self.assertTrue(projection)
            self.assertEqual(
                projection,
                writer.observer_projection(actor_scope=ROLE_ARCHITECT),
            )

            permit = reader.architect_permit(
                result["permit_hash"],
                actor_scope=ROLE_ARCHITECT,
            )
            decision = reader.architect_decision(
                result["request_hash"],
                actor_scope=ROLE_ARCHITECT,
            )
            registry = reader.registry_record(
                declaration["connector"]["connector_id"],
                actor_scope=ROLE_ARCHITECT,
            )
            self.assertTrue(permit["consumed"])
            self.assertEqual(decision["request_hash"], result["request_hash"])
            self.assertEqual(reader.ledger_head(ROLE_ARCHITECT), writer.ledger.head())
            self.assertEqual(registry["latest_receipt_root"], sha256_hex([receipt["receipt_hash"]]))

            # Authenticate malformed payloads with the fixture key so the
            # payload guard, rather than a hash/MAC mismatch, must refuse.
            state = writer._snapshot_state()
            permit_hash = result["permit_hash"]
            rows = (
                ("STATE_FIELDS", (("status",), "delete", None)),
                ("STATE_VERSION", (("state_version",), "set", "3.0.0")),
                ("STATE_PROFILE_MISMATCH", (("profile_hash",), "set", "0" * 64)),
                ("STATE_DECLARATION_MISMATCH", (("declaration_hash",), "set", "0" * 64)),
                ("STATE_PERMIT_TTL_MISMATCH", (("permit_ttl_seconds",), "set", 1)),
                ("STATE_STATUS", (("status",), "set", "UNKNOWN")),
                ("STATE_GRANTS", (("grants",), "set", [])),
                ("STATE_REVOKED_GRANTS", (("revoked_grants",), "set", {})),
                ("STATE_REVOKED_PERMIT_KEYS", (("revoked_permit_keys",), "set", [0])),
                ("STATE_PERMITS", (("permits",), "set", [])),
                ("STATE_PERMIT_FIELDS", (("permits", permit_hash, "consumed"), "delete", None)),
                ("STATE_PERMIT_KEY_MISMATCH", (("permits", permit_hash, "permit_hash"), "set", "0" * 64)),
                ("STATE_PERMIT_SIGNATURE", (("permits", permit_hash, "signature"), "set", {})),
                ("STATE_IDEMPOTENCY", (("idempotency",), "set", [])),
                ("STATE_IDEMPOTENCY_PAIR", (("idempotency",), "set", {"broken": ["only-one"]})),
                ("STATE_EXECUTION_REPLAYS", (("execution_replays",), "set", [])),
                ("STATE_EXECUTION_REPLAYS_PAIR", (("execution_replays",), "set", {"broken": ["only-one"]})),
                ("STATE_COMMITTED_RESOURCES", (("committed_resources",), "set", {})),
                ("STATE_COMMITTED_RESOURCE_FIELDS", (("committed_resources", 0, "debits"), "delete", None)),
            )
            reads = (
                ("observer", lambda: reader.observer_projection(actor_scope=ROLE_ARCHITECT)),
                ("permit", lambda: reader.architect_permit(permit_hash, actor_scope=ROLE_ARCHITECT)),
                ("decision", lambda: reader.architect_decision(result["request_hash"], actor_scope=ROLE_ARCHITECT)),
                ("registry", lambda: reader.registry_record(declaration["connector"]["connector_id"], actor_scope=ROLE_ARCHITECT)),
                ("head", lambda: reader.ledger_head(ROLE_ARCHITECT)),
                ("evaluate", lambda: reader.evaluate_intent(intent, fixture.evidence, actor_scope=ROLE_OPERATOR)),
                ("reopen", lambda: UniversalConnectionLedger(
                    profile, declaration, signing_key=b"synthetic-reference-signing-key",
                    clock=fixture.clock, state_path=state_path,
                )),
            )

            def install(payload):
                connection = writer._state_store.begin_immediate()
                try:
                    writer._state_store.save(
                        connection, writer.declaration_hash, writer.profile_hash,
                        b"synthetic-reference-signing-key", payload,
                    )
                    connection.commit()
                finally:
                    connection.close()

            def stored_row():
                with closing(sqlite3.connect(state_path)) as connection:
                    return connection.execute("SELECT * FROM ledger_state").fetchall()

            corruptions = [(code, self._corrupt(state, (operation,))) for code, operation in rows]
            corruptions.append(("STATE_SHAPE", []))
            for code, changed in corruptions:
                install(changed)
                before = stored_row()
                for surface, call in reads:
                    with self.subTest(state_refusal=code, surface=surface):
                        with self.assertRaisesRegex(ContractViolation, rf"^{code}(:|$)"):
                            call()
                        self.assertEqual(stored_row(), before, "refusal changed durable state")
                install(state)
                with self.subTest(state_control=code):
                    self.assertEqual(reader.ledger_head(ROLE_ARCHITECT), writer.ledger.head())
                    self.assertEqual(reader._snapshot_state(), state)

            for code, column in (("STATE_HASH_FAILURE", "state_hash"), ("STATE_MAC_FAILURE", "state_mac")):
                with closing(sqlite3.connect(state_path)) as connection:
                    connection.execute(f"UPDATE ledger_state SET {column} = ?", ("0" * 64,))
                    connection.commit()
                before = stored_row()
                for surface, call in reads:
                    with self.subTest(state_refusal=code, surface=surface):
                        with self.assertRaisesRegex(IntegrityViolation, rf"^{code}(:|$)"):
                            call()
                        self.assertEqual(stored_row(), before, "refusal changed durable state")
                install(state)
                with self.subTest(state_control=code):
                    self.assertEqual(reader.ledger_head(ROLE_ARCHITECT), writer.ledger.head())
                    self.assertEqual(reader._snapshot_state(), state)

    def test_action_target_pair_is_bound_by_declaration(self) -> None:
        fixture = self.fixture()
        engine, intent, _ = fixture.engine()
        intent = copy.deepcopy(intent)
        intent["target_system_id"] = "local-fallback"
        result = engine.evaluate_intent(
            intent,
            fixture.evidence,
            actor_scope=ROLE_OPERATOR,
        )
        decision = engine.architect_decision(
            result["request_hash"],
            actor_scope=ROLE_ARCHITECT,
        )
        self.assertEqual(result["disposition"], "REFUSAL")
        self.assertEqual(decision["message_code"], "ACTION_TARGET_MISMATCH")

    def test_observer_projection_uses_public_message_code(self) -> None:
        fixture = self.fixture()
        engine, intent, _ = fixture.engine()
        intent = copy.deepcopy(intent)
        intent["target_system_id"] = "local-fallback"
        result = engine.evaluate_intent(
            intent,
            fixture.evidence,
            actor_scope=ROLE_OPERATOR,
        )
        projection = engine.observer_projection(actor_scope=ROLE_ARCHITECT)
        self.assertEqual(result["message_code"], "EXECUTION_DENIED")
        self.assertEqual(projection[-1]["message_code"], "EXECUTION_DENIED")

        success_engine, success_intent, _ = fixture.engine()
        success_result = success_engine.evaluate_intent(
            success_intent,
            fixture.evidence,
            actor_scope=ROLE_OPERATOR,
        )
        success_request = fixture.execution_request(
            success_engine, success_result, success_intent
        )
        success_engine.commit_execution(
            success_request,
            actor_scope=ROLE_EXECUTOR,
            route_permit_hash=success_request["permit_hash"],
        )
        success_projection = success_engine.observer_projection(
            actor_scope=ROLE_ARCHITECT
        )
        self.assertEqual(
            success_result["message_code"], "EXECUTION_AUTHORIZED"
        )
        self.assertEqual(
            success_projection[-1]["message_code"], "EXECUTION_AUTHORIZED"
        )
        self.assertNotEqual(
            success_projection[-1]["message_code"], "EXECUTION_RECORDED"
        )
        self.assertEqual(
            PUBLIC_MESSAGE_CODES,
            frozenset(
                {
                    "EXECUTION_AUTHORIZED",
                    "EXECUTION_DENIED",
                    "HUMAN_REVIEW_REQUIRED",
                }
            ),
        )
        self.assertLessEqual(
            {
                projection[-1]["message_code"],
                success_projection[-1]["message_code"],
            },
            PUBLIC_MESSAGE_CODES,
        )

        # Fault the internal translator after a valid event exists, keeping
        # the public vocabulary intact; observer output must still refuse it.
        before = engine._snapshot_state()
        with patch.object(engine, "_public_message_code", return_value="UNRECOGNIZED"):
            with self.assertRaisesRegex(IntegrityViolation, "^PUBLIC_MESSAGE_CODE_INVALID(:|$)"):
                engine.observer_projection(actor_scope=ROLE_ARCHITECT)
        self.assertEqual(engine._snapshot_state(), before)
        self.assertEqual(engine.observer_projection(actor_scope=ROLE_ARCHITECT), projection)

    def test_failed_execution_is_not_projected_as_authorized(self) -> None:
        fixture = self.fixture()
        engine, intent, _ = fixture.engine()
        result = engine.evaluate_intent(
            intent, fixture.evidence, actor_scope=ROLE_OPERATOR
        )
        authorized_before = sum(
            1
            for record in engine.observer_projection(actor_scope=ROLE_ARCHITECT)
            if record["message_code"] == "EXECUTION_AUTHORIZED"
        )
        request = fixture.execution_request(engine, result, intent, outcome="FAILED")
        receipt = engine.commit_execution(
            request,
            actor_scope=ROLE_EXECUTOR,
            route_permit_hash=request["permit_hash"],
        )
        self.assertEqual(receipt["outcome"], "FAILED")
        authorized_after = sum(
            1
            for record in engine.observer_projection(actor_scope=ROLE_ARCHITECT)
            if record["message_code"] == "EXECUTION_AUTHORIZED"
        )
        # A FAILED commit must add no EXECUTION_AUTHORIZED to the observer feed;
        # otherwise a failed execution is indistinguishable from a committed one
        # on the observer's monitoring surface.
        self.assertEqual(authorized_after, authorized_before)

    def test_review_bundle_is_deterministic_and_manifest_bound(self) -> None:
        manifest = json.loads(
            (ROOT / "PACKAGE-MANIFEST.json").read_text(encoding="utf-8")
        )
        expected_paths = sorted(
            [item["path"] for item in manifest["files"]]
            + ["PACKAGE-MANIFEST.json"]
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            first_path = Path(temporary_directory) / "first.md"
            second_path = Path(temporary_directory) / "second.md"
            first = build_artifact(ROOT, first_path)
            second = build_artifact(ROOT, second_path)
            first_bytes = first_path.read_bytes()
            self.assertEqual(first, second)
            self.assertEqual(first_bytes, second_path.read_bytes())
            self.assertEqual(
                first["artifact_sha256"],
                hashlib.sha256(first_bytes).hexdigest().upper(),
            )
            self.assertEqual(first["file_count"], len(expected_paths))
            artifact_lines = first_bytes.decode("utf-8").splitlines()
            actual_paths = [
                line.removeprefix("## FILE: /")
                for line in artifact_lines
                if line.startswith("## FILE: /")
            ]
            self.assertEqual(actual_paths, expected_paths)
            self.assertIn(
                f"Baseline format: {BASELINE_FORMAT}", artifact_lines
            )

    @staticmethod
    def _acceptance_report_fixture(external_core: dict | None) -> dict:
        # Pinned figures. Two are read back by an assertion, which keeps its
        # own literal on purpose - an expectation derived from this fixture
        # would compare the fixture with itself and hold on every model, a
        # tautology that cannot fail; two independent statements, pinned to
        # agree. The verifier's figure is not chosen: the generator refuses
        # any figure but its own check count, so it is the one live number.
        _SYNTHETIC_STEP_FIGURES = {
            # Outside the derived band 1000+index, so a figure landing in the wrong
            # row is visible: 1005 was also what index 5 derives, and the row it
            # pins is index 4.
            "contract_regressions": 2005,
            "failure_surface_ratchet": 2009,
            "package_verifier": len(ALL_PACKAGE_CHECK_IDS),
        }
        results = {
            "format": "nc25-acceptance-results/v1",
            "completed_utc": "2030-02-03T04:05:06Z",
            "status": "PASS",
            # Obviously synthetic digests: the generator carries them into the
            # report unread, and the verifier - not this fixture - is what
            # holds them to the shipped bytes.
            "bound_manifest_digest": "A" * 64,
            "bound_document_sha256": "B" * 64,
            "acceptance_steps": {
                "passed": len(GATE_ROWS),
                "total": len(GATE_ROWS),
            },
            # The step list is DERIVED from the gate rows rather than written
            # out again. It was written out, and an added step broke this
            # fixture rather than the thing the fixture guards - a second
            # writer of one list, found the moment the eighth step arrived.
            #
            # Deliberately impossible figures, and that property survives the
            # derivation. What this fixture tests is that the generator carries
            # ITS INPUT into the report, so the numbers must not be mistakable
            # for live counts: an earlier edition read as a stale copy of real
            # figures and invited exactly that misreading. The ids pinned above
            # are the exceptions, each for the reason given there.
            "steps": [
                {
                    "id": step_id,
                    "status": "PASS",
                    "passed": _SYNTHETIC_STEP_FIGURES.get(step_id, 1000 + index),
                    "total": _SYNTHETIC_STEP_FIGURES.get(step_id, 1000 + index),
                }
                for index, step_id in enumerate(GATE_ROWS)
            ],
        }
        if external_core is not None:
            results["external_core"] = external_core
        return results

    @staticmethod
    def _acceptance_geometry_fixture() -> dict:
        return {
            "status": "GREEN",
            "page_count": 19,
            "page_sizes": [[612.0, 792.0]],
            "hard_issue_count": 0,
            "warning_count": 7,
            # The document the acceptance fixture binds ("B" * 64).
            "source_docx_sha256": "B" * 64,
        }

    def _render_acceptance_report(
        self,
        external_core: dict | None,
        package_verifier_total: int | None = None,
        geometry_overrides: dict | None = None,
    ):
        if package_verifier_total is None:
            package_verifier_total = len(ALL_PACKAGE_CHECK_IDS)
        fixture_geometry = self._acceptance_geometry_fixture()
        for key, value in (geometry_overrides or {}).items():
            if value is None:
                fixture_geometry.pop(key, None)
            else:
                fixture_geometry[key] = value
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        temporary = Path(workspace.name)
        report = temporary / "ACCEPTANCE-REPORT.md"
        results = temporary / "acceptance.json"
        geometry = temporary / "geometry.json"
        report.write_text(
            (ROOT / "ACCEPTANCE-REPORT.md").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        acceptance = self._acceptance_report_fixture(external_core)
        for step in acceptance["steps"]:
            if step["id"] == "package_verifier":
                step["passed"] = package_verifier_total
                step["total"] = package_verifier_total
                break
        results.write_text(json.dumps(acceptance), encoding="utf-8")
        geometry.write_text(json.dumps(fixture_geometry), encoding="utf-8")
        update_report(report, results, geometry)
        return report.read_text(encoding="utf-8")

    def test_a_geometry_file_whose_lists_agree_with_its_counts_is_published(self) -> None:
        """A count is held to the list beside it, and an agreeing file still renders.

        The refusal rows plant a count that disagrees with its list - zero hard findings
        beside one listed, seven warnings beside none. Without this control a gate that
        refused every file carrying a list at all would satisfy them both, and the audit's
        own output carries the lists on every run.
        """
        rendered = self._render_acceptance_report(
            {"source_mode": "strict", "external_source_checks": "PASS"},
            geometry_overrides={
                "hard_issues": [],
                "warnings": [{"code": "PAGE_SIZE"} for _ in range(7)],
            },
        )
        self.assertIn("Verification date: `2030-02-03 UTC`", rendered)

    def test_the_generator_refuses_a_same_named_module_from_another_tree(self) -> None:
        """The bootstrap imports are held to files in this tree, not to their names.

        `sys.path` decides where a module is FOUND, not which one is BOUND: a module of the
        same name already in `sys.modules` is handed over untouched. Measured before the
        check existed - a planted `verify_package` with no file at all was the module this
        generator bound, and its check ids and digest rule are what the report publishes.
        The control is the same import with nothing planted.
        """
        with tempfile.TemporaryDirectory() as directory:
            planted = Path(directory) / "planted.py"
            # The package root goes on the path explicitly: a script run from another
            # directory puts its OWN directory there, not the working directory.
            preamble = "import sys\nsys.path.insert(0, %r)\n" % str(ROOT)
            planted.write_text(
                preamble
                + "import types\n"
                "sys.modules['verify_package'] = types.ModuleType('verify_package')\n"
                "import tools.build_acceptance_report\n",
                encoding="utf-8",
                newline="\n",
            )
            clean = Path(directory) / "clean.py"
            clean.write_text(
                preamble
                + "import tools.build_acceptance_report as g\n"
                "print(g.verify_package.__file__)\n",
                encoding="utf-8",
                newline="\n",
            )
            refused = subprocess.run(
                [sys.executable, "-B", str(planted)],
                cwd=str(ROOT), capture_output=True, text=True, check=False)
            admitted = subprocess.run(
                [sys.executable, "-B", str(clean)],
                cwd=str(ROOT), capture_output=True, text=True, check=False)
        self.assertNotEqual(refused.returncode, 0, refused.stdout)
        self.assertIn("ACCEPTANCE_VERIFIER_MODULE_FOREIGN", refused.stderr)
        self.assertEqual(admitted.returncode, 0, admitted.stderr)
        self.assertEqual(
            Path(admitted.stdout.strip()).resolve().parent, (ROOT / "tests").resolve())

    def test_acceptance_report_command_tokens(self) -> None:
        """Require the canonical command and reject complete literal launcher invocations."""
        canonical = "python -B tests/run_acceptance.py"
        source = (ROOT / "ACCEPTANCE-REPORT.md").read_text(encoding="utf-8")
        self.assertEqual(source.count(canonical), 1)
        cases = [
            ("canonical", source, False),
            ("inline punctuation", source.replace(canonical, "`" + canonical + "`."), False),
            ("bare punctuation", source.replace(canonical, canonical + "."), False),
            ("hyphenated executable", source.replace(canonical, "not-" + canonical), True),
            ("filename suffix", source.replace(canonical, canonical + ".backup"), True),
            ("executable path", source.replace(canonical, "other/" + canonical), True),
        ]
        forbidden = [
            r'& "C:\Windows\py.exe" -3 -B tests/run_acceptance.py',
            r'&"C:\Windows\py.exe" -3 -B tests/run_acceptance.py',
            r"& 'C:\Program Files\Python Launcher\py.exe' -3 -B tests/run_acceptance.py",
            'py -3 -X "utf8" -B tests/run_acceptance.py',
            "py -3 -W 'ignore' tests/run_acceptance.py",
            "py -3 --check-hash-based-pycs always tests/run_acceptance.py",
            r'"C:\Program Files\pyw.exe" -3 "D:\work with spaces\tests\run_acceptance.py"',
            "`py -3 -B tests/run_acceptance.py`.",
            "(py -3 tests/run_acceptance.py)",
            "echo ready;py -3 tests/run_acceptance.py",
            "py -3 tests/run_acceptance.py;echo done",
            "py -3 tests/run_acceptance.py|echo done",
            "py\t-3\ttests/run_acceptance.py",
            # Backticks are read as spaces rather than removed: removed, the colon would
            # sit against `py` and the command would no longer start at a boundary.
            "Invocation:`py -3 tests/run_acceptance.py`",
            # `-c` takes a value and ENDS the options, so Python runs no script after it:
            # this line does not invoke the file and is refused anyway, because the
            # generic switch branch reads `-c` like any other switch and the quoted path
            # follows it directly. The row keeps that over-refusal deliberate - it can
            # only refuse a line, never admit an invocation - rather than leaving it to
            # be discovered again. Its twin is in the allowed list below.
            'py -3 -c "tests/run_acceptance.py"',
        ]
        # Horizontal whitespace joins tokens whatever its code point: PowerShell reads a
        # no-break space as a separator (measured), and the joiner once narrowed to space
        # and tab let these three through.
        forbidden.extend(
            "py" + space + "-3" + space + "tests/run_acceptance.py"
            for space in ("\u00a0", "\u2009", "\u3000")
        )
        allowed = [
            "not-py -3 tests/run_acceptance.py",
            "py.backup -3 tests/run_acceptance.py",
            "py -3 tests/run_acceptance.py.backup",
            'py -3 "tests/run_acceptance.py.backup"',
            "py -3 'tests/run_acceptance.py.backup'",
            '"not-py" -3 tests/run_acceptance.py',
            '"py.exe.backup" -3 tests/run_acceptance.py',
            "py -3 the tests/run_acceptance.py file",
            "`py` -3\n`tests/run_acceptance.py`",
            # The twin of the `-c` row above, and the asymmetry between them is the
            # scan's, not Python's: `-m` takes a MODULE name, so the script path does not
            # stand directly after the switch and the options group ends at a token that
            # is neither switch nor script. Neither line invokes the file; one is refused
            # and the other is not, and both are written down so the next reader measures
            # the guard instead of inferring it.
            "py -3 -m json.tool tests/run_acceptance.py",
        ]
        allowed.extend(
            "py -3" + separator + "tests/run_acceptance.py"
            for separator in ("\v", "\f", "\x1c", "\x85", "\u2028", "\u2029")
        )
        for forbidden_shape, commands in ((True, forbidden), (False, allowed)):
            for command in commands:
                cases.append((command, command + "\n" + source, forbidden_shape))
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            report = work / "report.md"
            acceptance = work / "acceptance.json"
            geometry = work / "geometry.json"
            acceptance.write_text(json.dumps(self._acceptance_report_fixture(
                {"source_mode": "strict", "external_source_checks": "PASS"},
            )), encoding="utf-8")
            geometry.write_text(json.dumps(self._acceptance_geometry_fixture()), encoding="utf-8")
            for name, text, refused in cases:
                with self.subTest(command_case=name):
                    report.write_text(text, encoding="utf-8")
                    before = report.read_bytes()
                    if refused:
                        with self.assertRaisesRegex(ValueError, "^REPORT_CANONICAL_COMMAND$"):
                            update_report(report, acceptance, geometry)
                        self.assertEqual(report.read_bytes(), before)
                    else:
                        update_report(report, acceptance, geometry)
                        self.assertIn(
                            "Verification date: `2030-02-03 UTC`",
                            report.read_text(encoding="utf-8"),
                        )
                    self.assertEqual(list(work.glob("*.tmp")), [])

    def test_the_report_terminal_line_names_the_gate_rows(self) -> None:
        """The report's required terminal result is the count the gate rows make.

        `ACCEPTANCE_STEPS=8/8 PASS` stands in the report as a literal the generator never
        rewrites - the table rows, the date, the status and the sections it owns are
        rewritten, and this line is none of them - so a ninth gate row would have left it
        naming eight while every row beside it moved. Held here against `GATE_ROWS`, the one
        home of that count: the line stays hand-kept, and this is what keeps it honest.
        """
        report = (ROOT / "ACCEPTANCE-REPORT.md").read_text(encoding="utf-8")
        lines = re.findall(r"^ACCEPTANCE_STEPS=(\d+)/(\d+) PASS$", report, flags=re.MULTILINE)
        self.assertEqual(lines, [(str(len(GATE_ROWS)), str(len(GATE_ROWS)))])

    def test_every_rendered_count_takes_its_noun_through_plural(self) -> None:
        """No count in the generator's text is printed beside a noun frozen in the plural.

        The helper's docstring lists the nouns that bypass it, and that list was read against
        the code by hand, round after round, and was wrong the last time: the core section's
        `bytes` and `lines` were frozen and unlisted. This is the reading made mechanical.
        The plants are the control in both directions - a frozen noun is named, and a noun
        through the helper, a function word and a `key=` label are not - so an empty answer
        on the generator is the scan finding nothing, not the scan seeing nothing.
        """
        self.assertEqual(frozen_count_nouns('x = f"{n} bytes, {m} lines"'),
                         ["1: bytes", "1: lines"])
        for silent in ('x = f"{n} {plural(n, \'byte\')}"', 'x = f"{name} is generated"',
                       'x = f"{d} pages={n}"'):
            with self.subTest(control=silent):
                self.assertEqual(frozen_count_nouns(silent), [])
        source = Path(inspect.getsourcefile(update_report)).read_text(encoding="utf-8")
        self.assertEqual(frozen_count_nouns(source), [])

    def test_acceptance_report_rejects_undeclared_table_rows(self) -> None:
        """Every row belongs to the declared table, independently of its result syntax."""
        source = (ROOT / "ACCEPTANCE-REPORT.md").read_text(encoding="utf-8")
        anchor = "| Package integrity checks |"
        self.assertEqual(source.count(anchor), 1)
        first = next(line for line in source.splitlines() if line.startswith(
            "| Functional behavior across all three reference profiles |"))
        second = next(line for line in source.splitlines() if line.startswith(
            "| Semantic contracts |"))
        variants = {
            "compact extra": source.replace(anchor, "|Retired gate|`1/1 PASS`|\n" + anchor),
            "failed extra": source.replace(anchor, "| Retired gate | `FAIL` |\n" + anchor),
            "unknown result": source.replace(anchor, "| Retired gate | unknown |\n" + anchor),
            "optional edge pipes": source.replace(anchor, "Retired gate | `1/1 PASS`\n" + anchor),
            "compact duplicate": source.replace(anchor, "|Semantic contracts|`15/15 PASS`|\n" + anchor),
            "reordered": source.replace(first, "ROW_SWAP").replace(second, first).replace("ROW_SWAP", second),
            "three columns": source.replace(anchor, "| Retired gate | result | extra |\n" + anchor),
            "duplicate header": source.replace("## Bound bytes", "| Gate | Recorded result |\n|---|---:|\n\n## Bound bytes"),
        }
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            report = work / "report.md"
            acceptance = work / "acceptance.json"
            geometry = work / "geometry.json"
            acceptance.write_text(json.dumps(self._acceptance_report_fixture(
                {"source_mode": "strict", "external_source_checks": "PASS"})), encoding="utf-8")
            geometry.write_text(json.dumps(self._acceptance_geometry_fixture()), encoding="utf-8")
            report.write_text(source, encoding="utf-8")
            update_report(report, acceptance, geometry)
            self.assertIn("Verification date: `2030-02-03 UTC`", report.read_text(encoding="utf-8"))
            for name, candidate in variants.items():
                with self.subTest(name=name):
                    report.write_text(candidate, encoding="utf-8")
                    before = report.read_bytes()
                    with self.assertRaisesRegex(ValueError, r"^REPORT_GATE_ROWS$"):
                        update_report(report, acceptance, geometry)
                    self.assertEqual(report.read_bytes(), before)

    def test_acceptance_report_verifier_reads_complete_table(self) -> None:
        """The shipped verifier rejects extra, duplicate and reordered table rows."""
        import verify_package as verifier
        from spec_counts import test_method_count

        source = (ROOT / "ACCEPTANCE-REPORT.md").read_text(encoding="utf-8")
        # A source edit legitimately moves these counts before the report is rebuilt.
        # Keep this table-population fixture truthful to the currently running tests.
        current_counts = {
            "Contract regression cases": test_method_count(
                ROOT / "tests/test_contract_regressions.py", "ContractRegressions"),
            "OTCS bridge behaviour and refusal vocabulary": test_method_count(
                ROOT / "tests/test_otcs_bridge.py", "OTCSBridgeRegressions"),
            "Package integrity checks": len(ALL_PACKAGE_CHECK_IDS),
        }
        for label, total in current_counts.items():
            source, matched = re.subn(
                rf"(?m)^\| {re.escape(label)} \| .*?\|$",
                f"| {label} | `{total}/{total} PASS` |", source)
            self.assertEqual(matched, 1)
        compact = "\n".join(
            "|".join(part.strip() for part in line.split("|"))
            if line.startswith("|") else line for line in source.splitlines()) + "\n"
        without_edges = "\n".join(
            line[1:-1] if line.startswith("|") and line.endswith("|") else line
            for line in compact.splitlines()) + "\n"
        header = "| Gate | Recorded result |\n|---|---:|"
        table_end = source.index("\n\n", source.index(header))
        first = next(line for line in source.splitlines() if line.startswith(
            "| Functional behavior across all three reference profiles |"))
        second = next(line for line in source.splitlines() if line.startswith(
            "| Semantic contracts |"))
        refused = {
            "compact extra": source.replace("| Package integrity checks |", "|Retired gate|`1/1 PASS`|\n| Package integrity checks |"),
            "failed extra": source.replace("| Package integrity checks |", "| Retired gate | FAIL |\n| Package integrity checks |"),
            "duplicate": source.replace(second, second + "\n|Semantic contracts|`15/15 PASS`|"),
            "reordered": source.replace(first, "ROW_SWAP").replace(second, first).replace("ROW_SWAP", second),
            "missing": source.replace(second + "\n", ""),
            "malformed separator": source.replace("|---|---:|", "|---|word|"),
            "fenced table": source[:source.index(header)] + "```text\n" + source[source.index(header):table_end] + "\n\n```" + source[table_end:],
            "indented code": source[:source.index(header)] + "\n".join(
                "    " + line for line in source[source.index(header):table_end].splitlines()) + source[table_end:],
        }
        read_text = Path.read_text
        def run(candidate: str) -> list[str]:
            def reading(path, *args, **kwargs):
                if path == ROOT / "ACCEPTANCE-REPORT.md":
                    return candidate
                return read_text(path, *args, **kwargs)
            with patch.object(Path, "read_text", reading):
                return verifier.acceptance_report_row_mismatches()
        for name, candidate in (("canonical", source), ("compact", compact), ("optional edges", without_edges)):
            with self.subTest(control=name):
                self.assertEqual(run(candidate), [])
        for name, candidate in refused.items():
            with self.subTest(refusal=name):
                self.assertIn("gate-row table population or order differs from declared rows", run(candidate))
        lines = source.splitlines()
        header_index = lines.index("| Gate | Recorded result |")
        separator_index = header_index + 1
        body_indices = list(range(separator_index + 1, next(
            index for index in range(separator_index + 1, len(lines))
            if not lines[index].strip())))
        self.assertEqual(len(body_indices), len(GATE_ROWS))
        # Markdown permits up to three leading spaces on each table line.
        # A leading tab reaches column four, including after one to three spaces.
        # Hold the header, delimiter and both ends of the body to the same rule.
        for site, indices in (
            ("header", [header_index]),
            ("separator", [separator_index]),
            ("first body row", [body_indices[0]]),
            ("last body row", [body_indices[-1]]),
            ("whole table", [header_index, separator_index, *body_indices]),
        ):
            for prefix in ("", " ", "  ", "   ", "    ", "\t", " \t", "  \t", "   \t"):
                with self.subTest(indentation_site=site, prefix=repr(prefix)):
                    candidate_lines = list(lines)
                    for index in indices:
                        candidate_lines[index] = prefix + candidate_lines[index]
                    problems = run("\n".join(candidate_lines) + "\n")
                    if "\t" not in prefix and len(prefix) <= 3:
                        self.assertEqual(problems, [])
                    else:
                        self.assertIn("gate-row table population or order differs from declared rows", problems)
        with self.subTest(refusal="declared row with non-PASS result"):
            self.assertIn("Semantic contracts: result is not a PASS count", run(source.replace(second, "| Semantic contracts | FAIL |")))

    def test_citation_metadata_contract_rejects_wrong_license_form_and_name(self) -> None:
        """Citation metadata preserves the project name and separate material licences."""
        import verify_package as verifier
        import yaml

        good = {
            "cff-version": "1.2.0",
            "title": "NC25OL - Navigational Cybernetics 2.5 Open Ledger",
            "license": ["MIT", "CC-BY-4.0"],
        }
        cases = {
            "SPDX expression": {**good, "license": "MIT AND CC-BY-4.0"},
            "wrong name": {**good, "title": "NC2.5 Universal Connection Ledger"},
            "duplicate licence": {**good, "license": ["MIT", "MIT"]},
            "missing licence": {key: value for key, value in good.items() if key != "license"},
            "non-string licence": {**good, "license": ["MIT", {"name": "CC-BY-4.0"}]},
        }
        with tempfile.TemporaryDirectory() as directory:
            citation = Path(directory) / "CITATION.cff"
            with patch.object(verifier, "ROOT", Path(directory)):
                for value in (good, {**good, "license": ["CC-BY-4.0", "MIT"]}):
                    citation.write_text(yaml.safe_dump(value), encoding="utf-8")
                    self.assertEqual(verifier.citation_metadata_mismatches(), [])
                for name, value in cases.items():
                    with self.subTest(name=name):
                        citation.write_text(yaml.safe_dump(value), encoding="utf-8")
                        self.assertTrue(verifier.citation_metadata_mismatches())
                for malformed in ("[broken", "- sequence\n", "scalar", ""):
                    with self.subTest(malformed=malformed):
                        citation.write_text(malformed, encoding="utf-8")
                        self.assertTrue(verifier.citation_metadata_mismatches())
                citation.unlink()
                self.assertTrue(verifier.citation_metadata_mismatches())

    def test_acceptance_report_generator_refuses_each_code_by_name(self) -> None:
        # Every refusal of the acceptance-report generator, driven by name
        # through one malformed input and asserted by exception type and exact
        # text, detail included. Coverage is credited to the (site, code) pair
        # actually raised - the site read from the traceback - never to the
        # code a row declares, and it is held to the closed world that
        # generator_refusal_sites reads from the generator's source.
        #
        # Not covered here, by name: none. And the list of what stays outside has shrunk
        # to one, because two of its three entries were closed rather than conceded -
        # this comment went on naming them for a round after they were. The indexed reads
        # of the failure-surface baseline are `.get` calls now, so an absent key refuses
        # as FAILURE_SURFACE_* like a malformed one; a file that is missing, unreadable,
        # not UTF-8, not JSON or nested past the parser's limit is named by
        # EVIDENCE_FILE_UNREADABLE or EVIDENCE_JSON_INVALID, and rows below drive all
        # five shapes; the report itself, read by both halves, is named by
        # REPORT_UNREADABLE and driven absent and not UTF-8 through each. What remains
        # outside is two things, said as what they are. `bound_bytes`, which raises from
        # run_acceptance and not from the generator. And a failure to WRITE the report -
        # a locked destination, a full disk - which keeps its OSError on purpose: the
        # vocabulary names inputs that are malformed, and an environment that will not
        # take the output is not an input. The residue case drives that failure and
        # asserts the OSError. A conceded exclusion that keeps producing findings was a
        # gap, not a boundary; this list said "only bound_bytes" while the report was
        # read bare in two places.
        module = sys.modules[update_report.__module__]
        source_path = Path(inspect.getsourcefile(module)).resolve()
        sites, unclassified = generator_refusal_sites(source_path.read_text(encoding="utf-8"))
        self.assertEqual(unclassified, [], "the generator carries a raise this reader cannot classify")
        # The import-time guards stand outside the DRIVEN world by construction: they fire
        # while the module is being bound, before any of the three drivers below exists, so
        # no data row can reach them and the completeness test must not ask for one. They
        # are named here instead, so a new one is a red in this list rather than a silent
        # exemption, and the case that drives them is the subprocess one above.
        import_time = {
            code for site, codes in sites.items() for code in codes
            if site[0] == IMPORT_TIME_OWNER
        }
        self.assertEqual(
            import_time,
            {"ACCEPTANCE_VERIFIER_MODULE_FOREIGN", "ACCEPTANCE_RUNNER_MODULE_FOREIGN"},
        )
        world = {
            (site, code) for site, codes in sites.items() for code in codes
            if site[0] != IMPORT_TIME_OWNER
        }

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        strict_core = {"source_mode": "strict", "external_source_checks": "PASS"}
        source_manifest = json.loads((ROOT / "SOURCE-MANIFEST.json").read_text(encoding="utf-8"))
        core = next(
            index for index, item in enumerate(source_manifest["inputs"])
            if isinstance(item, dict) and item.get("role") == "immutable_nc25_core"
        )
        package_manifest = json.loads((ROOT / "PACKAGE-MANIFEST.json").read_text(encoding="utf-8"))
        document_entry = next(
            index for index, entry in enumerate(package_manifest["files"])
            if entry["path"].endswith(".docx")
        )
        verifier = list(GATE_ROWS).index("package_verifier")
        standalone = len(STANDALONE_PACKAGE_CHECK_IDS)

        def drive(name, driver, target, operations):
            work = Path(temporary.name) / name
            (work / "root" / "tests").mkdir(parents=True)
            for relative in (
                "SOURCE-MANIFEST.json",
                "PACKAGE-MANIFEST.json",
                "tests/failure-surface-baseline.json",
            ):
                shutil.copyfile(ROOT / relative, work / "root" / relative)
            documents = {
                "acceptance": (work / "acceptance.json", self._acceptance_report_fixture(strict_core)),
                "geometry": (work / "geometry.json", self._acceptance_geometry_fixture()),
                "source_manifest": (work / "root" / "SOURCE-MANIFEST.json", None),
                "baseline": (work / "root" / "tests" / "failure-surface-baseline.json", None),
                "manifest": (work / "root" / "PACKAGE-MANIFEST.json", None),
            }
            for label, (path, document) in documents.items():
                if target == f"{label}_raw":
                    path.write_text(operations, encoding="utf-8")
                    continue
                if target == f"{label}_bytes":
                    # Bytes, not text: the third escape, for evidence whose problem is
                    # below the level of characters. `_raw` writes a string and cannot
                    # express a file that is not UTF-8 at all, which is one of the two
                    # shapes that used to walk out of the reader unnamed.
                    path.write_bytes(operations)
                    continue
                if target == f"{label}_absent":
                    # Not written at all. `_raw` is this loop's escape from "write the
                    # parsed document" when the bytes must be wrong; this is the escape
                    # when there must be no bytes. Needed because a refusal for evidence
                    # that cannot be READ has no other way to be driven, and the closed
                    # world below is an equality: a code no row can reach would have to be
                    # exempted, and an exemption is how a closed world quietly becomes a
                    # subset check.
                    path.unlink(missing_ok=True)
                    continue
                if document is None and target != label:
                    continue
                if document is None:
                    document = json.loads(path.read_text(encoding="utf-8"))
                if target == label:
                    document = self._corrupt(document, operations)
                path.write_text(json.dumps(document), encoding="utf-8")
            # The rebind and cli drivers act on the copy's own report: the cli
            # driver points the generator's REPORT_PATH there, so "untouched"
            # compares the file a rebind would rewrite, not a bystander.
            report = (work / "root" / "ACCEPTANCE-REPORT.md") if driver in ("rebind", "cli") else (work / "report.md")
            text = (ROOT / "ACCEPTANCE-REPORT.md").read_text(encoding="utf-8")
            if target == "report":
                for old, new, occurrences in operations:
                    # A reworded report fails here as a fixture fault, not as
                    # a refusal the row did not mean.
                    self.assertEqual(text.count(old), occurrences, f"fixture text {old!r}")
                    text = text.replace(old, new)
            if driver == "cli":
                # The copy's report already carries the digests a rebind would
                # write, so a rebind of it changes no byte. A stale manifest
                # digest makes any rebind before a refusal visible.
                text, stale = re.subn(
                    r"(every entry except this report, digest to `)[A-F0-9]{64}(`)",
                    lambda match: match.group(1) + "0" * 64 + match.group(2),
                    text,
                )
                self.assertEqual(stale, 1, "fixture text: the report's manifest digest sentence")
            # Two escapes for the REPORT, which the loop above cannot express because it
            # writes only the evidence files: `report_absent` leaves no report at all, and
            # `report_bytes` writes the row's bytes as the report. Both exist because the
            # report is an input too, and a reader of it that failed was a raw exception
            # until it had a name.
            if target == "report_bytes":
                report.write_bytes(operations)
            elif target != "report_absent":
                report.write_text(text, encoding="utf-8", newline="\n")
            before = report.read_bytes() if report.exists() else None
            raised = None
            try:
                if driver == "update":
                    update_report(report, work / "acceptance.json", work / "geometry.json", root=work / "root")
                elif driver == "rebind":
                    rebind_report_to_manifest(work / "root")
                else:
                    # A cli row's operations are its command-line arguments.
                    argv = ["build_acceptance_report.py", *(operations or [])]
                    with patch.object(sys, "argv", argv), patch.object(module, "REPORT_PATH", report.resolve()):
                        generator_main()
            except (ValueError, SystemExit) as exc:
                raised = exc
            # Two claims, returned apart because they do not apply to the same rows. "The
            # report is unchanged" is a claim about a REFUSAL; a successful run is supposed
            # to change it. "No temporary remains" holds on EVERY path, and while the two
            # travelled as one predicate the second went wherever the first could not be
            # asserted - so on the control rows, the only rows where the generator actually
            # succeeds, nothing looked at the temporary at all.
            # Returned apart in the values as well as in the prose. The first form of this
            # kept the conjunction in the second value while adding the third - and since
            # `no_temporary` is asserted FIRST at every row, the conjunction was thereafter
            # equal to `unchanged` and the half of its message about a temporary file could
            # never be the reason it fired. A message advertising a cause it cannot have is
            # the same defect one layer up.
            # Every `.tmp` beside the report, not the one name. The writer's temporary was
            # `<report>.tmp` and this checked that name; the writer now takes a name of its
            # own per call, and a check of the old name would have gone on passing while
            # measuring nothing - the predicate has to follow the class, not the spelling.
            no_temporary = not list(report.parent.glob("*.tmp"))
            # For an absent report "unchanged" means still absent: a refusal must not
            # create the file it refused to read.
            unchanged = (report.read_bytes() if report.exists() else None) == before
            return raised, unchanged, report, no_temporary

        def site_of(exc):
            frames = [
                frame for frame in traceback.extract_tb(exc.__traceback__)
                if os.path.normcase(str(Path(frame.filename).resolve())) == os.path.normcase(str(source_path))
                and frame.name not in REPORT_GENERATOR_PINNED_HELPERS
            ]
            if not frames:
                return None
            frame = frames[-1]
            matches = [
                site for site in sites
                if site[0] == frame.name and site[1] <= frame.lineno <= site[2]
            ]
            return matches[0] if len(matches) == 1 else None

        # Controls: the unmutated inputs are accepted by both drivers.
        with self.subTest(control="update"):
            raised, _untouched, report, no_temporary = drive("control-update", "update", None, None)
            self.assertIsNone(raised)
            self.assertTrue(no_temporary, "a successful update left its temporary file")
            self.assertIn("Verification date: `2030-02-03 UTC`", report.read_text(encoding="utf-8"))
        with self.subTest(control="rebind"):
            raised, _untouched, _report, no_temporary = drive("control-rebind", "rebind", None, None)
            self.assertIsNone(raised)
            self.assertTrue(no_temporary, "a successful rebind left its temporary file")
        # A third control, and the only one that drives an input rather than leaving it
        # alone: a sentence NAMING the launcher and the script is not an invocation and
        # must survive. The guard searches the report with backticks removed, which joins
        # fragments that were never one command, so while anything was allowed between the
        # launcher and the path this line was refused - measured, before the pattern
        # required an invocation's shape. The refusal rows above prove the guard bites;
        # only this one proves it does not bite everything, which is the half a widening
        # cannot demonstrate about itself.
        with self.subTest(control="a sentence about the launcher is not an invocation"):
            raised, _untouched, _report, no_temporary = drive(
                "control-prose", "update", "report",
                [("## Bound bytes",
                  "Neither `py` nor `pyw` is used here; the script is "
                  "`tests/run_acceptance.py`.\n\n## Bound bytes", 1)])
            self.assertIsNone(
                raised, "a sentence about the launcher was refused as an invocation")
            self.assertTrue(no_temporary, "a successful update left its temporary file")
        # One word between a switch and the script. While any switch could carry a detached
        # value this was refused as an invocation - `the` read as the value of `-3` - and
        # the prose control above passed only because its line holds `;` and `nor`. This
        # one has nothing incidental to hide behind: it is admitted because a detached value
        # is allowed only after the switches that take one - `-X`, `-W` and
        # `--check-hash-based-pycs` - and `-3` is not one of them.
        with self.subTest(control="one word between a switch and the script is prose"):
            raised, _untouched, _report, no_temporary = drive(
                "control-one-word", "update", "report",
                [("## Bound bytes",
                  "py -3 the tests/run_acceptance.py file\n\n## Bound bytes", 1)])
            self.assertIsNone(
                raised, "a sentence with one word after a switch was refused as an invocation")
            self.assertTrue(no_temporary, "a successful update left its temporary file")
        # The launcher half of the trailing boundary, and the only way to show it: a
        # refusal row proves the guard bites a longer name, and cannot show that the guard
        # stopped biting a DIFFERENT file. `py -3 tests/run_acceptance.pyx` is an
        # invocation of something else, and the guard refused it while its path was
        # bounded on the left alone - measured. The canonical command stays in the report
        # here, so a refusal could only come from the launcher pattern.
        with self.subTest(control="a launcher invoking a different file is not this one"):
            raised, _untouched, _report, no_temporary = drive(
                "control-other-file", "update", "report",
                [("## Bound bytes",
                  "py -3 tests/run_acceptance.pyx\n\n## Bound bytes", 1)])
            self.assertIsNone(
                raised, "an invocation of another file was refused as this one")
            self.assertTrue(no_temporary, "a successful update left its temporary file")
        # And the same across two lines. The widening that closed the one-line form
        # replaced the `[^\n]*` that had been the line bound, and `\s` matches a newline,
        # so a launcher on one line and the script path on the next matched as one
        # invocation - measured. A control, not a refusal row, because these two lines are
        # prose the report is allowed to carry.
        with self.subTest(control="a launcher and a path on two lines are two sentences"):
            raised, _untouched, _report, no_temporary = drive(
                "control-prose-two-lines", "update", "report",
                # No punctuation after the launcher and none before the path: the first
                # form of this control ended the line with `py.`, and the full stop
                # blocked the match on its own, so the control passed for a reason that
                # had nothing to do with the line bound - a fixture outside the class its
                # own name claims. These two lines are the measured form.
                [("## Bound bytes",
                  "the Windows launcher is `py`\n"
                  "`tests/run_acceptance.py` is the script it would run\n\n## Bound bytes",
                  1)])
            self.assertIsNone(
                raised, "a launcher and a path on separate lines were read as one command")
            self.assertTrue(no_temporary, "a successful update left its temporary file")

        steps = ("steps",)
        geometry_sizes = ("page_sizes",)
        core_input = ("inputs", core)
        rows = [
            ("ACCEPTANCE_RESULTS_FORMAT", "update", "acceptance", [(("format",), "set", "nc25-acceptance-results/v0")]),
            ("ACCEPTANCE_RESULTS_NOT_PASS", "update", "acceptance", [(("status",), "set", "FAIL")]),
            ("ACCEPTANCE_COMPLETED_UTC", "update", "acceptance", [(("completed_utc",), "set", "2030-02-03")]),
            ("ACCEPTANCE_COMPLETED_UTC", "update", "acceptance", [(("completed_utc",), "set", "٢٠٣٠-02-03T04:05:06Z")]),
            # The right shape, no such moment: month ninety-nine, day ninety-nine, hour
            # twenty-five, minute and second sixty-one. It passed while the shape test was
            # the whole check, and would have been printed as the report's verification
            # date.
            ("ACCEPTANCE_COMPLETED_UTC", "update", "acceptance", [(("completed_utc",), "set", "2030-99-99T25:61:61Z")]),
            ("ACCEPTANCE_STEP_GATE", "update", "acceptance", [(("acceptance_steps",), "set", [])]),
            ("STEP_PASSED", "update", "acceptance", [(("acceptance_steps", "passed"), "set", -1)]),
            ("STEP_TOTAL", "update", "acceptance", [(("acceptance_steps", "total"), "set", "8")]),
            ("ACCEPTANCE_STEP_GATE", "update", "acceptance", [(("acceptance_steps", "passed"), "set", len(GATE_ROWS) - 1)]),
            ("ACCEPTANCE_STEP_GATE", "update", "acceptance", [(("acceptance_steps", "passed"), "set", len(GATE_ROWS) + 1), (("acceptance_steps", "total"), "set", len(GATE_ROWS) + 1)]),
            ("ACCEPTANCE_STEPS", "update", "acceptance", [(steps, "set", {})]),
            ("ACCEPTANCE_STEP_ENTRY", "update", "acceptance", [(steps + (0,), "set", "functional_behaviour")]),
            ("ACCEPTANCE_STEP_ENTRY", "update", "acceptance", [(steps + (0, "status"), "set", "FAIL")]),
            ("STEP_COUNT", "update", "acceptance", [(steps + (0, "passed"), "set", -1)]),
            ("STEP_COUNT", "update", "acceptance", [(steps + (0, "total"), "set", None)]),
            ("ACCEPTANCE_STEP_ENTRY", "update", "acceptance", [(steps + (0, "id"), "set", 5)]),
            ("ACCEPTANCE_STEP_ENTRY", "update", "acceptance", [(steps + (1, "id"), "set", "functional_behaviour")]),
            ("ACCEPTANCE_STEP_ENTRY", "update", "acceptance", [(steps + (0, "total"), "set", 94)]),
            # A gate that ran NO checks. `passed == total` admits zero on both sides, so
            # eight of these beside the aggregate `8/8` published eight gates passed with
            # nothing run - and the runner reaches the shape from our own tree, since a
            # suite that ran no tests still prints `Ran 0 tests` and `OK`.
            ("ACCEPTANCE_STEP_ENTRY", "update", "acceptance", [(steps + (0, "passed"), "set", 0), (steps + (0, "total"), "set", 0)]),
            ("ACCEPTANCE_STEP_SET", "update", "acceptance", [(steps + (0, "id"), "set", "unknown_step")]),
            ("GEOMETRY_NOT_GREEN", "update", "geometry", [(("status",), "set", "RED")]),
            ("PAGE_COUNT", "update", "geometry", [(("page_count",), "set", "19")]),
            ("HARD_ISSUE_COUNT", "update", "geometry", [(("hard_issue_count",), "set", -1)]),
            ("WARNING_COUNT", "update", "geometry", [(("warning_count",), "set", True)]),
            ("GEOMETRY_GATE", "update", "geometry", [(("page_count",), "set", 0)]),
            ("GEOMETRY_GATE", "update", "geometry", [(("hard_issue_count",), "set", 1)]),
            ("GEOMETRY_GATE", "update", "geometry", [(geometry_sizes, "set", "612x792")]),
            # Each count against the list it counts, where the file carries one. The audit
            # writes both from their own lists, so these two rows plant a file our audit
            # cannot produce - which is the file this gate exists for, since the report
            # publishes the COUNT and a reader would take the list for its evidence.
            ("GEOMETRY_GATE", "update", "geometry", [(("hard_issues",), "set", [{"code": "PAGE_SIZE"}])]),
            ("GEOMETRY_GATE", "update", "geometry", [(("warnings",), "set", [])]),
            ("GEOMETRY_PAGE_SIZES", "update", "geometry", [(geometry_sizes, "set", [])]),
            ("GEOMETRY_PAGE_SIZES", "update", "geometry", [(("page_count",), "set", 1), (geometry_sizes, "set", [[612.0, 792.0], [595.0, 842.0]])]),
            ("GEOMETRY_PAGE_SIZE_ENTRY", "update", "geometry", [(geometry_sizes, "set", ["A4"])]),
            ("GEOMETRY_PAGE_SIZE_ENTRY", "update", "geometry", [(geometry_sizes, "set", [1])]),
            ("GEOMETRY_PAGE_SIZE_ENTRY", "update", "geometry", [(geometry_sizes, "set", [[612.0]])]),
            ("GEOMETRY_PAGE_SIZE_ENTRY", "update", "geometry", [(geometry_sizes, "set", [[612.0, True]])]),
            # A width JSON admits and a C double does not. `math.isfinite` converts its
            # argument, so this raised OverflowError out of the guard that names this very
            # input. The conversion was KEPT and its overflow made the answer - a number
            # that cannot be a double is not a finite double - which is what
            # `_finite_double` says and does. This comment said the conversion had been
            # removed: a description of a fix considered and not made, sitting beside the
            # row whose value still takes that exact path.
            ("GEOMETRY_PAGE_SIZE_ENTRY", "update", "geometry", [(geometry_sizes, "set", [[10 ** 309, 792.0]])]),
            ("GEOMETRY_PAGE_SIZE_ENTRY", "update", "geometry", [(geometry_sizes, "set", [[0, 792.0]])]),
            ("GEOMETRY_PAGE_SIZE_ENTRY", "update", "geometry", [(geometry_sizes, "set", [[float("nan"), 792.0]])]),
            ("GEOMETRY_PAGE_SIZES_NOT_DISTINCT", "update", "geometry", [(geometry_sizes, "set", [[612.0, 792.0], [612.0, 792.0]])]),
            ("ACCEPTANCE_EXTERNAL_CORE_MISSING", "update", "acceptance", [(("external_core",), "delete", None)]),
            ("EXTERNAL_CORE_NOT_VERIFIED", "update", "acceptance", [(("external_core", "external_source_checks"), "set", "NOT_RUN")]),
            ("ACCEPTANCE_EXTERNAL_CORE_MODE", "update", "acceptance", [(("external_core", "source_mode"), "set", "auto")]),
            ("STRICT_PACKAGE_VERIFIER_REQUIRED", "update", "acceptance", [(steps + (verifier, "passed"), "set", standalone), (steps + (verifier, "total"), "set", standalone)]),
            ("ACCEPTANCE_CORE_INPUT_MISSING", "update", "source_manifest", [(core_input + ("role",), "set", "other_input")]),
            ("CORE_BYTES", "update", "source_manifest", [(core_input + ("byte_length",), "set", -1)]),
            ("CORE_LINES", "update", "source_manifest", [(core_input + ("line_count",), "set", "14228")]),
            ("ACCEPTANCE_CORE_INPUT_SHAPE", "update", "source_manifest", [(core_input + ("file_name",), "set", 7)]),
            ("ACCEPTANCE_CORE_INPUT_SHAPE", "update", "source_manifest", [(core_input + ("sha256",), "set", "a" * 64)]),
            # A NUMBER whose decimal form is sixty-four digits. The guard matched
            # `str(core_sha)` against a hex pattern, so this value satisfied a test for a
            # digest and would have been printed into the report as one - the check was
            # run on text the check itself manufactured. The row
            # drives the value and not the conversion, so it stays true however the guard
            # is written.
            ("ACCEPTANCE_CORE_INPUT_SHAPE", "update", "source_manifest", [(core_input + ("sha256",), "set", 10 ** 63)]),
            # The manifest's version, which a shared helper re-reads and indexes bare further
            # down: absent, it raised KeyError from inside that helper; a number, it raised
            # AttributeError. Both drove the generator out of its vocabulary from a module
            # the closed world does not read. And `inputs`, iterated: a number there raised
            # TypeError from the loop.
            ("SOURCE_MANIFEST_PACKAGE_VERSION", "update", "source_manifest", [(("package_version",), "delete", None)]),
            ("SOURCE_MANIFEST_PACKAGE_VERSION", "update", "source_manifest", [(("package_version",), "set", 3)]),
            ("SOURCE_MANIFEST_INPUTS", "update", "source_manifest", [(("inputs",), "set", 7)]),
            # The core's NAME, which is a string and was asked nothing else, and which the
            # generator puts into the report AFTER the command guard has read the template.
            # Measured on a copy of the package: this value left the template clean, passed
            # the guard, and stood in the report the run wrote, with the run reported as a
            # success. The guard asks the final text now, which is what this row drives.
            ("REPORT_CANONICAL_COMMAND", "update", "source_manifest", [(core_input + ("file_name",), "set", "core.md`; py -3 tests/run_acceptance.py; `x")]),
            # A gate row nobody declares. Each declared row is rewritten exactly once,
            # which says nothing about an extra one: measured, the written report carried
            # nine rows under a terminal line reading `8/8`.
            ("REPORT_GATE_ROWS", "update", "report", [("| Package integrity checks |", "| Retired gate | `1/1 PASS` |\n| Package integrity checks |", 1)]),
            # A code name written twice in the baseline. `len` counted entries, so the
            # figure the report calls a count of codes was a count of lines.
            ("FAILURE_SURFACE_ENGINE_CODES", "update", "baseline", [(("engine_refusal_codes",), "set", ["X", "X"])]),
            ("REPORT_CANONICAL_COMMAND", "update", "report", [("python -B tests/run_acceptance.py", "python tests/run_acceptance.py", 1)]),
            ("REPORT_CANONICAL_COMMAND", "update", "report", [("## Bound bytes", "py -3 tests/run_acceptance.py\n\n## Bound bytes", 1)]),
            ("REPORT_CANONICAL_COMMAND", "update", "report", [("## Bound bytes", "py -3 -B tests/run_acceptance.py\n\n## Bound bytes", 1)]),
            ("REPORT_CANONICAL_COMMAND", "update", "report", [("## Bound bytes", "py -3 -B tests\\run_acceptance.py\n\n## Bound bytes", 1)]),
            ("REPORT_CANONICAL_COMMAND", "update", "report", [("## Bound bytes", "py -B tests/run_acceptance.py\n\n## Bound bytes", 1)]),
            ("REPORT_CANONICAL_COMMAND", "update", "report", [("## Bound bytes", "py.exe -3 -B tests\\run_acceptance.py\n\n## Bound bytes", 1)]),
            # Upper case is the same invocation on Windows, where a command and a path are
            # resolved without regard to case; before the pattern was matched that way this
            # row passed the guard.
            ("REPORT_CANONICAL_COMMAND", "update", "report", [("## Bound bytes", "PY -3 -B TESTS\\run_acceptance.py\n\n## Bound bytes", 1)]),
            # The launcher named by its path. The two exemptions used to be one character
            # class that also held the separators, and this spelling then matched nothing.
            ("REPORT_CANONICAL_COMMAND", "update", "report", [("## Bound bytes", "C:\\Windows\\py.exe -3 -B tests\\run_acceptance.py\n\n## Bound bytes", 1)]),
            # The launcher's windowed twin, installed beside `py.exe` by the same installer
            # and running the same script. A boundary written for `py` alone let both of its
            # spellings past; these two rows are what stops that being found a sixth time.
            ("REPORT_CANONICAL_COMMAND", "update", "report", [("## Bound bytes", "pyw -3 -B tests\\run_acceptance.py\n\n## Bound bytes", 1)]),
            ("REPORT_CANONICAL_COMMAND", "update", "report", [("## Bound bytes", "pyw.exe -3 -B tests\\run_acceptance.py\n\n## Bound bytes", 1)]),
            # The same invocation with the path quoted. The class that keeps a quote out of
            # the path's own characters was also keeping out the one it OPENS with, so both
            # quote forms walked past - measured. A path of several directories was measured
            # at the same time and did not walk past, so nothing was widened for it.
            ("REPORT_CANONICAL_COMMAND", "update", "report", [("## Bound bytes", "py -3 -B \"tests/run_acceptance.py\"\n\n## Bound bytes", 1)]),
            ("REPORT_CANONICAL_COMMAND", "update", "report", [("## Bound bytes", "py -3 -B 'tests/run_acceptance.py'\n\n## Bound bytes", 1)]),
            # A switch whose value is DETACHED. The switch group took a switch token and a
            # value attached to it, so this spelling matched nothing and passed - under a
            # comment claiming any launcher spelling is refused, not one form of it. It is
            # the fifth spelling found one at a time, and it is pinned here so it is the
            # last.
            ("REPORT_CANONICAL_COMMAND", "update", "report", [("## Bound bytes", "py -3 -X utf8 tests/run_acceptance.py\n\n## Bound bytes", 1)]),
            # The other switch that takes a detached value. Named because the pattern now
            # allows a value after `-X` and `-W` only, and a row for one of the two leaves
            # the other's half of the alternation unwitnessed.
            ("REPORT_CANONICAL_COMMAND", "update", "report", [("## Bound bytes", "py -3 -W ignore tests/run_acceptance.py\n\n## Bound bytes", 1)]),
            # The end-of-options marker, which the launcher honours: measured, `py -3 --
            # script.py` runs the script. It walked past while a switch needed a character
            # after its dashes other than a dash; the hyphen in the switch's class is what
            # lets the bare marker read as one, and the break for this row removes it.
            ("REPORT_CANONICAL_COMMAND", "update", "report", [("## Bound bytes", "py -3 -- tests/run_acceptance.py\n\n## Bound bytes", 1)]),
            # The canonical command was required by an unbounded substring test, so a line
            # that CONTAINS it without being it satisfied the requirement - and the
            # launcher pattern does not catch this one either, naming `py` and `pyw` rather
            # than an arbitrary prefix. The report could then certify a command it did not
            # carry.
            ("REPORT_CANONICAL_COMMAND", "update", "report", [("python -B tests/run_acceptance.py", "notpython -B tests/run_acceptance.py", 1)]),
            # A longer NAME, not a longer line. Both patterns were bounded on the left
            # only, so `run_acceptance.pyx` - a different file - satisfied the requirement
            # for the canonical command. The mirror control below
            # drives the launcher half of the same open end.
            ("REPORT_CANONICAL_COMMAND", "update", "report", [("python -B tests/run_acceptance.py", "python -B tests/run_acceptance.pyx", 1)]),
            ("REPORT_DATE:0", "update", "report", [("Verification date: ", "Verified on: ", 1)]),
            ("REPORT_DATE:2", "update", "report", [("Verification date: ", "Verification date: earlier\n\nVerification date: ", 1)]),
            ("REPORT_STATUS:0", "update", "report", [("Status: ", "State: ", 1)]),
            # One row written out by hand pins the code's form; the loop below
            # drives every gate row.
            ("REPORT_ROW_otcs_bridge:0", "update", "report", [("| OTCS bridge behaviour and refusal vocabulary |", "| OTCS bridge (renamed) |", 1)]),
        ]
        rows += [
            (f"REPORT_ROW_{step_id}:0", "update", "report", [(f"| {label} |", f"| {label} (renamed) |", 1)])
            for step_id, label in GATE_ROWS.items()
        ]
        rows += [
            ("REPORT_CORE_SECTION:0", "update", "report", [("## Core source binding", "## Core binding", 1)]),
            ("REPORT_CORE_SECTION:2", "update", "report", [("## Core source binding", "## Core source binding\n\nearlier\n\n## Core source binding", 1)]),
            ("ACCEPTANCE_BOUND_MANIFEST_DIGEST_SHAPE", "update", "acceptance", [(("bound_manifest_digest",), "set", "a" * 64)]),
            ("ACCEPTANCE_BOUND_DOCUMENT_SHA256_SHAPE", "update", "acceptance", [(("bound_document_sha256",), "set", None)]),
            ("GEOMETRY_DOCUMENT_SHAPE", "update", "geometry", [(("source_docx_sha256",), "delete", None)]),
            ("GEOMETRY_DOCUMENT_MISMATCH", "update", "geometry", [(("source_docx_sha256",), "set", "C" * 64)]),
            ("REPORT_BOUND_SECTION:0", "update", "report", [("## Bound bytes", "## Bytes", 1)]),
            ("REPORT_BOUND_SECTION:2", "update", "report", [("## Bound bytes", "## Bound bytes\n\nearlier\n\n## Bound bytes", 1)]),
            ("FAILURE_SURFACE_BASELINE_RUNTIME", "update", "baseline", [(("runtime",), "set", [])]),
            # Reading evidence, and the two ways it fails before a shape is ever asked
            # about. Both were raw before - `JSONDecodeError` and `FileNotFoundError` -
            # while every neighbouring failure had a name; the suite's own comment conceded
            # them as "outside that world", and a concession is disclosure, not closure.
            # Planted into the GEOMETRY evidence on purpose: acceptance is loaded first, so
            # a plant there would be answered before this site is reached and the row would
            # be measuring the order of two loads.
            ("EVIDENCE_JSON_INVALID: geometry.json", "update", "geometry_raw", "{"),
            ("EVIDENCE_FILE_UNREADABLE: geometry.json", "update", "geometry_absent", None),
            # The same two codes by the two routes that used to escape them. Bytes that
            # are not UTF-8 fail in `read_text`, before the parser is reached, as
            # UnicodeDecodeError - a ValueError and not an OSError, so the read clause
            # named only files that were missing or locked. Nesting past the interpreter's
            # limit fails in the parser as RecursionError - a RuntimeError and not a
            # ValueError, so the parse clause named only syntax. Both are properties of
            # the evidence and both now answer in its vocabulary; the rows drive the
            # shapes rather than the types, so they stay true if the clauses are rewritten.
            ("EVIDENCE_FILE_UNREADABLE: geometry.json", "update", "geometry_bytes", b"\xff\xfe{}"),
            # The report is an input to both halves as well as their output, and it was read
            # bare in both. Absent and not UTF-8, through each half, since each has its own
            # read of it.
            ("REPORT_UNREADABLE: report.md", "update", "report_absent", None),
            ("REPORT_UNREADABLE: report.md", "update", "report_bytes", b"\xff\xfe# report"),
            ("REPORT_UNREADABLE: ACCEPTANCE-REPORT.md", "rebind", "report_absent", None),
            ("REPORT_UNREADABLE: ACCEPTANCE-REPORT.md", "rebind", "report_bytes", b"\xff\xfe# report"),
            ("EVIDENCE_JSON_INVALID: geometry.json", "update", "geometry_raw",
             "[" * 5000 + "]" * 5000),
            ("FAILURE_SURFACE_ALL", "update", "baseline", [(("emission_points_all",), "set", -1)]),
            # The eight figures were `len(...)` of whatever the key held, and `len` is true
            # of a string and of a mapping as well as of a list. A bare string
            # was published as one code. The plants differ on
            # purpose - a string, a mapping and a scalar are three different ways a key
            # stops holding a collection, and eight copies of one plant would read as eight
            # rows of coverage while testing one shape.
            ("FAILURE_SURFACE_ENGINE_CODES", "update", "baseline", [(("engine_refusal_codes",), "set", "X")]),
            ("FAILURE_SURFACE_WIRE_CODES", "update", "baseline", [(("wire_error_codes",), "set", {"a": 1})]),
            ("FAILURE_SURFACE_DYNAMIC_POINTS", "update", "baseline", [(("dynamic_emission_points",), "set", 12)]),
            ("FAILURE_SURFACE_CONSTRUCTED_CODES", "update", "baseline", [(("runtime", "constructed_engine_codes"), "set", "X")]),
            ("FAILURE_SURFACE_FOREIGN_CODES", "update", "baseline", [(("runtime", "foreign_translated_codes"), "set", {"a": 1})]),
            ("FAILURE_SURFACE_WITNESSED_CODES", "update", "baseline", [(("runtime", "witnessed_codes"), "set", 3)]),
            ("FAILURE_SURFACE_UNWITNESSED_CODES", "update", "baseline", [(("runtime", "unwitnessed_codes"), "set", "X")]),
            ("FAILURE_SURFACE_BRIDGE_CODES", "update", "baseline", [(("bridge_refusal_codes",), "set", {"a": 1})]),
            ("FAILURE_SURFACE_STATIC", "update", "baseline", [(("emission_points_static",), "set", "462")]),
            # The figures section ends at the next heading, so that heading is
            # what goes: removing the figures heading itself is refused first,
            # by the core section, whose block ends there.
            ("REPORT_FIGURES_SECTION:0", "update", "report", [("## Document artifact", "## Document", 1)]),
            ("REPORT_FIGURES_SECTION:2", "update", "report", [("## Failure-surface figures", "## Failure-surface figures\n\nearlier\n\n## Failure-surface figures", 1)]),
            ("REPORT_DOCUMENT_SECTION:0", "update", "report", [("## Security and data boundary", "## Security", 1)]),
            ("REPORT_DOCUMENT_SECTION:2", "update", "report", [("## Document artifact", "## Document artifact\n\nearlier\n\n## Document artifact", 1)]),
            ("EVIDENCE_JSON_OBJECT_REQUIRED", "update", "acceptance_raw", "[]"),
            ("EVIDENCE_JSON_OBJECT_REQUIRED", "update", "geometry_raw", "[]"),
            ("EVIDENCE_JSON_OBJECT_REQUIRED", "update", "source_manifest_raw", "[]"),
            ("EVIDENCE_JSON_OBJECT_REQUIRED", "update", "baseline_raw", "[]"),
            ("EVIDENCE_JSON_OBJECT_REQUIRED", "rebind", "manifest_raw", "[]"),
            ("REBIND_MANIFEST_DIGEST:0", "rebind", "report", [("every entry except this report, digest to `", "every entry except this report, digests to `", 1)]),
            ("REBIND_MANIFEST_DIGEST:2", "rebind", "report", [("## Bound bytes", "every entry except this report, digest to `" + "A" * 64 + "`\n\n## Bound bytes", 1)]),
            # The same doubling wearing the disguise the count did not check for: a second
            # sentence whose digest is lowercase. Counting only well-formed occurrences made
            # it invisible, the one visible occurrence was rewritten, and the report was
            # saved carrying both claims - which is what this guard exists to refuse.
            ("REBIND_MANIFEST_DIGEST:2", "rebind", "report", [("## Bound bytes", "every entry except this report, digest to `" + "a" * 64 + "`\n\n## Bound bytes", 1)]),
            # A SOLE claim whose digest is lowercase: the count sees one sentence and is
            # satisfied, and the substitution - which matches the well-formed digest -
            # matches nothing. Before `count_pattern` existed this was refused `:0`;
            # after it the function returned the text unchanged and the caller reported
            # the new digests as written. The row pins the direction: the fix for a
            # missed duplicate must not buy itself a silent no-op.
            ("REBIND_MANIFEST_DIGEST:0", "rebind", "report", [("every entry except this report, digest to `", "every entry except this report, digest to `" + "a" * 64 + "`x`", 1)]),
            ("REBIND_DOCUMENT_DIGEST:0", "rebind", "report", [("the geometry below describes has SHA-256 `", "the geometry below describe has SHA-256 `", 1)]),
            # Unchecked, this value went into the report through the substitution
            # template, its backslash read as a template escape.
            ("REBIND_DOCUMENT_DIGEST_SHAPE", "rebind", "manifest", [(("files", document_entry, "sha256"), "set", "A" * 63 + "\\")]),
            ("ACCEPTANCE_REPORT_INPUTS_REQUIRED", "cli", None, None),
            ("REBIND_ONLY_REPORT_IS_THE_PACKAGE_REPORT", "cli", None, ["--rebind-only", "--report", "elsewhere.md"]),
        ]

        observed: set[tuple[tuple[str, int, int], str]] = set()
        for index, (expected, driver, target, operations) in enumerate(rows):
            with self.subTest(refusal=expected, driver=driver, target=target, row=index):
                raised, untouched, _report, no_temporary = drive(f"row-{index}", driver, target, operations)
                self.assertIsNotNone(raised, "the malformed input was accepted")
                self.assertIs(type(raised), SystemExit if driver == "cli" else ValueError)
                text = raised.code if isinstance(raised, SystemExit) else str(raised)
                self.assertEqual(text, expected)
                self.assertTrue(no_temporary, "a refusal left its temporary file behind")
                self.assertTrue(untouched, "a refusal changed the report")
                site = site_of(raised)
                self.assertIsNotNone(site, "the refusal was not raised at a site the reader names")
                observed.add((site, text.partition(":")[0]))

        # Held to the closed world in both directions and by equality: a site
        # no row reaches is named, and a row credited to something the reader
        # does not name is refused.
        # Against the empty set directly, and no named exemption list: a site here is a
        # triple carrying LINE NUMBERS, so any entry would rot at the first edit to the
        # generator. A name promising an extension point nobody can use is worse than
        # none, because the next reader spends the edit discovering it does not work.
        self.assertEqual(world - observed, set())
        self.assertEqual(observed - world, set())

        # The reader itself, broken on in-memory sources.
        base = source_path.read_text(encoding="utf-8")

        def edited(old: str, new: str) -> str:
            self.assertEqual(base.count(old), 1, f"scanner plant anchor {old!r}")
            return base.replace(old, new)

        plants = (
            ("a new literal code joins the world",
             base + "\n\ndef planted_check(value):\n    raise ValueError(\"PLANTED_CODE\")\n",
             lambda found, unknown: "PLANTED_CODE" in {c for codes in found.values() for c in codes} and not unknown),
            ("a raise of a bare parameter is unclassified",
             base + "\n\ndef planted_check(value):\n    raise ValueError(value)\n",
             lambda found, unknown: bool(unknown)),
            ("a helper label held in a variable is unclassified",
             edited('geometry.get("page_count"), "PAGE_COUNT")', 'geometry.get("page_count"), page_label)'),
             lambda found, unknown: bool(unknown)),
            ("a third row of the digest-shape table is derived",
             edited('("BOUND_MANIFEST_DIGEST", bound_manifest_digest),', '("BOUND_MANIFEST_DIGEST", bound_manifest_digest),\n        ("PLANTED_DIGEST", bound_manifest_digest),'),
             lambda found, unknown: "ACCEPTANCE_PLANTED_DIGEST_SHAPE" in {c for codes in found.values() for c in codes} and not unknown),
            ("a renamed pinned helper is unclassified",
             edited("def require_non_negative_int(", "def require_count("),
             lambda found, unknown: bool(unknown)),
            ("a raise of another exception type is unclassified",
             base + "\n\ndef planted_check(value):\n    raise RuntimeError(\"PLANTED_CODE\")\n",
             lambda found, unknown: bool(unknown)),
        )
        for label, planted, holds in plants:
            with self.subTest(scanner_plant=label):
                found, unknown = generator_refusal_sites(planted)
                self.assertTrue(holds(found, unknown), f"found={len(found)} unclassified={unknown}")

    @staticmethod
    def _indexed_evidence_reads(source: str) -> list[str]:
        """Constant-key subscripts on values this module read out of a JSON file.

        The names come from every form that binds one name to a value - a single-name
        assignment, an annotated one, and `:=` - from `load_json(...)`, and every name
        bound from a `.get(...)` on one of those - rather
        than listed here. A list I keep by hand goes stale the first time a figure is read
        from a new mapping, and the defect this guards is precisely one that arrived with
        a figure added later.

        Why this and not "no constant-key subscript at all": `steps["package_verifier"]`
        is such a read and is correct, because the line above it asserts that the key set
        of `steps` equals GATE_ROWS. The class is not indexing; it is indexing a mapping
        whose keys nothing has established.
        """
        tree = ast.parse(source)
        parsed: set[str] = set()
        for _ in range(2):  # the direct binding, then one level of `.get` off it
            for node in ast.walk(tree):
                if isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
                    target = node.target
                elif isinstance(node, ast.Assign) and len(node.targets) == 1:
                    target = node.targets[0]
                else:
                    continue
                if not isinstance(target, ast.Name):
                    continue
                value = node.value
                if isinstance(value, ast.Call):
                    function = value.func
                    if isinstance(function, ast.Name) and function.id == "load_json":
                        parsed.add(target.id)
                    elif (
                        isinstance(function, ast.Attribute)
                        and function.attr == "get"
                        and isinstance(function.value, ast.Name)
                        and function.value.id in parsed
                    ):
                        parsed.add(target.id)
        found = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Name)
                and node.value.id in parsed
                and isinstance(node.slice, ast.Constant)
                and isinstance(node.slice.value, str)
            ):
                found.append(f"{node.value.id}[{node.slice.value!r}] at line {node.lineno}")
        return found

    def test_acceptance_report_generator_reads_evidence_by_name_not_by_index(self) -> None:
        """Every figure asks its mapping with `.get`, so an absent key refuses by name.

        Half the failure-surface figures were indexed and half were not, and the indexed
        half raised a bare KeyError for a baseline missing a key: not a raise site, so
        outside the closed world the sweep above holds this generator to, and outside the
        vocabulary its callers are promised.

        A ratchet rather than a row per figure: rows cover the figures that exist, and the
        defect arrived with a figure that did not exist when the rows were written.
        """
        module = sys.modules[update_report.__module__]
        source = Path(inspect.getsourcefile(module)).read_text(encoding="utf-8")
        self.assertEqual(self._indexed_evidence_reads(source), [])

        # The finder bites: planted reads of both shapes are named.
        planted = source.replace(
            'baseline.get("engine_refusal_codes")', 'baseline["engine_refusal_codes"]', 1
        ).replace(
            'runtime.get("witnessed_codes")', 'runtime["witnessed_codes"]', 1
        )
        self.assertEqual(len(self._indexed_evidence_reads(planted)), 2)

        # And it does not bite a mapping this module built and checked itself - the
        # control that decides whether the predicate names a class or just an operator.
        self.assertNotIn(
            "steps", " ".join(self._indexed_evidence_reads(planted))
        )

    def test_evidence_read_finder_handles_annotations(self) -> None:
        """Annotated evidence stays classified; locally built mappings stay outside."""
        for annotation in ("", ": dict"):
            with self.subTest(binding=annotation or "unannotated"):
                source = (
                    f"evidence{annotation} = load_json(path)\n"
                    f"nested{annotation} = evidence.get('runtime')\n"
                    "evidence['missing']\n"
                    "nested['missing']\n"
                    "local: dict = {'checked': 1}\n"
                    "local['checked']\n"
                    "declared_only: dict\n"
                )
                self.assertEqual(
                    self._indexed_evidence_reads(source),
                    ["evidence['missing'] at line 3", "nested['missing'] at line 4"],
                )
        # The third form that binds one name: `:=`. Measured before it was added - the plain
        # assignment was reported and this binding, with the same read, was not.
        with self.subTest(binding="walrus"):
            source = (
                "if (evidence := load_json(path)):\n"
                "    evidence['missing']\n"
            )
            self.assertEqual(
                self._indexed_evidence_reads(source), ["evidence['missing'] at line 2"])

        module = sys.modules[update_report.__module__]
        source = Path(inspect.getsourcefile(module)).read_text(encoding="utf-8")
        anchor = '    baseline = load_json(root / "tests" / "failure-surface-baseline.json")'
        read = 'baseline.get("bridge_refusal_codes")'
        self.assertEqual(source.count(anchor), 1)
        self.assertEqual(source.count(read), 1)
        planted = source.replace(
            anchor,
            anchor + '\n    extra_evidence: dict = load_json(root / "tests" / "failure-surface-baseline.json")',
        ).replace(read, 'extra_evidence["bridge_refusal_codes"]')
        # Only what the plant adds is this test's fact. Whether the generator itself reads a
        # figure by index is the name-not-index test's, and counting it here reddened this
        # test on that defect too - measured. Line numbers are dropped: the plant adds one.
        def reads(text: str) -> list[str]:
            return sorted(
                finding.rsplit(" at line ", 1)[0]
                for finding in self._indexed_evidence_reads(text)
            )

        self.assertEqual(
            reads(planted),
            sorted(reads(source) + ["extra_evidence['bridge_refusal_codes']"]),
        )

    def test_a_failed_replace_leaves_no_temporary_report(self) -> None:
        """No residue on the path where the replace itself fails.

        The sweep's rows show no temporary after a refusal, because every refusal they
        drive happens before anything is written. What none of them reaches is a write
        that succeeded followed by a replace that did not - a locked destination, a device
        error - and the sentence above those rows promised every path.
        """
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "ACCEPTANCE-REPORT.md"
            report.write_text("before\n", encoding="utf-8", newline="\n")
            with patch.object(Path, "replace", side_effect=OSError("destination locked")):
                with self.assertRaises(OSError):
                    write_through_temporary(report, "after\n")
            self.assertEqual(report.read_text(encoding="utf-8"), "before\n")
            self.assertEqual(
                [path.name for path in Path(temporary).iterdir()],
                ["ACCEPTANCE-REPORT.md"],
            )
        # Control: the ordinary path still replaces, and still leaves nothing behind.
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "ACCEPTANCE-REPORT.md"
            report.write_text("before\n", encoding="utf-8", newline="\n")
            write_through_temporary(report, "after\n")
            self.assertEqual(report.read_text(encoding="utf-8"), "after\n")
            self.assertEqual(
                [path.name for path in Path(temporary).iterdir()],
                ["ACCEPTANCE-REPORT.md"],
            )

    def test_a_writer_leaves_another_writers_temporary_alone(self) -> None:
        """Another writer's temporary is not this call's to touch.

        The name used to be `<report>.tmp` for every writer, so a second writer overwrote
        the first one's bytes and its `finally` then deleted a file it did not own. Planted
        here at that old shared name: a call that takes its own name leaves it exactly as
        it was. This stood inside the failed-replace case, whose name it did not fit.
        """
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "ACCEPTANCE-REPORT.md"
            report.write_text("before\n", encoding="utf-8", newline="\n")
            neighbour = report.with_name(report.name + ".tmp")
            neighbour.write_text("another writer's text\n", encoding="utf-8", newline="\n")
            write_through_temporary(report, "after\n")
            self.assertEqual(report.read_text(encoding="utf-8"), "after\n")
            # Asked to exist first: the shared name removes it, and reading a removed file
            # reddened this case as a FileNotFoundError rather than under its own message.
            self.assertTrue(
                neighbour.is_file(), "a temporary this call did not create was removed")
            self.assertEqual(
                neighbour.read_text(encoding="utf-8"), "another writer's text\n",
                "a temporary this call did not create was overwritten")
        # And a file another writer puts at THIS call's temporary name once the replace has
        # moved the temporary away: the name is free from that moment, and the `finally`
        # used to remove whatever stood there. Planted by a replace that moves the file and
        # then writes at the name it left.
        real_replace = Path.replace
        reused = []

        def replace_then_reuse(source, target):
            moved = real_replace(source, target)
            source.write_text("another writer's text\n", encoding="utf-8", newline="\n")
            reused.append(source)
            return moved

        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "ACCEPTANCE-REPORT.md"
            report.write_text("before\n", encoding="utf-8", newline="\n")
            with patch.object(Path, "replace", replace_then_reuse):
                write_through_temporary(report, "after\n")
            self.assertEqual(report.read_text(encoding="utf-8"), "after\n")
            self.assertEqual(len(reused), 1)
            self.assertTrue(reused[0].is_file(),
                            "a file another writer put at the released name was removed")

    def test_a_failure_before_the_write_leaves_no_temporary_report(self) -> None:
        """No residue when the failure comes the moment the temporary exists.

        Before anything is written - where an interrupt lands between creating the file
        and using it. Closing the handle and naming the path used to stand before the
        `try`, so this left the file. The close really happens before the failure: an open
        handle is a file Windows cannot remove, and that would measure the platform instead
        of the code. This stood inside the failed-replace case, whose name it did not fit.
        """
        real_close = os.close

        def close_then_fail(handle):
            real_close(handle)
            raise RuntimeError("interrupted after the temporary was created")

        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "ACCEPTANCE-REPORT.md"
            report.write_text("before\n", encoding="utf-8", newline="\n")
            with patch.object(os, "close", close_then_fail):
                with self.assertRaises(RuntimeError):
                    write_through_temporary(report, "after\n")
            self.assertEqual(report.read_text(encoding="utf-8"), "before\n")
            self.assertEqual(
                [path.name for path in Path(temporary).iterdir()],
                ["ACCEPTANCE-REPORT.md"],
            )

    def test_acceptance_report_machine_fields_follow_evidence(self) -> None:
        rendered = self._render_acceptance_report(
            {"source_mode": "strict", "external_source_checks": "PASS"}
        )
        self.assertIn("Verification date: `2030-02-03 UTC`", rendered)
        self.assertIn(
            "| Contract regression cases | `2005/2005 PASS` |", rendered
        )
        self.assertIn("| Failure-surface ratchet | `2009/2009 PASS` |", rendered)
        self.assertIn("7 non-blocking warnings", rendered)
        self.assertIn(
            "Automated geometry evidence does not claim", rendered
        )
        self.assertNotIn("visually inspected", rendered)
        self.assertIn("headless LibreOffice PDF render", rendered)
        self.assertNotIn("Microsoft Word", rendered)

        # The geometry is evidence about one document: a render that does not
        # name the document it rendered, or names another, is refused rather
        # than published as describing the bound one.
        for label, overrides, code in (
            ("geometry names no rendered document", {"source_docx_sha256": None},
             "GEOMETRY_DOCUMENT_SHAPE"),
            ("geometry names a document in the wrong form", {"source_docx_sha256": "b" * 64},
             "GEOMETRY_DOCUMENT_SHAPE"),
            ("geometry rendered a different document", {"source_docx_sha256": "C" * 64},
             "GEOMETRY_DOCUMENT_MISMATCH"),
        ):
            with self.subTest(geometry=label):
                with self.assertRaisesRegex(ValueError, rf"^{code}$"):
                    self._render_acceptance_report(
                        {"source_mode": "strict", "external_source_checks": "PASS"},
                        geometry_overrides=overrides,
                    )

    def test_acceptance_report_requires_verified_core(self) -> None:
        core_manifest = next(
            item
            for item in json.loads(
                (ROOT / "SOURCE-MANIFEST.json").read_text(encoding="utf-8")
            )["inputs"]
            if item["role"] == "immutable_nc25_core"
        )
        # A verified external core renders the disclosure line with the exact hash.
        rendered = self._render_acceptance_report(
            {"source_mode": "strict", "external_source_checks": "PASS"}
        )
        self.assertIn("## Core source binding", rendered)
        self.assertIn("was bound and verified", rendered)
        self.assertIn(core_manifest["sha256"], rendered)
        self.assertIn(core_manifest["file_name"], rendered)
        self.assertNotIn("PENDING core-source binding", rendered)
        self.assertEqual(
            core_deposit_availability_claims(rendered), [], "CORE_DEPOSIT_AVAILABILITY"
        )
        self.assertIn(
            "local core file supplied through `NC25_SOURCES_ROOT`",
            " ".join(rendered.split()),
            "LOCAL_CORE_SUPPLY_INSTRUCTION",
        )
        false_claims = (
            "The core can be retrieved from the deposit.",
            "The core is available from the DOI record.",
            "The core is supplied by the deposit.",
            "Obtain the core (DOI 10.17605/OSF.IO/NHTC5).",
            "Download the core via the public DOI record.",
            "Fetch the core through the OSF deposit.",
            "THE CORE CAN BE RETRIEVED\nFROM THE DEPOSIT.",
            "The core can be obtained after verifying its name, byte length, "
            "line count and digest from the deposit.",
            "The core is not published locally but is available from the DOI record.",
            "The core is not available locally; download it from the deposit.",
            "The core is not only available from the DOI record.",
        )
        honest_instructions = (
            "The core is not part of the public deposit; the DOI identifies the core line.",
            "The core was supplied locally; the DOI identifies its lineage.",
            "The core is not available from the DOI record.",
            "The core is not yet available from the DOI record.",
            "The core cannot be retrieved from the deposit.",
            "Do not fetch the core from the deposit.",
            "The core isn't currently available from the DOI record.",
            "Never download the core from the deposit.",
        )
        for claim in false_claims:
            with self.subTest(availability_claim=claim):
                self.assertTrue(
                    core_deposit_availability_claims(claim),
                    "CORE_DEPOSIT_AVAILABILITY_MISSED",
                )
        for instruction in honest_instructions:
            with self.subTest(honest_instruction=instruction):
                self.assertEqual(
                    core_deposit_availability_claims(instruction), [],
                    "CORE_DEPOSIT_AVAILABILITY_FALSE_POSITIVE",
                )
        # A NOT_RUN core, or an absent field, must refuse the release report.
        with self.assertRaisesRegex(ValueError, "^EXTERNAL_CORE_NOT_VERIFIED(:|$)"):
            self._render_acceptance_report(
                {"source_mode": "standalone", "external_source_checks": "NOT_RUN"}
            )
        with self.assertRaisesRegex(ValueError, "^ACCEPTANCE_EXTERNAL_CORE_MISSING(:|$)"):
            self._render_acceptance_report(None)
        with self.assertRaisesRegex(ValueError, "^STRICT_PACKAGE_VERIFIER_REQUIRED(:|$)"):
            self._render_acceptance_report(
                {"source_mode": "strict", "external_source_checks": "PASS"},
                package_verifier_total=len(STANDALONE_PACKAGE_CHECK_IDS),
            )
        with self.assertRaisesRegex(ValueError, "^ACCEPTANCE_EXTERNAL_CORE_MODE(:|$)"):
            self._render_acceptance_report(
                {"source_mode": "standalone", "external_source_checks": "PASS"}
            )

    def test_mapping_witness_case_and_counterpart_profile_contracts(self) -> None:
        # Three casings, not one: both lower passes a comparison that merely
        # lower-cases both sides AND one that compares raw strings that happen
        # to agree. Only the MIXED rows prove the comparison is insensitive.
        fixture = self.fixture()
        casings = (
            ("both lower", str.lower, str.lower),
            ("profile upper, declaration lower", str.upper, str.lower),
            ("profile lower, declaration upper", str.lower, str.upper),
        )
        for label, profile_case, declaration_case in casings:
            with self.subTest(casing=label):
                profile = copy.deepcopy(fixture.profile)
                declaration = copy.deepcopy(fixture.declaration)
                witness = profile["mapping_witness"]
                witness["witness_hash"] = profile_case(witness["witness_hash"])
                binding = declaration["mapping_witness_binding"]
                binding["witness_hash"] = declaration_case(binding["witness_hash"])
                self.assertNotEqual(
                    witness["witness_hash"] == binding["witness_hash"],
                    label != "both lower",
                    "the mixed rows must differ as raw strings",
                )
                bound_profile, bound_declaration, _, _ = bind_fixture(
                    profile,
                    declaration,
                    fixture.grant,
                    fixture.intent,
                )
                engine = UniversalConnectionLedger(
                    bound_profile,
                    bound_declaration,
                    signing_key=b"synthetic-reference-signing-key",
                    clock=fixture.clock,
                )
                self.assertEqual(engine.status, "DRAFT")

        # The standalone declaration validator also rejects a damaged
        # counterpart profile. Constructor-level profile validation is a
        # separate, earlier boundary and is not bypassed by this test.
        for code, path, value in (
            ("PROFILE_CORE_MISMATCH", ("core_anchor",), {}),
            ("PROFILE_WITNESS_HASH", ("mapping_witness", "witness_hash"), None),
            ("PROFILE_WITNESS_HASH", ("mapping_witness", "witness_hash"), "a" * 63),
        ):
            with self.subTest(counterpart_profile=code, value=value):
                profile = copy.deepcopy(fixture.profile)
                declaration = copy.deepcopy(fixture.declaration)
                target = profile
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                declaration["profile_binding"]["profile_hash"] = sha256_hex(profile)
                before = copy.deepcopy((declaration, profile))
                with self.assertRaisesRegex(ContractViolation, "^" + code + "(:|$)"):
                    validate_declaration(declaration, profile)
                self.assertEqual((declaration, profile), before)
        validate_declaration(fixture.declaration, fixture.profile)

    def test_banking_crosswalk_mirrors_fixed_failure_posture(self) -> None:
        crosswalk = json.loads(
            (
                ROOT
                / "profiles"
                / "banking"
                / "questionnaire-crosswalk.json"
            ).read_text(encoding="utf-8")
        )
        entry = next(
            item
            for item in crosswalk["sections"]
            if item["questionnaire_section"].startswith("7.")
        )
        statement = entry["connection_effect"]
        self.assertIn("missing required data is REFUSAL", statement)
        self.assertIn("ambiguity is MANUAL_REVIEW", statement)
        self.assertNotIn("configurable routing", statement)

    def test_architect_selectors_and_registry_projection_contracts(self) -> None:
        fixture = self.fixture()
        engine, intent, _ = fixture.engine()
        active_connector_id = engine.declaration["connector"]["connector_id"]
        record = engine.registry_record(
            active_connector_id,
            actor_scope=ROLE_ARCHITECT,
        )
        self.assertEqual(record["connector_id"], active_connector_id)
        with self.assertRaisesRegex(ContractViolation, "^CONNECTOR_NOT_FOUND(:|$)"):
            engine.registry_record(
                "connector-not-active",
                actor_scope=ROLE_ARCHITECT,
            )

        result = engine.evaluate_intent(intent, fixture.evidence, actor_scope=ROLE_OPERATOR)
        for name, read, code, valid_hash in (
            ("permit", engine.architect_permit, "PERMIT_HASH", result["permit_hash"]),
            ("decision", engine.architect_decision, "REQUEST_HASH", result["request_hash"]),
        ):
            expected = read(valid_hash, actor_scope=ROLE_ARCHITECT)
            self.assertEqual(read(valid_hash.lower(), actor_scope=ROLE_ARCHITECT), expected)
            for value in (None, 0, [], "", "a" * 63, "g" * 64):
                with self.subTest(selector=name, value=value):
                    before = engine._snapshot_state()
                    with self.assertRaisesRegex(ContractViolation, "^" + code + "(:|$)"):
                        read(value, actor_scope=ROLE_ARCHITECT)
                    self.assertEqual(engine._snapshot_state(), before)
        for value in (None, 0, [], "", "1invalid"):
            with self.subTest(selector="connector", value=value):
                with self.assertRaisesRegex(ContractViolation, "^REGISTRY_CONNECTOR_ID(:|$)"):
                    engine.registry_record(value, actor_scope=ROLE_ARCHITECT)

        # This is output-corruption injection at the real registry boundary,
        # not a claim that these records are reachable from ordinary input.
        validate_record = engine._assert_registry_projection
        rows = [("schema_version", "2.0.0", "REGISTRY_SCHEMA_VERSION")]
        rows += [(field, value, "REGISTRY_IDENTIFIER")
                 for field in ("connector_id", "profile_id", "declaration_id")
                 for value in (None, "", "1invalid")]
        rows += [(field, value, "REGISTRY_VERSION")
                 for field in ("profile_version", "declaration_version")
                 for value in (None, "bad")]
        rows += [(field, value, "REGISTRY_HASH")
                 for field in ("profile_hash", "declaration_hash", "ledger_head_hash")
                 for value in (None, "a" * 63)]
        rows += [("core_anchor", None, "REGISTRY_CORE_ANCHOR"),
                 ("core_anchor", {}, "REGISTRY_CORE_ANCHOR"),
                 ("activated_at", 0, "REGISTRY_ACTIVATED_AT")]
        rows += [("revoked", value, "REGISTRY_REVOKED") for value in (None, 0, 1, "false")]
        rows += [("latest_receipt_root", value, "REGISTRY_RECEIPT_ROOT")
                 for value in (0, "a" * 63)]
        for field, value, code in rows:
            with self.subTest(registry_contract=code, field=field, value=value):
                def corrupt_and_validate(record):
                    record[field] = copy.deepcopy(value)
                    before_record = copy.deepcopy(record)
                    try:
                        return validate_record(record)
                    finally:
                        self.assertEqual(record, before_record)
                before = engine._snapshot_state()
                with patch.object(engine, "_assert_registry_projection", side_effect=corrupt_and_validate):
                    with self.assertRaisesRegex(IntegrityViolation, "^REGISTRY_PROJECTION_INVALID(:|$)") as caught:
                        engine.registry_record(active_connector_id, actor_scope=ROLE_ARCHITECT)
                self.assertIsInstance(caught.exception.__cause__, ContractViolation)
                self.assertEqual(caught.exception.__cause__.code, code)
                self.assertEqual(engine._snapshot_state(), before)
        request = fixture.execution_request(engine, result, intent)
        engine.commit_execution(request, actor_scope=ROLE_EXECUTOR,
                                route_permit_hash=request["permit_hash"])
        record = engine.registry_record(active_connector_id, actor_scope=ROLE_ARCHITECT)
        self.assertEqual(record["latest_receipt_root"], sha256_hex(engine.receipt_hashes))
        self.assertEqual(record["revoked"], False)

    def test_detached_signer_configuration_and_event_integrity(self) -> None:
        fixture = self.fixture()
        key = bytes(range(32))
        private = Ed25519DetachedSigner.from_private_bytes("fixture-signing", key)
        public = Ed25519DetachedSigner.from_public_bytes(
            "fixture-signing", private.public_key_bytes()
        )
        message = b"synthetic-signer-contract"
        self.assertTrue(public.verify(message, private.sign(message)))
        with self.assertRaisesRegex(ContractViolation, "^ED25519_PRIVATE_KEY_REQUIRED(:|$)"):
            public.sign(message)
        for name, make, code in (
            ("private", Ed25519DetachedSigner.from_private_bytes, "ED25519_PRIVATE_KEY"),
            ("public", Ed25519DetachedSigner.from_public_bytes, "ED25519_PUBLIC_KEY"),
        ):
            for value in (None, "x" * 32, b"", b"x" * 31, b"x" * 33, bytearray(key), list(key)):
                with self.subTest(signer_bytes=name, value_type=type(value).__name__, value=value):
                    with self.assertRaisesRegex(ContractViolation, "^" + code + "(:|$)"):
                        make("fixture-signing", value)

        def permit_with_id(key_id):
            signer = HmacDetachedSigner(key, "fixture-signing")
            signer.key_id = key_id
            return fixture.engine(permit_signer=signer)

        for name, make in (
            ("hmac", lambda key_id: HmacDetachedSigner(key, key_id)),
            ("ed25519", lambda key_id: Ed25519DetachedSigner.from_private_bytes(key_id, key)),
            ("permit", permit_with_id),
        ):
            for value in ("k", "k" * 200):
                with self.subTest(signer_id=name, valid_length=len(value)):
                    self.assertIsNotNone(make(value))
            for value in (None, 0, True, "", "k" * 201):
                with self.subTest(signer_id=name, invalid_id=value):
                    with self.assertRaisesRegex(ContractViolation, "^SIGNATURE_KEY_ID(:|$)"):
                        make(value)

        with self.subTest(signer_key="hmac-empty"):
            with self.assertRaisesRegex(ContractViolation, "^SIGNING_KEY_REQUIRED(:|$)"):
                HmacDetachedSigner(b"", "fixture-signing")
        profile, declaration, _, _ = bind_fixture(
            fixture.profile, fixture.declaration, fixture.grant, fixture.intent
        )
        with self.subTest(signer_key="event-ledger-empty"):
            with self.assertRaisesRegex(ContractViolation, "^SIGNING_KEY_REQUIRED(:|$)"):
                UniversalConnectionLedger(
                    profile, declaration, signing_key=b"", clock=fixture.clock,
                    permit_signer=private, event_signer=private,
                )

        for name, code in (("event_signer", "EVENT_SIGNER_INVALID"),
                           ("permit_signer", "PERMIT_SIGNER_INVALID")):
            for attrs in ({}, {"sign": lambda self, value: {}},
                          {"verify": lambda self, value, signature: True},
                          {"sign": 0, "verify": 0}):
                with self.subTest(signer_interface=name, attributes=tuple(attrs)):
                    invalid = type("InvalidSigner", (), attrs)()
                    with self.assertRaisesRegex(ContractViolation, "^" + code + "(:|$)"):
                        fixture.engine(**{name: invalid})

        with patch("nc25_universal_ledger._ED25519_AVAILABLE", False):
            for name, operation in (
                ("generate", lambda: Ed25519DetachedSigner.generate("fixture-signing")),
                ("private", lambda: Ed25519DetachedSigner.from_private_bytes("fixture-signing", key)),
                ("public", lambda: Ed25519DetachedSigner.from_public_bytes("fixture-signing", public.public_key_bytes())),
            ):
                with self.subTest(signer_backend=name):
                    with self.assertRaisesRegex(ContractViolation, "^ED25519_UNAVAILABLE(:|$)"):
                        operation()
        self.assertTrue(public.verify(message, private.sign(message)))

        fixture = self.fixture()
        signer = Ed25519DetachedSigner.from_private_bytes(
            "fixture-ledger-key-v1",
            bytes(range(32)),
        )
        engine, _, _ = fixture.engine(event_signer=signer)
        self.assertTrue(engine.ledger.verify())

        event = engine.ledger._events[0]
        original = copy.deepcopy(event["signature"])
        self.assertEqual(original["version"], "1")
        self.assertEqual(original["algorithm"], "Ed25519")
        encoded = original["signature"]
        event["signature"]["signature"] = (
            ("A" if encoded[0] != "A" else "B") + encoded[1:]
        )
        self.assertFalse(engine.ledger.verify())

        event["signature"] = original
        self.assertTrue(engine.ledger.verify())
        engine.ledger._event_signer = Ed25519DetachedSigner.from_private_bytes(
            "fixture-ledger-key-v1",
            bytes(range(31, -1, -1)),
        )
        self.assertFalse(engine.ledger.verify())

    def test_signer_identity_mismatch_is_not_a_chain_verdict(self) -> None:
        """A signer that cannot speak for the envelope refuses as such.

        Two cases a type-based guard could not see: an envelope whose
        algorithm the configured signer does not implement, and one carrying a
        different declared key_id. Both are the absence of any means to
        answer, not an answer about the chain, and a routine key rotation is
        the second one.

        The control keeps the third case a chain verdict: the same declared
        key_id over different key material is indistinguishable from a forger
        by construction, so widening the new channel to cover it would let the
        channel swallow a forged chain.
        """
        fixture = self.fixture()
        engine, _, _ = fixture.engine()
        self.assertTrue(engine.ledger.verify())
        envelope = engine.ledger._events[0]["signature"]
        self.assertEqual(envelope["algorithm"], "HMAC-SHA256")
        self.assertEqual(envelope["key_id"], "ledger-hmac")
        original = engine.ledger._event_signer

        # The persisted chain is HMAC and the configured signer speaks
        # Ed25519 only. The earlier guard looked at this pairing the other way
        # round, so this direction read as a broken chain.
        engine.ledger._event_signer = Ed25519DetachedSigner.from_private_bytes(
            "fixture-ledger-key-v1",
            bytes(range(32)),
        )
        with self.assertRaisesRegex(
            IntegrityViolation, r"^EVENT_SIGNER_REQUIRED(:|$)"
        ):
            engine.ledger.verify()

        # Same algorithm, rotated key under a new declared id: nothing here
        # can verify the persisted envelopes, and saying "chain failure"
        # would report a forgery where the truth is a configuration gap.
        engine.ledger._event_signer = HmacDetachedSigner(
            b"rotated-reference-signing-key",
            "ledger-hmac-2",
        )
        with self.assertRaisesRegex(
            IntegrityViolation, r"^EVENT_SIGNER_REQUIRED(:|$)"
        ):
            engine.ledger.verify()

        # CONTROL, over-firing side: the declared identity matches and only
        # the key material differs. That is exactly what a forger presents,
        # so it stays a chain verdict on the bool and on the public surface.
        engine.ledger._event_signer = HmacDetachedSigner(
            b"a-different-secret-under-the-same-declared-id",
            "ledger-hmac",
        )
        self.assertFalse(engine.ledger.verify())
        with self.assertRaisesRegex(
            IntegrityViolation, r"^LEDGER_CHAIN_FAILURE(:|$)"
        ):
            engine.observer_projection(actor_scope=ROLE_ARCHITECT)

        # CONTROL, quiet side: the original signer still verifies its chain.
        engine.ledger._event_signer = original
        self.assertTrue(engine.ledger.verify())

    def allow_permit(self, fixture, engine, intent):
        result = engine.evaluate_intent(
            intent,
            fixture.evidence,
            actor_scope=ROLE_OPERATOR,
        )
        self.assertEqual(result["disposition"], "ALLOW")
        return result

    def test_permit_signature_is_versioned_envelope_end_to_end(self) -> None:
        fixture = self.fixture()
        engine, intent, _ = fixture.engine()
        result = self.allow_permit(fixture, engine, intent)
        view = engine.architect_permit(
            result["permit_hash"],
            actor_scope=ROLE_ARCHITECT,
        )
        envelope = view["signature"]
        self.assertEqual(set(envelope), set(SIGNATURE_ENVELOPE_FIELDS))
        self.assertEqual(envelope["version"], "1")
        self.assertEqual(envelope["algorithm"], "HMAC-SHA256")
        self.assertEqual(envelope["key_id"], "reference-hmac")
        issued = [
            event
            for event in engine.ledger.events_copy()
            if event["event_type"] == "PERMIT_ISSUED"
        ]
        self.assertEqual(len(issued), 1)
        self.assertEqual(issued[0]["payload"]["permit_signature"], envelope)
        receipt = engine.commit_execution(
            fixture.execution_request(engine, result, intent),
            actor_scope=ROLE_EXECUTOR,
            route_permit_hash=result["permit_hash"],
        )
        self.assertEqual(receipt["outcome"], "COMMITTED")

    def test_permit_signature_tamper_and_envelope_shape_fail_closed(self) -> None:
        fixture = self.fixture()
        engine, intent, _ = fixture.engine()
        result = self.allow_permit(fixture, engine, intent)
        record = engine.permits[result["permit_hash"]]
        request = fixture.execution_request(engine, result, intent)
        original = copy.deepcopy(record.signature)

        encoded = original["signature"]
        record.signature["signature"] = (
            ("a" if encoded[0] != "a" else "b") + encoded[1:]
        )
        with self.assertRaisesRegex(
            IntegrityViolation, "^PERMIT_SIGNATURE_FAILURE(:|$)"
        ):
            engine.commit_execution(
                request,
                actor_scope=ROLE_EXECUTOR,
                route_permit_hash=result["permit_hash"],
            )

        record.signature = {
            key: value
            for key, value in original.items()
            if key != "key_id"
        }
        with self.assertRaisesRegex(
            IntegrityViolation, "^PERMIT_SIGNATURE_ENVELOPE(:|$)"
        ):
            engine.commit_execution(
                request,
                actor_scope=ROLE_EXECUTOR,
                route_permit_hash=result["permit_hash"],
            )

        record.signature = dict(original, version=1)
        with self.assertRaisesRegex(
            IntegrityViolation, "^PERMIT_SIGNATURE_ENVELOPE(:|$)"
        ):
            engine.commit_execution(
                request,
                actor_scope=ROLE_EXECUTOR,
                route_permit_hash=result["permit_hash"],
            )

        record.signature = original
        receipt = engine.commit_execution(
            request,
            actor_scope=ROLE_EXECUTOR,
            route_permit_hash=result["permit_hash"],
        )
        self.assertEqual(receipt["outcome"], "COMMITTED")

    def test_ed25519_permit_signer_signs_and_verifies_independently(self) -> None:
        fixture = self.fixture()
        signer = Ed25519DetachedSigner.generate("permit-ed-1")
        engine, intent, _ = fixture.engine(permit_signer=signer)
        result = self.allow_permit(fixture, engine, intent)
        view = engine.architect_permit(
            result["permit_hash"],
            actor_scope=ROLE_ARCHITECT,
        )
        envelope = view["signature"]
        self.assertEqual(envelope["algorithm"], "Ed25519")
        self.assertEqual(envelope["key_id"], "permit-ed-1")
        # Independent verification from the published public key alone.
        verifier = Ed25519DetachedSigner.from_public_bytes(
            "permit-ed-1",
            signer.public_key_bytes(),
        )
        self.assertTrue(
            verifier.verify(result["permit_hash"].encode("ascii"), envelope)
        )
        receipt = engine.commit_execution(
            fixture.execution_request(engine, result, intent),
            actor_scope=ROLE_EXECUTOR,
            route_permit_hash=result["permit_hash"],
        )
        self.assertEqual(receipt["outcome"], "COMMITTED")

    def test_permit_wrong_key_and_unknown_key_fail_closed(self) -> None:
        fixture = self.fixture()
        signer = Ed25519DetachedSigner.generate("permit-ed-1")
        engine, intent, _ = fixture.engine(permit_signer=signer)
        result = self.allow_permit(fixture, engine, intent)
        record = engine.permits[result["permit_hash"]]
        request = fixture.execution_request(engine, result, intent)
        message = result["permit_hash"].encode("ascii")

        # Same key_id, different private key: the crypto check must reject.
        impostor = Ed25519DetachedSigner.generate("permit-ed-1")
        record.signature = dict(impostor.sign(message))
        with self.assertRaisesRegex(
            IntegrityViolation, "^PERMIT_SIGNATURE_FAILURE(:|$)"
        ):
            engine.commit_execution(
                request,
                actor_scope=ROLE_EXECUTOR,
                route_permit_hash=result["permit_hash"],
            )

        # A key this engine never held: unknown, fail closed.
        foreign = Ed25519DetachedSigner.generate("foreign-key")
        record.signature = dict(foreign.sign(message))
        with self.assertRaisesRegex(IntegrityViolation, "^PERMIT_KEY_UNKNOWN(:|$)"):
            engine.commit_execution(
                request,
                actor_scope=ROLE_EXECUTOR,
                route_permit_hash=result["permit_hash"],
            )

    def test_permit_key_rotation_keeps_old_permits_verifiable(self) -> None:
        fixture = self.fixture()
        key_one = Ed25519DetachedSigner.generate("permit-key-1")
        engine, intent, _ = fixture.engine(permit_signer=key_one)
        result_one = self.allow_permit(fixture, engine, intent)

        key_two = Ed25519DetachedSigner.generate("permit-key-2")
        engine.rotate_permit_signer(key_two, actor_scope=ROLE_GOVERNANCE)

        # New permits are signed under the new key.
        second_intent = copy.deepcopy(intent)
        second_intent["intent_id"] = "synthetic-intent-002"
        second_intent["idempotency_key"] = "synthetic-idempotency-002"
        second_evidence = copy.deepcopy(fixture.evidence)
        second_evidence["intent_id"] = second_intent["intent_id"]
        result_two = engine.evaluate_intent(
            second_intent,
            second_evidence,
            actor_scope=ROLE_OPERATOR,
        )
        self.assertEqual(result_two["disposition"], "ALLOW")
        view_two = engine.architect_permit(
            result_two["permit_hash"],
            actor_scope=ROLE_ARCHITECT,
        )
        self.assertEqual(view_two["signature"]["key_id"], "permit-key-2")

        # The pre-rotation permit still verifies and commits.
        receipt = engine.commit_execution(
            fixture.execution_request(engine, result_one, intent),
            actor_scope=ROLE_EXECUTOR,
            route_permit_hash=result_one["permit_hash"],
        )
        self.assertEqual(receipt["outcome"], "COMMITTED")

        with self.assertRaisesRegex(
            ContractViolation, "^PERMIT_KEY_ROTATION_DUPLICATE(:|$)"
        ):
            engine.rotate_permit_signer(
                Ed25519DetachedSigner.generate("permit-key-2"),
                actor_scope=ROLE_GOVERNANCE,
            )
        with self.assertRaisesRegex(ContractViolation, "^PERMIT_KEY_ACTIVE(:|$)"):
            engine.revoke_permit_key("permit-key-2", actor_scope=ROLE_GOVERNANCE)
        with self.assertRaisesRegex(
            ContractViolation, "^PERMIT_KEY_NOT_REGISTERED(:|$)"
        ):
            engine.revoke_permit_key("never-registered", actor_scope=ROLE_GOVERNANCE)

    def test_revoked_permit_key_fails_closed(self) -> None:
        fixture = self.fixture()
        key_one = HmacDetachedSigner(b"rotating-permit-key", "permit-key-1")
        engine, intent, _ = fixture.engine(permit_signer=key_one)
        result = self.allow_permit(fixture, engine, intent)

        engine.rotate_permit_signer(
            HmacDetachedSigner(b"rotating-permit-key-2", "permit-key-2"),
            actor_scope=ROLE_GOVERNANCE,
        )
        engine.revoke_permit_key("permit-key-1", actor_scope=ROLE_GOVERNANCE)
        with self.assertRaisesRegex(ContractViolation, "^PERMIT_KEY_REVOKED(:|$)"):
            engine.commit_execution(
                fixture.execution_request(engine, result, intent),
                actor_scope=ROLE_EXECUTOR,
                route_permit_hash=result["permit_hash"],
            )
        # Revocation is permanent: the revoked key_id cannot be rotated back
        # in, which would otherwise self-brick issuance (signed-then-refused).
        with self.assertRaisesRegex(ContractViolation, "^PERMIT_KEY_REVOKED(:|$)"):
            engine.rotate_permit_signer(
                HmacDetachedSigner(b"resurrected-key-material", "permit-key-1"),
                actor_scope=ROLE_GOVERNANCE,
            )

    def test_contract_surfaces_pin_narrowed_disposition_alphabet(self) -> None:
        # The three-value disposition alphabet is ratcheted on the CONTRACT
        # files, not only the engine: re-widening a schema or OpenAPI enum
        # would reopen the declared-but-unproducible gap silently, because
        # conformance validates live instances that never exercise the
        # widened branch.
        operator_result = self.schema["$defs"]["operator_result"]
        self.assertEqual(
            operator_result["properties"]["disposition"]["enum"],
            ["ALLOW", "REFUSAL", "MANUAL_REVIEW"],
        )
        self.assertEqual(
            operator_result["properties"]["channel"]["enum"],
            ["OUTPUT", "REFUSAL"],
        )
        self.assertEqual(
            operator_result["properties"]["message_code"]["enum"],
            [
                "EXECUTION_AUTHORIZED",
                "EXECUTION_DENIED",
                "HUMAN_REVIEW_REQUIRED",
            ],
        )
        self.assertEqual(len(operator_result["oneOf"]), 3)
        openapi_text = (
            ROOT / "protocol" / "universal-connection.openapi.yaml"
        ).read_text(encoding="utf-8")
        for token in ("- HOLD", "- ERROR", "EXECUTION_HELD", "SYSTEM_ERROR"):
            self.assertNotIn(token, openapi_text)

    def test_downstream_receipt_hash_is_outcome_conditional(self) -> None:
        # COMMITTED requires a real 64-hex downstream receipt hash; FAILED and
        # ABORTED require an explicit null — both directions are enforced, so
        # an executor can neither omit a real receipt nor fabricate one.
        fixture = self.fixture()
        engine, intent, _ = fixture.engine()
        result = self.allow_permit(fixture, engine, intent)

        fabricated = fixture.execution_request(
            engine, result, intent, outcome="FAILED"
        )
        fabricated["downstream_receipt_hash"] = "9" * 64
        with self.assertRaisesRegex(
            ContractViolation, "^DOWNSTREAM_RECEIPT_FORBIDDEN(:|$)"
        ):
            engine.commit_execution(
                fabricated,
                actor_scope=ROLE_EXECUTOR,
                route_permit_hash=result["permit_hash"],
            )

        missing = fixture.execution_request(engine, result, intent)
        missing["downstream_receipt_hash"] = None
        with self.assertRaisesRegex(
            ContractViolation, "^DOWNSTREAM_RECEIPT_HASH(:|$)"
        ):
            engine.commit_execution(
                missing,
                actor_scope=ROLE_EXECUTOR,
                route_permit_hash=result["permit_hash"],
            )

        honest = fixture.execution_request(
            engine, result, intent, outcome="FAILED"
        )
        receipt = engine.commit_execution(
            honest,
            actor_scope=ROLE_EXECUTOR,
            route_permit_hash=result["permit_hash"],
        )
        self.assertEqual(receipt["outcome"], "FAILED")
        recorded = [
            event
            for event in engine.ledger.events_copy()
            if event["event_type"] == "EXECUTION_RECORDED"
        ]
        self.assertEqual(len(recorded), 1)
        self.assertIsNone(
            recorded[0]["payload"]["receipt_seed"]["downstream_receipt_hash"]
        )

    def test_engine_runs_standard_library_only_without_cryptography(self) -> None:
        # The default HMAC paths must import and run with the third-party
        # `cryptography` wheel absent; Ed25519 construction must fail closed.
        import subprocess

        probe = "\n".join(
            [
                "import sys",
                "class Blocker:",
                "    def find_spec(self, name, path=None, target=None):",
                "        if name == 'cryptography' or name.startswith('cryptography.'):",
                "            raise ImportError('blocked: ' + name)",
                "        return None",
                "sys.meta_path.insert(0, Blocker())",
                f"sys.path.insert(0, {str(ROOT / 'sdk' / 'python')!r})",
                "import nc25_universal_ledger as m",
                "assert m._ED25519_AVAILABLE is False",
                "signer = m.HmacDetachedSigner(b'k' * 32, 'reference-hmac')",
                "envelope = signer.sign(b'A' * 64)",
                "assert signer.verify(b'A' * 64, envelope)",
                "try:",
                "    m.Ed25519DetachedSigner.generate('x')",
                "    raise SystemExit('ED25519_FAILED_OPEN')",
                "except m.ContractViolation as exc:",
                "    assert exc.code == 'ED25519_UNAVAILABLE', exc.code",
                "print('STDLIB_ONLY_OK')",
            ]
        )
        completed = subprocess.run(
            [sys.executable, "-B", "-c", probe],
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("STDLIB_ONLY_OK", completed.stdout)

    def test_permit_rotation_without_revocation_across_restore(self) -> None:
        # Documented ceremony-replay semantics: the verifier registry is
        # runtime configuration, so after a restart with only the new active
        # signer a retired (non-revoked) key's permit fails closed with
        # PERMIT_KEY_UNKNOWN; replaying the rotation ceremony (construct with
        # the original signer, then rotate) makes it verifiable again.
        fixture = self.fixture()
        key_one = HmacDetachedSigner(b"rotating-permit-key", "permit-key-1")
        key_two = HmacDetachedSigner(b"rotating-permit-key-2", "permit-key-2")
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "state.sqlite"
            engine, _, _, intent = self.persistent_engine(
                fixture, state_path, permit_signer=key_one
            )
            result = self.allow_permit(fixture, engine, intent)
            engine.rotate_permit_signer(key_two, actor_scope=ROLE_GOVERNANCE)

            # Restart with only the new signer: the retired key is not in the
            # registry, so its permit fails closed (documented, not silent).
            restarted, _, _, restarted_intent = self.persistent_engine(
                fixture,
                state_path,
                permit_signer=HmacDetachedSigner(
                    b"rotating-permit-key-2", "permit-key-2"
                ),
            )
            with self.assertRaisesRegex(
                IntegrityViolation, "^PERMIT_KEY_UNKNOWN(:|$)"
            ):
                restarted.commit_execution(
                    fixture.execution_request(
                        restarted, result, restarted_intent
                    ),
                    actor_scope=ROLE_EXECUTOR,
                    route_permit_hash=result["permit_hash"],
                )

            # Ceremony replay: original signer active, then rotate — the
            # retired key is back in the registry and the permit commits.
            replayed, _, _, replayed_intent = self.persistent_engine(
                fixture,
                state_path,
                permit_signer=HmacDetachedSigner(
                    b"rotating-permit-key", "permit-key-1"
                ),
            )
            replayed.rotate_permit_signer(
                HmacDetachedSigner(b"rotating-permit-key-2", "permit-key-2"),
                actor_scope=ROLE_GOVERNANCE,
            )
            receipt = replayed.commit_execution(
                fixture.execution_request(replayed, result, replayed_intent),
                actor_scope=ROLE_EXECUTOR,
                route_permit_hash=result["permit_hash"],
            )
            self.assertEqual(receipt["outcome"], "COMMITTED")

    def test_permit_key_revocation_survives_state_restore(self) -> None:
        fixture = self.fixture()
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "state.sqlite"
            engine, _, _, intent = self.persistent_engine(fixture, state_path)
            result = self.allow_permit(fixture, engine, intent)
            engine.rotate_permit_signer(
                HmacDetachedSigner(b"rotating-permit-key-2", "permit-key-2"),
                actor_scope=ROLE_GOVERNANCE,
            )
            engine.revoke_permit_key("reference-hmac", actor_scope=ROLE_GOVERNANCE)

            # Restarting with the default construction would silently
            # resurrect the revoked default key; the restore must refuse.
            with self.assertRaisesRegex(
                IntegrityViolation, "^STATE_REVOKED_ACTIVE_KEY(:|$)"
            ):
                self.persistent_engine(fixture, state_path)

            # Restarting with a non-revoked active signer restores; the
            # revoked key's permit still fails closed as revoked.
            restarted, _, _, restarted_intent = self.persistent_engine(
                fixture,
                state_path,
                permit_signer=HmacDetachedSigner(
                    b"rotating-permit-key-2", "permit-key-2"
                ),
            )
            with self.assertRaisesRegex(
                ContractViolation, "^PERMIT_KEY_REVOKED(:|$)"
            ):
                restarted.commit_execution(
                    fixture.execution_request(
                        restarted, result, restarted_intent
                    ),
                    actor_scope=ROLE_EXECUTOR,
                    route_permit_hash=result["permit_hash"],
                )

    def test_control_resolver_overrides_connector_flags(self) -> None:
        # Spoofed connector controls cannot produce ALLOW when derivation is
        # wired: the resolver's derived results replace the intent flags for
        # every control surface.
        fixture = self.fixture()

        def derive(field: str, value):
            def resolver(intent, _resolved_at):
                controls = {
                    "prerequisite_results": dict(
                        intent["prerequisite_results"]
                    ),
                    "hard_block_flags": dict(intent["hard_block_flags"]),
                    "manual_review_flags": dict(
                        intent["manual_review_flags"]
                    ),
                    "ambiguity_flags": list(intent["ambiguity_flags"]),
                }
                controls[field] = value(intent)
                return controls

            return resolver

        cases = (
            (
                "hard_block_flags",
                lambda intent: {
                    flag: True for flag in intent["hard_block_flags"]
                },
                "REFUSAL",
                "EXECUTION_DENIED",
            ),
            (
                "prerequisite_results",
                lambda intent: {
                    flag: False for flag in intent["prerequisite_results"]
                },
                "REFUSAL",
                "EXECUTION_DENIED",
            ),
            (
                "ambiguity_flags",
                lambda intent: ["derived-ambiguity"],
                "MANUAL_REVIEW",
                "HUMAN_REVIEW_REQUIRED",
            ),
            # The fourth surface the resolver overrides. The table said "every
            # control surface" and listed three of the four.
            (
                "manual_review_flags",
                lambda intent: {
                    flag: True for flag in intent["manual_review_flags"]
                },
                "MANUAL_REVIEW",
                "HUMAN_REVIEW_REQUIRED",
            ),
        )
        for field, value, disposition, message_code in cases:
            with self.subTest(field=field):
                engine, intent, _ = fixture.engine(
                    control_resolver=derive(field, value)
                )
                result = engine.evaluate_intent(
                    intent,
                    fixture.evidence,
                    actor_scope=ROLE_OPERATOR,
                )
                self.assertEqual(result["disposition"], disposition)
                self.assertEqual(result["message_code"], message_code)
                self.assertIsNone(result["permit_hash"])

    def test_control_resolver_failure_is_fail_closed(self) -> None:
        # A broken or lying resolver never falls back to connector claims.
        fixture = self.fixture()

        def raising_resolver(_intent, _resolved_at):
            raise RuntimeError("control derivation unavailable")

        def missing_field_resolver(intent, _resolved_at):
            return {
                "prerequisite_results": dict(intent["prerequisite_results"]),
                "hard_block_flags": dict(intent["hard_block_flags"]),
                "manual_review_flags": dict(intent["manual_review_flags"]),
            }

        def foreign_flag_resolver(intent, _resolved_at):
            return {
                "prerequisite_results": dict(intent["prerequisite_results"]),
                "hard_block_flags": {"NOT_A_DECLARED_FLAG": False},
                "manual_review_flags": dict(intent["manual_review_flags"]),
                "ambiguity_flags": list(intent["ambiguity_flags"]),
            }

        def non_boolean_resolver(intent, _resolved_at):
            return {
                "prerequisite_results": {
                    flag: "yes" for flag in intent["prerequisite_results"]
                },
                "hard_block_flags": dict(intent["hard_block_flags"]),
                "manual_review_flags": dict(intent["manual_review_flags"]),
                "ambiguity_flags": list(intent["ambiguity_flags"]),
            }

        for name, resolver, code in (
            ("exception", raising_resolver, "CONTROL_RESOLUTION_FAILED"),
            ("missing", missing_field_resolver, "CONTROL_RESOLUTION_INVALID"),
            ("foreign", foreign_flag_resolver, "CONTROL_RESOLUTION_INVALID"),
            ("non_bool", non_boolean_resolver, "CONTROL_RESOLUTION_INVALID"),
        ):
            with self.subTest(name=name):
                engine, intent, _ = fixture.engine(control_resolver=resolver)
                with self.assertRaisesRegex(ContractViolation, rf"^{code}(:|$)"):
                    engine.evaluate_intent(
                        intent,
                        fixture.evidence,
                        actor_scope=ROLE_OPERATOR,
                    )

    def test_event_identifiers_and_default_signature_envelope(self) -> None:
        # One signature contract for the whole package: the default event
        # chain carries the same detached envelope shape as permits, and a
        # persisted Ed25519 chain reopened without a compatible signer fails
        # closed instead of quietly failing the chain.
        fixture = self.fixture()
        engine, intent, _ = fixture.engine()
        self.allow_permit(fixture, engine, intent)
        for event in engine.ledger.events_copy():
            envelope = event["signature"]
            self.assertEqual(set(envelope), set(SIGNATURE_ENVELOPE_FIELDS))
            self.assertEqual(envelope["algorithm"], "HMAC-SHA256")
            self.assertEqual(envelope["key_id"], "ledger-hmac")
        self.assertTrue(engine.ledger.verify())

        signer = Ed25519DetachedSigner.generate("ledger-ed-1")
        ed_engine, ed_intent, _ = fixture.engine(event_signer=signer)
        self.allow_permit(fixture, ed_engine, ed_intent)
        ed_engine.ledger._event_signer = HmacDetachedSigner(
            b"synthetic-reference-signing-key", "ledger-hmac"
        )
        with self.assertRaisesRegex(
            IntegrityViolation, "^EVENT_SIGNER_REQUIRED(:|$)"
        ):
            ed_engine.ledger.verify()

        for field, code in (("event_type", "EVENT_TYPE"), ("subject_ref", "EVENT_SUBJECT")):
            for value in (None, 0, "", "1invalid"):
                with self.subTest(event_contract=code, value=value):
                    args = dict(event_type="SYNTHETIC_EVENT", actor_role=ROLE_GOVERNANCE,
                                subject_ref="synthetic-subject", payload={})
                    args[field] = value
                    before = engine.ledger.events_copy()
                    with self.assertRaisesRegex(ContractViolation, "^" + code + "(:|$)"):
                        engine.ledger.append(**args)
                    self.assertEqual(engine.ledger.events_copy(), before)
        engine.ledger.append("SYNTHETIC_EVENT", ROLE_GOVERNANCE, "synthetic-subject", {})
        self.assertTrue(engine.ledger.verify())

    def test_evidence_resolver_overrides_connector_status(self) -> None:
        fixture = self.fixture()

        def resolver(intent, submitted, resolved_at):
            self.assertEqual(intent["intent_id"], submitted["intent_id"])
            self.assertEqual(resolved_at, fixture.clock.now())
            resolved = copy.deepcopy(dict(submitted))
            for item in resolved["items"]:
                item["status"] = "INVALID"
            return resolved

        engine, intent, _ = fixture.engine(evidence_resolver=resolver)
        submitted = copy.deepcopy(fixture.evidence)
        self.assertTrue(all(item["status"] == "VALID" for item in submitted["items"]))
        result = engine.evaluate_intent(
            intent,
            submitted,
            actor_scope=ROLE_OPERATOR,
        )
        self.assertEqual(result["disposition"], "REFUSAL")
        self.assertIsNone(result["permit_hash"])

    def test_evidence_resolver_failure_is_fail_closed(self) -> None:
        def raising_resolver(intent, submitted, resolved_at):
            raise RuntimeError("resolver unavailable")

        def mismatched_resolver(intent, submitted, resolved_at):
            resolved = copy.deepcopy(dict(submitted))
            resolved["intent_id"] = "different-intent"
            return resolved

        for name, resolver, code in (
            ("exception", raising_resolver, "EVIDENCE_RESOLUTION_FAILED"),
            ("malformed", mismatched_resolver, "EVIDENCE_RESOLUTION_INVALID"),
        ):
            with self.subTest(name=name):
                fixture = self.fixture()
                engine, intent, _ = fixture.engine(evidence_resolver=resolver)
                event_count = engine.ledger.head()["event_count"]
                with self.assertRaisesRegex(ContractViolation, rf"^{code}(:|$)"):
                    engine.evaluate_intent(
                        intent,
                        fixture.evidence,
                        actor_scope=ROLE_OPERATOR,
                    )
                self.assertEqual(engine.ledger.head()["event_count"], event_count)

    def test_docx_extended_properties_omit_false_statistics(self) -> None:
        docx_path = ROOT / spec_docx_name(ROOT)
        with zipfile.ZipFile(docx_path, "r") as archive:
            app_xml = archive.read("docProps/app.xml").decode("utf-8")
        for tag in (
            "Pages",
            "Words",
            "Characters",
            "CharactersWithSpaces",
            "Lines",
            "Paragraphs",
        ):
            self.assertNotIn(f"<{tag}>", app_xml)

    def test_public_acceptance_report_has_release_only_state(self) -> None:
        report = (ROOT / "ACCEPTANCE-REPORT.md").read_text(encoding="utf-8").lower()
        self.assertIn("status: `pass`", report)
        self.assertIn("## executable acceptance", report)
        self.assertIn("## production boundary", report)
        for marker in ("status: `pending`", "unfinished", "internal process"):
            self.assertNotIn(marker, report)
        self.assertIn("headless libreoffice pdf render", report)
        self.assertNotIn("microsoft word", report)


    def test_docx_audit_projection_is_current_and_bound(self) -> None:
        import hashlib
        import subprocess
        import sys
        import tempfile

        projection = ROOT / "DOCX-AUDIT-PROJECTION.md"
        docx = ROOT / spec_docx_name(ROOT)
        with tempfile.TemporaryDirectory() as temp_dir:
            generated = Path(temp_dir) / projection.name
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "tools" / "build_docx_audit_projection.py"),
                    "--output",
                    str(generated),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(generated.read_bytes(), projection.read_bytes())

        projection_text = projection.read_text(encoding="utf-8")
        docx_sha = hashlib.sha256(docx.read_bytes()).hexdigest().upper()
        self.assertIn(f"Source SHA-256: `{docx_sha}`", projection_text)
        self.assertIn("`word/document.xml`", projection_text)
        self.assertIn("## Relationships", projection_text)
        self.assertIn("## Visible text", projection_text)

if __name__ == "__main__":
    unittest.main(verbosity=2)


