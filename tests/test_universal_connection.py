"""Behavioral suite for the reference engine, run against every shipped profile.

The suite is written once against a `FixtureSet` of profile-independent handles
(action cost, resource id, declared control flags, governance actors) and is
instantiated for the banking, document-release, and OTCS registry profiles. A
test that would only pass on one domain's literals cannot exist here, so the
portability the README claims is exercised by every test, not by one happy path.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import sys
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python"))

from nc25_universal_ledger import (  # noqa: E402
    ContractViolation,
    FixedClock,
    IntegrityViolation,
    ROLE_ARCHITECT,
    ROLE_EXECUTOR,
    ROLE_GOVERNANCE,
    ROLE_OPERATOR,
    UniversalConnectionLedger,
    bind_fixture,
    load_json,
    sha256_hex,
)


class FixtureSet:
    """One fixture family plus the handles the suite needs from it."""

    def __init__(
        self,
        name: str,
        profile: dict,
        declaration: dict,
        grant: dict,
        intent: dict,
        evidence: dict,
    ) -> None:
        self.name = name
        self.profile = profile
        self.declaration = declaration
        self.grant = grant
        self.intent = intent
        self.evidence = evidence

        action = next(
            item
            for item in profile["action_alphabet"]
            if item["action_id"] == intent["action_id"]
        )
        self.action_cost = action["structural_cost"]
        self.resource_id = action["required_resource_ids"][0]
        self.claim = intent["resource_claims"][self.resource_id]
        self.capacity = declaration["structural_budget"]["capacity"]

        controls = profile["controls"]
        self.prerequisite_id = controls["required_prerequisite_ids"][0]
        self.hard_block_flag = controls["hard_block_flag_ids"][0]
        self.manual_review_flag = controls["manual_review_flag_ids"][0]

        governance = declaration["governance"]
        self.approval_owner = governance["approval_owner_id"]
        self.authority_issuer = governance["authority_issuer_id"]


def banking_fixtures() -> FixtureSet:
    return FixtureSet(
        "banking",
        load_json(ROOT / "profiles" / "banking" / "bank-profile.json"),
        load_json(ROOT / "examples" / "synthetic-connection-declaration.json"),
        load_json(ROOT / "examples" / "synthetic-authority-grant.json"),
        load_json(ROOT / "examples" / "synthetic-intent-allow.json"),
        load_json(ROOT / "examples" / "synthetic-evidence-bundle.json"),
    )


def document_release_fixtures() -> FixtureSet:
    bundle = load_json(
        ROOT / "profiles" / "document-release" / "reference-connection.json"
    )
    return FixtureSet(
        "document-release",
        bundle["profile"],
        bundle["declaration"],
        bundle["grant"],
        bundle["intent"],
        bundle["evidence"],
    )


def otcs_fixtures() -> FixtureSet:
    bundle = load_json(
        ROOT / "profiles" / "otcs" / "reference-connection.json"
    )
    return FixtureSet(
        "otcs-registry",
        bundle["profile"],
        bundle["declaration"],
        bundle["grant"],
        bundle["intent"],
        bundle["evidence"],
    )


def unique_intent(intent: dict, evidence: dict, suffix: str) -> tuple[dict, dict]:
    changed_intent = copy.deepcopy(intent)
    changed_evidence = copy.deepcopy(evidence)
    changed_intent["intent_id"] = f"synthetic-intent-{suffix}"
    changed_intent["idempotency_key"] = f"synthetic-idempotency-{suffix}"
    changed_intent["payload_hash"] = hashlib.sha256(suffix.encode()).hexdigest()
    changed_evidence["intent_id"] = changed_intent["intent_id"]
    return changed_intent, changed_evidence


# ---------------------------------------------------------------------------
# Public-surface invariants: shared enumeration, separately named claims.
#
# Three facts are asserted about the public surface, and they are three claims,
# not one: every operation demands an explicit role; the role check runs BEFORE
# the integrity halt; every operation halts on a broken chain. They share the
# enumeration below and nothing else — a single merged assertion would fail for
# three different reasons under one name, and would force one fixture on rows
# that need different ones.
#
# The role map is HARVESTED from the engine source, never typed here. A map a
# human fills in is answered with whatever string makes the suite green, which
# is by construction the string the method already accepts: that is a
# transcription of the code wearing the clothes of a decision. Harvesting makes
# the map an observation, and the observation is then cross-checked against the
# wire layer, which is an independent author of who owns an operation.
def harvested_surface_roles() -> dict:
    """Public engine method -> the role its state decorator demands.

    Read from the shipped engine source by AST. The role is declared on the
    decorator rather than in the body, because the check itself lives in the
    decorator: it must run before the locking wrapper opens the state store,
    or an unscoped caller reaches snapshot verification and learns integrity
    status. Fails loudly rather than skipping a method silently - a public
    method with no scope-bearing decorator is exactly the defect this file
    exists to catch.
    """
    source = (ROOT / "sdk" / "python" / "nc25_universal_ledger.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    engine = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "UniversalConnectionLedger"
    )
    roles = {}
    overloads = set()
    for item in engine.body:
        if not isinstance(item, ast.FunctionDef) or item.name.startswith("_"):
            continue
        # A typing overload declares a signature; only its concrete implementation
        # executes. Every overload group must still have a scoped implementation.
        if any(isinstance(d, ast.Name) and d.id == "overload" for d in item.decorator_list):
            overloads.add(item.name)
            continue
        found = None
        # decorator_list ONLY, never ast.walk: a `_state_locked(...)` mentioned
        # anywhere inside a body would otherwise be harvested as its role.
        for decorator in item.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and ast.unparse(decorator.func).split(".")[-1]
                in SCOPE_BEARING_DECORATORS
                and len(decorator.args) == 1
                and not decorator.keywords
                # A bare name, so a computed or aliased role cannot pass, and
                # a parenless `@_state_locked` is not an ast.Call at all and
                # so lands in the loud failure below rather than silently.
                and isinstance(decorator.args[0], ast.Name)
            ):
                found = decorator.args[0].id
                break
        if found is None:
            raise AssertionError(
                f"{item.name} is public and carries no scope-bearing state decorator"
            )
        roles[item.name] = ROLE_CONSTANTS[found]
    if overloads - roles.keys():
        raise AssertionError("overload has no scoped implementation: " + ", ".join(sorted(overloads - roles.keys())))
    return roles


SCOPE_BEARING_DECORATORS = frozenset({"_state_locked", "_state_read_locked"})


ROLE_CONSTANTS = {
    "ROLE_GOVERNANCE": ROLE_GOVERNANCE,
    "ROLE_OPERATOR": ROLE_OPERATOR,
    "ROLE_EXECUTOR": ROLE_EXECUTOR,
    "ROLE_ARCHITECT": ROLE_ARCHITECT,
}


# The wire layer's independent opinion of who owns an operation: the adapter
# mounts one route per operation and declares its scope there. Nine of the
# twelve public methods are routed; the three that are not are named here with
# the reason, because "no second source" is a fact worth stating rather than a
# silence. Key custody is deliberately out of band (no route exists), and the
# observer projection is documented as intentionally not a route.
# These three are the sites where this package has already had gaps, so the
# list is pinned by size as well as by content: an exemption list that can grow
# is an exemption field, which is the shape that was refused entry. Their second
# source is not the adapter but the regressions that call them with a
# hard-coded correct role - test_permit_rotation_without_revocation_across_restore,
# test_signer_rotation_rolls_back_on_persist_failure,
# test_permit_key_revocation_survives_state_restore and
# test_signer_revocation_rolls_back_on_persist_failure for the custody pair,
# and every observer_projection(actor_scope=ROLE_ARCHITECT) call site.
UNROUTED_BY_DESIGN = {
    "rotate_permit_signer": "key custody is out of band; no route is mounted",
    "revoke_permit_key": "key custody is out of band; no route is mounted",
    "observer_projection": "documented as intentionally not a route",
}


def adapter_route_table() -> list:
    """The adapter's mounted routes, as (scope, handler) from its source."""
    source = (ROOT / "sdk" / "python" / "nc25_universal_adapter.py").read_text(
        encoding="utf-8"
    )
    adapter = next(
        node for node in ast.parse(source).body
        if isinstance(node, ast.ClassDef)
        and node.name == "UniversalConnectionHttpAdapter"
    )
    rows = []
    for node in ast.walk(adapter):
        if isinstance(node, ast.Tuple) and len(node.elts) == 5:
            handler = ast.unparse(node.elts[4])
            if handler.startswith("self._"):
                rows.append((ast.unparse(node.elts[3]), handler.split(".")[-1]))
    return rows


def adapter_route_row_count() -> int:
    return len(adapter_route_table())


def harvested_wire_roles() -> dict:
    """Engine method -> the scope the adapter mounts its route under.

    Both halves are read from the adapter source, never assumed: which handler
    a route carries, and which engine method that handler calls. Matching them
    by NAME would be a convention rather than a fact, and the convention is
    already broken once — the route handler `_consume_permit` calls
    `commit_execution`.
    """
    source = (ROOT / "sdk" / "python" / "nc25_universal_adapter.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    adapter = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "UniversalConnectionHttpAdapter"
    )

    calls: dict[str, set] = {}
    for item in adapter.body:
        if not isinstance(item, ast.FunctionDef):
            continue
        reached = set()
        for node in ast.walk(item):
            if isinstance(node, ast.Call):
                target = ast.unparse(node.func)
                if target.startswith("self._engine."):
                    reached.add(target.split(".")[-1])
        calls[item.name] = reached

    routes = {}
    for node in ast.walk(adapter):
        if not isinstance(node, ast.Tuple) or len(node.elts) != 5:
            continue
        scope_node, handler_node = node.elts[3], node.elts[4]
        handler = ast.unparse(handler_node)
        if not handler.startswith("self._"):
            continue
        reached = calls.get(handler.split(".")[-1], set())
        for engine_method in reached:
            routes[engine_method] = ROLE_CONSTANTS[ast.unparse(scope_node)]
    return routes


def public_surface_methods() -> dict:
    return {
        name: member
        for name, member in inspect.getmembers(
            UniversalConnectionLedger, predicate=inspect.isfunction
        )
        if not name.startswith("_")
    }


def dummy_arguments(signature: inspect.Signature) -> tuple[list, dict]:
    """Placeholders for every required argument except `actor_scope`.

    Opaque placeholders are the point: both invariants must refuse before any
    argument is inspected, so a method that validated an argument first would
    raise its own code and redden its row.
    """
    positional: list = []
    keyword: dict = {}
    for parameter_name, parameter in signature.parameters.items():
        if parameter_name in ("self", "actor_scope"):
            continue
        if parameter.default is not inspect.Parameter.empty:
            continue
        if parameter.kind is inspect.Parameter.KEYWORD_ONLY:
            keyword[parameter_name] = object()
        else:
            positional.append(object())
    return positional, keyword


class ConnectionSuite:
    """Profile-independent behavioral tests; subclasses pick the fixtures."""

    make_fixtures: staticmethod

    def setUp(self) -> None:
        self.fx = type(self).make_fixtures()
        self.profile = self.fx.profile
        self.declaration = self.fx.declaration
        self.grant = self.fx.grant
        self.intent = self.fx.intent
        self.evidence = self.fx.evidence
        self.clock = FixedClock(
            datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)
        )

    def engine(
        self,
        profile: dict | None = None,
        declaration: dict | None = None,
        grant: dict | None = None,
        intent: dict | None = None,
        event_signer=None,
        evidence_resolver=None,
        permit_signer=None,
        control_resolver=None,
    ) -> tuple[UniversalConnectionLedger, dict, dict]:
        bound = bind_fixture(
            profile or self.profile,
            declaration or self.declaration,
            grant or self.grant,
            intent or self.intent,
        )
        bound_profile, bound_declaration, bound_grant, bound_intent = bound
        engine = UniversalConnectionLedger(
            bound_profile,
            bound_declaration,
            signing_key=b"synthetic-reference-signing-key",
            clock=self.clock,
            event_signer=event_signer,
            evidence_resolver=evidence_resolver,
            permit_signer=permit_signer,
            control_resolver=control_resolver,
        )
        engine.activate(
            self.fx.approval_owner,
            "evidence://synthetic/declaration-activation",
            actor_scope="nc25.governance",
        )
        engine.issue_grant(bound_grant, actor_scope="nc25.governance")
        return engine, bound_intent, bound_grant

    def execution_request(
        self,
        engine: UniversalConnectionLedger,
        result: dict,
        intent: dict,
        outcome: str = "COMMITTED",
        state_anchor: str | None = None,
    ) -> dict:
        return {
            "message_type": "execution_request",
            "permit_hash": result["permit_hash"],
            "connector_id": intent["connector_id"],
            "binding": intent["binding"],
            "state_anchor_hash": state_anchor or intent["state_anchor_hash"],
            "outcome": outcome,
            # A downstream receipt exists only for COMMITTED; FAILED and
            # ABORTED carry an honest explicit null per the contract.
            "downstream_receipt_hash": (
                "9" * 64 if outcome == "COMMITTED" else None
            ),
            "committed_at": "2026-08-01T10:00:00Z",
        }

    def test_happy_path_is_minimal_and_exactly_once(self) -> None:
        engine, intent, _ = self.engine()
        result = engine.evaluate_intent(intent, self.evidence, actor_scope="nc25.operator")
        self.assertEqual(result["disposition"], "ALLOW")
        self.assertEqual(result["channel"], "OUTPUT")
        self.assertEqual(result["message_code"], "EXECUTION_AUTHORIZED")
        self.assertEqual(
            set(result),
            {
                "message_type",
                "intent_id",
                "request_hash",
                "disposition",
                "channel",
                "message_code",
                "permit_hash",
                "expires_at",
            },
        )
        architect = engine.architect_permit(
            result["permit_hash"],
            actor_scope=ROLE_ARCHITECT,
        )
        self.assertEqual(architect["permit_body"]["gate_bit"], 1)
        self.assertEqual(architect["permit_body"]["ttl_seconds"], 300)
        self.assertTrue(architect["permit_body"]["structural_gate"])
        self.assertTrue(architect["permit_body"]["effect_gate"])

        request = self.execution_request(engine, result, intent)
        receipt = engine.commit_execution(
            request,
            actor_scope="nc25.executor",
            route_permit_hash=request["permit_hash"],
        )
        self.assertEqual(receipt["outcome"], "COMMITTED")
        self.assertEqual(receipt["structural_debit"], self.fx.action_cost)
        self.assertEqual(
            engine.structural_remaining,
            self.fx.capacity - self.fx.action_cost,
        )
        event_count = len(engine.ledger._events)
        receipt_count = len(engine.receipt_hashes)
        replay = engine.commit_execution(
            request,
            actor_scope="nc25.executor",
            route_permit_hash=request["permit_hash"],
        )
        self.assertEqual(replay, receipt)
        self.assertEqual(len(engine.ledger._events), event_count)
        self.assertEqual(len(engine.receipt_hashes), receipt_count)
        self.assertEqual(
            engine.structural_remaining,
            self.fx.capacity - self.fx.action_cost,
        )

    def test_operator_replay_identity_is_case_normalized(self) -> None:
        # The wire rule accepts a SHA-256 in either case and the documentation
        # says the engine normalizes comparisons - one sentence covering both
        # replay surfaces. The executor surface normalized and the operator
        # surface did not, so a resubmission differing only in the hex case of
        # a hash was refused as a conflict instead of replayed. The twin of
        # test_exact_execution_replay_survives_declaration_expiry, on the other
        # surface, because a sentence with "every" in it needs every surface.
        engine, intent, _ = self.engine()
        first = engine.evaluate_intent(
            intent, self.evidence, actor_scope="nc25.operator"
        )
        flipped = copy.deepcopy(intent)
        for field in ("payload_hash", "history_summary_hash", "state_anchor_hash"):
            flipped[field] = flipped[field].lower()
        flipped["binding"]["profile_hash"] = flipped["binding"]["profile_hash"].lower()
        flipped_evidence = copy.deepcopy(self.evidence)
        for item in flipped_evidence["items"]:
            item["sha256"] = item["sha256"].lower()
        replayed = engine.evaluate_intent(
            flipped, flipped_evidence, actor_scope="nc25.operator"
        )
        self.assertEqual(first, replayed)

    def test_idempotent_replay_and_conflict(self) -> None:
        engine, intent, _ = self.engine()
        first = engine.evaluate_intent(intent, self.evidence, actor_scope="nc25.operator")
        second = engine.evaluate_intent(intent, self.evidence, actor_scope="nc25.operator")
        self.assertEqual(first, second)
        engine.commit_execution(
            self.execution_request(engine, first, intent),
            actor_scope="nc25.executor",
            route_permit_hash=first["permit_hash"],
        )
        with self.assertRaisesRegex(
            ContractViolation,
            "^PERMIT_ALREADY_CONSUMED(:|$)",
        ):
            engine.evaluate_intent(intent, self.evidence, actor_scope="nc25.operator")
        changed = copy.deepcopy(intent)
        changed["resource_claims"][self.fx.resource_id] += 1
        with self.assertRaisesRegex(ContractViolation, "^IDEMPOTENCY_CONFLICT(:|$)"):
            engine.evaluate_intent(changed, self.evidence, actor_scope="nc25.operator")

        stale_engine, stale_intent, _ = self.engine()
        stale_result = stale_engine.evaluate_intent(stale_intent, self.evidence, actor_scope="nc25.operator")
        stale_record = stale_engine.permits[stale_result["permit_hash"]]
        self.clock.advance(seconds=301)
        with self.assertRaisesRegex(ContractViolation, "^PERMIT_EXPIRED(:|$)"):
            stale_engine.evaluate_intent(stale_intent, self.evidence, actor_scope="nc25.operator")
        self.assertFalse(stale_record.reservation_active)
        self.assertEqual(stale_record.invalidated_reason, "PERMIT_EXPIRED")

    def test_permit_ttl_is_protocol_bounded(self) -> None:
        engine, _, _ = self.engine()
        with self.assertRaisesRegex(ContractViolation, "^PERMIT_TTL(:|$)"):
            UniversalConnectionLedger(
                engine.profile,
                engine.declaration,
                signing_key=b"synthetic-reference-signing-key",
                clock=self.clock,
                permit_ttl_seconds=901,
            )

    def test_permit_expiry_is_the_earliest_of_its_three_bounds(self) -> None:
        # A permit expires at the earliest of its TTL, its grant's validity,
        # and the declaration's. On the shipped fixtures the TTL is always the
        # earliest, so the other two bounds are unreachable: dropping either
        # from the engine leaves every other test green. Each case below makes
        # a different bound the earliest, so each bound has a case that fails
        # without it.
        def issued_expiry(**overrides: dict) -> str:
            engine, intent, _ = self.engine(**overrides)
            result = engine.evaluate_intent(
                intent,
                self.evidence,
                actor_scope="nc25.operator",
            )
            self.assertEqual(result["disposition"], "ALLOW")
            return engine.permits[result["permit_hash"]].body["expires_at"]

        with self.subTest(bound="ttl"):
            # 10:00:00Z + the 300s default.
            self.assertEqual(issued_expiry(), "2026-08-01T10:05:00Z")

        grant = copy.deepcopy(self.grant)
        grant["valid_until"] = "2026-08-01T10:02:00Z"
        with self.subTest(bound="grant"):
            self.assertEqual(
                issued_expiry(grant=grant),
                "2026-08-01T10:02:00Z",
            )

        declaration = copy.deepcopy(self.declaration)
        declaration["expires_at"] = "2026-08-01T10:01:00Z"
        with self.subTest(bound="declaration"):
            self.assertEqual(
                issued_expiry(declaration=declaration),
                "2026-08-01T10:01:00Z",
            )

    def test_manual_review_and_ambiguity_are_not_executable(self) -> None:
        engine, intent, _ = self.engine()
        intent["manual_review_flags"][self.fx.manual_review_flag] = True
        result = engine.evaluate_intent(intent, self.evidence, actor_scope="nc25.operator")
        self.assertEqual(result["disposition"], "MANUAL_REVIEW")
        self.assertEqual(result["message_code"], "HUMAN_REVIEW_REQUIRED")
        self.assertIsNone(result["permit_hash"])
        decision = engine.architect_decision(result["request_hash"], actor_scope="nc25.architect")
        self.assertEqual(decision["message_code"], "MANUAL_REVIEW_REQUIRED")
        self.assertFalse(decision["gate_engaged"])
        self.assertIsNone(decision["gate_bit"])

    def test_hard_block_flag_refuses_before_gate(self) -> None:
        engine, intent, _ = self.engine()
        intent["hard_block_flags"][self.fx.hard_block_flag] = True
        result = engine.evaluate_intent(intent, self.evidence, actor_scope="nc25.operator")
        self.assertEqual(result["disposition"], "REFUSAL")
        self.assertEqual(result["message_code"], "EXECUTION_DENIED")
        self.assertIsNone(result["permit_hash"])
        decision = engine.architect_decision(result["request_hash"], actor_scope="nc25.architect")
        self.assertEqual(decision["message_code"], "HARD_BLOCK")
        self.assertFalse(decision["gate_engaged"])
        self.assertIsNone(decision["gate_bit"])

    def test_false_prerequisite_refuses_before_gate(self) -> None:
        engine, intent, _ = self.engine()
        intent["prerequisite_results"][self.fx.prerequisite_id] = False
        result = engine.evaluate_intent(intent, self.evidence, actor_scope="nc25.operator")
        self.assertEqual(result["disposition"], "REFUSAL")
        self.assertEqual(result["message_code"], "EXECUTION_DENIED")
        self.assertIsNone(result["permit_hash"])
        decision = engine.architect_decision(result["request_hash"], actor_scope="nc25.architect")
        self.assertEqual(decision["message_code"], "PREREQUISITE_FALSE")
        self.assertFalse(decision["gate_engaged"])
        self.assertIsNone(decision["gate_bit"])

    def test_missing_evidence_fails_before_gate(self) -> None:
        engine, intent, _ = self.engine()
        missing = copy.deepcopy(self.evidence)
        missing["items"] = missing["items"][:-1]
        result = engine.evaluate_intent(intent, missing, actor_scope="nc25.operator")
        self.assertEqual(result["message_code"], "EXECUTION_DENIED")
        self.assertNotEqual(result["disposition"], "ALLOW")
        decision = engine.architect_decision(result["request_hash"], actor_scope="nc25.architect")
        self.assertEqual(decision["message_code"], "EVIDENCE_MISSING")
        self.assertFalse(decision["gate_engaged"])

    def test_invalid_evidence_refuses_and_is_recorded(self) -> None:
        engine, intent, _ = self.engine()
        invalid = copy.deepcopy(self.evidence)
        invalid["items"][0]["status"] = "REVOKED"
        result = engine.evaluate_intent(intent, invalid, actor_scope="nc25.operator")
        self.assertEqual(result["disposition"], "REFUSAL")
        self.assertEqual(result["message_code"], "EXECUTION_DENIED")
        self.assertIsNone(result["permit_hash"])
        decision = engine.architect_decision(result["request_hash"], actor_scope="nc25.architect")
        self.assertEqual(decision["message_code"], "EVIDENCE_INVALID")
        self.assertFalse(decision["gate_engaged"])
        self.assertIn(result["request_hash"], engine.decisions)

    def test_active_reservation_prevents_overissue(self) -> None:
        declaration = copy.deepcopy(self.declaration)
        declaration["structural_budget"]["capacity"] = self.fx.action_cost
        engine, first_intent, grant = self.engine(declaration=declaration)
        first = engine.evaluate_intent(first_intent, self.evidence, actor_scope="nc25.operator")
        self.assertEqual(first["disposition"], "ALLOW")
        second_intent, second_evidence = unique_intent(
            first_intent,
            self.evidence,
            "reservation-002",
        )
        second = engine.evaluate_intent(second_intent, second_evidence, actor_scope="nc25.operator")
        self.assertEqual(second["message_code"], "EXECUTION_DENIED")
        decision = engine.architect_decision(second["request_hash"], actor_scope="nc25.architect")
        self.assertEqual(
            decision["message_code"],
            "STRUCTURAL_BUDGET_EXHAUSTED",
        )
        self.assertFalse(decision["structural_gate"])
        self.assertTrue(decision["effect_gate"])
        self.assertIn(grant["grant_id"], engine.grants)

    def test_reservation_requirement_is_honoured_per_resource(self) -> None:
        declaration = copy.deepcopy(self.declaration)
        for limit in declaration["resource_limits"]:
            if limit["resource_id"] == self.fx.resource_id:
                limit["max_per_intent"] = self.fx.claim
                limit["max_committed_per_window"] = 2 * self.fx.claim - 1

        # Reservation declared: an outstanding permit holds the window capacity,
        # so a second claim of the same size cannot be admitted.
        engine, first_intent, _ = self.engine(declaration=declaration)
        self.assertEqual(
            engine.evaluate_intent(first_intent, self.evidence, actor_scope="nc25.operator")["disposition"],
            "ALLOW",
        )
        second_intent, second_evidence = unique_intent(
            first_intent,
            self.evidence,
            "reservation-required-002",
        )
        second = engine.evaluate_intent(second_intent, second_evidence, actor_scope="nc25.operator")
        self.assertEqual(second["message_code"], "EXECUTION_DENIED")
        self.assertEqual(
            engine.architect_decision(second["request_hash"], actor_scope="nc25.architect")["message_code"],
            "RESOURCE_WINDOW_LIMIT",
        )

        # Reservation waived for that resource: an outstanding permit reserves
        # nothing, so only committed amounts count and the second claim passes.
        profile = copy.deepcopy(self.profile)
        for resource in profile["resource_catalog"]:
            if resource["resource_id"] == self.fx.resource_id:
                resource["reservation_required"] = False
        engine, first_intent, _ = self.engine(
            profile=profile,
            declaration=declaration,
        )
        first = engine.evaluate_intent(first_intent, self.evidence, actor_scope="nc25.operator")
        self.assertEqual(first["disposition"], "ALLOW")
        third_intent, third_evidence = unique_intent(
            first_intent,
            self.evidence,
            "reservation-waived-002",
        )
        third = engine.evaluate_intent(third_intent, third_evidence, actor_scope="nc25.operator")
        self.assertEqual(third["disposition"], "ALLOW")
        engine.commit_execution(
            self.execution_request(engine, first, first_intent),
            actor_scope="nc25.executor",
            route_permit_hash=first["permit_hash"],
        )
        third_record = engine.permits[third["permit_hash"]]
        with self.assertRaisesRegex(
            ContractViolation,
            "^RESOURCE_WINDOW_LIMIT(:|$)",
        ):
            engine.commit_execution(
                self.execution_request(engine, third, third_intent),
                actor_scope="nc25.executor",
                route_permit_hash=third["permit_hash"],
            )
        self.assertFalse(third_record.reservation_active)
        self.assertEqual(
            third_record.invalidated_reason,
            "RESOURCE_WINDOW_LIMIT",
        )

    def test_commit_recomputes_the_window_for_every_claimed_resource(self) -> None:
        # The contract says the commit recomputes committed usage for EVERY
        # claimed resource. No shipped action requires two, so on every shipped
        # fixture that claim is checked over a set of one - and over a set of
        # one, "every" and "the first one found" are the same program. A second
        # resource is declared here and made the offender, and it is named so
        # that it sorts AFTER the first, because the commit walks the claims in
        # sorted order: a loop that stopped at the first claim would commit
        # exactly what the second resource's window forbids.
        second = f"{self.fx.resource_id}_secondary"
        self.assertGreater(second, self.fx.resource_id)

        profile = copy.deepcopy(self.profile)
        action = next(
            item
            for item in profile["action_alphabet"]
            if item["action_id"] == self.intent["action_id"]
        )
        action["required_resource_ids"].append(second)
        profile["resource_catalog"].append(
            {
                "resource_id": second,
                "unit": "secondary units",
                "claim_rule": "POSITIVE",
                # Reservation waived, so an outstanding permit holds none of
                # this resource's window and both permits are issued before
                # either commits. The refusal below can then only come from the
                # commit-time recomputation, not from the issue-time gate.
                "reservation_required": False,
            }
        )
        declaration = copy.deepcopy(self.declaration)
        declaration["resource_limits"].append(
            {
                "resource_id": second,
                "max_per_intent": 2,
                "max_committed_per_window": 3,
                "window_seconds": 86400,
            }
        )
        intent = copy.deepcopy(self.intent)
        intent["resource_claims"][second] = 2

        engine, first_intent, _ = self.engine(
            profile=profile,
            declaration=declaration,
            intent=intent,
        )
        first = engine.evaluate_intent(
            first_intent,
            self.evidence,
            actor_scope="nc25.operator",
        )
        self.assertEqual(first["disposition"], "ALLOW")
        second_intent, second_evidence = unique_intent(
            first_intent,
            self.evidence,
            "every-resource-002",
        )
        issued = engine.evaluate_intent(
            second_intent,
            second_evidence,
            actor_scope="nc25.operator",
        )
        # This ALLOW is the second claim this fixture witnesses: the runbook
        # says EACH resource declares its own `reservation_required`, and here
        # the two resources declare opposite values. Were the flag read once
        # for the engine rather than per resource, the outstanding permit would
        # hold 2 of the second resource's 3-unit window and this second permit
        # would be refused at issue.
        self.assertEqual(issued["disposition"], "ALLOW")

        engine.commit_execution(
            self.execution_request(engine, first, first_intent),
            actor_scope="nc25.executor",
            route_permit_hash=first["permit_hash"],
        )
        # 2 of the second resource's 3-unit window are now committed, while the
        # first resource is still far inside its own. A commit that recomputed
        # only the first claim would admit this one.
        record = engine.permits[issued["permit_hash"]]
        with self.assertRaisesRegex(
            ContractViolation,
            "^RESOURCE_WINDOW_LIMIT(:|$)",
        ):
            engine.commit_execution(
                self.execution_request(engine, issued, second_intent),
                actor_scope="nc25.executor",
                route_permit_hash=issued["permit_hash"],
            )
        self.assertFalse(record.reservation_active)
        self.assertEqual(record.invalidated_reason, "RESOURCE_WINDOW_LIMIT")

    def test_expired_permit_releases_reservation(self) -> None:
        declaration = copy.deepcopy(self.declaration)
        declaration["structural_budget"]["capacity"] = self.fx.action_cost
        engine, first_intent, _ = self.engine(declaration=declaration)
        first = engine.evaluate_intent(first_intent, self.evidence, actor_scope="nc25.operator")
        self.assertEqual(first["disposition"], "ALLOW")
        first_record = engine.permits[first["permit_hash"]]
        self.clock.advance(seconds=301)
        second_intent, second_evidence = unique_intent(
            first_intent,
            self.evidence,
            "expired-reservation-002",
        )
        second = engine.evaluate_intent(second_intent, second_evidence, actor_scope="nc25.operator")
        self.assertEqual(second["disposition"], "ALLOW")
        self.assertFalse(first_record.reservation_active)
        self.assertEqual(first_record.invalidated_reason, "PERMIT_EXPIRED")

    def test_grant_expiry_between_evaluation_and_commit_blocks(self) -> None:
        grant = copy.deepcopy(self.grant)
        grant["valid_until"] = "2026-08-01T10:00:30Z"
        engine, intent, _ = self.engine(grant=grant)
        result = engine.evaluate_intent(intent, self.evidence, actor_scope="nc25.operator")
        record = engine.permits[result["permit_hash"]]
        self.clock.advance(seconds=120)
        request = self.execution_request(engine, result, intent)
        request["committed_at"] = "2026-08-01T10:02:00Z"
        with self.assertRaisesRegex(ContractViolation, "^AUTHORITY_EXPIRED(:|$)"):
            engine.commit_execution(
                request,
                actor_scope="nc25.executor",
                route_permit_hash=request["permit_hash"],
            )
        self.assertFalse(record.reservation_active)
        self.assertEqual(record.invalidated_reason, "AUTHORITY_EXPIRED")
        self.assertEqual(engine.structural_remaining, self.fx.capacity)
        self.assertFalse(engine.committed_resources)

    def test_revocation_invalidates_outstanding_permit(self) -> None:
        # TWO outstanding permits, because the contract says revocation
        # invalidates EVERY permit issued under the grant. With one permit the
        # claim and "invalidate the first match you find" are indistinguishable,
        # and the regression from the former to the latter would stay green.
        engine, intent, grant = self.engine()
        result = engine.evaluate_intent(intent, self.evidence, actor_scope="nc25.operator")
        second_intent, second_evidence = unique_intent(
            intent, self.evidence, "revocation-sibling"
        )
        second = engine.evaluate_intent(
            second_intent, second_evidence, actor_scope="nc25.operator"
        )
        self.assertNotEqual(result["permit_hash"], second["permit_hash"])
        engine.revoke_grant(
            {
                "message_type": "authority_revocation",
                "grant_id": grant["grant_id"],
                "declaration_hash": engine.declaration_hash,
                "revoked_at": "2026-08-01T10:00:00Z",
                "revoked_by": self.fx.authority_issuer,
                "reason_code": "SYNTHETIC_REVOCATION",
                "evidence_ref": "evidence://synthetic/revocation/001",
            },
            actor_scope="nc25.governance",
        )
        registry = engine.registry_record(engine.declaration["connector"]["connector_id"], actor_scope="nc25.architect")
        self.assertTrue(registry["revoked"])
        self.assertEqual(registry["status"], "ACTIVE")
        # Assert the invalidation ITSELF, not the commit refusal. A refused
        # commit proves nothing about plurality: commit re-checks grant
        # validity independently, so a permit whose reservation was never
        # released still refuses there. Measured - with the release loop cut
        # to its first match, the commit-based version of this test stayed
        # green. The record state is the observable that separates "every"
        # from "the first one".
        for label, outcome, source_intent in (
            ("first", result, intent),
            ("second", second, second_intent),
        ):
            with self.subTest(permit=label):
                record = engine.permits[outcome["permit_hash"]]
                self.assertEqual(record.invalidated_reason, "AUTHORITY_REVOKED")
                self.assertFalse(record.reservation_active)
                with self.assertRaisesRegex(ContractViolation, "^AUTHORITY_REVOKED(:|$)"):
                    engine.commit_execution(
                        self.execution_request(engine, outcome, source_intent),
                        actor_scope="nc25.executor",
                        route_permit_hash=outcome["permit_hash"],
                    )

    def test_state_anchor_change_blocks_commit(self) -> None:
        engine, intent, _ = self.engine()
        result = engine.evaluate_intent(intent, self.evidence, actor_scope="nc25.operator")
        with self.assertRaisesRegex(ContractViolation, "^STATE_ANCHOR_CHANGED(:|$)"):
            engine.commit_execution(
                self.execution_request(
                    engine,
                    result,
                    intent,
                    state_anchor="8" * 64,
                ),
                actor_scope="nc25.executor",
                route_permit_hash=result["permit_hash"],
            )

    def test_failed_execution_consumes_without_debit(self) -> None:
        engine, intent, _ = self.engine()
        result = engine.evaluate_intent(intent, self.evidence, actor_scope="nc25.operator")
        receipt = engine.commit_execution(
            self.execution_request(engine, result, intent, outcome="FAILED"),
            actor_scope="nc25.executor",
            route_permit_hash=result["permit_hash"],
        )
        self.assertEqual(receipt["structural_debit"], 0)
        self.assertEqual(engine.structural_remaining, self.fx.capacity)
        with self.assertRaisesRegex(ContractViolation, "^EXECUTION_REPLAY_CONFLICT(:|$)"):
            engine.commit_execution(
                self.execution_request(engine, result, intent, outcome="COMMITTED"),
                actor_scope="nc25.executor",
                route_permit_hash=result["permit_hash"],
            )

    def test_ledger_tamper_fails_closed(self) -> None:
        engine, intent, _ = self.engine()
        engine.evaluate_intent(intent, self.evidence, actor_scope="nc25.operator")
        engine.ledger._events[0]["payload"]["activated_by"] = "tampered"
        with self.assertRaisesRegex(IntegrityViolation, "^LEDGER_CHAIN_FAILURE(:|$)"):
            engine.ledger_head(actor_scope="nc25.architect")

    def test_registry_and_observer_are_minimal(self) -> None:
        engine, intent, _ = self.engine()
        result = engine.evaluate_intent(intent, self.evidence, actor_scope="nc25.operator")
        registry = engine.registry_record(engine.declaration["connector"]["connector_id"], actor_scope="nc25.architect")
        engine.activated_at = {
            "raw_intent": {"payload": "must-not-leave-local-ledger"}
        }
        with self.assertRaisesRegex(
            IntegrityViolation,
            "^REGISTRY_DATA_EXPANSION(:|$)",
        ):
            engine.registry_record(engine.declaration["connector"]["connector_id"], actor_scope="nc25.architect")
        observer = engine.observer_projection(actor_scope="nc25.architect")
        self.assertTrue(observer)
        self.assertEqual(
            set(observer[-1]),
            {"channel", "message_code", "event_time", "subject_ref"},
        )
        self.assertNotIn(result["permit_hash"], observer[-1].values())
        narrow_profile = copy.deepcopy(self.profile)
        narrow_profile["roles"]["observer_projection_fields"] = [
            "channel",
            "event_time",
        ]
        narrow_engine, narrow_intent, _ = self.engine(profile=narrow_profile)
        narrow_result = narrow_engine.evaluate_intent(
            narrow_intent,
            self.evidence,
            actor_scope="nc25.operator",
        )
        narrow_observer = narrow_engine.observer_projection(actor_scope="nc25.architect")
        self.assertEqual(
            set(narrow_observer[-1]),
            {"channel", "event_time"},
        )
        self.assertNotIn(
            narrow_result["permit_hash"],
            narrow_observer[-1].values(),
        )
        narrow_engine.profile["roles"]["observer_projection_fields"] = [
            "channel",
            "message_code",
            "event_time",
            "subject_ref",
        ]
        with self.assertRaisesRegex(
            IntegrityViolation,
            "^PROFILE_SEAL_FAILURE(:|$)",
        ):
            narrow_engine.observer_projection(actor_scope="nc25.architect")

    def test_role_scope_must_be_explicit(self) -> None:
        # Claim one: every public operation refuses without an explicit role.
        # Asserted on a HEALTHY engine, so nothing about the chain can be the
        # reason it refuses. The surface is enumerated by introspection and
        # pinned against the harvested map, so a method added without a scope
        # check fails on arrival rather than shipping unswept.
        engine, _intent, _ = self.engine()
        methods = public_surface_methods()
        roles = harvested_surface_roles()
        self.assertEqual(
            set(methods), set(roles),
            "public surface and harvested scope checks disagree - a public "
            "method exists whose role could not be read from its own source",
        )
        for name, method in methods.items():
            signature = inspect.signature(method)
            self.assertIn(
                "actor_scope", signature.parameters,
                f"{name} declares no actor_scope parameter",
            )
            positional, keyword = dummy_arguments(signature)
            # The argument is OMITTED, not passed as None: an omitted argument
            # is never bound, so a default that had drifted to a live role
            # could not satisfy it silently.
            # Called through the BOUND method, which is the callable a client
            # actually holds - an unbound class function cannot show that the
            # client's own handle carries no role of its own.
            with self.subTest(method=name):
                with self.assertRaises(ContractViolation) as caught:
                    getattr(engine, name)(*positional, **keyword)
                self.assertEqual(
                    type(caught.exception), ContractViolation,
                    f"{name} refused, but with {type(caught.exception).__name__} "
                    f"- a contract refusal promoted to an integrity halt would "
                    f"pass a base-type assertion unnoticed",
                )
                # Anchored like every other code assertion in the suite: a
                # substring match also accepts a code that merely contains
                # this one.
                self.assertRegex(
                    str(caught.exception), r"^ROLE_SCOPE_MISMATCH(:|$)"
                )

    def test_scope_check_precedes_the_integrity_halt(self) -> None:
        # Claim two, and it is a claim in its own right: the role check runs
        # BEFORE the chain is verified. Reordering them would make integrity
        # status observable to a caller holding no role at all. Asserted on a
        # TAMPERED engine: if the halt ran first the call would surface
        # LEDGER_CHAIN_FAILURE, and the code regex below would fail.
        # IntegrityViolation subclasses ContractViolation, so the exception
        # type catches both and only the CODE separates them - do not
        # "simplify" the regex away.
        engine, _intent, _ = self.engine()
        engine.ledger._events[0]["payload"]["activated_by"] = "tampered"
        for name, method in public_surface_methods().items():
            positional, keyword = dummy_arguments(inspect.signature(method))
            with self.subTest(method=name):
                with self.assertRaises(ContractViolation) as caught:
                    getattr(engine, name)(*positional, **keyword)
                # Exact type: on a tampered engine an integrity halt IS a
                # ContractViolation subclass, so the base type alone would
                # accept the very inversion this claim exists to forbid.
                self.assertEqual(
                    type(caught.exception), ContractViolation,
                    f"{name} verified the chain before checking the role",
                )
                self.assertRegex(
                    str(caught.exception), r"^ROLE_SCOPE_MISMATCH(:|$)"
                )

    def test_integrity_halt_covers_the_public_surface(self) -> None:
        # Claim three: a broken chain blocks every public operation. Called
        # with the harvested role so the call reaches past the scope check.
        engine, _intent, _ = self.engine()
        roles = harvested_surface_roles()
        engine.ledger._events[0]["payload"]["activated_by"] = "tampered"
        for name, method in public_surface_methods().items():
            positional, keyword = dummy_arguments(inspect.signature(method))
            with self.subTest(method=name):
                with self.assertRaisesRegex(
                    IntegrityViolation, "^LEDGER_CHAIN_FAILURE(:|$)",
                    msg=f"{name} ran on an engine with a broken event chain",
                ):
                    method(engine, *positional, actor_scope=roles[name], **keyword)

    def test_harvested_roles_agree_with_the_wire_layer(self) -> None:
        # The harvested map is an observation of the engine. On its own it
        # cannot say whether a role is the RIGHT owner - only that it is the
        # one the method happens to demand. The adapter's route table is an
        # independent author of that judgement, so the two sources are made to
        # agree. The three methods with no route are named with their reason
        # rather than skipped silently: "no second source" is a fact worth
        # asserting, and a route appearing for one of them must be noticed.
        roles = harvested_surface_roles()
        wire = harvested_wire_roles()
        unrouted = set(roles) - set(wire)
        self.assertEqual(
            unrouted, set(UNROUTED_BY_DESIGN),
            "the set of public methods with no mounted route changed - a "
            "route appeared or vanished without the reason being recorded",
        )
        # The denominator, not just the rows. Every sweep in this file ranges
        # over the methods that are public NOW, so contracting that set
        # contracts every invariant at once while leaving each sweep green -
        # renaming a public operation to a private helper behind a thin public
        # delegate is an ordinary-looking refactor that does exactly this. The
        # wire layer is the witness: a route still reaches the operation, so a
        # method the adapter drives that is no longer part of the public
        # surface is a contraction, and it reddens here.
        self.assertEqual(
            set(wire) - set(roles), set(),
            "a mounted route reaches an engine method that is not part of the "
            "public surface - the swept domain has contracted under the sweeps",
        )
        for name, scope in wire.items():
            self.assertEqual(
                roles[name], scope,
                f"{name}: the engine demands {roles[name]} but the wire "
                f"mounts it under {scope}",
            )
        # Cardinality, not just membership. With it, a method leaving the
        # public surface has only two exits and both are red: stay routed and
        # the assertion above fires, or join the exempt list and this one does.
        # Without it the list absorbs the loss quietly, which is how an
        # exemption field returns after being refused entry.
        self.assertEqual(
            len(UNROUTED_BY_DESIGN), 3,
            "the exempt list changed size - an operation left the routed set",
        )
        # The other way work escapes every sweep: mount it on the adapter and
        # never call the engine at all. Tie the size of the harvest to the
        # number of route rows, the way http_scope_sweep_covers_all_routes
        # (test_contract_conformance.py) ties its sweep to the route table, so
        # a handler that stops reaching the engine cannot pass unseen.
        self.assertEqual(
            len(wire), adapter_route_row_count(),
            "a mounted route reaches no public engine method - work has moved "
            "to the adapter layer, outside every sweep in this file",
        )

    def test_integrity_guard_covers_all_three_seals(self) -> None:
        # The sweep above runs every public method against ONE integrity fact,
        # which proves the guard is called and called early enough. The guard
        # itself holds three facts, and they live in it rather than in the
        # methods - so they are proved here, once, instead of twelve times.
        # Without this, deleting either of the two unswept branches was green.
        # Each seal gets its OWN engine: tampering is not undone, so one shared
        # engine would leave the second break running against the first one's
        # damage and the code asserted would depend on the order of the tuple.
        seals = (
            ("profile seal", lambda e: e.profile.__setitem__("profile_id", "x"),
             "PROFILE_SEAL_FAILURE"),
            ("declaration seal",
             lambda e: e.declaration.__setitem__("declaration_id", "x"),
             "DECLARATION_SEAL_FAILURE"),
            ("event chain",
             lambda e: e.ledger._events[0]["payload"].__setitem__(
                 "activated_by", "tampered"),
             "LEDGER_CHAIN_FAILURE"),
        )
        for label, tamper, code in seals:
            with self.subTest(seal=label):
                fresh, _i, _g = self.engine()
                tamper(fresh)
                with self.assertRaisesRegex(IntegrityViolation, rf"^{code}(:|$)"):
                    fresh.ledger_head(actor_scope=ROLE_ARCHITECT)

    def test_every_public_method_carries_its_scope_at_runtime(self) -> None:
        # A witness that does not read source. The harvester and the wire check
        # both parse text; this one reads what Python actually built, so a role
        # that exists in the file but not in the constructed class - or the
        # reverse - is visible. It also refuses `__wrapped__`: that attribute
        # is a handle onto the undecorated function, which since the scope
        # check moved into the decorator carries no check at all.
        roles = harvested_surface_roles()
        for name, role in roles.items():
            member = getattr(UniversalConnectionLedger, name)
            with self.subTest(method=name):
                self.assertEqual(
                    getattr(member, "__nc25_required_scope__", None), role,
                    f"{name}: the built class does not carry the role its "
                    f"source declares",
                )
                self.assertFalse(
                    hasattr(member, "__wrapped__"),
                    f"{name} publishes __wrapped__, a path around the "
                    f"decorator that now holds the only scope check",
                )

    def test_role_scopes_are_non_interchangeable(self) -> None:
        engine, intent, _ = self.engine()
        result = engine.evaluate_intent(intent, self.evidence, actor_scope="nc25.operator")
        with self.assertRaisesRegex(ContractViolation, "^ROLE_SCOPE_MISMATCH(:|$)"):
            engine.architect_permit(
                result["permit_hash"],
                actor_scope="nc25.operator",
            )

    def test_material_change_requires_rebinding(self) -> None:
        changed = copy.deepcopy(self.profile)
        changed["domain"]["description"] += " Material revision."
        with self.assertRaisesRegex(ContractViolation, "^PROFILE_HASH_MISMATCH(:|$)"):
            UniversalConnectionLedger(
                changed,
                self.declaration,
                signing_key=b"synthetic-reference-signing-key",
                clock=self.clock,
            )


    def test_profile_control_classes_are_pairwise_disjoint(self) -> None:
        changed = copy.deepcopy(self.profile)
        changed["controls"]["hard_block_flag_ids"].append(
            self.fx.prerequisite_id
        )
        with self.assertRaisesRegex(
            ContractViolation,
            "^CONTROL_CLASS_OVERLAP(:|$)",
        ):
            bound = bind_fixture(
                changed,
                self.declaration,
                self.grant,
                self.intent,
            )
            UniversalConnectionLedger(
                bound[0],
                bound[1],
                signing_key=b"synthetic-reference-signing-key",
                clock=self.clock,
            )

    def test_concurrent_structural_reservation_is_serialized(self) -> None:
        declaration = copy.deepcopy(self.declaration)
        declaration["structural_budget"]["capacity"] = self.fx.action_cost
        engine, first_intent, _ = self.engine(declaration=declaration)
        second_intent, second_evidence = unique_intent(
            first_intent,
            self.evidence,
            "concurrent-reservation-002",
        )
        original = engine._active_structural_reserved

        def delayed(now: datetime) -> int:
            value = original(now)
            time.sleep(0.05)
            return value

        engine._active_structural_reserved = delayed
        results: list[dict] = []
        errors: list[BaseException] = []

        def evaluate(candidate_intent: dict, candidate_evidence: dict) -> None:
            try:
                results.append(
                    engine.evaluate_intent(
                        candidate_intent,
                        candidate_evidence,
                        actor_scope="nc25.operator",
                    )
                )
            except BaseException as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=evaluate, args=(first_intent, self.evidence)),
            threading.Thread(target=evaluate, args=(second_intent, second_evidence)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)
        self.assertFalse(errors)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(
            sorted(result["disposition"] for result in results),
            ["ALLOW", "REFUSAL"],
        )

    def test_temporal_causality_is_enforced(self) -> None:
        engine, intent, _ = self.engine()
        future_intent = copy.deepcopy(intent)
        future_intent["received_at"] = "2026-08-01T10:00:06Z"
        with self.assertRaisesRegex(ContractViolation, "^INTENT_TIME_IN_FUTURE(:|$)"):
            engine.evaluate_intent(
                future_intent,
                self.evidence,
                actor_scope="nc25.operator",
            )

        engine, intent, _ = self.engine()
        future_evidence = copy.deepcopy(self.evidence)
        future_evidence["collected_at"] = "2026-08-01T10:00:06Z"
        with self.assertRaisesRegex(ContractViolation, "^EVIDENCE_TIME_IN_FUTURE(:|$)"):
            engine.evaluate_intent(
                intent,
                future_evidence,
                actor_scope="nc25.operator",
            )

        engine, intent, _ = self.engine()
        result = engine.evaluate_intent(
            intent,
            self.evidence,
            actor_scope="nc25.operator",
        )
        request = self.execution_request(engine, result, intent)
        request["committed_at"] = "2026-08-01T09:59:54Z"
        with self.assertRaisesRegex(
            ContractViolation,
            "^EXECUTION_TIME_PRECEDES_PERMIT(:|$)",
        ):
            engine.commit_execution(
                request,
                actor_scope="nc25.executor",
                route_permit_hash=request["permit_hash"],
            )

        engine, _, grant = self.engine()
        # The call below is load-bearing already: it asserts acceptance by not
        # raising, and the five-second skew bound is pinned from both sides
        # (narrowing it reddens here, widening it reddens the anchored case
        # further down). What was never asserted is the EFFECT - that an
        # accepted revocation actually revokes and actually reaches the chain.
        events_before = engine.ledger.head()["event_count"]
        engine.revoke_grant(
            {
                "message_type": "authority_revocation",
                "grant_id": grant["grant_id"],
                "declaration_hash": engine.declaration_hash,
                "revoked_at": "2026-08-01T10:00:05Z",
                "revoked_by": self.fx.authority_issuer,
                "reason_code": "SYNTHETIC_REVOCATION",
                "evidence_ref": "evidence://synthetic/revocation/skew-accepted",
            },
            actor_scope="nc25.governance",
        )
        self.assertIn(grant["grant_id"], engine.revoked_grants)
        self.assertEqual(
            engine.ledger.head()["event_count"],
            events_before + 1,
            "an accepted revocation must reach the chain",
        )

        future_engine, _, future_grant = self.engine()
        with self.assertRaisesRegex(ContractViolation, "^REVOCATION_IN_FUTURE(:|$)"):
            future_engine.revoke_grant(
                {
                    "message_type": "authority_revocation",
                    "grant_id": future_grant["grant_id"],
                    "declaration_hash": future_engine.declaration_hash,
                    "revoked_at": "2026-08-01T10:00:06Z",
                    "revoked_by": self.fx.authority_issuer,
                    "reason_code": "SYNTHETIC_REVOCATION",
                    "evidence_ref": "evidence://synthetic/revocation/skew-rejected",
                },
                actor_scope="nc25.governance",
            )


class BankingConnectionTests(ConnectionSuite, unittest.TestCase):
    make_fixtures = staticmethod(banking_fixtures)


class DocumentReleaseConnectionTests(ConnectionSuite, unittest.TestCase):
    make_fixtures = staticmethod(document_release_fixtures)


class OTCSConnectionTests(ConnectionSuite, unittest.TestCase):
    make_fixtures = staticmethod(otcs_fixtures)


if __name__ == "__main__":
    unittest.main(verbosity=2)
