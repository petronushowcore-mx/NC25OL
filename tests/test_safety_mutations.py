from __future__ import annotations

import copy
import hashlib
import sys
import threading
import time
from collections import UserDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python"))

from nc25_universal_ledger import (  # noqa: E402
    ContractViolation,
    FixedClock,
    HmacDetachedSigner,
    ROLE_OPERATOR,
    UniversalConnectionLedger,
    bind_fixture,
    load_json,
    sha256_hex,
    validate_declaration,
    validate_profile,
)


SIGNING_KEY = b"synthetic-reference-signing-key"
EXPECTED_MUTATION_IDS = frozenset(
    {
        "CORE_ANCHOR", "WITNESS_HASH", "WITNESS_COVERAGE",
        "ZERO_EFFECT_FALLBACK", "PROFILE_FAILURE_POSTURE_SURFACE",
        "DECLARATION_FAILURE_POSTURE_OVERRIDE", "PROFILE_BINDING",
        "DECLARATION_SEAL", "PROFILE_SCOPE_EXPANSION", "OFF_LIMITS_TARGET",
        "AUTHORITY_SCOPE", "ROLE_SCOPE", "OPERATOR_GATE_DATA",
        "MISSING_EVIDENCE", "AMBIGUITY", "HARD_BLOCK", "MANUAL_REVIEW",
        "STRUCTURAL_CONJUNCTION", "RESOURCE_PER_INTENT",
        "RESOURCE_WINDOW_COMMIT", "RESOURCE_WINDOW_BOUNDARY", "IDEMPOTENCY",
        "REVOCATION_BEFORE_COMMIT", "PERMIT_EXPIRY_AT_COMMIT",
        "GRANT_EXPIRY_AT_COMMIT", "STATE_ANCHOR", "EXACTLY_ONCE",
        "UNAUTHORIZED_REVOKER", "EXECUTION_CONNECTOR", "PERMIT_SEAL",
        "LEDGER_CHAIN", "REGISTRY_MINIMIZATION", "MATERIAL_CHANGE_REBIND",
        "NO_EFFECT_RESOURCE", "REPLAYED_NON_EXECUTABLE_PERMIT",
        "SECRET_SCOPED_FIELD", "CANONICAL_SURROGATE",
        "MAPPING_CANONICALIZATION", "NESTING_DEPTH",
        "SCOPE_CONSTRAINT_VALUE_TYPE", "GOVERNANCE_EVIDENCE_TYPE",
        "ACTIVATION_ATOMICITY", "REVOKED_GRANT_REISSUE",
        "AUTHORITY_NOT_YET_VALID", "EXECUTION_REPLAY_CONFLICT",
        "STRUCTURAL_RESERVATION_SERIALIZATION", "REVOCATION_CLOCK_SKEW",
        "STRUCTURAL_PROVENANCE", "UNAUTHORIZED_ACTIVATOR",
        "CUSTODY_ROTATE_SCOPE", "CUSTODY_REVOKE_SCOPE",
    }
)
executed_mutations: set[str] = set()


def _record_mutation(label: str, marker: str) -> None:
    if label not in EXPECTED_MUTATION_IDS:
        raise AssertionError(f"UNDECLARED_SAFETY_MUTATION: {label}")
    if label in executed_mutations:
        raise AssertionError(f"DUPLICATE_SAFETY_MUTATION: {label}")
    executed_mutations.add(label)
    print(f"PASS {label}: {marker}")


def fixtures() -> tuple[dict, dict, dict, dict, dict]:
    return (
        load_json(ROOT / "profiles" / "banking" / "bank-profile.json"),
        load_json(ROOT / "examples" / "synthetic-connection-declaration.json"),
        load_json(ROOT / "examples" / "synthetic-authority-grant.json"),
        load_json(ROOT / "examples" / "synthetic-intent-allow.json"),
        load_json(ROOT / "examples" / "synthetic-evidence-bundle.json"),
    )


def clock() -> FixedClock:
    return FixedClock(datetime(2026, 8, 1, 10, 0, tzinfo=timezone.utc))


def ungranted_engine(
    profile: dict | None = None,
    declaration: dict | None = None,
    grant: dict | None = None,
    intent: dict | None = None,
) -> tuple[UniversalConnectionLedger, dict, dict, dict]:
    base_profile, base_declaration, base_grant, base_intent, evidence = fixtures()
    bound = bind_fixture(
        profile or base_profile,
        declaration or base_declaration,
        grant or base_grant,
        intent or base_intent,
    )
    bound_profile, bound_declaration, bound_grant, bound_intent = bound
    engine = UniversalConnectionLedger(
        bound_profile,
        bound_declaration,
        signing_key=SIGNING_KEY,
        clock=clock(),
    )
    engine.activate(
        "synthetic-approval-owner",
        "evidence://synthetic/declaration-activation",
        actor_scope="nc25.governance",
    )
    return engine, bound_grant, bound_intent, evidence


def draft_engine() -> UniversalConnectionLedger:
    """An engine still in DRAFT — for mutations that must attack activation."""
    base_profile, base_declaration, base_grant, base_intent, _ = fixtures()
    bound_profile, bound_declaration, _, _ = bind_fixture(
        base_profile, base_declaration, base_grant, base_intent
    )
    return UniversalConnectionLedger(
        bound_profile,
        bound_declaration,
        signing_key=SIGNING_KEY,
        clock=clock(),
    )


def ready_engine(
    profile: dict | None = None,
    declaration: dict | None = None,
    grant: dict | None = None,
    intent: dict | None = None,
) -> tuple[UniversalConnectionLedger, dict, dict, dict]:
    engine, bound_grant, bound_intent, evidence = ungranted_engine(
        profile,
        declaration,
        grant,
        intent,
    )
    engine.issue_grant(bound_grant, actor_scope="nc25.governance")
    return engine, bound_grant, bound_intent, evidence


def unique_intent(intent: dict, evidence: dict, suffix: str) -> tuple[dict, dict]:
    changed_intent = copy.deepcopy(intent)
    changed_evidence = copy.deepcopy(evidence)
    changed_intent["intent_id"] = f"synthetic-intent-{suffix}"
    changed_intent["idempotency_key"] = f"synthetic-idempotency-{suffix}"
    changed_intent["payload_hash"] = hashlib.sha256(suffix.encode()).hexdigest()
    changed_evidence["intent_id"] = changed_intent["intent_id"]
    return changed_intent, changed_evidence


def execution_request(
    engine: UniversalConnectionLedger,
    result: dict,
    intent: dict,
    state_anchor: str | None = None,
) -> dict:
    return {
        "message_type": "execution_request",
        "permit_hash": result["permit_hash"],
        "connector_id": intent["connector_id"],
        "binding": intent["binding"],
        "state_anchor_hash": state_anchor or intent["state_anchor_hash"],
        "outcome": "COMMITTED",
        "downstream_receipt_hash": "9" * 64,
        "committed_at": "2026-08-01T10:00:00Z",
    }


def expect_exception(
    label: str,
    expected_code: str,
    action: Callable[[], object],
) -> None:
    try:
        action()
    except ContractViolation as exc:
        if exc.code != expected_code:
            raise AssertionError(
                f"{label}: expected {expected_code}, received {exc.code}"
            ) from exc
        _record_mutation(label, expected_code)
        return
    raise AssertionError(f"{label}: mutation did not fail")


def expect_result(
    label: str,
    expected_code: str,
    action: Callable[[], dict],
    expected_disposition: str | None = None,
) -> None:
    result = action()
    operator_codes = {
        "ALLOW": "EXECUTION_AUTHORIZED",
        "REFUSAL": "EXECUTION_DENIED",
        "MANUAL_REVIEW": "HUMAN_REVIEW_REQUIRED",
    }
    expected_operator_code = operator_codes[result["disposition"]]
    if result["message_code"] != expected_operator_code:
        raise AssertionError(
            f"{label}: expected operator code {expected_operator_code}, "
            f"received {result['message_code']}"
        )
    if result["disposition"] == "ALLOW":
        raise AssertionError(f"{label}: mutation became executable")
    if expected_disposition and result["disposition"] != expected_disposition:
        raise AssertionError(
            f"{label}: expected {expected_disposition}, "
            f"received {result['disposition']}"
        )
    if result["permit_hash"] is not None:
        raise AssertionError(f"{label}: non-executable result carried a permit")
    captured_engines = [
        cell.cell_contents
        for cell in (action.__closure__ or ())
        if isinstance(cell.cell_contents, UniversalConnectionLedger)
    ]
    if len(captured_engines) != 1:
        raise AssertionError(
            f"{label}: mutation must capture exactly one ledger engine"
        )
    architect_code = captured_engines[0].architect_decision(
        result["request_hash"],
        actor_scope="nc25.architect",
    )["message_code"]
    if architect_code != expected_code:
        raise AssertionError(
            f"{label}: expected architect code {expected_code}, "
            f"received {architect_code}"
        )
    _record_mutation(label, expected_code)


def main() -> None:
    executed_mutations.clear()
    profile, declaration, grant, intent, evidence = fixtures()
    baseline, _, baseline_intent, baseline_evidence = ready_engine()
    baseline_result = baseline.evaluate_intent(
        baseline_intent,
        baseline_evidence,
        actor_scope="nc25.operator",
    )
    if baseline_result["disposition"] != "ALLOW":
        raise AssertionError("baseline did not allow")
    print("PASS BASELINE_ALLOW")

    changed = copy.deepcopy(profile)
    changed["core_anchor"]["sha256"] = "0" * 64
    expect_exception(
        "CORE_ANCHOR",
        "CORE_ANCHOR_MISMATCH",
        lambda: validate_profile(changed),
    )

    changed = copy.deepcopy(profile)
    changed["mapping_witness"]["method"] += " altered"
    expect_exception(
        "WITNESS_HASH",
        "WITNESS_HASH_MISMATCH",
        lambda: validate_profile(changed),
    )

    changed = copy.deepcopy(profile)
    changed["mapping_witness"]["covered_action_ids"].pop()
    expect_exception(
        "WITNESS_COVERAGE",
        "WITNESS_ACTION_COVERAGE",
        lambda: validate_profile(changed),
    )

    changed = copy.deepcopy(profile)
    for action in changed["action_alphabet"]:
        if action["action_id"] == "NO_EFFECT_FALLBACK":
            action["structural_cost"] = 1
    expect_exception(
        "ZERO_EFFECT_FALLBACK",
        "SAFE_FALLBACK_NOT_ZERO_EFFECT",
        lambda: validate_profile(changed),
    )

    changed = copy.deepcopy(profile)
    changed["failure_posture"]["integrity_failure"] = "ERROR"
    expect_exception(
        "PROFILE_FAILURE_POSTURE_SURFACE",
        "FAILURE_POSTURE",
        lambda: validate_profile(changed),
    )

    changed_declaration = copy.deepcopy(declaration)
    changed_declaration["failure_posture"] = copy.deepcopy(
        profile["failure_posture"]
    )
    expect_exception(
        "DECLARATION_FAILURE_POSTURE_OVERRIDE",
        "DECLARATION_FIELDS",
        lambda: validate_declaration(changed_declaration, profile),
    )

    changed_declaration = copy.deepcopy(declaration)
    changed_declaration["profile_binding"]["profile_hash"] = "0" * 64
    expect_exception(
        "PROFILE_BINDING",
        "PROFILE_HASH_MISMATCH",
        lambda: validate_declaration(changed_declaration, profile),
    )

    changed_declaration = copy.deepcopy(declaration)
    changed_declaration["structural_budget"]["provenance"] = "vendor_asserted"
    expect_exception(
        "STRUCTURAL_PROVENANCE",
        "STRUCTURAL_PROVENANCE",
        lambda: validate_declaration(changed_declaration, profile),
    )

    engine, _, changed_intent, bundle = ready_engine()
    engine.declaration["declaration_version"] = "1.0.1"
    expect_exception(
        "DECLARATION_SEAL",
        "DECLARATION_SEAL_FAILURE",
        lambda: engine.evaluate_intent(changed_intent, bundle, actor_scope="nc25.operator"),
    )

    changed_declaration = copy.deepcopy(declaration)
    changed_declaration["instance_scope"]["action_ids"].append("UNDECLARED_ACTION")
    expect_exception(
        "PROFILE_SCOPE_EXPANSION",
        "SCOPE_UNKNOWN_ACTION",
        lambda: validate_declaration(changed_declaration, profile),
    )

    changed_declaration = copy.deepcopy(declaration)
    changed_declaration["interfaces"]["off_limits_system_ids"].append(
        "bank-sandbox-ledger"
    )
    expect_exception(
        "OFF_LIMITS_TARGET",
        "TARGET_OFF_LIMITS_OVERLAP",
        lambda: validate_declaration(changed_declaration, profile),
    )

    engine, changed_grant, _, _ = ungranted_engine()
    changed_grant["permitted_action_ids"].append("UNDECLARED_ACTION")
    expect_exception(
        "AUTHORITY_SCOPE",
        "AUTHORITY_ACTION_SCOPE",
        lambda: engine.issue_grant(changed_grant, actor_scope="nc25.governance"),
    )

    engine, _, _, _ = ungranted_engine()
    expect_exception(
        "ROLE_SCOPE",
        "ROLE_SCOPE_MISMATCH",
        lambda: engine.issue_grant(grant, actor_scope=ROLE_OPERATOR),
    )

    engine, _, changed_intent, bundle = ready_engine()
    changed_intent["scope"]["gate_margin"] = "0.01"
    expect_exception(
        "OPERATOR_GATE_DATA",
        "OPERATOR_GATE_DATA_FORBIDDEN",
        lambda: engine.evaluate_intent(changed_intent, bundle, actor_scope="nc25.operator"),
    )

    engine, _, changed_intent, bundle = ready_engine()
    missing_bundle = copy.deepcopy(bundle)
    missing_bundle["items"] = missing_bundle["items"][:-1]
    expect_result(
        "MISSING_EVIDENCE",
        "EVIDENCE_MISSING",
        lambda: engine.evaluate_intent(
            changed_intent,
            missing_bundle,
            actor_scope="nc25.operator",
        ),
        "REFUSAL",
    )

    engine, _, changed_intent, bundle = ready_engine()
    changed_intent["ambiguity_flags"] = ["synthetic-ambiguity"]
    expect_result(
        "AMBIGUITY",
        "AMBIGUOUS_INTENT",
        lambda: engine.evaluate_intent(
            changed_intent,
            bundle,
            actor_scope="nc25.operator",
        ),
        "MANUAL_REVIEW",
    )

    engine, _, changed_intent, bundle = ready_engine()
    changed_intent["hard_block_flags"]["ACCOUNT_FROZEN"] = True
    expect_result(
        "HARD_BLOCK",
        "HARD_BLOCK",
        lambda: engine.evaluate_intent(changed_intent, bundle, actor_scope="nc25.operator"),
        "REFUSAL",
    )

    engine, _, changed_intent, bundle = ready_engine()
    changed_intent["manual_review_flags"]["RULE_CONFLICT"] = True
    expect_result(
        "MANUAL_REVIEW",
        "MANUAL_REVIEW_REQUIRED",
        lambda: engine.evaluate_intent(changed_intent, bundle, actor_scope="nc25.operator"),
        "MANUAL_REVIEW",
    )

    low_capacity = copy.deepcopy(declaration)
    low_capacity["structural_budget"]["capacity"] = 100
    engine, _, first_intent, bundle = ready_engine(declaration=low_capacity)
    first = engine.evaluate_intent(first_intent, bundle, actor_scope="nc25.operator")
    if first["disposition"] != "ALLOW":
        raise AssertionError("reservation setup did not allow")
    second_intent, second_bundle = unique_intent(
        first_intent,
        bundle,
        "structural-reservation",
    )
    expect_result(
        "STRUCTURAL_CONJUNCTION",
        "STRUCTURAL_BUDGET_EXHAUSTED",
        lambda: engine.evaluate_intent(second_intent, second_bundle, actor_scope="nc25.operator"),
        "REFUSAL",
    )

    engine, _, changed_intent, bundle = ready_engine()
    changed_intent["resource_claims"]["money_minor_units"] = 50001
    expect_result(
        "RESOURCE_PER_INTENT",
        "RESOURCE_PER_INTENT_LIMIT",
        lambda: engine.evaluate_intent(changed_intent, bundle, actor_scope="nc25.operator"),
        "REFUSAL",
    )

    unreserved_profile = copy.deepcopy(profile)
    for resource in unreserved_profile["resource_catalog"]:
        if resource["resource_id"] == "money_minor_units":
            resource["reservation_required"] = False
    tight_window = copy.deepcopy(declaration)
    for limit in tight_window["resource_limits"]:
        if limit["resource_id"] == "money_minor_units":
            limit["max_per_intent"] = 20000
            limit["max_committed_per_window"] = 20000
    engine, _, first_intent, bundle = ready_engine(
        profile=unreserved_profile,
        declaration=tight_window,
    )
    first = engine.evaluate_intent(first_intent, bundle, actor_scope="nc25.operator")
    if first["disposition"] != "ALLOW":
        raise AssertionError("resource commit-window setup did not allow")
    second_intent, second_bundle = unique_intent(
        first_intent,
        bundle,
        "resource-commit-window",
    )
    second = engine.evaluate_intent(second_intent, second_bundle, actor_scope="nc25.operator")
    if second["disposition"] != "ALLOW":
        raise AssertionError("unreserved competing permit was not issued")
    engine.commit_execution(
        execution_request(engine, first, first_intent),
        actor_scope="nc25.executor",
        route_permit_hash=first["permit_hash"],
    )
    expect_exception(
        "RESOURCE_WINDOW_COMMIT",
        "RESOURCE_WINDOW_LIMIT",
        lambda: engine.commit_execution(
            execution_request(engine, second, second_intent),
            actor_scope="nc25.executor",
            route_permit_hash=second["permit_hash"],
        ),
    )
    window_seconds = next(
        limit["window_seconds"]
        for limit in tight_window["resource_limits"]
        if limit["resource_id"] == "money_minor_units"
    )
    engine.clock.advance(seconds=window_seconds)
    boundary_intent, boundary_bundle = unique_intent(
        first_intent,
        bundle,
        "resource-window-boundary",
    )
    expect_result(
        "RESOURCE_WINDOW_BOUNDARY",
        "RESOURCE_WINDOW_LIMIT",
        lambda: engine.evaluate_intent(
            boundary_intent,
            boundary_bundle,
            actor_scope="nc25.operator",
        ),
        "REFUSAL",
    )


    engine, _, changed_intent, bundle = ready_engine()
    engine.evaluate_intent(changed_intent, bundle, actor_scope="nc25.operator")
    conflict = copy.deepcopy(changed_intent)
    conflict["payload_hash"] = "7" * 64
    expect_exception(
        "IDEMPOTENCY",
        "IDEMPOTENCY_CONFLICT",
        lambda: engine.evaluate_intent(conflict, bundle, actor_scope="nc25.operator"),
    )

    engine, bound_grant, changed_intent, bundle = ready_engine()
    allowed = engine.evaluate_intent(changed_intent, bundle, actor_scope="nc25.operator")
    engine.revoke_grant(
        {
            "message_type": "authority_revocation",
            "grant_id": bound_grant["grant_id"],
            "declaration_hash": engine.declaration_hash,
            "revoked_at": "2026-08-01T10:00:00Z",
            "revoked_by": "synthetic-authority-issuer",
            "reason_code": "SYNTHETIC_REVOCATION",
            "evidence_ref": "evidence://synthetic/revocation/001",
        },
        actor_scope="nc25.governance",
    )
    expect_exception(
        "REVOCATION_BEFORE_COMMIT",
        "AUTHORITY_REVOKED",
        lambda: engine.commit_execution(
            execution_request(engine, allowed, changed_intent),
            actor_scope="nc25.executor",
            route_permit_hash=allowed["permit_hash"],
        ),
    )

    engine, _, changed_intent, bundle = ready_engine()
    allowed = engine.evaluate_intent(changed_intent, bundle, actor_scope="nc25.operator")
    engine.clock.advance(seconds=301)
    expect_exception(
        "PERMIT_EXPIRY_AT_COMMIT",
        "PERMIT_EXPIRED",
        lambda: engine.commit_execution(
            execution_request(engine, allowed, changed_intent),
            actor_scope="nc25.executor",
            route_permit_hash=allowed["permit_hash"],
        ),
    )

    expiring_grant = copy.deepcopy(grant)
    expiring_grant["valid_until"] = "2026-08-01T10:00:30Z"
    engine, _, changed_intent, bundle = ready_engine(grant=expiring_grant)
    allowed = engine.evaluate_intent(changed_intent, bundle, actor_scope="nc25.operator")
    engine.clock.advance(seconds=120)
    expired_grant_request = execution_request(engine, allowed, changed_intent)
    expired_grant_request["committed_at"] = "2026-08-01T10:02:00Z"
    expect_exception(
        "GRANT_EXPIRY_AT_COMMIT",
        "AUTHORITY_EXPIRED",
        lambda: engine.commit_execution(
            expired_grant_request,
            actor_scope="nc25.executor",
            route_permit_hash=expired_grant_request["permit_hash"],
        ),
    )

    engine, _, changed_intent, bundle = ready_engine()
    allowed = engine.evaluate_intent(changed_intent, bundle, actor_scope="nc25.operator")
    expect_exception(
        "STATE_ANCHOR",
        "STATE_ANCHOR_CHANGED",
        lambda: engine.commit_execution(
            execution_request(
                engine,
                allowed,
                changed_intent,
                state_anchor="8" * 64,
            ),
            actor_scope="nc25.executor",
            route_permit_hash=allowed["permit_hash"],
        ),
    )

    engine, _, changed_intent, bundle = ready_engine()
    allowed = engine.evaluate_intent(changed_intent, bundle, actor_scope="nc25.operator")
    request = execution_request(engine, allowed, changed_intent)
    first_receipt = engine.commit_execution(
        request,
        actor_scope="nc25.executor",
        route_permit_hash=request["permit_hash"],
    )
    event_count = len(engine.ledger._events)
    receipt_count = len(engine.receipt_hashes)
    structural_remaining = engine.structural_remaining
    replayed_receipt = engine.commit_execution(
        request,
        actor_scope="nc25.executor",
        route_permit_hash=request["permit_hash"],
    )
    if replayed_receipt != first_receipt:
        raise AssertionError("EXACTLY_ONCE: exact retry changed the receipt")
    if len(engine.ledger._events) != event_count:
        raise AssertionError("EXACTLY_ONCE: exact retry appended another event")
    if len(engine.receipt_hashes) != receipt_count:
        raise AssertionError("EXACTLY_ONCE: exact retry stored another receipt")
    if engine.structural_remaining != structural_remaining:
        raise AssertionError("EXACTLY_ONCE: exact retry debited structural budget")
    _record_mutation("EXACTLY_ONCE", "EXACT_REPLAY_WITHOUT_SECOND_DEBIT")

    changed_request = copy.deepcopy(request)
    changed_request["downstream_receipt_hash"] = "8" * 64
    expect_exception(
        "EXECUTION_REPLAY_CONFLICT",
        "EXECUTION_REPLAY_CONFLICT",
        lambda: engine.commit_execution(
            changed_request,
            actor_scope="nc25.executor",
            route_permit_hash=changed_request["permit_hash"],
        ),
    )

    engine, bound_grant, _, _ = ready_engine()
    expect_exception(
        "UNAUTHORIZED_REVOKER",
        "REVOCATION_ACTOR_UNAUTHORIZED",
        lambda: engine.revoke_grant(
            {
                "message_type": "authority_revocation",
                "grant_id": bound_grant["grant_id"],
                "declaration_hash": engine.declaration_hash,
                "revoked_at": "2026-08-01T10:00:00Z",
                "revoked_by": "synthetic-unauthorized-revoker",
                "reason_code": "SYNTHETIC_REVOCATION",
                "evidence_ref": "evidence://synthetic/revocation/unauthorized",
            },
            actor_scope="nc25.governance",
        ),
    )

    engine, _, _, _ = ready_engine()
    expect_exception(
        "UNAUTHORIZED_ACTIVATOR",
        "ACTIVATION_ACTOR_UNAUTHORIZED",
        lambda: draft_engine().activate(
            "synthetic-unauthorized-activator",
            "evidence://synthetic/declaration-activation",
            actor_scope="nc25.governance",
        ),
    )

    # Key custody is the pair that shipped outside the explicit-scope rule.
    # Both members carry a named mutation so the class cannot regress quietly
    # on one method while the other stays pinned.
    engine, _, _, _ = ready_engine()
    expect_exception(
        "CUSTODY_ROTATE_SCOPE",
        "ROLE_SCOPE_MISMATCH",
        lambda: engine.rotate_permit_signer(
            HmacDetachedSigner(b"synthetic-unscoped-rotation", "unscoped-key"),
        ),
    )

    engine, _, _, _ = ready_engine()
    engine.rotate_permit_signer(
        HmacDetachedSigner(b"synthetic-retiring-key", "retired-key"),
        actor_scope="nc25.governance",
    )
    expect_exception(
        "CUSTODY_REVOKE_SCOPE",
        "ROLE_SCOPE_MISMATCH",
        lambda: engine.revoke_permit_key("reference-hmac"),
    )

    engine, _, changed_intent, bundle = ready_engine()
    allowed = engine.evaluate_intent(changed_intent, bundle, actor_scope="nc25.operator")
    changed_request = execution_request(engine, allowed, changed_intent)
    changed_request["connector_id"] = "synthetic-other-connector"
    expect_exception(
        "EXECUTION_CONNECTOR",
        "EXECUTION_CONNECTOR_MISMATCH",
        lambda: engine.commit_execution(
            changed_request,
            actor_scope="nc25.executor",
            route_permit_hash=changed_request["permit_hash"],
        ),
    )

    engine, _, changed_intent, bundle = ready_engine()
    allowed = engine.evaluate_intent(changed_intent, bundle, actor_scope="nc25.operator")
    engine.permits[allowed["permit_hash"]].body["action_id"] = "TAMPERED_ACTION"
    expect_exception(
        "PERMIT_SEAL",
        "PERMIT_HASH_FAILURE",
        lambda: engine.commit_execution(
            execution_request(engine, allowed, changed_intent),
            actor_scope="nc25.executor",
            route_permit_hash=allowed["permit_hash"],
        ),
    )

    engine, _, changed_intent, bundle = ready_engine()
    engine.evaluate_intent(changed_intent, bundle, actor_scope="nc25.operator")
    engine.ledger._events[0]["payload"]["activated_by"] = "tampered"
    expect_exception(
        "LEDGER_CHAIN",
        "LEDGER_CHAIN_FAILURE",
        lambda: engine.ledger_head(actor_scope="nc25.architect"),
    )

    engine, _, _, _ = ready_engine()
    engine.activated_at = {
        "raw_intent": {"payload": "must-not-leave-local-ledger"}
    }
    expect_exception(
        "REGISTRY_MINIMIZATION",
        "REGISTRY_DATA_EXPANSION",
        lambda: engine.registry_record(engine.declaration["connector"]["connector_id"], actor_scope="nc25.architect"),
    )

    changed_profile = copy.deepcopy(profile)
    changed_profile["domain"]["description"] += " Material change."
    expect_exception(
        "MATERIAL_CHANGE_REBIND",
        "PROFILE_HASH_MISMATCH",
        lambda: validate_declaration(declaration, changed_profile),
    )

    engine, _, fallback_intent, _ = ready_engine()
    fallback_intent["intent_id"] = "synthetic-intent-fallback"
    fallback_intent["idempotency_key"] = "synthetic-idempotency-fallback"
    fallback_intent["action_id"] = "NO_EFFECT_FALLBACK"
    fallback_intent["target_system_id"] = "local-fallback"
    fallback_intent["resource_claims"] = {"money_minor_units": 1}
    fallback_bundle = {
        "message_type": "evidence_bundle",
        "intent_id": fallback_intent["intent_id"],
        "collected_at": "2026-08-01T09:59:50Z",
        "items": [
            {
                "evidence_type": "DECLARATION_BINDING",
                "ref": "evidence://synthetic/declaration-binding/001",
                "sha256": "A" * 64,
                "status": "VALID",
            }
        ],
    }
    expect_result(
        "NO_EFFECT_RESOURCE",
        "RESOURCE_CLAIM_SET",
        lambda: engine.evaluate_intent(fallback_intent, fallback_bundle, actor_scope="nc25.operator"),
        "REFUSAL",
    )

    # Same intent and idempotency key as NO_EFFECT_RESOURCE above, so this call
    # is served from the idempotency store instead of being re-evaluated. The
    # property it covers is therefore the narrow one: replaying a stored
    # non-executable result must not acquire a permit. The first-evaluation
    # case is already covered by expect_result, which asserts a null
    # permit_hash for every non-executable mutation above.
    replayed_non_executable_result = engine.evaluate_intent(
        fallback_intent,
        fallback_bundle,
        actor_scope="nc25.operator",
    )
    if replayed_non_executable_result["permit_hash"] is not None:
        raise AssertionError(
            "REPLAYED_NON_EXECUTABLE_PERMIT: replayed non-executable result "
            "carried a permit"
        )
    _record_mutation(
        "REPLAYED_NON_EXECUTABLE_PERMIT",
        "REPLAYED_NON_EXECUTABLE_RESULT_HAS_NO_PERMIT",
    )

    expect_exception(
        "CANONICAL_SURROGATE",
        "CANONICAL_JSON_INVALID",
        lambda: sha256_hex({"text": "\ud800"}),
    )

    plain_mapping = {"alpha": [1, 2, 3]}
    if sha256_hex(UserDict(plain_mapping)) != sha256_hex(plain_mapping):
        raise AssertionError(
            "MAPPING_CANONICALIZATION: Mapping and dict hashes diverged"
        )
    _record_mutation("MAPPING_CANONICALIZATION", "MAPPING_NORMALIZED")

    def nested_lists(depth: int) -> list:
        root: list = []
        cursor = root
        for _ in range(depth):
            child: list = []
            cursor.append(child)
            cursor = child
        return root

    # The bound from both sides, as LITERALS. A single probe at depth 66 stayed
    # green when the limit moved from 64 to 65 - measured - because 66 exceeds
    # both. Depth 64 must hash and depth 65 must not. The numbers are written
    # here rather than imported from the engine: a row built from the engine's
    # own constant follows the very mutation it exists to catch, and it did -
    # measured, that version stayed green at a limit of 65 as well.
    sha256_hex(nested_lists(64))
    expect_exception(
        "NESTING_DEPTH",
        "NESTING_DEPTH_EXCEEDED",
        lambda: sha256_hex(nested_lists(65)),
    )

    invalid_constraints = copy.deepcopy(declaration)
    first_dimension = next(
        iter(invalid_constraints["instance_scope"]["scope_constraints"])
    )
    invalid_constraints["instance_scope"]["scope_constraints"][first_dimension] = [
        {"not": "a string"}
    ]
    expect_exception(
        "SCOPE_CONSTRAINT_VALUE_TYPE",
        "SCOPE_CONSTRAINT_VALUES",
        lambda: validate_declaration(invalid_constraints, profile),
    )

    bound_profile, bound_declaration, _, _ = bind_fixture(
        profile,
        declaration,
        grant,
        intent,
    )

    def assert_code(action: Callable[[], object], expected: str) -> None:
        try:
            action()
        except ContractViolation as exc:
            if exc.code != expected:
                raise AssertionError(
                    f"expected {expected}, received {exc.code}"
                ) from exc
            return
        raise AssertionError(f"expected {expected}, but the call succeeded")

    activation_engine = UniversalConnectionLedger(
        bound_profile,
        bound_declaration,
        signing_key=SIGNING_KEY,
        clock=clock(),
    )
    assert_code(
        lambda: activation_engine.activate(
            "synthetic-approval-owner",
            {"ref": "not-a-string"},
            actor_scope="nc25.governance",
        ),
        "ACTIVATION_EVIDENCE_REQUIRED",
    )
    evidence_engine, evidence_grant, _, _ = ungranted_engine()
    invalid_grant_evidence = copy.deepcopy(evidence_grant)
    invalid_grant_evidence["approval_evidence_ref"] = {"ref": "not-a-string"}
    assert_code(
        lambda: evidence_engine.issue_grant(
            invalid_grant_evidence,
            actor_scope="nc25.governance",
        ),
        "AUTHORITY_EVIDENCE_REQUIRED",
    )
    revocation_engine, revocation_grant, _, _ = ready_engine()
    assert_code(
        lambda: revocation_engine.revoke_grant(
            {
                "message_type": "authority_revocation",
                "grant_id": revocation_grant["grant_id"],
                "declaration_hash": revocation_engine.declaration_hash,
                "revoked_at": "2026-08-01T10:00:00Z",
                "revoked_by": "synthetic-authority-issuer",
                "reason_code": "SYNTHETIC_REVOCATION",
                "evidence_ref": {"ref": "not-a-string"},
            },
            actor_scope="nc25.governance",
        ),
        "REVOCATION_EVIDENCE_REQUIRED",
    )
    _record_mutation(
        "GOVERNANCE_EVIDENCE_TYPE",
        "STRING_EVIDENCE_REFERENCE_REQUIRED",
    )

    class NaiveClock:
        @staticmethod
        def now() -> datetime:
            return datetime(2026, 8, 1, 10, 0)

    atomic_engine = UniversalConnectionLedger(
        bound_profile,
        bound_declaration,
        signing_key=SIGNING_KEY,
        clock=NaiveClock(),
    )
    assert_code(
        lambda: atomic_engine.activate(
            "synthetic-approval-owner",
            "evidence://synthetic/declaration-activation",
            actor_scope="nc25.governance",
        ),
        "TIMEZONE_REQUIRED",
    )
    if atomic_engine.status != "DRAFT" or atomic_engine.ledger._events:
        raise AssertionError(
            "ACTIVATION_ATOMICITY: failed activation changed durable state"
        )
    _record_mutation("ACTIVATION_ATOMICITY", "FAILED_ACTIVATION_IS_ATOMIC")

    reissue_engine, reissue_grant, _, _ = ready_engine()
    reissue_engine.revoke_grant(
        {
            "message_type": "authority_revocation",
            "grant_id": reissue_grant["grant_id"],
            "declaration_hash": reissue_engine.declaration_hash,
            "revoked_at": "2026-08-01T10:00:00Z",
            "revoked_by": "synthetic-authority-issuer",
            "reason_code": "SYNTHETIC_REVOCATION",
            "evidence_ref": "evidence://synthetic/revocation/reissue",
        },
        actor_scope="nc25.governance",
    )
    expect_exception(
        "REVOKED_GRANT_REISSUE",
        "AUTHORITY_REVOKED",
        lambda: reissue_engine.issue_grant(
            reissue_grant,
            actor_scope="nc25.governance",
        ),
    )

    future_grant = copy.deepcopy(grant)
    future_grant["valid_from"] = "2026-08-01T10:00:30Z"
    future_engine, future_bound_grant, future_intent, future_evidence = (
        ungranted_engine(grant=future_grant)
    )
    future_engine.issue_grant(
        future_bound_grant,
        actor_scope="nc25.governance",
    )
    future_result = future_engine.evaluate_intent(
        future_intent,
        future_evidence,
        actor_scope="nc25.operator",
    )
    future_code = future_engine.architect_decision(
        future_result["request_hash"],
        actor_scope="nc25.architect",
    )["message_code"]
    if future_result["disposition"] != "REFUSAL":
        raise AssertionError("AUTHORITY_NOT_YET_VALID: future grant was executable")
    if future_code != "AUTHORITY_NOT_YET_VALID":
        raise AssertionError(f"AUTHORITY_NOT_YET_VALID: received {future_code}")
    _record_mutation("AUTHORITY_NOT_YET_VALID", future_code)

    skewEngine, skewGrant, _, _ = ready_engine()
    skewEngine.revoke_grant(
        {
            "message_type": "authority_revocation",
            "grant_id": skewGrant["grant_id"],
            "declaration_hash": skewEngine.declaration_hash,
            "revoked_at": "2026-08-01T10:00:05Z",
            "revoked_by": "synthetic-authority-issuer",
            "reason_code": "SYNTHETIC_REVOCATION",
            "evidence_ref": "evidence://synthetic/revocation/skew-accepted",
        },
        actor_scope="nc25.governance",
    )
    rejectedSkewEngine, rejectedSkewGrant, _, _ = ready_engine()
    expect_exception(
        "REVOCATION_CLOCK_SKEW",
        "REVOCATION_IN_FUTURE",
        lambda: rejectedSkewEngine.revoke_grant(
            {
                "message_type": "authority_revocation",
                "grant_id": rejectedSkewGrant["grant_id"],
                "declaration_hash": rejectedSkewEngine.declaration_hash,
                "revoked_at": "2026-08-01T10:00:06Z",
                "revoked_by": "synthetic-authority-issuer",
                "reason_code": "SYNTHETIC_REVOCATION",
                "evidence_ref": "evidence://synthetic/revocation/skew-rejected",
            },
            actor_scope="nc25.governance",
        ),
    )

    limited_declaration = copy.deepcopy(declaration)
    action = next(
        item
        for item in profile["action_alphabet"]
        if item["action_id"] == intent["action_id"]
    )
    limited_declaration["structural_budget"]["capacity"] = action["structural_cost"]
    race_engine, _, first_intent, first_evidence = ready_engine(
        declaration=limited_declaration
    )
    second_intent, second_evidence = unique_intent(
        first_intent,
        first_evidence,
        "concurrent-reservation-002",
    )
    original_reserved = race_engine._active_structural_reserved

    def delayed_reserved(now: datetime) -> int:
        value = original_reserved(now)
        time.sleep(0.05)
        return value

    race_engine._active_structural_reserved = delayed_reserved
    race_results: list[dict] = []
    race_errors: list[BaseException] = []

    def race_evaluate(race_intent: dict, race_evidence: dict) -> None:
        try:
            race_results.append(
                race_engine.evaluate_intent(
                    race_intent,
                    race_evidence,
                    actor_scope="nc25.operator",
                )
            )
        except BaseException as exc:
            race_errors.append(exc)

    race_threads = [
        threading.Thread(target=race_evaluate, args=(first_intent, first_evidence)),
        threading.Thread(target=race_evaluate, args=(second_intent, second_evidence)),
    ]
    for thread in race_threads:
        thread.start()
    for thread in race_threads:
        thread.join(timeout=2)
    if race_errors or any(thread.is_alive() for thread in race_threads):
        raise AssertionError(
            "STRUCTURAL_RESERVATION_SERIALIZATION: concurrent evaluation failed"
        )
    if sorted(result["disposition"] for result in race_results) != [
        "ALLOW",
        "REFUSAL",
    ]:
        raise AssertionError(
            "STRUCTURAL_RESERVATION_SERIALIZATION: reservation oversubscribed"
        )
    _record_mutation(
        "STRUCTURAL_RESERVATION_SERIALIZATION",
        "IN_PROCESS_RESERVATION_SERIALIZED",
    )
    # The local secret-name guard must reject secret-shaped keys at each
    # free-form trust boundary, including mappings nested inside lists. Exact
    # error and path checks prove that the guard itself rejected the injected
    # key rather than an earlier validator masking the result.
    def expect_secret_guard(
        label: str,
        action: Callable[[], object],
        detail_fragment: str,
    ) -> None:
        try:
            action()
        except ContractViolation as exc:
            if exc.code != "SECRET_FIELD_FORBIDDEN":
                raise AssertionError(
                    f"{label}: raised {exc.code}, expected SECRET_FIELD_FORBIDDEN"
                )
            if detail_fragment not in (exc.detail or ""):
                raise AssertionError(
                    f"{label}: rejection detail {exc.detail!r} did not contain "
                    f"{detail_fragment!r}"
                )
        else:
            raise AssertionError(f"{label}: secret-shaped field was accepted")

    secret_scope_variants = [
        # casing / separator variants of enumerated concepts
        "bearerToken", "client_secret", "clientSecret", "auth_token",
        "sessionKey", "session_token", "signing_key", "apiToken", "accessToken",
        "privateKey", "refresh_token", "api-key", "DB_PASSWORD",
        # prefixed forms an integrator commonly uses (vendor tag / x- header)
        "x-api-key", "x_bearer_token",
        # the *_secret family, caught by the trailing-word rule
        "secret_key", "api_secret", "webhook_secret", "jwt_secret",
        "aws_secret_access_key",
        # further standard credential heads
        "oauth_token", "id_token", "personal_access_token", "passphrase",
        "encryption_key", "master_key", "ssh_key",
        # high-signal bare, vendor, and content-bearing forms
        "authorization", "authorization_header", "jwt", "jwt_token", "token",
        "credential", "credentials", "client_token", "security_token",
        "subscription_key", "sas_token", "raw_payload", "secret_value",
        "private_key_pem", "password_hash", "api_key_v2",
    ]
    for dimension in secret_scope_variants:
        probe_declaration = copy.deepcopy(declaration)
        probe_declaration["instance_scope"]["scope_constraints"][dimension] = [
            "smuggled-value"
        ]
        expect_secret_guard(
            f"SECRET_SCOPED_FIELD dimension {dimension!r}",
            lambda probe=probe_declaration: validate_declaration(probe, profile),
            f".{dimension}",
        )

    intent_engine, _, bound_intent, _ = ready_engine()
    intent_scope_probe = copy.deepcopy(bound_intent)
    intent_scope_probe["scope"]["authorization"] = "Bearer smuggled-value"
    expect_secret_guard(
        "SECRET_INTENT_SCOPE",
        lambda: intent_engine._validate_intent(intent_scope_probe),
        ".scope.authorization",
    )
    resource_claim_probe = copy.deepcopy(bound_intent)
    resource_claim_probe["resource_claims"]["token"] = 1
    expect_secret_guard(
        "SECRET_RESOURCE_CLAIM",
        lambda: intent_engine._validate_intent(resource_claim_probe),
        ".resource_claims.token",
    )

    audit_engine, _, _, _ = ready_engine()
    expect_secret_guard(
        "SECRET_AUDIT_LIST_RECURSION",
        lambda: audit_engine.ledger.append(
            "SECRET_SCAN_PROBE",
            ROLE_OPERATOR,
            "secret-scan-probe",
            {"items": [{"client_secret": "smuggled-value"}]},
        ),
        ".items[0].client_secret",
    )

    unicode_scope_probe = copy.deepcopy(bound_intent)
    unicode_scope_probe["scope"]["client_se\u0441ret"] = "smuggled-value"
    try:
        intent_engine._validate_intent(unicode_scope_probe)
    except ContractViolation as exc:
        if exc.code != "INTENT_SCOPE_DIMENSION":
            raise AssertionError(
                "UNICODE_INTENT_SCOPE: expected identifier gate, "
                f"received {exc.code}"
            )
    else:
        raise AssertionError("UNICODE_INTENT_SCOPE: homoglyph key was accepted")

    # Positive controls prove that the guard does not reject ordinary
    # references, policy fields, metadata predicates, or classification labels.
    benign_dimensions = [
        # names that merely CONTAIN a secret word but hold no secret
        "idempotency_reference", "secret_manager_ref", "password_policy",
        "api_key_rotation_days", "next_page_token",
        # bare heads "key"/"token" must not blanket-block these real fields
        "idempotency_key", "public_key", "session_id",
        # explicit references and public verifiable-credential vocabulary
        "signing_key_ref", "encryption_key_arn", "ssh_key_fingerprint",
        "credential_type", "credential_ref", "verifiable_credential_type",
        # metadata predicates and document classifications do not carry secrets
        "is_secret", "contains_secret", "requires_client_secret",
        "uses_api_key", "supports_session_token", "trade_secret", "top_secret",
    ]
    for dimension in benign_dimensions:
        benign_declaration = copy.deepcopy(declaration)
        benign_declaration["instance_scope"]["scope_constraints"][dimension] = [
            "benign-value"
        ]
        try:
            validate_declaration(benign_declaration, profile)
        except ContractViolation as exc:
            raise AssertionError(
                f"SECRET_SCOPED_FIELD: guard wrongly rejected benign dimension "
                f"{dimension!r} with {exc.code}; a name that merely contains a "
                "secret word must not be treated as a secret"
            )
    _record_mutation("SECRET_SCOPED_FIELD", "SECRET_FIELD_FORBIDDEN")

    missing = EXPECTED_MUTATION_IDS - executed_mutations
    extra = executed_mutations - EXPECTED_MUTATION_IDS
    if missing or extra:
        raise AssertionError(
            f"SAFETY_MUTATION_MANIFEST missing={sorted(missing)} extra={sorted(extra)}"
        )
    print(
        f"SAFETY_MUTATIONS={len(executed_mutations)}/"
        f"{len(EXPECTED_MUTATION_IDS)} PASS"
    )


def test_safety_mutation_suite() -> None:
    main()


if __name__ == "__main__":
    main()

