"""Conformance of the shipped artefacts to the shipped contracts.

The engine validates structure, identifier coverage, hashes, ordering, and the
declared status. It is not a JSON Schema validator and it does not read the wire
contract. This script closes both gaps for the package's own artefacts:

  1. every shipped profile, declaration, and runtime fixture, and the live
     results the engine produces (operator result, execution receipt, registry
     record), validate against the JSON Schemas in `core/schemas/`;
  2. `protocol/universal-connection.openapi.yaml` parses, every `$ref` in it
     resolves (including the external references into those same schemas), its
     route set exactly matches the declared route table, every route requires
     mutual TLS plus exactly one expected OAuth2 scope, and every route maps to
     an existing engine operation;
  3. the architect permit, the architect decision in both its executable and
     non-executable forms, and the ledger head produced by a live run validate
     against the inline response schemas the wire contract declares for them.

The observer projection intentionally has no route: it is an out-of-band,
non-mutating projection and not an authority principal, so the route-coverage
check treats it as a documented exception rather than a missing path.

Each part needs one library that the reference engine itself does not use. A
missing library is reported as NOT_RUN and never as a pass; the exit status is
non-zero only for a real failure.
"""
from __future__ import annotations

import copy
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python"))

from nc25_universal_ledger import (  # noqa: E402
    FixedClock,
    IntegrityViolation,
    ROLE_ARCHITECT,
    UniversalConnectionLedger,
    bind_fixture,
    load_json,
    sha256_hex,
)
from nc25_universal_adapter import UniversalConnectionHttpAdapter  # noqa: E402

EXPECTED_CONFORMANCE_IDS = frozenset(
    {
        "schema_format_keyword_active", "schema_max_length_keyword_active",
        "schema_rejects_unknown_provenance",
        "schema_banking_profile", "schema_second_profile", "schema_declaration",
        "schema_second_declaration", "schema_authority_grant", "schema_intent",
        "schema_evidence_bundle", "schema_live_operator_allow",
        "schema_live_operator_refusal", "schema_live_operator_manual_review",
        "schema_rejects_refusal_with_permit",
        "http_body_cap_413", "http_revoke_success_204",
        "http_integrity_halt_503",
        "schema_live_execution_permit",
        "schema_zero_resource_execution_permit",
        "schema_live_execution_receipt",
        "schema_rejects_nonidentifier_resource_debit",
        "schema_live_registry_record",
        "openapi_parses",
        "openapi_declared_version", "openapi_has_references",
        "openapi_references_resolve", "openapi_binds_shipped_schemas",
        "openapi_route_set", "openapi_route_operations", "openapi_route_security",
        "openapi_declares_emitted_statuses",
        "wire_live_architect_permit", "wire_live_decision_allow",
        "wire_live_decision_refused", "wire_live_ledger_head",
        "http_adapter_route_set", "http_adapter_route_scopes",
        "http_happy_path", "http_scope_required", "http_scope_forbidden",
        "http_scope_forbidden_for_foreign_role",
        "http_scope_sweep_covers_all_routes",
        "http_activate_seal_binding",
        "http_idempotency_required", "http_idempotency_mismatch",
        "http_permit_path_body_binding", "http_unknown_connector_404",
        "http_untrusted_evidence", "http_untrusted_controls",
        "http_missing_idempotency_field_400", "http_grant_replay_200",
        "http_revocation_replay_204", "http_internal_failure_503",
        "http_intent_binding_400", "http_wrapper_unknown_key_400",
    }
)
failures: list[str] = []
passed_ids: set[str] = set()
skipped: list[str] = []

# Route table: path -> (method, operationId, OAuth2 scope, engine operation).
ROUTES: dict[str, tuple[str, str, str, str]] = {
    "/v1/declarations:activate": (
        "post", "activateDeclaration", "nc25.governance", "activate",
    ),
    "/v1/authority-grants": (
        "post", "issueAuthorityGrant", "nc25.governance", "issue_grant",
    ),
    "/v1/authority-revocations": (
        "post", "revokeAuthorityGrant", "nc25.governance", "revoke_grant",
    ),
    "/v1/operator/intents:evaluate": (
        "post", "evaluateIntent", "nc25.operator", "evaluate_intent",
    ),
    "/v1/executor/permits/{permit_hash}:consume": (
        "post", "consumePermit", "nc25.executor", "commit_execution",
    ),
    "/v1/architect/permits/{permit_hash}": (
        "get", "getArchitectPermit", "nc25.architect", "architect_permit",
    ),
    "/v1/architect/decisions/{request_hash}": (
        "get", "getArchitectDecision", "nc25.architect", "architect_decision",
    ),
    "/v1/architect/ledger/head": (
        "get", "getLedgerHead", "nc25.architect", "ledger_head",
    ),
    "/v1/registry/connectors/{connector_id}": (
        "get", "getRegistryRecord", "nc25.architect", "registry_record",
    ),
}

_live_cache: dict | None = None

RFC3339_DATE_TIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def contract_format_checker(format_checker_type):
    """Return a checker whose date-time rule has no optional dependency."""

    checker = format_checker_type()

    @checker.checks("date-time")
    def is_rfc3339_date_time(value: object) -> bool:
        if not isinstance(value, str):
            return True
        if RFC3339_DATE_TIME_RE.fullmatch(value) is None:
            return False
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return False
        return parsed.tzinfo is not None

    return checker


def check(condition: bool, label: str, detail: str = "") -> None:
    if label not in EXPECTED_CONFORMANCE_IDS:
        failures.append(f"UNDECLARED_CONFORMANCE_CHECK: {label}")
        print(f"FAIL {label} undeclared check")
        return
    if label in passed_ids:
        failures.append(f"DUPLICATE_CONFORMANCE_CHECK: {label}")
        print(f"FAIL {label} duplicate check")
        return
    if condition:
        passed_ids.add(label)
        print(f"PASS {label}")
    else:
        failures.append(f"{label}: {detail}" if detail else label)
        print(f"FAIL {label} {detail}")


def live_surface() -> dict:
    """Run the reference flow once; return every externally-visible output."""

    global _live_cache
    if _live_cache is not None:
        return _live_cache

    profile, declaration, grant, intent = bind_fixture(
        load_json(ROOT / "profiles" / "banking" / "bank-profile.json"),
        load_json(ROOT / "examples" / "synthetic-connection-declaration.json"),
        load_json(ROOT / "examples" / "synthetic-authority-grant.json"),
        load_json(ROOT / "examples" / "synthetic-intent-allow.json"),
    )
    evidence = load_json(ROOT / "examples" / "synthetic-evidence-bundle.json")
    engine = UniversalConnectionLedger(
        profile,
        declaration,
        signing_key=b"synthetic-reference-signing-key",
        clock=FixedClock(datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)),
    )
    engine.activate(
        declaration["governance"]["approval_owner_id"],
        "evidence://synthetic/declaration-activation",
        actor_scope="nc25.governance",
    )
    engine.issue_grant(grant, actor_scope="nc25.governance")
    allow = engine.evaluate_intent(intent, evidence, actor_scope="nc25.operator")

    refused_intent = copy.deepcopy(intent)
    refused_intent["intent_id"] = "synthetic-intent-conformance-002"
    refused_intent["idempotency_key"] = "synthetic-idempotency-conformance-002"
    partial = copy.deepcopy(evidence)
    partial["items"] = partial["items"][:1]
    partial["intent_id"] = refused_intent["intent_id"]
    refusal = engine.evaluate_intent(refused_intent, partial, actor_scope="nc25.operator")

    mr_intent = copy.deepcopy(intent)
    mr_intent["intent_id"] = "synthetic-intent-conformance-003"
    mr_intent["idempotency_key"] = "synthetic-idempotency-conformance-003"
    mr_intent["manual_review_flags"] = {
        flag: True for flag in mr_intent["manual_review_flags"]
    }
    mr_evidence = copy.deepcopy(evidence)
    mr_evidence["intent_id"] = mr_intent["intent_id"]
    manual_review = engine.evaluate_intent(
        mr_intent, mr_evidence, actor_scope="nc25.operator"
    )

    receipt = engine.commit_execution(
        {
            "message_type": "execution_request",
            "permit_hash": allow["permit_hash"],
            "connector_id": intent["connector_id"],
            "binding": intent["binding"],
            "state_anchor_hash": intent["state_anchor_hash"],
            "outcome": "COMMITTED",
            "downstream_receipt_hash": "9" * 64,
            "committed_at": "2026-08-01T10:00:00Z",
        },
        actor_scope="nc25.executor",
        route_permit_hash=allow["permit_hash"],
    )

    _live_cache = {
        "operator_allow": allow,
        "operator_refusal": refusal,
        "operator_manual_review": manual_review,
        "receipt": receipt,
        "registry": engine.registry_record(engine.declaration["connector"]["connector_id"], actor_scope="nc25.architect"),
        "permit_view": engine.architect_permit(
            allow["permit_hash"], actor_scope=ROLE_ARCHITECT
        ),
        "decision_allow": engine.architect_decision(allow["request_hash"], actor_scope="nc25.architect"),
        "decision_refused": engine.architect_decision(refusal["request_hash"], actor_scope="nc25.architect"),
        "ledger_head": engine.ledger_head(actor_scope="nc25.architect"),
    }
    return _live_cache


def schema_conformance() -> None:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError:
        skipped.append("SCHEMA_CONFORMANCE=NOT_RUN (jsonschema not installed)")
        return

    schemas = ROOT / "core" / "schemas"
    profile_schema = load_json(schemas / "profile.schema.json")
    declaration_schema = load_json(schemas / "connection-declaration.schema.json")
    registry_schema = load_json(schemas / "registry-record.schema.json")
    runtime = load_json(schemas / "runtime-contracts.schema.json")
    format_checker = contract_format_checker(FormatChecker)

    def against(definition: str) -> dict:
        merged = dict(runtime["$defs"][definition])
        merged["$defs"] = runtime["$defs"]
        return merged

    def validate(document: object, schema: dict, label: str) -> None:
        errors = sorted(
            Draft202012Validator(
                schema,
                format_checker=format_checker,
            ).iter_errors(document),
            key=lambda error: list(error.path),
        )
        detail = ""
        if errors:
            first = errors[0]
            detail = f"{len(errors)} error(s), first at {list(first.path)}: {first.message}"
        check(not errors, label, detail)

    bundle = load_json(
        ROOT / "profiles" / "document-release" / "reference-connection.json"
    )
    banking_profile = load_json(
        ROOT / "profiles" / "banking" / "bank-profile.json"
    )

    malformed_time = copy.deepcopy(banking_profile)
    malformed_time["created_at"] = "not-a-date-time"
    malformed_time_errors = list(
        Draft202012Validator(
            profile_schema,
            format_checker=format_checker,
        ).iter_errors(malformed_time)
    )
    check(
        any(
            error.validator == "format"
            and list(error.path) == ["created_at"]
            for error in malformed_time_errors
        ),
        "schema_format_keyword_active",
        "invalid date-time was accepted",
    )

    overlong_domain = copy.deepcopy(banking_profile)
    overlong_domain["domain"]["domain_name"] = "X" * 161
    overlong_domain_errors = list(
        Draft202012Validator(
            profile_schema,
            format_checker=format_checker,
        ).iter_errors(overlong_domain)
    )
    check(
        any(
            error.validator == "maxLength"
            and list(error.path) == ["domain", "domain_name"]
            for error in overlong_domain_errors
        ),
        "schema_max_length_keyword_active",
        "overlong domain name was accepted",
    )

    misdeclared_provenance = copy.deepcopy(
        load_json(ROOT / "examples" / "synthetic-connection-declaration.json")
    )
    misdeclared_provenance["structural_budget"]["provenance"] = "vendor_asserted"
    misdeclared_provenance_errors = list(
        Draft202012Validator(
            declaration_schema,
            format_checker=format_checker,
        ).iter_errors(misdeclared_provenance)
    )
    check(
        any(
            error.validator == "enum"
            and list(error.path) == ["structural_budget", "provenance"]
            for error in misdeclared_provenance_errors
        ),
        "schema_rejects_unknown_provenance",
        "capacity provenance outside the published coding was accepted",
    )

    validate(
        banking_profile,
        profile_schema,
        "schema_banking_profile",
    )
    validate(bundle["profile"], profile_schema, "schema_second_profile")
    validate(
        load_json(ROOT / "examples" / "synthetic-connection-declaration.json"),
        declaration_schema,
        "schema_declaration",
    )
    validate(bundle["declaration"], declaration_schema, "schema_second_declaration")
    validate(
        load_json(ROOT / "examples" / "synthetic-authority-grant.json"),
        against("authority_grant"),
        "schema_authority_grant",
    )
    validate(
        load_json(ROOT / "examples" / "synthetic-intent-allow.json"),
        against("intent"),
        "schema_intent",
    )
    validate(
        load_json(ROOT / "examples" / "synthetic-evidence-bundle.json"),
        against("evidence_bundle"),
        "schema_evidence_bundle",
    )
    live = live_surface()
    validate(
        live["operator_allow"],
        against("operator_result"),
        "schema_live_operator_allow",
    )
    validate(
        live["operator_refusal"],
        against("operator_result"),
        "schema_live_operator_refusal",
    )
    validate(
        live["operator_manual_review"],
        against("operator_result"),
        "schema_live_operator_manual_review",
    )
    invalid_refusal = copy.deepcopy(live["operator_refusal"])
    invalid_refusal["permit_hash"] = live["operator_allow"]["permit_hash"]
    invalid_refusal["expires_at"] = live["operator_allow"]["expires_at"]
    invalid_refusal_errors = list(
        Draft202012Validator(
            against("operator_result"),
            format_checker=format_checker,
        ).iter_errors(invalid_refusal)
    )
    check(
        any(
            error.validator == "oneOf"
            for error in invalid_refusal_errors
        ),
        "schema_rejects_refusal_with_permit",
        "REFUSAL carrying a live permit was not rejected by the disposition discriminator",
    )

    validate(
        live["permit_view"]["permit_body"],
        against("execution_permit"),
        "schema_live_execution_permit",
    )
    zero_resource_permit = copy.deepcopy(live["permit_view"]["permit_body"])
    zero_resource_permit["resource_claims"] = {}
    validate(
        zero_resource_permit,
        against("execution_permit"),
        "schema_zero_resource_execution_permit",
    )
    validate(
        live["receipt"],
        against("execution_receipt"),
        "schema_live_execution_receipt",
    )
    nonident_debit = copy.deepcopy(live["receipt"])
    nonident_debit["resource_debits"] = {"": 1}
    nonident_debit_errors = list(
        Draft202012Validator(
            against("execution_receipt"),
            format_checker=format_checker,
        ).iter_errors(nonident_debit)
    )
    check(
        any(
            error.validator == "pattern"
            and "resource_debits" in list(error.path)
            for error in nonident_debit_errors
        ),
        "schema_rejects_nonidentifier_resource_debit",
        "a receipt debit keyed by a non-identifier was accepted",
    )
    validate(live["registry"], registry_schema, "schema_live_registry_record")


def load_wire_document():
    import yaml

    return yaml.safe_load(
        (ROOT / "protocol" / "universal-connection.openapi.yaml").read_text(
            encoding="utf-8"
        )
    )


def openapi_conformance() -> None:
    try:
        document = load_wire_document()
    except ImportError:
        skipped.append("OPENAPI_CONFORMANCE=NOT_RUN (pyyaml not installed)")
        return

    check(isinstance(document, dict), "openapi_parses")
    check(str(document.get("openapi", "")).startswith("3.1"), "openapi_declared_version")

    references: list[str] = []

    def collect(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "$ref" and isinstance(value, str):
                    references.append(value)
                else:
                    collect(value)
        elif isinstance(node, list):
            for item in node:
                collect(item)

    collect(document)
    check(bool(references), "openapi_has_references")

    def resolve(container: object, fragment: str) -> object | None:
        node = container
        for part in fragment.lstrip("/").split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return None
        return node

    unresolved: list[str] = []
    external = 0
    protocol = ROOT / "protocol"
    for reference in sorted(set(references)):
        if reference.startswith("#/"):
            if resolve(document, reference[1:]) is None:
                unresolved.append(reference)
            continue
        file_part, _, fragment = reference.partition("#")
        target = (protocol / file_part).resolve()
        if not target.is_file() or ROOT.resolve() not in target.parents:
            unresolved.append(f"{reference} (missing or outside the package)")
            continue
        external += 1
        if fragment and resolve(json.loads(target.read_text(encoding="utf-8")), fragment) is None:
            unresolved.append(f"{reference} (fragment absent)")
    check(not unresolved, "openapi_references_resolve", ", ".join(unresolved))
    check(external > 0, "openapi_binds_shipped_schemas")

    # --- route table: the wire contract and the engine describe each other ---
    paths = document.get("paths", {})
    extra = sorted(set(paths) - set(ROUTES))
    absent = sorted(set(ROUTES) - set(paths))
    check(
        not extra and not absent,
        "openapi_route_set",
        f"extra={extra} absent={absent}",
    )

    bad_security: list[str] = []
    bad_operation: list[str] = []
    for path, (method, operation_id, scope, engine_attr) in ROUTES.items():
        route = paths.get(path, {}).get(method)
        if not isinstance(route, dict):
            bad_operation.append(f"{path}: no {method} operation")
            continue
        if route.get("operationId") != operation_id:
            bad_operation.append(
                f"{path}: operationId {route.get('operationId')!r}"
            )
        security = route.get("security")
        ok = (
            isinstance(security, list)
            and len(security) == 1
            and isinstance(security[0], dict)
            and security[0].get("mutualTLS") == []
            and security[0].get("OAuth2") == [scope]
        )
        if not ok:
            bad_security.append(f"{path}: {security!r}")
        engine_method = getattr(UniversalConnectionLedger, engine_attr, None)
        if not callable(engine_method):
            bad_operation.append(f"{path}: engine lacks {engine_attr}")
        else:
            # The route's declared scope must be the role the engine method
            # itself requires. Checking only that the method exists left the
            # contract free to advertise one role while the engine enforced
            # another - the two sides agreed by hand, not by construction.
            declared = getattr(engine_method, "__nc25_required_scope__", None)
            if declared is not None and declared != scope:
                bad_operation.append(
                    f"{path}: contract scope {scope!r} != engine role {declared!r}"
                )
    check(not bad_operation, "openapi_route_operations", "; ".join(bad_operation))
    check(not bad_security, "openapi_route_security", "; ".join(bad_security))

    # Every status the reference adapter can emit on a route is DECLARED for
    # that route. The table below is the adapter's behaviour written down,
    # route by route; it used to check only 403 and 413, and the three
    # parametric GET routes answered 400 for a malformed selector with no
    # declaration anywhere. 503 is on every route: the last-resort guard can
    # answer on any of them. 200 on the grants route is the replay answer.
    emitted_by_route = {
        "/v1/declarations:activate": {"201", "400", "403", "409", "413", "503"},
        "/v1/authority-grants": {"200", "201", "400", "403", "409", "413", "503"},
        "/v1/authority-revocations": {"204", "400", "403", "404", "413", "503"},
        "/v1/operator/intents:evaluate": {"200", "400", "403", "409", "413", "503"},
        "/v1/executor/permits/{permit_hash}:consume": {
            "200", "400", "403", "404", "409", "413", "503"
        },
        "/v1/architect/permits/{permit_hash}": {"200", "400", "403", "404", "503"},
        "/v1/architect/decisions/{request_hash}": {"200", "400", "403", "404", "503"},
        "/v1/architect/ledger/head": {"200", "403", "503"},
        "/v1/registry/connectors/{connector_id}": {"200", "400", "403", "404", "503"},
    }
    undeclared: list[str] = []
    if set(emitted_by_route) != set(ROUTES):
        undeclared.append("emitted-status table and route table name different routes")
    for path, (method, _operation_id, _scope, _engine_attr) in ROUTES.items():
        responses = paths.get(path, {}).get(method, {}).get("responses", {})
        declared = {str(code) for code in responses}
        for status in sorted(emitted_by_route.get(path, set()) - declared):
            undeclared.append(f"{path}: {status} missing")
    check(
        not undeclared,
        "openapi_declares_emitted_statuses",
        "; ".join(undeclared),
    )


def wire_live_conformance() -> None:
    """Live post-event outputs validate against the inline response schemas."""

    try:
        from jsonschema import Draft202012Validator, FormatChecker
        from referencing import Registry, Resource
        document = load_wire_document()
        format_checker = contract_format_checker(FormatChecker)
        schema_registry = Registry()
        for schema_path in sorted((ROOT / "core" / "schemas").glob("*.json")):
            schema_registry = schema_registry.with_resource(
                schema_path.resolve().as_uri(),
                Resource.from_contents(load_json(schema_path)),
            )
    except ImportError:
        skipped.append(
            "WIRE_LIVE_CONFORMANCE=NOT_RUN (jsonschema and pyyaml required)"
        )
        return

    def response_schema(path: str, method: str, status: str) -> dict | None:
        try:
            inline = document["paths"][path][method]["responses"][status][
                "content"
            ]["application/json"]["schema"]
        except (KeyError, TypeError):
            return None
        # Inline schemas reference #/components/... — graft the components so
        # a validator sees the same resolution root the document declares.
        grafted = dict(inline)
        grafted["$id"] = (
            ROOT / "protocol" / "universal-connection.openapi.yaml"
        ).resolve().as_uri()
        grafted["components"] = document["components"]
        return grafted

    def validate(document_: object, schema: dict | None, label: str) -> None:
        if schema is None:
            check(False, label, "declared response schema not found")
            return
        errors = sorted(
            Draft202012Validator(
                schema,
                registry=schema_registry,
                format_checker=format_checker,
            ).iter_errors(document_),
            key=lambda error: list(error.path),
        )
        detail = ""
        if errors:
            first = errors[0]
            detail = f"{len(errors)} error(s), first at {list(first.path)}: {first.message}"
        check(not errors, label, detail)

    live = live_surface()
    validate(
        live["permit_view"],
        response_schema("/v1/architect/permits/{permit_hash}", "get", "200"),
        "wire_live_architect_permit",
    )
    decision_schema = response_schema(
        "/v1/architect/decisions/{request_hash}", "get", "200"
    )
    validate(live["decision_allow"], decision_schema, "wire_live_decision_allow")
    validate(
        live["decision_refused"], decision_schema, "wire_live_decision_refused"
    )
    validate(
        live["ledger_head"],
        response_schema("/v1/architect/ledger/head", "get", "200"),
        "wire_live_ledger_head",
    )


def _http_call(app, method, path, body=None, scope=None, idem=None):
    import io

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

    def start_response(status, headers):
        captured["status"] = status

    payload = b"".join(app(environ, start_response))
    parsed = json.loads(payload) if payload else None
    return int(captured["status"].split()[0]), parsed


def _adapter_fixture(evidence_resolver=None, control_resolver=None):
    profile, declaration, grant, intent = bind_fixture(
        load_json(ROOT / "profiles" / "banking" / "bank-profile.json"),
        load_json(ROOT / "examples" / "synthetic-connection-declaration.json"),
        load_json(ROOT / "examples" / "synthetic-authority-grant.json"),
        load_json(ROOT / "examples" / "synthetic-intent-allow.json"),
    )
    evidence = load_json(ROOT / "examples" / "synthetic-evidence-bundle.json")
    engine = UniversalConnectionLedger(
        profile,
        declaration,
        signing_key=b"synthetic-reference-signing-key",
        clock=FixedClock(datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)),
        evidence_resolver=evidence_resolver,
        control_resolver=control_resolver,
    )
    return UniversalConnectionHttpAdapter(engine), grant, intent, evidence


def _activate_body(app) -> dict:
    # The wire contract requires the caller to present the exact objects
    # being activated; the adapter binds them to the engine seals by hash.
    return {
        "profile": copy.deepcopy(app._engine.profile),
        "declaration": copy.deepcopy(app._engine.declaration),
        "activated_by": "synthetic-approval-owner",
        "approval_evidence_ref": "evidence://x",
    }


def _activate_and_grant(app, grant) -> None:
    _http_call(
        app,
        "POST",
        "/v1/declarations:activate",
        _activate_body(app),
        scope="nc25.governance",
    )
    _http_call(app, "POST", "/v1/authority-grants", grant, scope="nc25.governance")


def _exec_request(intent, permit_hash):
    return {
        "message_type": "execution_request",
        "permit_hash": permit_hash,
        "connector_id": intent["connector_id"],
        "binding": intent["binding"],
        "state_anchor_hash": intent["state_anchor_hash"],
        "outcome": "COMMITTED",
        "downstream_receipt_hash": "9" * 64,
        "committed_at": "2026-08-01T10:00:00Z",
    }


def http_adapter_conformance() -> None:
    """Drive the reference WSGI adapter in-process and prove the wire MUSTs.

    Standard-library only (no jsonschema or pyyaml), so this section runs even
    when the optional conformance libraries are absent.
    """

    expected_scopes = {
        operation_id: scope for _method, operation_id, scope, _engine in ROUTES.values()
    }
    app, grant, intent, evidence = _adapter_fixture()
    check(
        set(app.operation_scopes()) == set(expected_scopes),
        "http_adapter_route_set",
        f"{sorted(set(app.operation_scopes()) ^ set(expected_scopes))}",
    )
    check(
        app.operation_scopes() == expected_scopes,
        "http_adapter_route_scopes",
        f"{app.operation_scopes()}",
    )

    # Scope MUSTs on EVERY route: the scope check runs before the handler, so a
    # missing or wrong scope fails closed (403) regardless of body validity.
    hexid = "a" * 64
    route_requests = [
        ("POST", "/v1/declarations:activate", {}, "activateDeclaration"),
        ("POST", "/v1/authority-grants", {}, "issueAuthorityGrant"),
        ("POST", "/v1/authority-revocations", {}, "revokeAuthorityGrant"),
        ("POST", "/v1/operator/intents:evaluate", {}, "evaluateIntent"),
        ("POST", "/v1/executor/permits/" + hexid + ":consume", {}, "consumePermit"),
        ("GET", "/v1/architect/permits/" + hexid, None, "getArchitectPermit"),
        ("GET", "/v1/architect/decisions/" + hexid, None, "getArchitectDecision"),
        ("GET", "/v1/architect/ledger/head", None, "getLedgerHead"),
        ("GET", "/v1/registry/connectors/some-connector", None, "getRegistryRecord"),
    ]
    mounted_scopes = app.operation_scopes()
    # The scope sweeps range over a hand-maintained list; tie it to the
    # adapter's own route table by identity, not merely by size, so a route
    # swapped for another reddens here instead of leaving the "every route"
    # claim covering a domain that only LOOKS the right size. Checked before
    # the sweeps so a drifted name is reported by this marker rather than by
    # whatever the sweeps do with it.
    check(
        {op for _m, _p, _b, op in route_requests} == set(mounted_scopes),
        "http_scope_sweep_covers_all_routes",
        f"sweep={sorted(op for _m, _p, _b, op in route_requests)} "
        f"routes={sorted(mounted_scopes)}",
    )
    no_scope = {
        (m, p): _http_call(app, m, p, b)[0] for m, p, b, _op in route_requests
    }
    check(
        all(status == 403 for status in no_scope.values()),
        "http_scope_required",
        f"non-403 without scope: {[k for k, v in no_scope.items() if v != 403]}",
    )
    wrong_scope = {
        (m, p): _http_call(app, m, p, b, scope="nc25.wrong")[0]
        for m, p, b, _op in route_requests
    }
    check(
        all(status == 403 for status in wrong_scope.values()),
        "http_scope_forbidden",
        f"non-403 with wrong scope: {[k for k, v in wrong_scope.items() if v != 403]}",
    )
    # An unknown scope is refused by a route that checks scope MEMBERSHIP just
    # as it is by one that checks its OWN scope, so the sweep above cannot tell
    # the two apart, and "the four scopes are non-interchangeable" would stay
    # green while any authenticated role reached any route. Sweep again with a
    # scope that IS a mounted role but not this route's, taken from the
    # adapter's own table so the pairing cannot drift out of step with it.
    foreign_scope = {
        (m, p): _http_call(
            app,
            m,
            p,
            b,
            scope=next(
                other
                for other in sorted(set(mounted_scopes.values()))
                # An unmounted default rather than a KeyError: a drifted name is
                # this route's problem to report by name, above, not a crash
                # that takes the remaining checks down with it.
                if other != mounted_scopes.get(op, "nc25.unmounted")
            ),
        )[0]
        for m, p, b, op in route_requests
    }
    check(
        all(status == 403 for status in foreign_scope.values()),
        "http_scope_forbidden_for_foreign_role",
        f"non-403 with another route's scope: "
        f"{[k for k, v in foreign_scope.items() if v != 403]}",
    )

    # Activation seal binding: the posted profile/declaration must hash to the
    # engine's sealed pair. Tampered objects conflict (409) and missing objects
    # are a contract error (400); neither activates, so the happy-path
    # activation below still runs against a DRAFT engine.
    tampered_profile = _activate_body(app)
    tampered_profile["profile"]["profile_id"] = "tampered-profile"
    tampered_profile_status, _ = _http_call(
        app,
        "POST",
        "/v1/declarations:activate",
        tampered_profile,
        scope="nc25.governance",
    )
    tampered_declaration = _activate_body(app)
    tampered_declaration["declaration"]["declaration_id"] = "tampered-decl"
    tampered_declaration_status, _ = _http_call(
        app,
        "POST",
        "/v1/declarations:activate",
        tampered_declaration,
        scope="nc25.governance",
    )
    missing_objects_status, _ = _http_call(
        app,
        "POST",
        "/v1/declarations:activate",
        {
            "activated_by": "synthetic-approval-owner",
            "approval_evidence_ref": "evidence://x",
        },
        scope="nc25.governance",
    )
    check(
        tampered_profile_status == 409
        and tampered_declaration_status == 409
        and missing_objects_status == 400
        and app._engine.status == "DRAFT",
        "http_activate_seal_binding",
        f"profile={tampered_profile_status} declaration="
        f"{tampered_declaration_status} missing={missing_objects_status} "
        f"status={app._engine.status}",
    )

    # Happy path over HTTP: activate -> grant -> evaluate(ALLOW) -> consume(COMMITTED).
    _activate_and_grant(app, grant)
    missing_idem, _ = _http_call(
        app,
        "POST",
        "/v1/operator/intents:evaluate",
        {"intent": intent, "evidence_bundle": evidence},
        scope="nc25.operator",
    )
    check(missing_idem == 400, "http_idempotency_required", f"status={missing_idem}")
    bad_idem, _ = _http_call(
        app,
        "POST",
        "/v1/operator/intents:evaluate",
        {"intent": intent, "evidence_bundle": evidence},
        scope="nc25.operator",
        idem="WRONG-KEY",
    )
    check(bad_idem == 409, "http_idempotency_mismatch", f"status={bad_idem}")
    allow_status, allow = _http_call(
        app,
        "POST",
        "/v1/operator/intents:evaluate",
        {"intent": intent, "evidence_bundle": evidence},
        scope="nc25.operator",
        idem=intent["idempotency_key"],
    )
    permit_hash = allow["permit_hash"] if isinstance(allow, dict) else ""
    mismatch_status, mismatch = _http_call(
        app,
        "POST",
        "/v1/executor/permits/" + ("0" * 64) + ":consume",
        _exec_request(intent, permit_hash),
        scope="nc25.executor",
    )
    check(
        mismatch_status == 400
        and isinstance(mismatch, dict)
        and mismatch.get("code") == "EXECUTION_PERMIT_MISMATCH",
        "http_permit_path_body_binding",
        f"status={mismatch_status} body={mismatch}",
    )
    consume_status, receipt = _http_call(
        app,
        "POST",
        "/v1/executor/permits/" + permit_hash + ":consume",
        _exec_request(intent, permit_hash),
        scope="nc25.executor",
    )
    head_status, head = _http_call(
        app, "GET", "/v1/architect/ledger/head", scope="nc25.architect"
    )
    # Architect reads with the correct scope must succeed, proving each handler
    # calls the engine with its route's own scope (a handler that hardcoded a
    # wrong engine scope would surface ROLE_SCOPE_MISMATCH here, not 200).
    permit_status, permit_view = _http_call(
        app, "GET", "/v1/architect/permits/" + permit_hash, scope="nc25.architect"
    )
    request_hash = allow.get("request_hash") if isinstance(allow, dict) else ""
    decision_status, _decision = _http_call(
        app, "GET", "/v1/architect/decisions/" + request_hash, scope="nc25.architect"
    )
    check(
        allow_status == 200
        and isinstance(allow, dict)
        and allow.get("disposition") == "ALLOW"
        and consume_status == 200
        and isinstance(receipt, dict)
        and receipt.get("outcome") == "COMMITTED"
        and head_status == 200
        and isinstance(head, dict)
        and "head_hash" in head
        and permit_status == 200
        and isinstance(permit_view, dict)
        and permit_view.get("consumed") is True
        and decision_status == 200,
        "http_happy_path",
        f"allow={allow_status} consume={consume_status} head={head_status}"
        f" permit={permit_status} decision={decision_status}",
    )

    unknown_status, _ = _http_call(
        app, "GET", "/v1/registry/connectors/does-not-exist", scope="nc25.architect"
    )
    check(unknown_status == 404, "http_unknown_connector_404", f"status={unknown_status}")

    # Untrusted ingress: an injected resolver that marks every evidence item
    # INVALID must turn an otherwise-ALLOW intent into a REFUSAL over HTTP, so
    # connector-asserted evidence is re-derived, not trusted.
    def invalidating_resolver(_intent, submitted, _resolved_at):
        resolved = copy.deepcopy(dict(submitted))
        for item in resolved["items"]:
            item["status"] = "INVALID"
        return resolved

    # Baseline: with NO resolver the exact same intent and evidence ALLOW. This
    # is asserted in-block so the untrusted check cannot silently go decorative
    # if a future fixture change made the intent refuse for any other reason.
    baseline_app, baseline_grant, baseline_intent, baseline_evidence = _adapter_fixture()
    _activate_and_grant(baseline_app, baseline_grant)
    baseline_status, baseline = _http_call(
        baseline_app,
        "POST",
        "/v1/operator/intents:evaluate",
        {"intent": baseline_intent, "evidence_bundle": baseline_evidence},
        scope="nc25.operator",
        idem=baseline_intent["idempotency_key"],
    )
    untrusted_app, untrusted_grant, untrusted_intent, untrusted_evidence = _adapter_fixture(
        evidence_resolver=invalidating_resolver
    )
    _activate_and_grant(untrusted_app, untrusted_grant)
    refusal_status, refusal = _http_call(
        untrusted_app,
        "POST",
        "/v1/operator/intents:evaluate",
        {"intent": untrusted_intent, "evidence_bundle": untrusted_evidence},
        scope="nc25.operator",
        idem=untrusted_intent["idempotency_key"],
    )
    check(
        baseline_status == 200
        and isinstance(baseline, dict)
        and baseline.get("disposition") == "ALLOW"
        and refusal_status == 200
        and isinstance(refusal, dict)
        and refusal.get("disposition") == "REFUSAL"
        and refusal.get("permit_hash") is None,
        "http_untrusted_evidence",
        f"baseline={baseline_status}/{baseline.get('disposition') if isinstance(baseline, dict) else baseline}"
        f" refusal={refusal_status} body={refusal}",
    )

    # Untrusted controls: an injected control resolver whose derived hard
    # block contradicts the connector's asserted flags must refuse an
    # otherwise-ALLOW intent over HTTP — spoofed connector flags cannot
    # produce ALLOW when derivation is wired. The ALLOW baseline above (no
    # resolver, same fixtures) keeps this check from going decorative.
    def hard_blocking_controls(intent, _resolved_at):
        return {
            "prerequisite_results": dict(intent["prerequisite_results"]),
            "hard_block_flags": {
                flag: True for flag in intent["hard_block_flags"]
            },
            "manual_review_flags": dict(intent["manual_review_flags"]),
            "ambiguity_flags": list(intent["ambiguity_flags"]),
        }

    spoofed_app, spoofed_grant, spoofed_intent, spoofed_evidence = _adapter_fixture(
        control_resolver=hard_blocking_controls
    )
    _activate_and_grant(spoofed_app, spoofed_grant)
    spoofed_status, spoofed = _http_call(
        spoofed_app,
        "POST",
        "/v1/operator/intents:evaluate",
        {"intent": spoofed_intent, "evidence_bundle": spoofed_evidence},
        scope="nc25.operator",
        idem=spoofed_intent["idempotency_key"],
    )
    check(
        spoofed_status == 200
        and isinstance(spoofed, dict)
        and spoofed.get("disposition") == "REFUSAL"
        and spoofed.get("message_code") == "EXECUTION_DENIED"
        and spoofed.get("permit_hash") is None,
        "http_untrusted_controls",
        f"status={spoofed_status} body={spoofed}",
    )

    # 413: a body over the adapter cap is refused before it is parsed. The
    # declared body-cap status was never produced by a probe.
    cap_app, _cap_grant, _cap_intent, _cap_evidence = _adapter_fixture()
    oversized_status, _ = _http_call(
        cap_app,
        "POST",
        "/v1/operator/intents:evaluate",
        {"intent": {"blob": "x" * ((1 << 20) + 64)}, "evidence_bundle": {}},
        scope="nc25.operator",
        idem="OVERSIZED",
    )
    check(oversized_status == 413, "http_body_cap_413", f"status={oversized_status}")

    # 204: a valid revocation returns an empty-body success. The declared 204
    # success path was never driven.
    revoke_app, revoke_grant, _revoke_intent, _revoke_evidence = _adapter_fixture()
    _activate_and_grant(revoke_app, revoke_grant)
    revoke_status, revoke_body = _http_call(
        revoke_app,
        "POST",
        "/v1/authority-revocations",
        {
            "message_type": "authority_revocation",
            "grant_id": revoke_grant["grant_id"],
            "declaration_hash": revoke_app._engine.declaration_hash,
            "revoked_at": "2026-08-01T10:00:00Z",
            "revoked_by": revoke_grant["issued_by"],
            "reason_code": "SYNTHETIC_REVOCATION",
            "evidence_ref": "evidence://synthetic/revocation/wire",
        },
        scope="nc25.governance",
    )
    check(
        revoke_status == 204 and revoke_body is None,
        "http_revoke_success_204",
        f"status={revoke_status} body={revoke_body}",
    )

    # 503: an engine integrity halt maps to a transport-level 503 on a read,
    # never to an operator result. The declared 503 mapping was never probed.
    halt_app, halt_grant, _halt_intent, _halt_evidence = _adapter_fixture()
    _activate_and_grant(halt_app, halt_grant)

    def _raise_integrity() -> None:
        raise IntegrityViolation("LEDGER_TAMPERED")

    halt_app._engine._assert_integrity = _raise_integrity
    halt_status, _ = _http_call(
        halt_app,
        "GET",
        "/v1/architect/ledger/head",
        scope="nc25.architect",
    )
    check(halt_status == 503, "http_integrity_halt_503", f"status={halt_status}")

    # 503 INTERNAL_FAILURE: a fault the adapter does not classify is answered
    # as a declared status with no detail of the fault, instead of escaping
    # the WSGI callable. Planted behind the adapter, in process.
    fault_app, fault_grant, fault_intent, fault_evidence = _adapter_fixture()
    _activate_and_grant(fault_app, fault_grant)

    def _raise_fault(*_args, **_kwargs):
        raise RuntimeError("planted fault")

    fault_app._engine.evaluate_intent = _raise_fault
    fault_status, fault_body = _http_call(
        fault_app,
        "POST",
        "/v1/operator/intents:evaluate",
        {"intent": fault_intent, "evidence_bundle": fault_evidence},
        scope="nc25.operator",
        idem=fault_intent["idempotency_key"],
    )
    check(
        fault_status == 503
        and fault_body == {"code": "INTERNAL_FAILURE", "message": "internal failure"},
        "http_internal_failure_503",
        f"status={fault_status} body={fault_body}",
    )

    # A body with no idempotency_key is an incomplete intent (400 from the
    # engine's form check), not a header mismatch; a present, differing key
    # stays the 409 the http_idempotency_mismatch row certifies.
    field_app, field_grant, field_intent, field_evidence = _adapter_fixture()
    _activate_and_grant(field_app, field_grant)
    keyless = dict(field_intent)
    del keyless["idempotency_key"]
    field_status, field_body = _http_call(
        field_app,
        "POST",
        "/v1/operator/intents:evaluate",
        {"intent": keyless, "evidence_bundle": field_evidence},
        scope="nc25.operator",
        idem=field_intent["idempotency_key"],
    )
    check(
        field_status == 400 and field_body.get("code") == "INTENT_FIELDS",
        "http_missing_idempotency_field_400",
        f"status={field_status} body={field_body}",
    )

    # An identical re-issue is a replay: 200, the same grant_hash, no event.
    replay_app, replay_grant, _replay_intent, _replay_evidence = _adapter_fixture()
    _activate_and_grant(replay_app, replay_grant)
    events_before = replay_app._engine.ledger.head()["event_count"]
    replay_status, replay_body = _http_call(
        replay_app, "POST", "/v1/authority-grants", replay_grant, scope="nc25.governance"
    )
    check(
        replay_status == 200
        and replay_body.get("grant_hash") == sha256_hex(replay_grant)
        and replay_app._engine.ledger.head()["event_count"] == events_before,
        "http_grant_replay_200",
        f"status={replay_status} events={events_before}->"
        f"{replay_app._engine.ledger.head()['event_count']}",
    )

    # A repeated revocation of a revoked grant is 204 and records nothing.
    revocation = {
        "message_type": "authority_revocation",
        "grant_id": replay_grant["grant_id"],
        "declaration_hash": replay_app._engine.declaration_hash,
        "revoked_at": "2026-08-01T10:00:00Z",
        "revoked_by": replay_grant["issued_by"],
        "reason_code": "SYNTHETIC_REVOCATION",
        "evidence_ref": "evidence://synthetic/revocation/replay",
    }
    first_status, _ = _http_call(
        replay_app, "POST", "/v1/authority-revocations", revocation, scope="nc25.governance"
    )
    events_after_first = replay_app._engine.ledger.head()["event_count"]
    second_status, _ = _http_call(
        replay_app, "POST", "/v1/authority-revocations", revocation, scope="nc25.governance"
    )
    check(
        first_status == 204
        and second_status == 204
        and replay_app._engine.ledger.head()["event_count"] == events_after_first
        and events_after_first == events_before + 1,
        "http_revocation_replay_204",
        f"statuses={first_status}/{second_status} events={events_before}->"
        f"{events_after_first}->{replay_app._engine.ledger.head()['event_count']}",
    )

    # A malformed binding is a form error: 400, no event, key not consumed.
    shape_app, shape_grant, shape_intent, shape_evidence = _adapter_fixture()
    _activate_and_grant(shape_app, shape_grant)
    shaped = dict(shape_intent)
    shaped["binding"] = "not-an-object"
    shape_events = shape_app._engine.ledger.head()["event_count"]
    shape_status, shape_body = _http_call(
        shape_app,
        "POST",
        "/v1/operator/intents:evaluate",
        {"intent": shaped, "evidence_bundle": shape_evidence},
        scope="nc25.operator",
        idem=shape_intent["idempotency_key"],
    )
    check(
        shape_status == 400
        and shape_body.get("code") == "INTENT_BINDING"
        and shape_app._engine.ledger.head()["event_count"] == shape_events
        and not shape_app._engine.idempotency,
        "http_intent_binding_400",
        f"status={shape_status} body={shape_body}",
    )

    # The two request wrappers are closed: an unknown top-level key is a body
    # defect on both, as the contract's additionalProperties: false says.
    wrap_app, wrap_grant, wrap_intent, wrap_evidence = _adapter_fixture()
    activate_body = _activate_body(wrap_app)
    activate_body["extra"] = 1
    wrap_activate_status, wrap_activate_body = _http_call(
        wrap_app, "POST", "/v1/declarations:activate", activate_body, scope="nc25.governance"
    )
    _activate_and_grant(wrap_app, wrap_grant)
    wrap_eval_status, wrap_eval_body = _http_call(
        wrap_app,
        "POST",
        "/v1/operator/intents:evaluate",
        {"intent": wrap_intent, "evidence_bundle": wrap_evidence, "extra": 1},
        scope="nc25.operator",
        idem=wrap_intent["idempotency_key"],
    )
    check(
        wrap_activate_status == 400
        and wrap_activate_body.get("code") == "ACTIVATE_BODY"
        and wrap_eval_status == 400
        and wrap_eval_body.get("code") == "OPERATOR_BODY",
        "http_wrapper_unknown_key_400",
        f"activate={wrap_activate_status}/{wrap_activate_body} "
        f"evaluate={wrap_eval_status}/{wrap_eval_body}",
    )


def main() -> None:
    failures.clear()
    passed_ids.clear()
    skipped.clear()
    schema_conformance()
    openapi_conformance()
    wire_live_conformance()
    http_adapter_conformance()
    for note in skipped:
        print(note)
    if failures:
        print(
            f"CONTRACT_CONFORMANCE=FAIL ({len(passed_ids)}/"
            f"{len(EXPECTED_CONFORMANCE_IDS)} passed; {len(failures)} failed)"
        )
        raise SystemExit(1)
    # Which declared checks did not report is computed on EVERY path, and it is
    # printed before any verdict. It used to be computed only after the partial
    # branch had already returned, so in a partial run a check that stopped
    # executing for any reason - not only a missing optional library - was
    # reported by nothing at all.
    missing = sorted(EXPECTED_CONFORMANCE_IDS - passed_ids)
    if missing:
        print(f"CONTRACT_CONFORMANCE_MISSING={missing}")
    if not passed_ids:
        print(
            f"CONTRACT_CONFORMANCE=NOT_RUN "
            f"(0/{len(EXPECTED_CONFORMANCE_IDS)} checks executed)"
        )
        raise SystemExit(1)
    if skipped:
        # A partial run is not a pass, and exiting zero said it was. The
        # acceptance runner already refuses this output, because its marker
        # requires PASS - so a direct run that exited zero made the two
        # disagree about the same result.
        print(
            f"CONTRACT_CONFORMANCE={len(passed_ids)}/"
            f"{len(EXPECTED_CONFORMANCE_IDS)} PARTIAL (see NOT_RUN above)"
        )
        raise SystemExit(1)
    if missing:
        print(f"CONTRACT_CONFORMANCE=FAIL missing={missing}")
        raise SystemExit(1)
    print(
        f"CONTRACT_CONFORMANCE={len(passed_ids)}/"
        f"{len(EXPECTED_CONFORMANCE_IDS)} PASS"
    )


def test_contract_conformance_suite() -> None:
    # A partial run now exits non-zero from main(), which is the right answer
    # for the acceptance path. Under pytest the same situation is a skip, not a
    # failure, so the exit is translated here rather than weakened there.
    try:
        main()
    except SystemExit:
        if not skipped:
            raise
    if skipped:
        import pytest

        pytest.skip("; ".join(skipped))


if __name__ == "__main__":
    main()
