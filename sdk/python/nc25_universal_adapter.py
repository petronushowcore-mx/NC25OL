"""Reference WSGI HTTP adapter for the NC25OL.

This is the executable counterpart to `protocol/universal-connection.openapi.yaml`.
It exists so the wire-level MUST rules that the OpenAPI states as prose are
enforced and testable end-to-end, rather than left to each integrator:

  * every route requires the exact workload scope, derived from the transport
    identity and never from the request body; omission or the wrong scope fails
    closed;
  * the activation route binds the posted profile and declaration objects to
    the engine's sealed hashes; a mismatch conflicts instead of activating;
  * the operator route requires an `Idempotency-Key` header exactly equal to
    `intent.idempotency_key`, rejected before evaluation;
  * the executor route binds the path `{permit_hash}` to the body permit hash
    through the engine's required `route_permit_hash` argument;
  * connector-supplied evidence and control claims are untrusted: the engine
    accepts an `evidence_resolver` and a `control_resolver`, each re-deriving
    its surface at ingress with fail-closed failures. Without the control
    resolver the reference engine gates on the declared intent flags (a
    documented reference boundary); production MUST wire both resolvers to
    authoritative systems;
  * engine outcomes map to the declared HTTP statuses (400/404/409/503).
    Those four are the statuses an ENGINE outcome can become; the adapter also
    raises 403 for scope and 413 for the body cap on its own, and answers
    200/201/204 on success.

It is standard-library only and framework-free (a plain WSGI callable), so it
is driven in-process by the conformance suite with no network. The engine it
wraps is standard-library on every default path; only the optional Ed25519
signers need the pinned `cryptography` wheel. It is a REFERENCE: production
replaces the scope header with mutual TLS plus scoped OAuth derived from a
verified workload identity, and adds durable transactional storage.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Iterable, Mapping

from nc25_universal_ledger import (
    ContractViolation,
    IntegrityViolation,
    MAX_NESTING_DEPTH,
    ROLE_ARCHITECT,
    ROLE_EXECUTOR,
    ROLE_GOVERNANCE,
    ROLE_OPERATOR,
    UniversalConnectionLedger,
    sha256_hex,
)

# The scope carried by the transport identity. In production this is the
# mTLS + OAuth2 verified workload scope; here it is a request header so the
# adapter can prove the scope never comes from the request body.
SCOPE_HEADER = "HTTP_X_WORKLOAD_SCOPE"
IDEMPOTENCY_HEADER = "HTTP_IDEMPOTENCY_KEY"

# A reference bound so a hostile Content-Length cannot force an unbounded read.
MAX_BODY_BYTES = 1 << 20

# ContractViolation codes that are HTTP conflicts, not contract errors.
_CONFLICT_CODES = frozenset(
    {
        "IDEMPOTENCY_CONFLICT",
        "EXECUTION_REPLAY_CONFLICT",
        "AUTHORITY_ID_CONFLICT",
        "DECLARATION_ALREADY_ACTIVATED",
    }
)
# ContractViolation codes that mean the addressed object does not exist here.
_NOT_FOUND_CODES = frozenset(
    {
        "CONNECTOR_NOT_FOUND",
        "DECISION_UNKNOWN",
        "PERMIT_UNKNOWN",
        "AUTHORITY_UNKNOWN",
    }
)


class WireError(Exception):
    """An HTTP-level failure carrying a status and a stable error code."""

    def __init__(self, status: int, code: str, message: str = "") -> None:
        self.status = status
        self.code = code
        self.message = message or code
        super().__init__(f"{status} {code}")


def _reject_deep_nesting(text: str) -> None:
    """Refuse a body nested deeper than the engine's own limit.

    `json.loads` recurses, so a body nested a few thousand deep raises
    RecursionError out of the parser - before any engine code, and therefore
    outside the refusal vocabulary entirely: over the wire it surfaced as an
    unhandled fault. The engine's MAX_NESTING_DEPTH is checked when a document
    is hashed or canonicalised, which is strictly later. This scan is a
    character walk rather than a parse, so it cannot itself recurse.
    """
    depth = 0
    inside_string = False
    escaped = False
    for character in text:
        if inside_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                inside_string = False
            continue
        if character == '"':
            inside_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_NESTING_DEPTH:
                raise WireError(
                    400, "BODY_NESTING", "request body is nested too deeply"
                )
        elif character in "]}":
            depth -= 1


# The adapter's own details are bounded like the engine's: a message that
# lists the caller's keys would otherwise be as long as the caller made it.
MAX_DETAIL_LENGTH = 128


def _bounded(detail: str) -> str:
    return detail if len(detail) <= MAX_DETAIL_LENGTH else detail[:MAX_DETAIL_LENGTH] + "..."


def _header_text(environ: Mapping[str, Any], name: str) -> str:
    """A header's CHARACTERS, read by `str`'s own implementation.

    Everything this layer asks of a header - truthiness, `!=` - runs the value's own code
    if it has any, and the two headers that reach this reader decide an authorised scope
    and an idempotency match. A server hands native strings and nothing changes for it; in
    process the environ is whatever the caller builds, and there the checks were the only
    gate. Measured one layer in, at the bridge, against the same shape of comparison: an
    object answering every comparison with agreement passed a binding written exactly like
    these. `type` is asked rather than `isinstance`, which consults `__class__` and can be
    answered by a property; the conversion runs nothing a subclass defines. A value that is
    no string at all reads as an absent header, which is what it is to this reader, and the
    caller's own refusal names it.
    """
    value = environ.get(name)
    return str.__str__(value) if issubclass(type(value), str) else ""


def _status_line(status: int) -> str:
    return {
        200: "200 OK",
        201: "201 Created",
        204: "204 No Content",
        400: "400 Bad Request",
        403: "403 Forbidden",
        404: "404 Not Found",
        409: "409 Conflict",
        413: "413 Payload Too Large",
        503: "503 Service Unavailable",
    }[status]


def _violation_status(exc: ContractViolation) -> int:
    if isinstance(exc, IntegrityViolation):
        return 503
    if exc.code in _CONFLICT_CODES:
        return 409
    if exc.code in _NOT_FOUND_CODES:
        return 404
    return 400


class UniversalConnectionHttpAdapter:
    """A framework-free WSGI app over one `UniversalConnectionLedger`.

    Untrusted ingress is handled by the engine: construct it with an
    `evidence_resolver` and a `control_resolver` so connector-asserted
    evidence claims and control flags are re-derived rather than trusted, and
    the operator route inherits both boundaries through the engine it wraps.
    Without the control resolver the reference engine gates on the declared
    intent flags — a documented reference boundary that production closes by
    wiring both resolvers to authoritative systems.
    """

    def __init__(self, engine: UniversalConnectionLedger) -> None:
        self._engine = engine
        # (method, compiled path) -> (required scope, handler). One row per
        # OpenAPI operation; the conformance suite asserts this set is exact.
        # Anchored with \Z, not $: in Python `$` also matches immediately
        # before a trailing newline, so every route had a second spelling that
        # differed by one appended %0A - including the state-changing ones.
        # Anything outside this process that treats the path as the identity of
        # a resource (a proxy allow-list, an audit trail, a rate limiter) sees
        # two different strings where the adapter saw one route.
        self._routes: list[tuple[str, re.Pattern[str], str, str, Callable[..., Any]]] = [
            ("POST", re.compile(r"^/v1/declarations:activate\Z"), "activateDeclaration", ROLE_GOVERNANCE, self._activate),
            ("POST", re.compile(r"^/v1/authority-grants\Z"), "issueAuthorityGrant", ROLE_GOVERNANCE, self._issue_grant),
            ("POST", re.compile(r"^/v1/authority-revocations\Z"), "revokeAuthorityGrant", ROLE_GOVERNANCE, self._revoke_grant),
            ("POST", re.compile(r"^/v1/operator/intents:evaluate\Z"), "evaluateIntent", ROLE_OPERATOR, self._evaluate_intent),
            ("POST", re.compile(r"^/v1/executor/permits/(?P<permit_hash>[^/]+):consume\Z"), "consumePermit", ROLE_EXECUTOR, self._consume_permit),
            ("GET", re.compile(r"^/v1/architect/permits/(?P<permit_hash>[^/]+)\Z"), "getArchitectPermit", ROLE_ARCHITECT, self._architect_permit),
            ("GET", re.compile(r"^/v1/architect/decisions/(?P<request_hash>[^/]+)\Z"), "getArchitectDecision", ROLE_ARCHITECT, self._architect_decision),
            ("GET", re.compile(r"^/v1/architect/ledger/head\Z"), "getLedgerHead", ROLE_ARCHITECT, self._ledger_head),
            ("GET", re.compile(r"^/v1/registry/connectors/(?P<connector_id>[^/]+)\Z"), "getRegistryRecord", ROLE_ARCHITECT, self._registry_record),
        ]

    # ---- introspection used by the conformance suite -----------------------
    def operation_scopes(self) -> dict[str, str]:
        """operationId -> required OAuth2 scope for every mounted route."""
        return {operation_id: scope for _, _, operation_id, scope, _ in self._routes}

    # ---- WSGI entry point --------------------------------------------------
    def __call__(
        self, environ: Mapping[str, Any], start_response: Callable[..., Any]
    ) -> Iterable[bytes]:
        try:
            try:
                status, payload = self._dispatch(environ)
                body = b"" if status == 204 else json.dumps(payload).encode("utf-8")
            except WireError:
                raise
            except Exception as exc:  # noqa: BLE001 - the last resort, by design
                # Anything that is not a declared wire error is answered as a
                # declared one, with no detail of the fault: a 503 the contract
                # names, instead of an exception escaping the WSGI callable
                # into whatever the server does with it. This is a real raise
                # with a literal code so the wire vocabulary counts it. It
                # does not replace the validations that keep it from firing.
                raise WireError(503, "INTERNAL_FAILURE", "internal failure") from exc
        except WireError as exc:
            status = exc.status
            body = json.dumps({"code": exc.code, "message": exc.message}).encode("utf-8")
        # start_response is called exactly once, after everything that can
        # fail has either succeeded or been turned into a wire error.
        if status == 204:
            start_response(_status_line(status), [("Content-Length", "0")])
            return [b""]
        start_response(
            _status_line(status),
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
            ],
        )
        return [body]

    # ---- dispatch + shared request handling --------------------------------
    def _dispatch(self, environ: Mapping[str, Any]) -> tuple[int, Any]:
        method = environ.get("REQUEST_METHOD", "")
        path = environ.get("PATH_INFO", "")
        # \Z closes the trailing-newline alias on the six fixed routes, but on
        # the three routes ending in a captured segment the class [^/]+ simply
        # eats the newline and \Z still matches - the value then reaches the
        # handler with a control character inside it. So the anchor is not
        # enough on its own: a path carrying any control character is refused
        # here, before dispatch, with the same opaque 404 an unknown path gets.
        if any(character < " " or character == "\x7f" for character in path):
            raise WireError(404, "NOT_FOUND", "no such route")
        for route_method, pattern, _operation_id, scope, handler in self._routes:
            match = pattern.match(path)
            if match is None or route_method != method:
                continue
            self._require_scope(environ, scope)
            # Taken as the server left it. PATH_INFO is already percent-decoded
            # per WSGI, so decoding again turned a literal `%73...` selector
            # into `s...` - the contract's explicit MUST NOT, since the caller
            # asked for one connector and was served the active one.
            params = dict(match.groupdict())
            try:
                return handler(environ, params)
            except (IntegrityViolation, ContractViolation) as exc:
                raise WireError(
                    _violation_status(exc), exc.code, _bounded(exc.detail or exc.code)
                ) from exc
        # A wrong method on a known path and a wholly unknown path return the same
        # opaque 404: an unauthenticated caller learns nothing about which paths
        # exist beyond what the published OpenAPI already states.
        raise WireError(404, "NOT_FOUND", "no such route")

    def _require_scope(self, environ: Mapping[str, Any], expected: str) -> None:
        # The scope comes from the transport identity header, never the body. A
        # missing or non-matching scope fails closed before any engine call.
        presented = _header_text(environ, SCOPE_HEADER)
        if not presented:
            raise WireError(403, "SCOPE_REQUIRED", "workload scope required")
        if presented != expected:
            raise WireError(403, "SCOPE_FORBIDDEN", "workload scope not authorized")

    @staticmethod
    def _read_json(environ: Mapping[str, Any]) -> dict[str, Any]:
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except (TypeError, ValueError):
            raise WireError(400, "BODY_LENGTH", "invalid content length")
        if length < 0:
            raise WireError(400, "BODY_LENGTH", "invalid content length")
        if length > MAX_BODY_BYTES:
            raise WireError(413, "BODY_TOO_LARGE", "request body too large")
        stream = environ.get("wsgi.input")
        if stream is None:
            raise WireError(400, "BODY_STREAM", "no request body stream")
        raw = stream.read(length) if length > 0 else b""
        try:
            text = raw.decode("utf-8") if raw else ""
        except UnicodeDecodeError:
            raise WireError(400, "BODY_JSON", "request body is not valid JSON")
        _reject_deep_nesting(text)
        # ValueError, not only its JSONDecodeError subclass: an integer
        # literal longer than the interpreter's digit limit is refused by the
        # parser with a plain ValueError. Caught as the decode error alone, a
        # body the caller shaped left the refusal vocabulary and was answered
        # as an unclassified 503 - the same escape the nesting scan above
        # closes for RecursionError.
        try:
            value = json.loads(text) if text else {}
        except ValueError:
            raise WireError(400, "BODY_JSON", "request body is not valid JSON")
        if not isinstance(value, dict):
            raise WireError(400, "BODY_OBJECT", "request body must be a JSON object")
        return value

    # ---- handlers ----------------------------------------------------------
    def _activate(self, environ, _params) -> tuple[int, Any]:
        body = self._read_json(environ)
        # Seal binding: the wire contract requires the caller to present the
        # exact profile and declaration objects being activated. Their
        # canonical hashes must equal the engine's sealed pair; a mismatch is
        # a conflict, never a silent activation of something else.
        profile = body.get("profile")
        declaration = body.get("declaration")
        if not isinstance(profile, dict) or not isinstance(declaration, dict):
            raise WireError(
                400, "ACTIVATE_BODY", "profile and declaration required"
            )
        # The wrapper is closed in the contract (additionalProperties: false)
        # and was open here: an unknown top-level key was accepted in silence.
        unknown = set(body) - {
            "profile", "declaration", "activated_by", "approval_evidence_ref"
        }
        if unknown:
            raise WireError(400, "ACTIVATE_BODY", _bounded(f"unknown fields: {sorted(unknown)}"))
        if sha256_hex(profile) != self._engine.profile_hash:
            raise WireError(
                409, "ACTIVATE_PROFILE_MISMATCH",
                "posted profile does not hash to the sealed profile",
            )
        if sha256_hex(declaration) != self._engine.declaration_hash:
            raise WireError(
                409, "ACTIVATE_DECLARATION_MISMATCH",
                "posted declaration does not hash to the sealed declaration",
            )
        # Required by the contract, so its absence is a body defect and is
        # answered as one. Passing the missing value through produced
        # `ACTIVATION_ACTOR` with the message "None" - Python's repr of an
        # absent field, shown to the caller as if it were their input.
        activated_by = body.get("activated_by")
        if not isinstance(activated_by, str):
            raise WireError(400, "ACTIVATE_BODY", "activated_by required")
        declaration_hash = self._engine.activate(
            activated_by,
            body.get("approval_evidence_ref"),
            actor_scope=ROLE_GOVERNANCE,
        )
        return 201, {
            "profile_hash": self._engine.profile_hash,
            "declaration_hash": declaration_hash,
            "status": "ACTIVE",
        }

    def _issue_grant(self, environ, _params) -> tuple[int, Any]:
        body = self._read_json(environ)
        # Validate and determine creation in the SAME state transaction.
        # Reading engine.grants here would use stale state across instances
        # and would hash an unvalidated grant_id before the engine can refuse it.
        grant_hash, created = self._engine.issue_grant(
            body, actor_scope=ROLE_GOVERNANCE, with_status=True
        )
        return (201 if created else 200), {
            "grant_id": body.get("grant_id"),
            "grant_hash": grant_hash,
        }

    def _revoke_grant(self, environ, _params) -> tuple[int, Any]:
        body = self._read_json(environ)
        self._engine.revoke_grant(body, actor_scope=ROLE_GOVERNANCE)
        return 204, None

    def _evaluate_intent(self, environ, _params) -> tuple[int, Any]:
        body = self._read_json(environ)
        intent = body.get("intent")
        evidence_bundle = body.get("evidence_bundle")
        if not isinstance(intent, dict) or not isinstance(evidence_bundle, dict):
            raise WireError(400, "OPERATOR_BODY", "intent and evidence_bundle required")
        unknown = set(body) - {"intent", "evidence_bundle"}
        if unknown:
            raise WireError(400, "OPERATOR_BODY", _bounded(f"unknown fields: {sorted(unknown)}"))
        # Idempotency-Key MUST exactly equal intent.idempotency_key, rejected
        # before evaluation. A missing header is a contract error. A body that
        # carries NO key is not a mismatch but an incomplete intent, and the
        # engine answers that as the form error it is (400 INTENT_FIELDS);
        # comparing the header against an absent field answered 409 for it.
        header_key = _header_text(environ, IDEMPOTENCY_HEADER)
        if not header_key:
            raise WireError(400, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key required")
        if "idempotency_key" in intent and header_key != intent["idempotency_key"]:
            raise WireError(
                409, "IDEMPOTENCY_KEY_MISMATCH", "Idempotency-Key != intent.idempotency_key"
            )
        result = self._engine.evaluate_intent(
            intent,
            evidence_bundle,
            actor_scope=ROLE_OPERATOR,
        )
        return 200, result

    def _consume_permit(self, environ, params) -> tuple[int, Any]:
        body = self._read_json(environ)
        # The URL path permit hash is bound to the body through the engine's
        # required route_permit_hash argument; a mismatch fails closed.
        receipt = self._engine.commit_execution(
            body,
            actor_scope=ROLE_EXECUTOR,
            route_permit_hash=params["permit_hash"],
        )
        return 200, receipt

    def _architect_permit(self, environ, params) -> tuple[int, Any]:
        return 200, self._engine.architect_permit(
            params["permit_hash"], actor_scope=ROLE_ARCHITECT
        )

    def _architect_decision(self, environ, params) -> tuple[int, Any]:
        return 200, self._engine.architect_decision(
            params["request_hash"], actor_scope=ROLE_ARCHITECT
        )

    def _ledger_head(self, environ, _params) -> tuple[int, Any]:
        return 200, self._engine.ledger_head(actor_scope=ROLE_ARCHITECT)

    def _registry_record(self, environ, params) -> tuple[int, Any]:
        return 200, self._engine.registry_record(
            params["connector_id"], actor_scope=ROLE_ARCHITECT
        )
