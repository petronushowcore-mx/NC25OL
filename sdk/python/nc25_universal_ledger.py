"""Reference engine for the NC25OL.

Standard-library by default: the engine imports and runs every default path
(HMAC permit signing, HMAC state protection, evaluate-to-commit) without any
third-party package. The optional Ed25519 signers are the single exception —
they need the pinned `cryptography` wheel and fail closed without it.

The engine demonstrates contract behavior. It defaults to in-memory state,
optionally persists one declaration in SQLite, and protects state with HMAC.
Permit signatures and ledger-event signatures are versioned detached envelopes
(`{version, algorithm, key_id, signature}`) produced by a pluggable signer:
the reference default is HMAC-SHA256, and detached Ed25519 is supported for
both surfaces. Permit verification routes by `key_id`, so signing keys can be
rotated (old permits stay verifiable) and revoked (their permits fail closed).
Production substitutions are listed in the package runbook.
"""

from __future__ import annotations

import base64
import copy
from contextlib import contextmanager
import functools
import hashlib
import hmac
import inspect
import json
import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Literal, Mapping, Protocol, overload

# Ed25519 support needs the third-party `cryptography` wheel (pinned in
# requirements-lock.txt). Every default path — HMAC permit signing, HMAC state
# protection, the whole evaluate-to-commit flow — is standard-library only, so
# the engine imports and runs without the wheel; constructing an Ed25519
# signer then fails closed with ED25519_UNAVAILABLE instead of failing open
# or breaking import.
try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    _ED25519_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised by a subprocess regression
    InvalidSignature = None  # type: ignore[assignment,misc]
    serialization = None  # type: ignore[assignment]
    Ed25519PrivateKey = None  # type: ignore[assignment,misc]
    Ed25519PublicKey = None  # type: ignore[assignment,misc]
    _ED25519_AVAILABLE = False


CORE_ANCHOR = {
    "file_name": "NC25_v3_0_patched_v4.tex",
    "core_version": "3.0",
    "doi": "10.17605/OSF.IO/NHTC5",
    "sha256": "20F1EA17E0B986627CAD9AFA7C02E1DC5088C43A779435E5A38F11E43A06C9C3",
}

ROLE_GOVERNANCE = "nc25.governance"
ROLE_OPERATOR = "nc25.operator"
ROLE_EXECUTOR = "nc25.executor"
ROLE_ARCHITECT = "nc25.architect"

NON_EXECUTABLE = {"REFUSAL", "MANUAL_REVIEW"}
EXECUTION_OUTCOMES = {"COMMITTED", "FAILED", "ABORTED"}
IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{1,127}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")

# Secret-name backstop. A defense-in-depth guard behind the exact-key contract
# (_require_exact_keys): it refuses a MAPPING KEY that reads as a credential
# field name in any separator style or casing. Keys are lowercased and stripped
# to [a-z0-9] before comparison, so "api_key", "apiKey", and "x-api-key" all
# reduce to a form ending in "apikey". It cannot stop a secret value smuggled
# under a benign key; its job is to catch honest mislabeling, not a determined
# smuggler.
#
# Bare high-signal names and credential compounds are denied. Content-bearing
# qualifiers such as "_value", "_pem", and "_v2" do not make them benign.
# Explicit metadata predicates ("is_secret", "uses_api_key") and classification
# labels ("trade_secret", "top_secret") remain valid. Non-secret references
# must say what they are, for example "signing_key_ref" or "encryption_key_arn".
_SECRET_WORD_SUFFIXES = ("password", "passphrase", "secret")
_SECRET_COMPOUND_SUFFIXES = (
    "accesskey",
    "accesstoken",
    "apikey",
    "apitoken",
    "authorizationheader",
    "authtoken",
    "bearertoken",
    "clienttoken",
    "encryptionkey",
    "idtoken",
    "jwttoken",
    "masterkey",
    "oauthtoken",
    "privatekey",
    "refreshtoken",
    "sastoken",
    "secretkey",
    "securitytoken",
    "sessionkey",
    "sessiontoken",
    "signingkey",
    "sshkey",
    "subscriptionkey",
)
LOCAL_SECRET_KEYS = {
    "authorization",
    "credential",
    "credentials",
    "jwt",
    "rawpayload",
    "token",
}
_SECRET_CONTENT_SUFFIXES = (
    "blob",
    "bytes",
    "data",
    "digest",
    "hash",
    "header",
    "json",
    "material",
    "pem",
    "text",
    "value",
)
_NON_SECRET_EXACT_KEYS = {"topsecret", "tradesecret"}
_NON_SECRET_METADATA_PREFIXES = {
    "contains",
    "has",
    "is",
    "not",
    "requires",
    "supports",
    "uses",
}


def _key_tokens(key: Any) -> tuple[str, ...]:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(key))
    return tuple(
        part.lower()
        for part in re.split(r"[^A-Za-z0-9]+", separated)
        if part
    )


def _has_secret_shape(normalized: str) -> bool:
    candidate = normalized
    while candidate:
        if (
            candidate in LOCAL_SECRET_KEYS
            or candidate.endswith(_SECRET_WORD_SUFFIXES)
            or candidate.endswith(_SECRET_COMPOUND_SUFFIXES)
        ):
            return True
        versionless = re.sub(r"(?:v)?[0-9]+$", "", candidate)
        if versionless != candidate:
            candidate = versionless
            continue
        for suffix in _SECRET_CONTENT_SUFFIXES:
            if candidate.endswith(suffix) and len(candidate) > len(suffix):
                candidate = candidate[: -len(suffix)]
                break
        else:
            return False
    return False


def _is_secret_key_name(key: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
    if not normalized or normalized in _NON_SECRET_EXACT_KEYS:
        return False
    tokens = _key_tokens(key)
    if (
        len(tokens) > 1
        and tokens[0] in _NON_SECRET_METADATA_PREFIXES
        and _has_secret_shape("".join(tokens[1:]))
    ):
        return False
    return _has_secret_shape(normalized)


class ContractViolation(RuntimeError):
    """Raised when an input cannot satisfy the declared contract."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


class IntegrityViolation(ContractViolation):
    """Raised when a seal, signature, or append-only chain is invalid."""


MAX_NESTING_DEPTH = 64


def _plain_json(value: Any, path: str = "$", depth: int = 0) -> Any:
    if depth > MAX_NESTING_DEPTH:
        raise ContractViolation("NESTING_DEPTH_EXCEEDED", path)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContractViolation("JSON_OBJECT_KEY_TYPE", path)
            result[key] = _plain_json(item, f"{path}.{key}", depth + 1)
        return result
    if isinstance(value, list):
        return [
            _plain_json(item, f"{path}[{index}]", depth + 1)
            for index, item in enumerate(value)
        ]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ContractViolation("JSON_VALUE_TYPE", path)


def canonical_json(value: Any) -> bytes:
    """Return canonical UTF-8 JSON bytes for every protocol and domain hash.

    Not every hash in the package: `SQLiteStateStore._encode` serializes the
    persisted snapshot separately, with `ensure_ascii=True` and no NaN guard,
    and that text is hashed and MAC-ed on the storage path. The two are
    deliberately independent — one is the wire and domain canon, the other is
    private to the store — so neither is a substitute for the other.
    """

    try:
        return json.dumps(
            _plain_json(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except ContractViolation:
        raise
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ContractViolation(
            "CANONICAL_JSON_INVALID",
            type(exc).__name__,
        ) from exc


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest().upper()


def hmac_hex(key: bytes, text: str) -> str:
    return hmac.new(key, text.encode("ascii"), hashlib.sha256).hexdigest().upper()


class EventSigner(Protocol):
    def sign(self, message: bytes) -> Mapping[str, str]:
        ...

    def verify(self, message: bytes, signature: Any) -> bool:
        ...


EvidenceResolver = Callable[
    [Mapping[str, Any], Mapping[str, Any], datetime],
    Mapping[str, Any],
]

# Authoritative control derivation: receives the submitted intent and the
# evaluation instant, returns the control results derived from enterprise
# systems of record. They replace the connector-asserted flags as gate inputs
# and are bound into the request hash.
ControlResolver = Callable[
    [Mapping[str, Any], datetime],
    Mapping[str, Any],
]

# The three boolean control maps, keyed by the profile-declared flag ids.
CONTROL_BOOLEAN_FIELDS = (
    "prerequisite_results",
    "hard_block_flags",
    "manual_review_flags",
)
# The ambiguity surface is an identifier set, not a boolean map.
CONTROL_AMBIGUITY_FIELD = "ambiguity_flags"
CONTROL_FIELDS = CONTROL_BOOLEAN_FIELDS + (CONTROL_AMBIGUITY_FIELD,)

# Declared origin of the structural capacity, coded with the published
# instrument of NC2.5 Probe II (DOI 10.17605/OSF.IO/7SQMY, R2): the origin of
# a boundary is fully stipulated, empirically calibrated, derived from a load
# model, or mixed. The value is a sealed declaration datum read by governance
# and audit; the gate never reads it.
STRUCTURAL_PROVENANCE_VALUES = frozenset(
    {
        "fully_stipulated",
        "empirically_calibrated",
        "derived_from_load_model",
        "mixed",
    }
)


def _require_ed25519() -> None:
    if not _ED25519_AVAILABLE:
        raise ContractViolation("ED25519_UNAVAILABLE")


class Ed25519DetachedSigner:
    """Detached Ed25519 envelope for append-only event hashes."""

    VERSION = "1"
    ALGORITHM = "Ed25519"

    def __init__(
        self,
        key_id: str,
        private_key: "Ed25519PrivateKey | None",
        public_key: "Ed25519PublicKey",
    ) -> None:
        _require_ed25519()
        if not isinstance(key_id, str) or not key_id or len(key_id) > 200:
            raise ContractViolation("SIGNATURE_KEY_ID")
        self.key_id = key_id
        self._private_key = private_key
        self._public_key = public_key

    @classmethod
    def generate(cls, key_id: str) -> "Ed25519DetachedSigner":
        _require_ed25519()
        private_key = Ed25519PrivateKey.generate()
        return cls(key_id, private_key, private_key.public_key())

    @classmethod
    def from_private_bytes(
        cls,
        key_id: str,
        private_key_bytes: bytes,
    ) -> "Ed25519DetachedSigner":
        _require_ed25519()
        if not isinstance(private_key_bytes, bytes) or len(private_key_bytes) != 32:
            raise ContractViolation("ED25519_PRIVATE_KEY")
        private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        return cls(key_id, private_key, private_key.public_key())

    @classmethod
    def from_public_bytes(
        cls,
        key_id: str,
        public_key_bytes: bytes,
    ) -> "Ed25519DetachedSigner":
        _require_ed25519()
        if not isinstance(public_key_bytes, bytes) or len(public_key_bytes) != 32:
            raise ContractViolation("ED25519_PUBLIC_KEY")
        return cls(
            key_id,
            None,
            Ed25519PublicKey.from_public_bytes(public_key_bytes),
        )

    def public_key_bytes(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, message: bytes) -> Mapping[str, str]:
        if self._private_key is None:
            raise ContractViolation("ED25519_PRIVATE_KEY_REQUIRED")
        signature = self._private_key.sign(message)
        return {
            "version": self.VERSION,
            "algorithm": self.ALGORITHM,
            "key_id": self.key_id,
            "signature": base64.b64encode(signature).decode("ascii"),
        }

    def verify(self, message: bytes, signature: Any) -> bool:
        try:
            envelope = dict(signature)
            if set(envelope) != {"version", "algorithm", "key_id", "signature"}:
                return False
            if envelope["version"] != self.VERSION:
                return False
            if envelope["algorithm"] != self.ALGORITHM:
                return False
            if envelope["key_id"] != self.key_id:
                return False
            encoded = envelope["signature"]
            if not isinstance(encoded, str):
                return False
            signature_bytes = base64.b64decode(encoded, validate=True)
            if len(signature_bytes) != 64:
                return False
            self._public_key.verify(signature_bytes, message)
            return True
        except (InvalidSignature, TypeError, ValueError):
            return False


class HmacDetachedSigner:
    """Detached HMAC-SHA256 envelope — the reference default permit signer.

    Same envelope shape as `Ed25519DetachedSigner`, so the wire contract and
    the verification routing are identical across both algorithms. Production
    replaces this with an asymmetric signer whose key custody lives in a
    KMS/HSM; the HMAC default exists so the reference engine runs with no key
    material beyond its signing key.
    """

    VERSION = "1"
    ALGORITHM = "HMAC-SHA256"

    def __init__(self, key: bytes, key_id: str) -> None:
        if not key:
            raise ContractViolation("SIGNING_KEY_REQUIRED")
        if not isinstance(key_id, str) or not key_id or len(key_id) > 200:
            raise ContractViolation("SIGNATURE_KEY_ID")
        self._key = key
        self.key_id = key_id

    def sign(self, message: bytes) -> Mapping[str, str]:
        return {
            "version": self.VERSION,
            "algorithm": self.ALGORITHM,
            "key_id": self.key_id,
            "signature": hmac_hex(self._key, message.decode("ascii")),
        }

    def verify(self, message: bytes, signature: Any) -> bool:
        try:
            envelope = dict(signature)
            if set(envelope) != {"version", "algorithm", "key_id", "signature"}:
                return False
            if envelope["version"] != self.VERSION:
                return False
            if envelope["algorithm"] != self.ALGORITHM:
                return False
            if envelope["key_id"] != self.key_id:
                return False
            encoded = envelope["signature"]
            if not isinstance(encoded, str):
                return False
            return hmac.compare_digest(
                encoded,
                hmac_hex(self._key, message.decode("ascii")),
            )
        except (TypeError, ValueError, UnicodeDecodeError):
            return False


def utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ContractViolation("TIMEZONE_REQUIRED")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    # AttributeError is caught for the same reason TypeError is: a value of the
    # wrong type. An int, None, a list or a mapping has no `.replace`, and the
    # AttributeError that follows is not a ContractViolation and carries no
    # refusal code - so a caller reaches past the published vocabulary on a
    # path the package says is covered by it. Widening the catch keeps the one
    # refusal this function already raises; it adds no second one.
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ContractViolation("INVALID_TIMESTAMP", _short_detail(value)) from exc
    if parsed.tzinfo is None:
        raise ContractViolation("TIMEZONE_REQUIRED", _short_detail(value))
    return parsed.astimezone(timezone.utc)


def load_json(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ContractViolation("JSON_OBJECT_REQUIRED", str(path))
    return value


def _require_scope(actual: str, expected: str) -> None:
    if actual != expected:
        raise ContractViolation("ROLE_SCOPE_MISMATCH", f"expected {expected}")


def _require_mapping(value: Any, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractViolation(code, "object required")
    return value


def _require_exact_keys(
    value: Mapping[str, Any],
    required: set[str],
    code: str,
) -> None:
    actual = set(value)
    missing = required - actual
    extra = actual - required
    if missing:
        raise ContractViolation(code, f"missing fields: {sorted(missing)}")
    if extra:
        raise ContractViolation(code, f"unknown fields: {sorted(extra)}")


# A refused value is quoted back so the caller can see WHICH value was
# refused; it does not need to be quoted back in full. The adapter returns this
# detail as the error message, so without a bound the response length is set by
# the request: an identifier of 900 KiB came back as a message of 900 KiB.
# Every legitimate value the helpers that quote back a refused value accept is
# far shorter than the bound, so a truncated detail only ever appears on a
# value already refused. There are six such call sites across five functions,
# so the bound is stated once here rather than at each of them.
MAX_DETAIL_LENGTH = 128


def _short_detail(value: Any) -> str:
    text = str(value)
    if len(text) <= MAX_DETAIL_LENGTH:
        return text
    return text[:MAX_DETAIL_LENGTH] + "..."


def _require_identifier(value: Any, code: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise ContractViolation(code, _short_detail(value))
    return value


def _require_version(value: Any, code: str) -> str:
    if not isinstance(value, str) or not VERSION_RE.fullmatch(value):
        raise ContractViolation(code, _short_detail(value))
    return value


def _require_sha256(value: Any, code: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ContractViolation(code, _short_detail(value))
    return value.upper()


# The field names the shipped schemas declare as a SHA-256, nested ones
# included. Every other field - and every one of the schemas' `identifier`
# fields in particular - is case-SENSITIVE and must stay that way. The two sets
# do not overlap, and a regression check compares this inventory against the
# schemas themselves, so the two cannot drift apart in silence.
DECLARED_HASH_FIELDS = frozenset(
    {
        "declaration_hash",
        "downstream_receipt_hash",
        "history_summary_hash",
        "latest_receipt_root",
        "ledger_event_hash",
        "ledger_head_hash",
        "payload_hash",
        "permit_hash",
        "predecessor_declaration_hash",
        "profile_hash",
        "receipt_hash",
        "request_hash",
        "sha256",
        "state_anchor_hash",
        "witness_hash",
    }
)


def _normalize_declared_hash_case(value: Any, field: str | None = None) -> Any:
    """Upper-case the SHA-256 fields the schemas DECLARE, however deeply nested.

    This builds the replay identity of a request, and it honours the wire rule
    "a hash is accepted in either case" on the fields where that rule is given.

    It used to normalise by SHAPE - any 64-hex string anywhere - which quietly
    pulled opaque identifiers into the identity whenever a deployment chose
    hex-shaped values for them. Two consequences, both measured: an idempotency
    key differing only in case produced ONE request identity but TWO stored
    entries, so a single logical payment could hold two reservations and be
    executed twice; and two DIFFERENT principals presenting one key replayed
    each other's permit, because the conflict guard compared identities in
    which the requester's case had already been erased. The inventory is not a
    maintenance burden invented here - it is the schemas' own, and it is
    checked against them.
    """
    # The value's real type, and the base `upper`: `isinstance` asks `__class__`, which a
    # caller's object can answer as it likes - measured through the bridge, an object that
    # said `str` in a declared hash field reached `fullmatch`, and one that said `list`
    # was iterated, and each left as a raw TypeError. Asked of every branch, because the
    # class is the question and not the type it lies about.
    kind = type(value)
    if issubclass(kind, str):
        if field in DECLARED_HASH_FIELDS and SHA256_RE.fullmatch(value):
            return str.upper(value)
        return value
    if issubclass(kind, Mapping):
        return {
            key: _normalize_declared_hash_case(item, key)
            for key, item in value.items()
        }
    if issubclass(kind, (list, tuple)):
        # A list inherits the field it arrived under, so a declared hash field
        # holding a list of hashes is still normalised.
        return [_normalize_declared_hash_case(item, field) for item in value]
    return value


def _require_non_negative_int(value: Any, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractViolation(code, _short_detail(value))
    return value


def _unique_ids(values: Any, code: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(values, list) or (not values and not allow_empty):
        raise ContractViolation(code, "non-empty array required")
    result = [_require_identifier(value, code) for value in values]
    if len(result) != len(set(result)):
        raise ContractViolation(code, "duplicate identifier")
    return result


def _bool_map(value: Any, exact_keys: set[str], code: str) -> dict[str, bool]:
    mapping = _require_mapping(value, code)
    if set(mapping) != exact_keys:
        missing = exact_keys - set(mapping)
        extra = set(mapping) - exact_keys
        raise ContractViolation(
            code,
            f"missing={sorted(missing)} extra={sorted(extra)}",
        )
    if any(not isinstance(item, bool) for item in mapping.values()):
        raise ContractViolation(code, "boolean values required")
    return dict(mapping)


def _validate_core_anchor(value: Any, code: str = "CORE_ANCHOR_MISMATCH") -> None:
    anchor = _require_mapping(value, code)
    if dict(anchor) != CORE_ANCHOR:
        raise ContractViolation(code)


def _validate_evidence_ref(value: Any, code: str) -> None:
    item = _require_mapping(value, code)
    _require_exact_keys(item, {"evidence_type", "ref", "sha256"}, code)
    _require_identifier(item["evidence_type"], code)
    if not isinstance(item["ref"], str) or not item["ref"]:
        raise ContractViolation(code, "empty evidence reference")
    _require_sha256(item["sha256"], code)


def _deep_secret_scan(value: Any, path: str = "$", depth: int = 0) -> None:
    if depth > MAX_NESTING_DEPTH:
        raise ContractViolation("NESTING_DEPTH_EXCEEDED", path)
    if isinstance(value, Mapping):
        for key, item in value.items():
            if _is_secret_key_name(key):
                raise ContractViolation("SECRET_FIELD_FORBIDDEN", f"{path}.{key}")
            _deep_secret_scan(item, f"{path}.{key}", depth + 1)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _deep_secret_scan(item, f"{path}[{index}]", depth + 1)


def _find_forbidden_key(
    value: Any,
    forbidden: set[str],
    path: str = "$",
    depth: int = 0,
) -> str | None:
    if depth > MAX_NESTING_DEPTH:
        raise ContractViolation("NESTING_DEPTH_EXCEEDED", path)
    if isinstance(value, Mapping):
        for key, item in value.items():
            item_path = f"{path}.{key}"
            if str(key) in forbidden:
                return item_path
            nested = _find_forbidden_key(item, forbidden, item_path, depth + 1)
            if nested is not None:
                return nested
    elif isinstance(value, list):
        for index, item in enumerate(value):
            nested = _find_forbidden_key(
                item,
                forbidden,
                f"{path}[{index}]",
                depth + 1,
            )
            if nested is not None:
                return nested
    return None


def _deep_forbidden_operator_scan(value: Any, forbidden: set[str], path: str = "$") -> None:
    forbidden_path = _find_forbidden_key(value, forbidden, path)
    if forbidden_path is not None:
        raise ContractViolation("OPERATOR_GATE_DATA_FORBIDDEN", forbidden_path)


def validate_profile(profile: Mapping[str, Any]) -> None:
    required = {
        "schema_version",
        "profile_id",
        "profile_version",
        "created_at",
        "core_anchor",
        "domain",
        "action_alphabet",
        "effect_classes",
        "resource_catalog",
        "controls",
        "evidence_requirements",
        "mapping_witness",
        "roles",
        "failure_posture",
        "change_control",
        "registry_policy",
    }
    _require_exact_keys(profile, required, "PROFILE_FIELDS")
    if profile["schema_version"] != "1.0.0":
        raise ContractViolation("PROFILE_SCHEMA_VERSION")
    _require_identifier(profile["profile_id"], "PROFILE_ID")
    _require_version(profile["profile_version"], "PROFILE_VERSION")
    parse_utc(profile["created_at"])
    _validate_core_anchor(profile["core_anchor"])

    domain = _require_mapping(profile["domain"], "PROFILE_DOMAIN")
    _require_exact_keys(domain, {"domain_name", "description"}, "PROFILE_DOMAIN")
    if any(not isinstance(domain[key], str) or not domain[key] for key in domain):
        raise ContractViolation("PROFILE_DOMAIN")

    effects: dict[str, Mapping[str, Any]] = {}
    if not isinstance(profile["effect_classes"], list) or not profile["effect_classes"]:
        raise ContractViolation("PROFILE_EFFECTS")
    for raw in profile["effect_classes"]:
        effect = _require_mapping(raw, "PROFILE_EFFECT")
        _require_exact_keys(
            effect,
            {"effect_class_id", "description", "mutates_external_state"},
            "PROFILE_EFFECT",
        )
        effect_id = _require_identifier(effect["effect_class_id"], "PROFILE_EFFECT_ID")
        if effect_id in effects:
            raise ContractViolation("DUPLICATE_EFFECT_ID", effect_id)
        if not isinstance(effect["description"], str) or not effect["description"]:
            raise ContractViolation("PROFILE_EFFECT_DESCRIPTION", effect_id)
        if not isinstance(effect["mutates_external_state"], bool):
            raise ContractViolation("PROFILE_EFFECT_MUTATION_FLAG", effect_id)
        effects[effect_id] = effect

    resources: dict[str, Mapping[str, Any]] = {}
    if not isinstance(profile["resource_catalog"], list):
        raise ContractViolation("PROFILE_RESOURCES")
    for raw in profile["resource_catalog"]:
        resource = _require_mapping(raw, "PROFILE_RESOURCE")
        _require_exact_keys(
            resource,
            {"resource_id", "unit", "claim_rule", "reservation_required"},
            "PROFILE_RESOURCE",
        )
        resource_id = _require_identifier(resource["resource_id"], "PROFILE_RESOURCE_ID")
        if resource_id in resources:
            raise ContractViolation("DUPLICATE_RESOURCE_ID", resource_id)
        if not isinstance(resource["claim_rule"], str) or resource["claim_rule"] not in {
            "NON_NEGATIVE",
            "POSITIVE",
            "ZERO",
            "POSITIVE_IF_EFFECTFUL",
        }:
            raise ContractViolation("RESOURCE_CLAIM_RULE", resource_id)
        if not isinstance(resource["reservation_required"], bool):
            raise ContractViolation("RESOURCE_RESERVATION_FLAG", resource_id)
        if not isinstance(resource["unit"], str) or not resource["unit"]:
            raise ContractViolation("RESOURCE_UNIT", resource_id)
        resources[resource_id] = resource

    actions: dict[str, Mapping[str, Any]] = {}
    if not isinstance(profile["action_alphabet"], list) or not profile["action_alphabet"]:
        raise ContractViolation("PROFILE_ACTIONS")
    for raw in profile["action_alphabet"]:
        action = _require_mapping(raw, "PROFILE_ACTION")
        _require_exact_keys(
            action,
            {
                "action_id",
                "description",
                "effect_class_id",
                "structural_cost",
                "required_resource_ids",
            },
            "PROFILE_ACTION",
        )
        action_id = _require_identifier(action["action_id"], "PROFILE_ACTION_ID")
        if action_id in actions:
            raise ContractViolation("DUPLICATE_ACTION_ID", action_id)
        if not isinstance(action["effect_class_id"], str) or action["effect_class_id"] not in effects:
            raise ContractViolation("UNKNOWN_EFFECT_CLASS", action_id)
        required_resources = _unique_ids(
            action["required_resource_ids"],
            "ACTION_RESOURCE_IDS",
            allow_empty=True,
        )
        unknown_resources = set(required_resources) - set(resources)
        if unknown_resources:
            raise ContractViolation(
                "UNKNOWN_RESOURCE_ID",
                f"{action_id}: {sorted(unknown_resources)}",
            )
        _require_non_negative_int(action["structural_cost"], "STRUCTURAL_COST")
        if not isinstance(action["description"], str) or not action["description"]:
            raise ContractViolation("ACTION_DESCRIPTION", action_id)
        actions[action_id] = action

    controls = _require_mapping(profile["controls"], "PROFILE_CONTROLS")
    _require_exact_keys(
        controls,
        {
            "required_prerequisite_ids",
            "hard_block_flag_ids",
            "manual_review_flag_ids",
            "safe_fallback_action_id",
        },
        "PROFILE_CONTROLS",
    )
    prerequisites = set(
        _unique_ids(
            controls["required_prerequisite_ids"],
            "PREREQUISITE_IDS",
            allow_empty=True,
        )
    )
    hard_blocks = set(
        _unique_ids(
            controls["hard_block_flag_ids"],
            "HARD_BLOCK_IDS",
            allow_empty=True,
        )
    )
    manual_flags = set(
        _unique_ids(
            controls["manual_review_flag_ids"],
            "MANUAL_REVIEW_IDS",
            allow_empty=True,
        )
    )
    control_overlap = (
        (prerequisites & hard_blocks)
        | (prerequisites & manual_flags)
        | (hard_blocks & manual_flags)
    )
    if control_overlap:
        raise ContractViolation("CONTROL_CLASS_OVERLAP")
    fallback_id = _require_identifier(
        controls["safe_fallback_action_id"],
        "SAFE_FALLBACK_ID",
    )
    if fallback_id not in actions:
        raise ContractViolation("SAFE_FALLBACK_UNKNOWN")
    fallback = actions[fallback_id]
    fallback_effect = effects[fallback["effect_class_id"]]
    if (
        fallback["structural_cost"] != 0
        or fallback["required_resource_ids"]
        or fallback_effect["mutates_external_state"]
    ):
        raise ContractViolation("SAFE_FALLBACK_NOT_ZERO_EFFECT")

    evidence_covered_actions: set[str] = set()
    requirement_ids: set[str] = set()
    if (
        not isinstance(profile["evidence_requirements"], list)
        or not profile["evidence_requirements"]
    ):
        raise ContractViolation("EVIDENCE_REQUIREMENTS")
    for raw in profile["evidence_requirements"]:
        requirement = _require_mapping(raw, "EVIDENCE_REQUIREMENT")
        _require_exact_keys(
            requirement,
            {
                "requirement_id",
                "applies_to_action_ids",
                "required_evidence_types",
            },
            "EVIDENCE_REQUIREMENT",
        )
        requirement_id = _require_identifier(
            requirement["requirement_id"],
            "EVIDENCE_REQUIREMENT_ID",
        )
        if requirement_id in requirement_ids:
            raise ContractViolation("DUPLICATE_EVIDENCE_REQUIREMENT", requirement_id)
        requirement_ids.add(requirement_id)
        applies = set(
            _unique_ids(
                requirement["applies_to_action_ids"],
                "EVIDENCE_ACTION_IDS",
            )
        )
        if not applies <= set(actions):
            raise ContractViolation("EVIDENCE_UNKNOWN_ACTION")
        _unique_ids(
            requirement["required_evidence_types"],
            "REQUIRED_EVIDENCE_TYPES",
        )
        evidence_covered_actions |= applies
    if evidence_covered_actions != set(actions):
        raise ContractViolation(
            "EVIDENCE_ACTION_COVERAGE",
            f"missing={sorted(set(actions) - evidence_covered_actions)}",
        )

    witness = _require_mapping(profile["mapping_witness"], "MAPPING_WITNESS")
    _require_exact_keys(
        witness,
        {
            "witness_id",
            "method",
            "evidence_refs",
            "covered_action_ids",
            "covered_effect_class_ids",
            "witness_hash",
        },
        "MAPPING_WITNESS",
    )
    _require_identifier(witness["witness_id"], "WITNESS_ID")
    if not isinstance(witness["method"], str) or len(witness["method"]) < 20:
        raise ContractViolation("WITNESS_METHOD")
    if not isinstance(witness["evidence_refs"], list) or not witness["evidence_refs"]:
        raise ContractViolation("WITNESS_EVIDENCE")
    for item in witness["evidence_refs"]:
        _validate_evidence_ref(item, "WITNESS_EVIDENCE")
    if set(_unique_ids(witness["covered_action_ids"], "WITNESS_ACTIONS")) != set(
        actions
    ):
        raise ContractViolation("WITNESS_ACTION_COVERAGE")
    if set(
        _unique_ids(witness["covered_effect_class_ids"], "WITNESS_EFFECTS")
    ) != set(effects):
        raise ContractViolation("WITNESS_EFFECT_COVERAGE")
    witness_body = dict(witness)
    declared_witness_hash = _require_sha256(
        witness_body.pop("witness_hash"),
        "WITNESS_HASH",
    )
    if sha256_hex(witness_body) != declared_witness_hash:
        raise IntegrityViolation("WITNESS_HASH_MISMATCH")

    roles = _require_mapping(profile["roles"], "PROFILE_ROLES")
    _require_exact_keys(
        roles,
        {
            "governance_scope",
            "operator_scope",
            "executor_scope",
            "architect_scope",
            "observer_projection_fields",
            "forbidden_operator_fields",
        },
        "PROFILE_ROLES",
    )
    expected_roles = {
        "governance_scope": ROLE_GOVERNANCE,
        "operator_scope": ROLE_OPERATOR,
        "executor_scope": ROLE_EXECUTOR,
        "architect_scope": ROLE_ARCHITECT,
    }
    if any(roles[key] != expected for key, expected in expected_roles.items()):
        raise ContractViolation("ROLE_SCOPE_DEFINITION")
    projections = set(
        _unique_ids(
            roles["observer_projection_fields"],
            "OBSERVER_PROJECTION_FIELDS",
        )
    )
    if not projections <= {"channel", "message_code", "event_time", "subject_ref"}:
        raise ContractViolation("OBSERVER_PROJECTION_EXPANSION")
    forbidden = roles["forbidden_operator_fields"]
    if not isinstance(forbidden, list) or not forbidden or not all(isinstance(item, str) for item in forbidden):
        raise ContractViolation("FORBIDDEN_OPERATOR_FIELDS")
    required_forbidden = {
        "architect_trace",
        "boundary_geometry",
        "gate_margin",
        "gate_statistics",
        "reason_vector",
        "sub_verdicts",
        "threshold_vector",
    }
    if not required_forbidden <= set(forbidden):
        raise ContractViolation("FORBIDDEN_OPERATOR_COVERAGE")

    failure = _require_mapping(profile["failure_posture"], "FAILURE_POSTURE")
    required_failure = {
        "missing_required_data",
        "ambiguity",
    }
    _require_exact_keys(failure, required_failure, "FAILURE_POSTURE")
    if dict(failure) != {
        "missing_required_data": "REFUSAL",
        "ambiguity": "MANUAL_REVIEW",
    }:
        raise ContractViolation("FIXED_FAILURE_POSTURE")

    change = _require_mapping(profile["change_control"], "CHANGE_CONTROL")
    _require_exact_keys(
        change,
        {"material_fields_require_new_version", "live_gate_override_allowed"},
        "CHANGE_CONTROL",
    )
    if (
        change["material_fields_require_new_version"] is not True
        or change["live_gate_override_allowed"] is not False
    ):
        raise ContractViolation("LIVE_GATE_OVERRIDE")

    registry = _require_mapping(profile["registry_policy"], "REGISTRY_POLICY")
    _require_exact_keys(registry, {"mode", "forbidden_fields"}, "REGISTRY_POLICY")
    if registry["mode"] != "HASH_ONLY":
        raise ContractViolation("REGISTRY_NOT_HASH_ONLY")
    required_registry_forbidden = {
        "raw_intent",
        "raw_evidence",
        "reusable_credentials",
        "gate_geometry",
        "sub_verdicts",
        "reason_vector",
    }
    if (
        not isinstance(registry["forbidden_fields"], list)
        or not all(isinstance(item, str) for item in registry["forbidden_fields"])
        or not required_registry_forbidden <= set(registry["forbidden_fields"])
    ):
        raise ContractViolation("REGISTRY_FORBIDDEN_COVERAGE")

    _deep_secret_scan(profile)


def validate_declaration(
    declaration: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> None:
    required = {
        "schema_version",
        "declaration_id",
        "declaration_version",
        "predecessor_declaration_hash",
        "created_at",
        "effective_from",
        "expires_at",
        "core_anchor",
        "profile_binding",
        "connector",
        "instance_scope",
        "structural_budget",
        "resource_limits",
        "governance",
        "interfaces",
        "mapping_witness_binding",
        "evidence_refs",
    }
    _require_exact_keys(declaration, required, "DECLARATION_FIELDS")
    if declaration["schema_version"] != "1.0.0":
        raise ContractViolation("DECLARATION_SCHEMA_VERSION")
    _require_identifier(declaration["declaration_id"], "DECLARATION_ID")
    _require_version(declaration["declaration_version"], "DECLARATION_VERSION")
    predecessor = declaration["predecessor_declaration_hash"]
    if predecessor is not None:
        _require_sha256(predecessor, "PREDECESSOR_HASH")
    created = parse_utc(declaration["created_at"])
    effective = parse_utc(declaration["effective_from"])
    expires = parse_utc(declaration["expires_at"])
    if not created <= effective < expires:
        raise ContractViolation("DECLARATION_TIME_ORDER")
    _validate_core_anchor(declaration["core_anchor"])
    if declaration["core_anchor"] != profile["core_anchor"]:
        raise ContractViolation("PROFILE_CORE_MISMATCH")

    binding = _require_mapping(declaration["profile_binding"], "PROFILE_BINDING")
    _require_exact_keys(
        binding,
        {"profile_id", "profile_version", "profile_hash"},
        "PROFILE_BINDING",
    )
    if binding["profile_id"] != profile["profile_id"]:
        raise ContractViolation("PROFILE_ID_MISMATCH")
    if binding["profile_version"] != profile["profile_version"]:
        raise ContractViolation("PROFILE_VERSION_MISMATCH")
    if _require_sha256(binding["profile_hash"], "PROFILE_HASH") != sha256_hex(profile):
        raise IntegrityViolation("PROFILE_HASH_MISMATCH")

    connector = _require_mapping(declaration["connector"], "CONNECTOR")
    _require_exact_keys(
        connector,
        {"connector_id", "workload_identity_issuer", "environment_ids"},
        "CONNECTOR",
    )
    _require_identifier(connector["connector_id"], "CONNECTOR_ID")
    _require_identifier(
        connector["workload_identity_issuer"],
        "WORKLOAD_IDENTITY_ISSUER",
    )
    _unique_ids(connector["environment_ids"], "ENVIRONMENT_IDS")

    action_map = {item["action_id"]: item for item in profile["action_alphabet"]}
    effect_ids = {item["effect_class_id"] for item in profile["effect_classes"]}
    resource_ids = {item["resource_id"] for item in profile["resource_catalog"]}

    scope = _require_mapping(declaration["instance_scope"], "INSTANCE_SCOPE")
    _require_exact_keys(
        scope,
        {
            "action_ids",
            "effect_class_ids",
            "target_system_ids",
            "action_target_bindings",
            "scope_constraints",
        },
        "INSTANCE_SCOPE",
    )
    selected_actions = set(_unique_ids(scope["action_ids"], "SCOPE_ACTION_IDS"))
    selected_effects = set(_unique_ids(scope["effect_class_ids"], "SCOPE_EFFECT_IDS"))
    targets = set(_unique_ids(scope["target_system_ids"], "SCOPE_TARGET_IDS"))
    if not selected_actions <= set(action_map):
        raise ContractViolation("SCOPE_UNKNOWN_ACTION")
    action_target_bindings = _require_mapping(
        scope["action_target_bindings"],
        "SCOPE_ACTION_TARGET_BINDINGS",
    )
    if set(action_target_bindings) != selected_actions:
        raise ContractViolation("SCOPE_ACTION_TARGET_COVERAGE")
    for action_id, raw_targets in action_target_bindings.items():
        bound_targets = set(
            _unique_ids(raw_targets, "SCOPE_ACTION_TARGET_IDS")
        )
        if not bound_targets <= targets:
            raise ContractViolation("SCOPE_ACTION_TARGET_RANGE", action_id)
    if not selected_effects <= effect_ids:
        raise ContractViolation("SCOPE_UNKNOWN_EFFECT")
    mapped_effects = {action_map[action]["effect_class_id"] for action in selected_actions}
    if not mapped_effects <= selected_effects:
        raise ContractViolation("SCOPE_EFFECT_OMISSION")
    constraints = _require_mapping(scope["scope_constraints"], "SCOPE_CONSTRAINTS")
    if not constraints:
        raise ContractViolation("EMPTY_SCOPE_CONSTRAINTS")
    for name, values in constraints.items():
        _require_identifier(name, "SCOPE_DIMENSION_ID")
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(value, str) or not value for value in values)
        ):
            raise ContractViolation("SCOPE_CONSTRAINT_VALUES", name)
        if len(values) != len(set(values)):
            raise ContractViolation("SCOPE_CONSTRAINT_VALUES", name)

    structural = _require_mapping(
        declaration["structural_budget"],
        "STRUCTURAL_BUDGET",
    )
    _require_exact_keys(
        structural,
        {"selector_id", "capacity", "unit", "provenance"},
        "STRUCTURAL_BUDGET",
    )
    _require_identifier(structural["selector_id"], "SELECTOR_ID")
    _require_non_negative_int(structural["capacity"], "STRUCTURAL_CAPACITY")
    if not isinstance(structural["unit"], str) or not structural["unit"]:
        raise ContractViolation("STRUCTURAL_UNIT")
    if not isinstance(structural["provenance"], str) or structural["provenance"] not in STRUCTURAL_PROVENANCE_VALUES:
        raise ContractViolation("STRUCTURAL_PROVENANCE")

    if not isinstance(declaration["resource_limits"], list):
        raise ContractViolation("RESOURCE_LIMITS")
    limits: dict[str, Mapping[str, Any]] = {}
    for raw in declaration["resource_limits"]:
        limit = _require_mapping(raw, "RESOURCE_LIMIT")
        _require_exact_keys(
            limit,
            {
                "resource_id",
                "max_per_intent",
                "max_committed_per_window",
                "window_seconds",
            },
            "RESOURCE_LIMIT",
        )
        resource_id = _require_identifier(limit["resource_id"], "RESOURCE_LIMIT_ID")
        if resource_id in limits or resource_id not in resource_ids:
            raise ContractViolation("RESOURCE_LIMIT_ID", resource_id)
        max_per_intent = _require_non_negative_int(
            limit["max_per_intent"],
            "RESOURCE_MAX_PER_INTENT",
        )
        max_window = _require_non_negative_int(
            limit["max_committed_per_window"],
            "RESOURCE_MAX_WINDOW",
        )
        window_seconds = _require_non_negative_int(
            limit["window_seconds"],
            "RESOURCE_WINDOW_SECONDS",
        )
        if window_seconds == 0 or max_per_intent > max_window:
            raise ContractViolation("RESOURCE_LIMIT_ORDER", resource_id)
        limits[resource_id] = limit
    required_resources = {
        resource_id
        for action_id in selected_actions
        for resource_id in action_map[action_id]["required_resource_ids"]
    }
    if not required_resources <= set(limits):
        raise ContractViolation(
            "RESOURCE_LIMIT_COVERAGE",
            f"missing={sorted(required_resources - set(limits))}",
        )

    governance = _require_mapping(declaration["governance"], "GOVERNANCE")
    _require_exact_keys(
        governance,
        {
            "profile_owner_id",
            "declaration_owner_id",
            "approval_owner_id",
            "authority_issuer_id",
            "revision_authority_ids",
            "change_process_ref",
            "no_live_gate_override",
        },
        "GOVERNANCE",
    )
    for key in {
        "profile_owner_id",
        "declaration_owner_id",
        "approval_owner_id",
        "authority_issuer_id",
    }:
        _require_identifier(governance[key], "GOVERNANCE_ID")
    _unique_ids(governance["revision_authority_ids"], "REVISION_AUTHORITIES")
    if (
        not isinstance(governance["change_process_ref"], str)
        or not governance["change_process_ref"]
        or governance["no_live_gate_override"] is not True
    ):
        raise ContractViolation("GOVERNANCE_CHANGE_CONTROL")

    interfaces = _require_mapping(declaration["interfaces"], "INTERFACES")
    _require_exact_keys(
        interfaces,
        {
            "governance_service_id",
            "operator_service_id",
            "executor_service_id",
            "architect_store_id",
            "observer_projection_id",
            "off_limits_system_ids",
        },
        "INTERFACES",
    )
    interface_ids = []
    for key in {
        "governance_service_id",
        "operator_service_id",
        "executor_service_id",
        "architect_store_id",
        "observer_projection_id",
    }:
        interface_ids.append(_require_identifier(interfaces[key], "INTERFACE_ID"))
    if len(interface_ids) != len(set(interface_ids)):
        raise ContractViolation("INTERFACE_ROLE_OVERLAP")
    off_limits = set(
        _unique_ids(
            interfaces["off_limits_system_ids"],
            "OFF_LIMITS_SYSTEMS",
            allow_empty=True,
        )
    )
    if targets & off_limits:
        raise ContractViolation("TARGET_OFF_LIMITS_OVERLAP")

    witness_binding = _require_mapping(
        declaration["mapping_witness_binding"],
        "WITNESS_BINDING",
    )
    _require_exact_keys(
        witness_binding,
        {"witness_id", "witness_hash"},
        "WITNESS_BINDING",
    )
    if witness_binding["witness_id"] != profile["mapping_witness"]["witness_id"]:
        raise ContractViolation("WITNESS_ID_MISMATCH")
    if _require_sha256(
        witness_binding["witness_hash"],
        "WITNESS_HASH",
    ) != _require_sha256(
        profile["mapping_witness"]["witness_hash"],
        "PROFILE_WITNESS_HASH",
    ):
        raise IntegrityViolation("WITNESS_BINDING_MISMATCH")

    if not isinstance(declaration["evidence_refs"], list) or not declaration[
        "evidence_refs"
    ]:
        raise ContractViolation("DECLARATION_EVIDENCE")
    for item in declaration["evidence_refs"]:
        _validate_evidence_ref(item, "DECLARATION_EVIDENCE")

    _deep_secret_scan(declaration)


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FixedClock:
    def __init__(self, instant: datetime) -> None:
        if instant.tzinfo is None:
            raise ContractViolation("TIMEZONE_REQUIRED")
        self._instant = instant.astimezone(timezone.utc)

    def now(self) -> datetime:
        return self._instant

    def advance(self, **delta: int) -> None:
        self._instant += timedelta(**delta)


PUBLIC_MESSAGE_CODE_BY_DISPOSITION: dict[str, str] = {
    "ALLOW": "EXECUTION_AUTHORIZED",
    "REFUSAL": "EXECUTION_DENIED",
    "MANUAL_REVIEW": "HUMAN_REVIEW_REQUIRED",
}

PUBLIC_MESSAGE_CODES = frozenset(PUBLIC_MESSAGE_CODE_BY_DISPOSITION.values())

# Closed architect-facing decision vocabulary. The failure-surface ratchet
# extracts the live emitters independently and requires exact equality with
# this declaration, so adding a gate outcome cannot silently widen the public
# decision language.
ARCHITECT_DECISION_CODES = frozenset(
    {
        "ACTION_OUT_OF_SCOPE",
        "ACTION_TARGET_MISMATCH",
        "ALLOW_ISSUED",
        "AMBIGUOUS_INTENT",
        "AUTHORITY_EXPIRED",
        "AUTHORITY_NOT_YET_VALID",
        "AUTHORITY_REVOKED",
        "AUTHORITY_SUBJECT_MISMATCH",
        "AUTHORITY_UNKNOWN",
        "BINDING_MISMATCH",
        "CONNECTOR_MISMATCH",
        "EFFECTFUL_RESOURCE_MUST_BE_POSITIVE",
        "EFFECT_GATE_PASS",
        "EFFECT_OUT_OF_SCOPE",
        "EVIDENCE_INVALID",
        "EVIDENCE_MISSING",
        "HARD_BLOCK",
        "MANUAL_REVIEW_REQUIRED",
        "PREREQUISITE_FALSE",
        "RESOURCE_CLAIM_SET",
        "RESOURCE_MUST_BE_POSITIVE",
        "RESOURCE_MUST_BE_ZERO",
        "RESOURCE_PER_INTENT_LIMIT",
        "RESOURCE_WINDOW_LIMIT",
        "SCOPE_DIMENSION_MISMATCH",
        "SCOPE_VALUE_OUT_OF_RANGE",
        "STRUCTURAL_BUDGET_EXHAUSTED",
        "TARGET_OUT_OF_SCOPE",
    }
)


class AppendOnlyLedger:
    """In-memory signed hash chain used only as a reference behavior."""

    def __init__(
        self,
        signing_key: bytes,
        clock: SystemClock | FixedClock,
        event_signer: EventSigner | None = None,
    ) -> None:
        if not signing_key:
            raise ContractViolation("SIGNING_KEY_REQUIRED")
        if event_signer is None:
            # One signature contract for the whole package: the default event
            # signer emits the same versioned detached envelope as the permit
            # surface, so independent chain verifiers see a single shape.
            event_signer = HmacDetachedSigner(signing_key, "ledger-hmac")
        if not callable(getattr(event_signer, "sign", None)) or not callable(
            getattr(event_signer, "verify", None)
        ):
            raise ContractViolation("EVENT_SIGNER_INVALID")
        self._key = signing_key
        self._clock = clock
        self._event_signer = event_signer
        self._events: list[dict[str, Any]] = []

    def append(
        self,
        event_type: str,
        actor_role: str,
        subject_ref: str,
        payload: Mapping[str, Any],
    ) -> str:
        _require_identifier(event_type, "EVENT_TYPE")
        _require_identifier(subject_ref, "EVENT_SUBJECT")
        _deep_secret_scan(payload)
        previous = self._events[-1]["event_hash"] if self._events else "0" * 64
        body = {
            "event_index": len(self._events),
            "event_time": utc_text(self._clock.now()),
            "event_type": event_type,
            "actor_role": actor_role,
            "subject_ref": subject_ref,
            "payload": copy.deepcopy(dict(payload)),
            "previous_event_hash": previous,
        }
        event_hash = sha256_hex(body)
        signature = dict(self._event_signer.sign(event_hash.encode("ascii")))
        event = {
            **body,
            "event_hash": event_hash,
            "signature": signature,
        }
        self._events.append(event)
        return event_hash

    def verify(self) -> bool:
        """Report whether the recorded chain still holds.

        Returns False for a chain that does not verify: a broken index, a
        broken back-link, a hash that does not match, a malformed signature
        envelope, or a signature that fails.

        Raises ContractViolation when a stored event carries a value that
        cannot be canonicalised at all. That is not a verdict about the chain
        either: the bytes to hash cannot be formed. Each form leaves under its
        own code, measured: a non-finite number as CANONICAL_JSON_INVALID, a
        key that is not text as JSON_OBJECT_KEY_TYPE, a structure past
        MAX_NESTING_DEPTH as NESTING_DEPTH_EXCEEDED - `canonical_json` catches
        what the encoder raises and re-raises a ContractViolation untouched,
        so the walk's own codes reach the caller. This paragraph named all
        three as CANONICAL_JSON_INVALID until they were run. The hostile-value
        sweep drives them beside the integrity refusal for exactly that reason.

        Raises IntegrityViolation("EVENT_SIGNER_REQUIRED") for the cases that
        are not an answer about the chain but the absence of any means to
        answer: a persisted signed chain read back under a signer that does
        not declare the envelope's algorithm and key_id. The two channels are
        deliberate and distinct - "the chain does not verify" and "nothing
        here can verify it" are different facts, and collapsing them would
        lose the second. Callers that read the bool must therefore let this
        exception through.

        The separation runs on DECLARED signer identity, and that is as far as
        it reaches. A signer presenting the envelope's key_id with different
        key material is indistinguishable from a forger by construction, so it
        stays a chain verdict; a signer that does not declare both cannot be
        compared at all. The signature envelope is also outside the event
        hash, so a writer who can reach the stored chain can choose which of
        the two labels an operator sees. Both remain the same fail-closed
        refusal.
        """
        previous = "0" * 64
        for index, event in enumerate(self._events):
            if event.get("event_index") != index:
                return False
            if event.get("previous_event_hash") != previous:
                return False
            # Not copied. The copy that stood here had no reader - `sha256_hex` walks
            # this mapping through `_plain_json`, which builds fresh containers and
            # mutates nothing - and it ran BEFORE the walk, so it was the first thing a
            # deep stored value met: measured, a payload 600 levels deep left verify()
            # and the public read as a bare RecursionError, while the walk refuses at 65
            # by its own code. A copy taken ahead of a guard is a guard's worth of depth
            # spent before the guard.
            body = {
                key: value
                for key, value in event.items()
                if key not in {"event_hash", "signature"}
            }
            expected_hash = sha256_hex(body)
            # A stored hash that is not ASCII text is a hash that does not
            # match; compare_digest raises on it rather than answering, so the
            # type is settled first and the verdict stays False.
            stored_hash = event.get("event_hash")
            if (
                not isinstance(stored_hash, str)
                or not stored_hash.isascii()
                or not hmac.compare_digest(stored_hash, expected_hash)
            ):
                return False
            signature = event.get("signature")
            if (
                not isinstance(signature, Mapping)
                or set(signature) != SIGNATURE_ENVELOPE_FIELDS
            ):
                return False
            declared_algorithm = getattr(self._event_signer, "ALGORITHM", None)
            declared_key_id = getattr(self._event_signer, "key_id", None)
            if (
                declared_algorithm is not None
                and declared_key_id is not None
                and (
                    signature.get("algorithm") != declared_algorithm
                    or signature.get("key_id") != declared_key_id
                )
            ):
                # The configured signer cannot speak for this envelope at all:
                # a different algorithm, or the same algorithm under a
                # different declared key. Signer configuration is deliberately
                # not stored, so both are the absence of any means to answer
                # rather than an answer about the chain, and both fail closed
                # and loudly. Recognising the signer by what it DECLARES and
                # not by its type is what lets the second case be seen: a
                # rotated key read back as a forged chain is the report this
                # separation exists to prevent.
                #
                # The EventSigner protocol requires only sign and verify, so a
                # signer that does not declare BOTH cannot be compared this
                # way; for it the two facts collapse back into False. That is
                # a named limit of this check, not an oversight.
                raise IntegrityViolation("EVENT_SIGNER_REQUIRED")
            if not self._event_signer.verify(
                expected_hash.encode("ascii"),
                signature,
            ):
                return False
            previous = expected_hash
        return True

    def head(self) -> dict[str, Any]:
        return {
            "event_count": len(self._events),
            "head_hash": self._events[-1]["event_hash"]
            if self._events
            else "0" * 64,
        }

    def events_copy(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._events)

    def _restore_events(self, events: list[dict[str, Any]]) -> None:
        self._events = events


def refuse_stored_artefact(connection: "sqlite3.Connection", statements):
    """Run statements on a connection, naming a stored artefact rather than escaping.

    One home, because the guard was one statement wide and the class is not. The header
    read was guarded and described as running "before anything else on this connection" -
    and the statement that followed it on that same connection, the create, was not.
    Measured: a database whose first hundred bytes are a valid header and whose schema page
    is overwritten passes `PRAGMA schema_version` and then raises
    `sqlite3.DatabaseError: database disk image is malformed` out of the create, past both
    stores, which is the class both stores exist to close.

    Returns None when every statement ran, and the artefact detail paired with its driver
    error when one of them says the file is not our store. The RAISE stays with the caller,
    and that is a decision rather than a style: the refusal vocabulary belongs to the
    caller's module, and a raise whose exception class and code arrive as arguments is a
    raise no static reader of this tree can classify. The first form of this helper took
    both as parameters and raised here; it left one unclassified emission point, and off
    that single line came the static ratchet check, the disjoint-worlds control, and four
    ratchet plants that run the suite in a copy before planting and require it green.

    The connection is closed on the path this function answers - a `sqlite3.DatabaseError`,
    whether it becomes a refusal or is re-raised. Why here, given that both callers close
    their own: because this function RETURNS on the refusal path rather than raising, and
    a returned connection is one no statement in this function still owns. On the re-raise
    path that reason does not apply - the exception reaches a caller that closes its own -
    and the close runs there only because it stands before the branch deciding between the
    two. The reason
    given before was that "a caller that receives a refusal is not going to close it",
    and that was false of both callers there are - the bridge wraps its connection in
    `closing(...)`, the state store in a `try/finally` - so on the refusal path the
    connection is closed twice, which sqlite3 permits. Twice and known beats once and
    assumed. NOT on every path, which is what this said and was not: anything that is not a
    `sqlite3.DatabaseError` leaves through here with the connection open, because that is
    the only class the handler catches. `MemoryError`, the shape `SQLITE_NOMEM` takes, is
    the live example; a `TypeError` from a statement that is not a string is another, and
    unreachable while both callers pass literals. Said as a class with an example rather
    than as the example alone, which read as a complete list. Both callers close their own -
    one through `closing(...)`, one through a `finally` - so the code is right and only the
    claim was too wide; widening the code instead would duplicate what the callers already
    guarantee. And on success - `None`, every statement run - the connection is left open
    on purpose, because it is the caller's: the bridge commits the create on it, and the
    state store closes it in its `finally`.
    """
    for statement in statements:
        try:
            connection.execute(statement)
        except sqlite3.DatabaseError as exc:
            unreadable = refuse_unreadable_database(exc)
            connection.close()
            if unreadable is None:
                raise
            return unreadable, exc
    return None


def refuse_unreadable_database(exc: "sqlite3.DatabaseError") -> str | None:
    """Say whether a driver error means "this is not our store", or is transient.

    One home, because both stores ask it and the distinction is not obvious. The statements
    that read a stored table's columns are themselves statements: a path holding bytes that
    are not a SQLite database makes the first of them raise `sqlite3.DatabaseError`, before
    any guard sees a value, and that is the class both stores exist to close - a stored
    artefact leaving the refusal vocabulary - one layer above the values.

    The transient class is named POSITIVELY, by the driver's own error names, and not as
    "every OperationalError". That was this function's first form and it left a hole: a
    database whose stored table is a virtual table naming a module this build lacks makes
    `PRAGMA table_xinfo` raise `OperationalError: no such module`, which is not transient at
    all - it is a permanent property of that file against this build - and re-raising it
    put a raw driver error outside the refusal vocabulary, one layer above the values,
    which is the class both stores exist to close. Measured on this build (sqlite 3.45.3):
    a locked database is SQLITE_BUSY, an unopenable file is SQLITE_CANTOPEN, a path of
    foreign bytes is SQLITE_NOTADB, and `no such module` is plain SQLITE_ERROR.

    Which side is which is the second decision on this point. Naming the transient side
    positively was right and did not make its COMPLEMENT the artefact side - which is what
    the first form assumed. Measured then over eleven error names: five that
    belong to neither, `SQLITE_IOERR`, `SQLITE_NOMEM`, `SQLITE_FULL`, `SQLITE_INTERRUPT`
    and `SQLITE_PROTOCOL`, were being refused as `unreadable: <name>` under codes whose
    only declared meaning is that the table's columns are not ours. A full disk was
    published as an integrity verdict about a database that is correct, and the caller
    lost the exception type that would have told it to retry.

    That count is the measurement of the day, not the rows as they stand: the suite now
    drives each code by name on the side it belongs to, with the class the driver raises
    for each, and two shapes beside them, an extended code and an error the driver did not
    code at all. `SQLITE_NOMEM` left the rows in the same edit:
    the driver answers that code with MemoryError, which no `except sqlite3.DatabaseError`
    catches, so this function never sees it and a row about it asks a shape that never
    arrives.

    So an error is a verdict about the stored artefact only when it SAYS so: the file is
    not a database, its schema is malformed, or a statement against that schema failed -
    `no such module` on a virtual table is the live example. The function therefore holds
    ONE list, the artefact codes, and every code not in it keeps its own type, because a
    fault we cannot attribute to the artefact is not a statement about the artefact. The
    transient codes are named where they are pinned - in the bridge suite's by-name rows,
    which drive both sides with the class the driver raises for each.

    SQLITE_SCHEMA stood in that list without a measurement on either side - its row took
    the class from the module's documented mapping and could not provoke the code. By the
    criterion above it does not
    belong: it says the schema changed while a statement ran - after the driver, which
    prepares with `prepare_v2`, has already re-prepared the statement and tried again -
    which is a concurrent change, not a property of whose table this is. It keeps its type
    now, beside SQLITE_BUSY.

    Keyed on the driver's BASE code, not on its name. The driver reports EXTENDED result
    codes - measured, a primary-key violation arrives as SQLITE_CONSTRAINT_PRIMARYKEY,
    1555 - and SQLite defines an extended code as the base code with high bits set, so
    the low byte is the base. A table keyed by base names would have let an extended
    artefact code keep its type: SQLITE_CORRUPT_INDEX is 779, whose low byte is
    SQLITE_CORRUPT. The detail keeps the base wording, because the base is what the
    refusal is about.

    But the fold is not general, and applying it to every base was this function's next
    hole. Under SQLITE_CORRUPT the extensions all say corruption - _VTAB, _SEQUENCE,
    _INDEX - so the low byte answers for them. Under SQLITE_ERROR they say something
    else entirely: SQLITE_ERROR_RETRY, 513, is an instruction to try the statement again,
    and SQLITE_ERROR_SNAPSHOT, 769, is about a WAL snapshot that has moved on. Both mask
    to 1 and were published as "unreadable: SQLITE_ERROR" - a PERMANENT verdict about the
    file, which is the exact defect this function's own account describes one paragraph
    above: a transient condition named as permanent takes from the caller the exception
    type that would have told it to retry. Measured on this build, all three names exist
    and all three mask to 1. So the fold is per-base and named: only the families whose
    extensions carry the base's meaning are folded, and the rest must match exactly.

    An error with NO code gets no verdict and keeps its type. This used to fall back to a
    type test - every DatabaseError that was not an OperationalError read as "not a
    database" - on the ground that builds before 3.11 lack the attribute. Those builds are
    not supported, and on the ones that are the fallback was reached only by errors the
    MODULE raises itself, with no SQLite code behind them: measured on 3.12.9, a statement
    on a closed connection and a wrong binding count are ProgrammingError with no code, and
    both were published as a verdict that the stored file is not a database. A fault in
    the caller is not a statement about the file. Named limit: on a build before 3.11 a
    driver error carries no code either, so there a corrupt file keeps its type too; this
    function does not guess from message text.

    Returns the detail to refuse with, or None to re-raise.
    """
    artefact = {sqlite3.SQLITE_NOTADB: "not a database",
                sqlite3.SQLITE_CORRUPT: "malformed database",
                sqlite3.SQLITE_ERROR: "unreadable: SQLITE_ERROR",
                sqlite3.SQLITE_FORMAT: "unreadable: SQLITE_FORMAT",
                # One extension of SQLITE_ERROR named on its own, because the family is
                # not foldable and this member is not transient: a stored table declared
                # with a collation this build does not register raises
                # SQLITE_ERROR_MISSING_COLLSEQ, and no retry makes the collation appear.
                # Measured: a table created with a custom collation and reopened on a
                # connection without it answers `no such collation sequence` as an
                # OperationalError carrying this extended code, and the classifier said
                # None, so the store re-raised a raw driver error out of a public call.
                # Its two siblings stay off this side and keep their own type: RETRY is an
                # instruction to try again, SNAPSHOT is about a moved WAL snapshot.
                sqlite3.SQLITE_ERROR_MISSING_COLLSEQ: "unreadable: missing collation"}
    # The families whose extended codes mean what their base means. Only SQLITE_CORRUPT
    # qualifies on this build: its three extensions all report corruption. A base absent
    # from this set answers for itself alone, so an extension of it keeps its own type
    # rather than inheriting a verdict nobody measured.
    foldable = frozenset({sqlite3.SQLITE_CORRUPT})
    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, bool) or not isinstance(code, int):
        return None
    if code in artefact:
        return artefact[code]
    base = code & 0xFF
    if base in foldable:
        return artefact[base]
    return None


def _decode_stored_text(raw: bytes) -> str:
    """Decode a stored TEXT column without failing inside the driver.

    The default factory raises on bytes that are not valid UTF-8, and it raises at the
    fetch - before the type and encoding guards that every stored value is supposed to
    meet, and as a driver error that no refusal code describes. With surrogateescape the
    undecodable bytes survive as lone surrogates and the value reaches those guards.

    What refuses it there is each store's own rule, not one rule: the state store by the
    ASCII check its three hashed and MAC'd columns already carry, the bridge by a round
    trip through `encode`. The round trip is chosen because its subject is the write-back:
    it refuses exactly what cannot be stored again, which is where the value would die.
    Measured, and NOT a live difference today: every value the bridge itself writes into
    `last_error` is a code or an exception's type name, both ASCII, so nothing in that
    module tells the two predicates apart, and swapping one for the other leaves the whole
    bridge suite green. The round trip stays right if a future writer stores text.

    Nothing else changes: bytes that decode as UTF-8 decode identically here.
    """
    return raw.decode("utf-8", "surrogateescape")


def columns_detail(declared: Iterable[str], present: Iterable[str]) -> str:
    """Say what is wrong with a stored table's columns, or nothing when they agree.

    One home for the whole comparison, not only for the sentence. Both stores refuse the
    same class, and while each took its own set differences the two could drift - one
    sorted its names, the other kept declaration order, so the same fault read differently
    depending on which store saw it - and both told the same untruth about a table that is
    not there: `PRAGMA table_xinfo`, the read both stores make, answers an absent table with
    no rows at all, as `table_info` does, so every
    declared name fell into "missing" and the caller was handed a sentence describing a
    malformed table where there was none. An empty `present` is therefore its own answer.
    """
    declared = set(declared)
    present = set(present)
    # `declared and` matters: with nothing declared and nothing present the two sets AGREE,
    # and the answer is the empty sentence the equality earns. Without that clause the
    # absent-table answer would be a claim about a database made from the caller's own
    # empty argument - both callers pass a module constant, so it is unreachable today,
    # and the fix is a narrower branch rather than a new refusal nobody can classify.
    if declared and not present:
        return "table absent"
    missing = declared - present
    undeclared = present - declared
    parts = []
    if missing:
        parts.append("missing " + ",".join(sorted(missing)))
    if undeclared:
        parts.append("undeclared " + ",".join(sorted(undeclared)))
    return "; ".join(parts)


class SQLiteStateStore:
    """Single-node durable state for one or more declaration hashes."""

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS ledger_state (
            declaration_hash TEXT PRIMARY KEY,
            profile_hash TEXT NOT NULL,
            state_json TEXT NOT NULL,
            state_hash TEXT NOT NULL,
            state_mac TEXT NOT NULL
        ) WITHOUT ROWID
    """

    def __init__(self, path: str | Path) -> None:
        if isinstance(path, bool) or not isinstance(path, (str, Path)):
            raise ContractViolation("STATE_PATH")
        if str(path) == ":memory:":
            raise ContractViolation("STATE_PATH_NOT_DURABLE")
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = self._connect(require_table=False)
        try:
            # Under the same classifier as the prologue above it: these are statements
            # that touch the file, and a driver error from one of them belongs to the
            # refusal vocabulary rather than to the caller.
            #
            # SHADOWED here, and said so rather than implied: on THIS store the prologue
            # runs four statements under one guard, and both stored artefacts measured
            # reach it first - a path of foreign bytes at `PRAGMA schema_version`, and a
            # valid header over a corrupt schema page at `PRAGMA synchronous=FULL`. What
            # would reach this guard is a file that survives all four and fails on the
            # journal mode or on the create. None is exhibited, so no test witnesses this
            # site, and the two cases in the suite that look like its witnesses are
            # witnesses of the prologue.
            #
            # The bridge is the opposite case, which is where the class was found: its
            # prologue guards `PRAGMA schema_version` alone, so the create was the
            # statement that escaped, and a file of exactly this shape left it as a raw
            # driver error. Same shape, different reach - which is the reason this guard
            # is kept and disclosed rather than removed as unreachable.
            # Through the translator, like the row statements and the commit. The
            # helper asks `refuse_unreadable_database` about a driver error, and that
            # function answers None for the CONSTRAINT class on purpose - a constraint
            # failure is not "this file is not our store" - so an `IntegrityError` from
            # the create WOULD leave raw, past this module's vocabulary; none has been
            # seen to. Measured, no statement these constructors issue can produce one
            # today: a
            # `CREATE TABLE IF NOT EXISTS` over a foreign table raises nothing, and DDL
            # reaches that class only through a UNIQUE INDEX over stored duplicates,
            # which neither schema builds: this table's key is the table itself (WITHOUT
            # ROWID), and the bridge's primary-key index is built with its table, over no
            # rows - measured. The guard is one `with`, and the day a schema
            # grows such an index it is already here - with one caveat for that day: the
            # translator's detail, "constraint not declared by this store", is worded for a
            # ROW write, and stored rows breaking a new unique index would need their own.
            with self._translate():
                refusal = refuse_stored_artefact(
                    connection, ("PRAGMA journal_mode=WAL", self._SCHEMA))
            if refusal is not None:
                detail, cause = refusal
                raise IntegrityViolation("STATE_COLUMNS", detail) from cause
        finally:
            connection.close()
        # The connection above skips the column guard, because the table may not exist yet,
        # and the schema statement does nothing when a foreign table is already there. This
        # checked open refuses such a table where the store is opened, not at the first read.
        self._connect().close()

    _COLUMNS = ("declaration_hash", "profile_hash", "state_json", "state_hash", "state_mac")
    # The column the create statement makes the key of this WITHOUT ROWID table.
    _KEY = frozenset({"declaration_hash"})

    def _connect(self, *, require_table: bool = True) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.path),
            timeout=30.0,
            isolation_level=None,
        )
        # These are the first statements to touch the file, and a path holding bytes that
        # are not a SQLite database makes one of them raise before any guard runs - the
        # same class as a stored value leaving the vocabulary, one layer up. The helper
        # decides which driver errors mean "not our store" and which are transient.
        try:
            # `schema_version` first and deliberately: it reads the database header, while
            # a connection-level setting such as `busy_timeout` touches no file at all. The
            # guard must not depend on which of the settings below happens to reach disk.
            connection.execute("PRAGMA schema_version")
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA trusted_schema=OFF")
        except sqlite3.DatabaseError as exc:
            detail = refuse_unreadable_database(exc)
            connection.close()
            if detail is None:
                raise
            raise IntegrityViolation("STATE_COLUMNS", detail) from exc
        # A TEXT column holding bytes that are not valid UTF-8 fails inside the
        # driver at the fetch, as sqlite3.OperationalError, before any guard here
        # sees the value when the engine is already serving - a stored form no declared
        # code describes, which the wire then answers as an internal failure. Decoding
        # with surrogateescape
        # hands the guards a string instead: it is not ASCII, so the column's own
        # refusal names it. Valid values decode exactly as before.
        connection.text_factory = _decode_stored_text
        if require_table:
            # The store opens a table it did not create when one is already
            # there, so the table's columns are checked before any statement
            # names one: a missing column raised sqlite3.OperationalError past
            # the refusal vocabulary instead of an integrity code.
            # Both directions. A table with every declared column plus others is not
            # this store's table, and the store says so where it opens it. The reason is
            # not the outbox's: that decoder builds its record from `SELECT *`, so an
            # undeclared column leaves through a public read; here the read names its four
            # columns and an extra one is never returned. What the check buys here is that
            # a foreign table is refused as such instead of being written into.
            # Guarded for the same reason as the statements above: a database whose header
            # passed but whose schema page is unreadable fails HERE rather than there.
            try:
                columns = list(connection.execute("PRAGMA table_xinfo(ledger_state)"))
            except sqlite3.DatabaseError as exc:
                detail = refuse_unreadable_database(exc)
                connection.close()
                if detail is None:
                    raise
                raise IntegrityViolation("STATE_COLUMNS", detail) from exc
            detail = columns_detail(self._COLUMNS, {row[1] for row in columns})
            if detail:
                connection.close()
                raise IntegrityViolation("STATE_COLUMNS", detail)
            # And its KEY, which the names alone did not ask for. A create does nothing
            # when a foreign table of the name is already there and does not retrofit a
            # constraint, so a table with these five columns and no primary key passed -
            # and this one is a WITHOUT ROWID table whose key IS the table. The rows just
            # read report it: `table_xinfo` gives each column's position in the key, zero
            # outside it. Measured on the outbox, whose key is the same question one
            # module over: without it two rows sharing the identifiers lived in the table
            # and the reader answered with whichever came first.
            key = {row[1] for row in columns if row[5]}
            if key != self._KEY:
                connection.close()
                raise IntegrityViolation(
                    "STATE_COLUMNS",
                    "primary key %s" % (", ".join(sorted(key)) if key else "absent"))
        return connection

    @contextmanager
    def _translate(self):
        """Translate a driver error into this store's vocabulary, opening nothing.

        Named `_rows` until the bridge grew a `_rows` of its own that OPENS the outbox and
        yields a connection, while its translation-only half is called `_translate`. One
        name then carried two contracts in two files that send the reader from one to the
        other, so this one takes the name that says what it does. It guards the statements
        that read and write ROWS, as the prologue guards its own.

        The prologue and the create are guarded where they stand; these are the rest.
        Measured: a corrupt data page under an intact schema page passes the header read
        and the column read, and the row read then left `database disk image is malformed`
        out of a public call on a re-opened engine.

        A constraint failure is answered separately and deliberately. This store writes all
        five of its columns and upserts on its own key, so it cannot violate its own
        declaration; a constraint that fires is one the stored table carries and this store
        did not declare. Measured: a table with these five names and
        `CHECK (length(state_json) < 10)` is accepted by the name guard - which compares
        names by design, so the hostile-value sweep can build a typeless table - and the
        first write then left a raw IntegrityError.
        """
        try:
            yield
        except sqlite3.IntegrityError as exc:
            raise IntegrityViolation(
                "STATE_COLUMNS",
                "constraint not declared by this store",
            ) from exc
        except sqlite3.DatabaseError as exc:
            unreadable = refuse_unreadable_database(exc)
            if unreadable is None:
                raise
            raise IntegrityViolation("STATE_COLUMNS", unreadable) from exc

    def begin_immediate(self) -> sqlite3.Connection:
        connection = self._connect()
        try:
            with self._translate():
                connection.execute("BEGIN IMMEDIATE")
        except BaseException:
            connection.close()
            raise
        return connection

    @staticmethod
    def _encode(state: Mapping[str, Any]) -> str:
        return json.dumps(
            state,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )

    def load(
        self,
        connection: sqlite3.Connection,
        declaration_hash: str,
        profile_hash: str,
        signing_key: bytes,
    ) -> dict[str, Any] | None:
        # The fetch is inside the guard, not only the execute: a corrupt page can raise
        # when the row is read as well as when the statement is prepared.
        with self._translate():
            row = connection.execute(
                "SELECT profile_hash, state_json, state_hash, state_mac "
                "FROM ledger_state WHERE declaration_hash = ?",
                (declaration_hash,),
            ).fetchone()
        if row is None:
            return None
        stored_profile_hash, state_json, state_hash, state_mac = row
        if stored_profile_hash != profile_hash:
            raise IntegrityViolation("STATE_PROFILE_MISMATCH")
        # The writer stores ASCII text in all three columns, so a column that
        # is not ASCII text was not written by it. The type and encoding are
        # checked BEFORE hashing and comparing: `.encode("ascii")` raises
        # UnicodeEncodeError on non-ASCII text and AttributeError on bytes, and
        # `hmac.compare_digest` raises TypeError on non-ASCII text or bytes, so
        # a tampered row left the refusal vocabulary instead of answering with
        # the code it names.
        if not (
            isinstance(state_json, str)
            and state_json.isascii()
            and isinstance(state_hash, str)
            and state_hash.isascii()
        ):
            raise IntegrityViolation("STATE_HASH_FAILURE")
        expected_hash = hashlib.sha256(state_json.encode("ascii")).hexdigest().upper()
        if not hmac.compare_digest(state_hash, expected_hash):
            raise IntegrityViolation("STATE_HASH_FAILURE")
        # The MAC's subject is the digest recomputed from the stored text, not the stored
        # hash column. Today the two are the SAME STRING here - control reaches this line
        # only after the comparison above succeeded - so no stored row can tell the forms
        # apart, and this is defence in depth rather than a live distinction: the binding
        # survives a future removal or reordering of that comparison, which is the only
        # way the two subjects could ever differ.
        expected_mac = hmac_hex(signing_key, expected_hash)
        if not (
            isinstance(state_mac, str) and state_mac.isascii()
        ) or not hmac.compare_digest(state_mac, expected_mac):
            raise IntegrityViolation("STATE_MAC_FAILURE")
        value = json.loads(state_json)
        if not isinstance(value, dict):
            raise IntegrityViolation("STATE_SHAPE")
        return value

    def read(
        self,
        declaration_hash: str,
        profile_hash: str,
        signing_key: bytes,
    ) -> dict[str, Any] | None:
        connection = self._connect()
        try:
            with self._translate():
                connection.execute("BEGIN")
            value = self.load(
                connection,
                declaration_hash,
                profile_hash,
                signing_key,
            )
            with self._translate():
                connection.commit()
            return value
        except BaseException:
            if connection.in_transaction:
                with self._translate():
                    connection.rollback()
            raise
        finally:
            connection.close()

    def save(
        self,
        connection: sqlite3.Connection,
        declaration_hash: str,
        profile_hash: str,
        signing_key: bytes,
        state: Mapping[str, Any],
    ) -> None:
        state_json = self._encode(state)
        state_hash = hashlib.sha256(state_json.encode("ascii")).hexdigest().upper()
        state_mac = hmac_hex(signing_key, state_hash)
        with self._translate():
            connection.execute(
                "INSERT INTO ledger_state "
                "(declaration_hash, profile_hash, state_json, state_hash, state_mac) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(declaration_hash) DO UPDATE SET "
                "profile_hash = excluded.profile_hash, "
                "state_json = excluded.state_json, "
                "state_hash = excluded.state_hash, "
                "state_mac = excluded.state_mac",
                (
                    declaration_hash,
                    profile_hash,
                    state_json,
                    state_hash,
                    state_mac,
                ),
            )


@dataclass
class PermitRecord:
    body: dict[str, Any]
    permit_hash: str
    # Versioned detached envelope {version, algorithm, key_id, signature};
    # verification routes by key_id through the engine's verifier registry.
    signature: dict[str, str]
    consumed: bool = False
    reservation_active: bool = True
    invalidated_reason: str | None = None


# Exact field set of a detached signature envelope (permit and ledger-event).
SIGNATURE_ENVELOPE_FIELDS = frozenset(
    {"version", "algorithm", "key_id", "signature"}
)


MAX_PERMIT_TTL_SECONDS = 900


_KNOWN_ROLES = frozenset({ROLE_GOVERNANCE, ROLE_OPERATOR, ROLE_EXECUTOR, ROLE_ARCHITECT})


def _scope_reader(method: Any) -> tuple[Any, Any]:
    """Resolve, once at decoration time, how to read `actor_scope` off a call.

    Reading `kwargs["actor_scope"]` would be wrong: the argument is also
    passed positionally, so binding the real signature is the only way to
    find it without guessing. `bind_partial` never applies defaults, so an
    omitted role stays absent and refuses, which is the behaviour the
    contract names.
    """
    signature = inspect.signature(method)
    parameter = signature.parameters.get("actor_scope")
    if parameter is None:
        raise TypeError(f"{method.__qualname__} declares no actor_scope parameter")
    if parameter.default is not None:
        # A live role as the default would satisfy an omitted argument, and
        # nothing downstream would notice: the bind never consults defaults.
        raise TypeError(f"{method.__qualname__} actor_scope default must be None")

    def read(instance: Any, args: tuple, kwargs: dict) -> Any:
        return signature.bind_partial(instance, *args, **kwargs).arguments.get(
            "actor_scope"
        )

    return read, signature


def _state_locked(required_scope: str) -> Any:
    """Serialize a mutating operation, and refuse it before touching the store.

    The role is declared HERE, on the method, rather than in a central table:
    a table would be a second source of truth that drifts. It is checked as
    the wrapper's first statement, above the lock, so a refusal cannot open a
    transaction, cannot take the SQLite write lock, cannot verify a snapshot
    and cannot queue behind another writer. That placement is the property -
    while the check lived in the method body it ran AFTER the store had
    already loaded and verified a snapshot, so an unscoped caller on a
    state-backed engine learned integrity status and drove a durable write.
    """
    if required_scope not in _KNOWN_ROLES:
        raise TypeError("_state_locked requires a declared role constant")

    def decorate(method: Any) -> Any:
        read_scope, signature = _scope_reader(method)

        @functools.wraps(method)
        def locked(self: Any, *args: Any, **kwargs: Any) -> Any:
            _require_scope(read_scope(self, args, kwargs), required_scope)
            with self._state_lock:
                store = self._state_store
                if store is None:
                    return method(self, *args, **kwargs)

                connection = store.begin_immediate()
                rollback_state: dict[str, Any] | None = None
                try:
                    persisted = store.load(
                        connection,
                        self.declaration_hash,
                        self.profile_hash,
                        self._key,
                    )
                    if persisted is not None:
                        self._restore_state(persisted)
                    rollback_state = self._snapshot_state()
                    # The signer and verifier registry are process-local and are
                    # deliberately absent from the persisted snapshot. Capture them
                    # in memory so a save failure after a signer mutation (which the
                    # snapshot cannot carry) is rolled back with the rest of the
                    # state, not left applied while the database reverts.
                    signer_rollback = (
                        self._permit_signer,
                        dict(self._permit_verifiers),
                    )
                    try:
                        result = method(self, *args, **kwargs)
                    except IntegrityViolation:
                        raise
                    except ContractViolation:
                        store.save(
                            connection,
                            self.declaration_hash,
                            self.profile_hash,
                            self._key,
                            self._snapshot_state(),
                        )
                        # Under the store's guard, like the INSERT above it and like the
                        # read path's own commit. A commit is a statement on the stored
                        # file; leaving it outside meant one decorator kept the promise
                        # the other made. Named limit: a commit-time artefact error was
                        # NOT reproduced here - corrupting the row page after the INSERT
                        # still committed, the page being cached - so this is symmetry
                        # and enumeration, not a closed measurement.
                        with store._translate():
                            connection.commit()
                        rollback_state = None
                        raise
                    store.save(
                        connection,
                        self.declaration_hash,
                        self.profile_hash,
                        self._key,
                        self._snapshot_state(),
                    )
                    with store._translate():
                        connection.commit()
                    rollback_state = None
                    return result
                except BaseException:
                    if connection.in_transaction:
                        with store._translate():
                            connection.rollback()
                    if rollback_state is not None:
                        self._restore_state(rollback_state)
                        self._permit_signer = signer_rollback[0]
                        self._permit_verifiers = dict(signer_rollback[1])
                    raise
                finally:
                    connection.close()

        # The wrapper publishes the wrapped function's signature so callers and
        # tests read the real one, but NOT `__wrapped__`: that attribute is a
        # handle onto the undecorated function, and the undecorated function no
        # longer carries any scope check at all.
        locked.__signature__ = signature
        del locked.__wrapped__
        locked.__nc25_required_scope__ = required_scope
        return locked

    return decorate


def _state_read_locked(required_scope: str) -> Any:
    """Read under the state lock, and refuse before the store is consulted.

    Same placement rule as `_state_locked`: the role is checked first, so a
    refusal never reaches `store.read`, whose snapshot verification would
    otherwise answer an unscoped caller with an integrity code.
    """
    if required_scope not in _KNOWN_ROLES:
        raise TypeError("_state_read_locked requires a declared role constant")

    def decorate(method: Any) -> Any:
        read_scope, signature = _scope_reader(method)

        @functools.wraps(method)
        def locked(self: Any, *args: Any, **kwargs: Any) -> Any:
            _require_scope(read_scope(self, args, kwargs), required_scope)
            with self._state_lock:
                store = self._state_store
                if store is not None:
                    persisted = store.read(
                        self.declaration_hash,
                        self.profile_hash,
                        self._key,
                    )
                    if persisted is not None:
                        self._restore_state(persisted)
                return method(self, *args, **kwargs)

        locked.__signature__ = signature
        del locked.__wrapped__
        locked.__nc25_required_scope__ = required_scope
        return locked

    return decorate


class UniversalConnectionLedger:
    """Reference state machine for one profile and one connection declaration."""

    def __init__(
        self,
        profile: Mapping[str, Any],
        declaration: Mapping[str, Any],
        signing_key: bytes,
        clock: SystemClock | FixedClock | None = None,
        permit_ttl_seconds: int = 300,
        state_path: str | Path | None = None,
        event_signer: EventSigner | None = None,
        evidence_resolver: EvidenceResolver | None = None,
        permit_signer: EventSigner | None = None,
        control_resolver: ControlResolver | None = None,
    ) -> None:
        validate_profile(profile)
        validate_declaration(declaration, profile)
        if (
            isinstance(permit_ttl_seconds, bool)
            or not isinstance(permit_ttl_seconds, int)
            or not 1 <= permit_ttl_seconds <= MAX_PERMIT_TTL_SECONDS
        ):
            raise ContractViolation("PERMIT_TTL")
        self.profile = copy.deepcopy(dict(profile))
        self.declaration = copy.deepcopy(dict(declaration))
        self.profile_hash = sha256_hex(self.profile)
        self.declaration_hash = sha256_hex(self.declaration)
        self._key = signing_key
        self.clock = clock or SystemClock()
        self._evidence_resolver = evidence_resolver
        self._control_resolver = control_resolver
        # Active permit signer plus a key_id-routed verifier registry. The
        # default is the reference HMAC envelope signer; an asymmetric signer
        # (e.g. Ed25519DetachedSigner) is a drop-in through the same protocol.
        # Rotation keeps retired keys in the registry so their permits remain
        # verifiable; revocation removes a key so its permits fail closed.
        if permit_signer is None:
            permit_signer = HmacDetachedSigner(signing_key, "reference-hmac")
        self._require_permit_signer(permit_signer)
        self._permit_signer = permit_signer
        self._permit_verifiers: dict[str, EventSigner] = {
            permit_signer.key_id: permit_signer
        }
        self._revoked_permit_keys: set[str] = set()
        self._state_lock = threading.RLock()
        self._state_store = (
            SQLiteStateStore(state_path) if state_path is not None else None
        )
        self.ledger = AppendOnlyLedger(signing_key, self.clock, event_signer)
        self.permit_ttl_seconds = permit_ttl_seconds
        self.status = "DRAFT"
        self.activated_at: str | None = None
        self.grants: dict[str, dict[str, Any]] = {}
        self.revoked_grants: set[str] = set()
        self.permits: dict[str, PermitRecord] = {}
        self.decisions: dict[str, dict[str, Any]] = {}
        self.idempotency: dict[str, tuple[str, dict[str, Any]]] = {}
        self.execution_replays: dict[str, tuple[str, dict[str, Any]]] = {}
        self.structural_remaining = self.declaration["structural_budget"]["capacity"]
        self.committed_resources: list[tuple[datetime, dict[str, int]]] = []
        self.receipt_hashes: list[str] = []

        self._actions = {
            item["action_id"]: item for item in self.profile["action_alphabet"]
        }
        self._effects = {
            item["effect_class_id"]: item for item in self.profile["effect_classes"]
        }
        self._resources = {
            item["resource_id"]: item for item in self.profile["resource_catalog"]
        }
        self._limits = {
            item["resource_id"]: item for item in self.declaration["resource_limits"]
        }
        self._forbidden_operator_fields = set(
            self.profile["roles"]["forbidden_operator_fields"]
        )

        if self._state_store is not None:
            persisted = self._state_store.read(
                self.declaration_hash,
                self.profile_hash,
                self._key,
            )
            if persisted is not None:
                self._restore_state(persisted)
                self._assert_integrity()

    # ---- permit signing key custody (reference semantics) ------------------
    @staticmethod
    def _require_permit_signer(signer: Any) -> None:
        if not callable(getattr(signer, "sign", None)) or not callable(
            getattr(signer, "verify", None)
        ):
            raise ContractViolation("PERMIT_SIGNER_INVALID")
        key_id = getattr(signer, "key_id", None)
        if not isinstance(key_id, str) or not key_id or len(key_id) > 200:
            raise ContractViolation("SIGNATURE_KEY_ID")

    @_state_locked(ROLE_GOVERNANCE)
    def rotate_permit_signer(
        self,
        new_signer: EventSigner,
        actor_scope: str | None = None,
    ) -> None:
        """Make `new_signer` the signing key; retire the current one.

        Key custody is a governance operation: it decides which permits the
        engine can still verify, and revocation is irreversible, so it carries
        the same explicit-scope requirement as every other public operation.

        The retired key stays in the verifier registry, so permits it signed
        remain verifiable until the key is explicitly revoked. A revoked
        key_id can never be rotated back in: revocation is permanent for
        this declaration's lifetime, in-process and across state restore.
        """
        self._assert_integrity()
        self._require_permit_signer(new_signer)
        if new_signer.key_id in self._revoked_permit_keys:
            raise ContractViolation("PERMIT_KEY_REVOKED")
        if new_signer.key_id in self._permit_verifiers:
            raise ContractViolation("PERMIT_KEY_ROTATION_DUPLICATE")
        self._permit_verifiers[new_signer.key_id] = new_signer
        self._permit_signer = new_signer

    @_state_locked(ROLE_GOVERNANCE)
    def revoke_permit_key(
        self,
        key_id: str,
        actor_scope: str | None = None,
    ) -> None:
        """Revoke a retired key: permits signed under it now fail closed.

        Key custody is a governance operation, so this carries the same
        explicit-scope requirement as every other public operation.

        The active signing key cannot be revoked in place — rotate first, so
        the engine is never left unable to sign. Revocation is remembered, so
        a revoked key's permits refuse with `PERMIT_KEY_REVOKED` rather than
        being indistinguishable from tampering. With a `state_path`, the
        revoked set is part of the persisted snapshot, so revocation survives
        process restart.
        """
        self._assert_integrity()
        if key_id not in self._permit_verifiers:
            raise ContractViolation("PERMIT_KEY_NOT_REGISTERED")
        if key_id == self._permit_signer.key_id:
            raise ContractViolation("PERMIT_KEY_ACTIVE")
        del self._permit_verifiers[key_id]
        self._revoked_permit_keys.add(key_id)
        # A permit signed under a revoked key can never commit again — its
        # signature check fails closed with PERMIT_KEY_REVOKED. Holding its
        # capacity until the TTL expires would reserve structure for an
        # execution that cannot happen, so revocation releases it here, the
        # same way grant revocation releases the permits it kills.
        self._release_reservations(
            lambda record: record.signature.get("key_id") == key_id,
            "PERMIT_KEY_REVOKED",
        )

    def _verify_permit_signature(self, record: PermitRecord) -> None:
        # Fail closed on every branch. A revoked key is a policy refusal; an
        # envelope naming a key this engine never held, or failing the crypto
        # check, is an integrity failure.
        envelope = record.signature
        if (
            not isinstance(envelope, Mapping)
            or set(envelope) != SIGNATURE_ENVELOPE_FIELDS
            or not all(isinstance(value, str) for value in envelope.values())
        ):
            raise IntegrityViolation("PERMIT_SIGNATURE_ENVELOPE")
        key_id = envelope["key_id"]
        if key_id in self._revoked_permit_keys:
            raise ContractViolation("PERMIT_KEY_REVOKED")
        verifier = self._permit_verifiers.get(key_id)
        if verifier is None:
            raise IntegrityViolation("PERMIT_KEY_UNKNOWN")
        if not verifier.verify(record.permit_hash.encode("ascii"), envelope):
            raise IntegrityViolation("PERMIT_SIGNATURE_FAILURE")

    def _snapshot_state(self) -> dict[str, Any]:
        return {
            "state_version": "2.0.0",
            "profile_hash": self.profile_hash,
            "declaration_hash": self.declaration_hash,
            "permit_ttl_seconds": self.permit_ttl_seconds,
            "status": self.status,
            "activated_at": copy.deepcopy(self.activated_at),
            "grants": copy.deepcopy(self.grants),
            "revoked_grants": sorted(self.revoked_grants),
            # Revoked permit-signing keys are durable state: a revoked key_id
            # must stay dead across process restart, or a restart would
            # silently resurrect its permits. The verifier registry itself is
            # runtime configuration (keys are not serializable) and is NOT
            # persisted.
            "revoked_permit_keys": sorted(self._revoked_permit_keys),
            "permits": {
                permit_hash: {
                    "body": copy.deepcopy(record.body),
                    "permit_hash": record.permit_hash,
                    "signature": copy.deepcopy(record.signature),
                    "consumed": record.consumed,
                    "reservation_active": record.reservation_active,
                    "invalidated_reason": record.invalidated_reason,
                }
                for permit_hash, record in sorted(self.permits.items())
            },
            "decisions": copy.deepcopy(self.decisions),
            "idempotency": {
                key: [request_hash, copy.deepcopy(result)]
                for key, (request_hash, result) in sorted(self.idempotency.items())
            },
            "execution_replays": {
                key: [request_hash, copy.deepcopy(receipt)]
                for key, (request_hash, receipt) in sorted(
                    self.execution_replays.items()
                )
            },
            "structural_remaining": self.structural_remaining,
            "committed_resources": [
                {"committed_at": utc_text(instant), "debits": copy.deepcopy(debits)}
                for instant, debits in self.committed_resources
            ],
            "receipt_hashes": copy.deepcopy(self.receipt_hashes),
            "ledger_events": self.ledger.events_copy(),
        }

    def _restore_state(self, state: Mapping[str, Any]) -> None:
        required = {
            "state_version",
            "profile_hash",
            "declaration_hash",
            "permit_ttl_seconds",
            "status",
            "activated_at",
            "grants",
            "revoked_grants",
            "revoked_permit_keys",
            "permits",
            "decisions",
            "idempotency",
            "execution_replays",
            "structural_remaining",
            "committed_resources",
            "receipt_hashes",
            "ledger_events",
        }
        _require_exact_keys(state, required, "STATE_FIELDS")
        if state["state_version"] != "2.0.0":
            raise IntegrityViolation("STATE_VERSION")
        if state["profile_hash"] != self.profile_hash:
            raise IntegrityViolation("STATE_PROFILE_MISMATCH")
        if state["declaration_hash"] != self.declaration_hash:
            raise IntegrityViolation("STATE_DECLARATION_MISMATCH")
        if state["permit_ttl_seconds"] != self.permit_ttl_seconds:
            raise IntegrityViolation("STATE_PERMIT_TTL_MISMATCH")
        if not isinstance(state["status"], str) or state["status"] not in {"DRAFT", "ACTIVE"}:
            raise IntegrityViolation("STATE_STATUS")
        if not isinstance(state["grants"], dict):
            raise IntegrityViolation("STATE_GRANTS")
        if not isinstance(state["revoked_grants"], list):
            raise IntegrityViolation("STATE_REVOKED_GRANTS")
        revoked_permit_keys = state["revoked_permit_keys"]
        if not isinstance(revoked_permit_keys, list) or not all(
            isinstance(key_id, str) for key_id in revoked_permit_keys
        ):
            raise IntegrityViolation("STATE_REVOKED_PERMIT_KEYS")
        # A restored process must not sign under a key the persisted state
        # says is revoked. Constructing with the default (or any revoked)
        # signer against such state fails loudly instead of silently
        # resurrecting the key.
        if self._permit_signer.key_id in set(revoked_permit_keys):
            raise IntegrityViolation("STATE_REVOKED_ACTIVE_KEY")
        if not isinstance(state["permits"], dict):
            raise IntegrityViolation("STATE_PERMITS")

        permits: dict[str, PermitRecord] = {}
        for permit_hash, value in state["permits"].items():
            _require_exact_keys(
                value,
                {
                    "body",
                    "permit_hash",
                    "signature",
                    "consumed",
                    "reservation_active",
                    "invalidated_reason",
                },
                "STATE_PERMIT_FIELDS",
            )
            if permit_hash != value["permit_hash"]:
                raise IntegrityViolation("STATE_PERMIT_KEY_MISMATCH")
            envelope = value["signature"]
            if (
                not isinstance(envelope, Mapping)
                or set(envelope) != SIGNATURE_ENVELOPE_FIELDS
                or not all(
                    isinstance(field, str) for field in envelope.values()
                )
            ):
                raise IntegrityViolation("STATE_PERMIT_SIGNATURE")
            permits[permit_hash] = PermitRecord(
                body=copy.deepcopy(value["body"]),
                permit_hash=value["permit_hash"],
                signature=dict(envelope),
                consumed=value["consumed"],
                reservation_active=value["reservation_active"],
                invalidated_reason=value["invalidated_reason"],
            )

        def restore_pairs(name: str) -> dict[str, tuple[str, dict[str, Any]]]:
            source = state[name]
            if not isinstance(source, dict):
                raise IntegrityViolation(f"STATE_{name.upper()}")
            restored: dict[str, tuple[str, dict[str, Any]]] = {}
            for key, pair in source.items():
                if not isinstance(pair, list) or len(pair) != 2:
                    raise IntegrityViolation(f"STATE_{name.upper()}_PAIR")
                restored[key] = (pair[0], copy.deepcopy(pair[1]))
            return restored

        committed_resources: list[tuple[datetime, dict[str, int]]] = []
        if not isinstance(state["committed_resources"], list):
            raise IntegrityViolation("STATE_COMMITTED_RESOURCES")
        for item in state["committed_resources"]:
            _require_exact_keys(
                item,
                {"committed_at", "debits"},
                "STATE_COMMITTED_RESOURCE_FIELDS",
            )
            committed_resources.append(
                (parse_utc(item["committed_at"]), copy.deepcopy(item["debits"]))
            )

        self.status = state["status"]
        self.activated_at = copy.deepcopy(state["activated_at"])
        self.grants = copy.deepcopy(state["grants"])
        self.revoked_grants = set(state["revoked_grants"])
        self._revoked_permit_keys = set(revoked_permit_keys)
        self._permit_verifiers = {
            key_id: verifier
            for key_id, verifier in self._permit_verifiers.items()
            if key_id not in self._revoked_permit_keys
        }
        self.permits = permits
        self.decisions = copy.deepcopy(state["decisions"])
        self.idempotency = restore_pairs("idempotency")
        self.execution_replays = restore_pairs("execution_replays")
        self.structural_remaining = state["structural_remaining"]
        self.committed_resources = committed_resources
        self.receipt_hashes = copy.deepcopy(state["receipt_hashes"])
        self.ledger._restore_events(copy.deepcopy(state["ledger_events"]))

    def _now(self) -> datetime:
        value = self.clock.now()
        if not isinstance(value, datetime):
            raise ContractViolation("CLOCK_VALUE")
        if value.tzinfo is None:
            raise ContractViolation("TIMEZONE_REQUIRED")
        return value.astimezone(timezone.utc)

    def _assert_integrity(self) -> None:
        if sha256_hex(self.profile) != self.profile_hash:
            raise IntegrityViolation("PROFILE_SEAL_FAILURE")
        if sha256_hex(self.declaration) != self.declaration_hash:
            raise IntegrityViolation("DECLARATION_SEAL_FAILURE")
        if not self.ledger.verify():
            raise IntegrityViolation("LEDGER_CHAIN_FAILURE")

    def _assert_active(self) -> None:
        if self.status != "ACTIVE":
            raise ContractViolation("DECLARATION_NOT_ACTIVE")
        now = self._now()
        if not (
            parse_utc(self.declaration["effective_from"])
            <= now
            < parse_utc(self.declaration["expires_at"])
        ):
            raise ContractViolation("DECLARATION_OUTSIDE_VALIDITY")

    def _binding(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile["profile_id"],
            "profile_version": self.profile["profile_version"],
            "profile_hash": self.profile_hash,
            "declaration_id": self.declaration["declaration_id"],
            "declaration_version": self.declaration["declaration_version"],
            "declaration_hash": self.declaration_hash,
        }

    def _binding_matches(self, value: Any) -> bool:
        if not isinstance(value, Mapping):
            return False
        normalized = dict(value)
        for hash_field in ("profile_hash", "declaration_hash"):
            if isinstance(normalized.get(hash_field), str):
                normalized[hash_field] = normalized[hash_field].upper()
        return normalized == self._binding()

    @_state_locked(ROLE_GOVERNANCE)
    def activate(
        self,
        activated_by: str,
        approval_evidence_ref: str,
        actor_scope: str | None = None,
    ) -> str:
        self._assert_integrity()
        if self.status != "DRAFT":
            raise ContractViolation("DECLARATION_ALREADY_ACTIVATED")
        _require_identifier(activated_by, "ACTIVATION_ACTOR")
        # Activation attribution is pinned to the declared approval owner, the
        # same way issue_grant pins its issuer and revoke_grant its revoker —
        # otherwise the signed chain records an activator nothing verified.
        if activated_by != self.declaration["governance"]["approval_owner_id"]:
            raise ContractViolation("ACTIVATION_ACTOR_UNAUTHORIZED")
        if (
            not isinstance(approval_evidence_ref, str)
            or not approval_evidence_ref
        ):
            raise ContractViolation("ACTIVATION_EVIDENCE_REQUIRED")
        now = self._now()
        if not (
            parse_utc(self.declaration["effective_from"])
            <= now
            < parse_utc(self.declaration["expires_at"])
        ):
            raise ContractViolation("DECLARATION_OUTSIDE_VALIDITY")
        self.ledger.append(
            "DECLARATION_ACTIVATED",
            ROLE_GOVERNANCE,
            self.declaration["declaration_id"],
            {
                "activated_by": activated_by,
                "approval_evidence_ref": approval_evidence_ref,
                "profile_hash": self.profile_hash,
                "declaration_hash": self.declaration_hash,
            },
        )
        self.status = "ACTIVE"
        self.activated_at = utc_text(now)
        return self.declaration_hash

    def _validate_grant(self, grant: Mapping[str, Any]) -> None:
        required = {
            "message_type",
            "grant_id",
            "subject_id",
            "connector_id",
            "binding",
            "permitted_action_ids",
            "target_system_ids",
            "valid_from",
            "valid_until",
            "issued_by",
            "approval_evidence_ref",
        }
        _require_exact_keys(grant, required, "AUTHORITY_GRANT_FIELDS")
        if grant["message_type"] != "authority_grant":
            raise ContractViolation("AUTHORITY_MESSAGE_TYPE")
        for key in {"grant_id", "subject_id", "connector_id", "issued_by"}:
            _require_identifier(grant[key], "AUTHORITY_IDENTIFIER")
        if grant["connector_id"] != self.declaration["connector"]["connector_id"]:
            raise ContractViolation("AUTHORITY_CONNECTOR_MISMATCH")
        if not self._binding_matches(grant["binding"]):
            raise ContractViolation("AUTHORITY_BINDING_MISMATCH")
        actions = set(
            _unique_ids(grant["permitted_action_ids"], "AUTHORITY_ACTIONS")
        )
        targets = set(_unique_ids(grant["target_system_ids"], "AUTHORITY_TARGETS"))
        if not actions <= set(self.declaration["instance_scope"]["action_ids"]):
            raise ContractViolation("AUTHORITY_ACTION_SCOPE")
        if not targets <= set(self.declaration["instance_scope"]["target_system_ids"]):
            raise ContractViolation("AUTHORITY_TARGET_SCOPE")
        if grant["issued_by"] != self.declaration["governance"]["authority_issuer_id"]:
            raise ContractViolation("AUTHORITY_ISSUER_MISMATCH")
        valid_from = parse_utc(grant["valid_from"])
        valid_until = parse_utc(grant["valid_until"])
        if valid_from >= valid_until:
            raise ContractViolation("AUTHORITY_TIME_ORDER")
        # Directional on purpose: a grant whose window has already closed is
        # refused with the code its first use would have produced, instead of
        # entering the chain as an AUTHORITY_GRANTED event for an authority
        # that was never live. A grant whose window is wholly in the FUTURE
        # is still issued - pre-issuing is a legitimate operation, and a rule
        # of "valid now" would have broken it.
        if valid_until <= self._now():
            raise ContractViolation("AUTHORITY_EXPIRED", grant["grant_id"])
        if (
            not isinstance(grant["approval_evidence_ref"], str)
            or not grant["approval_evidence_ref"]
        ):
            raise ContractViolation("AUTHORITY_EVIDENCE_REQUIRED")
        _deep_secret_scan(grant)

    def _grant_validity(
        self,
        grant_id: str,
        now: datetime,
    ) -> tuple[dict[str, Any] | None, str | None]:
        grant = self.grants.get(grant_id)
        if grant is None:
            return None, "AUTHORITY_UNKNOWN"
        if grant_id in self.revoked_grants:
            return grant, "AUTHORITY_REVOKED"
        if now < parse_utc(grant["valid_from"]):
            return grant, "AUTHORITY_NOT_YET_VALID"
        if now >= parse_utc(grant["valid_until"]):
            return grant, "AUTHORITY_EXPIRED"
        return grant, None

    @overload
    def issue_grant(self, grant: Mapping[str, Any], actor_scope: str | None = None,
                    *, with_status: Literal[False] = False) -> str: ...

    @overload
    def issue_grant(self, grant: Mapping[str, Any], actor_scope: str | None = None,
                    *, with_status: Literal[True]) -> tuple[str, bool]: ...

    @overload
    def issue_grant(self, grant: Mapping[str, Any], actor_scope: str | None = None,
                    *, with_status: bool) -> str | tuple[str, bool]: ...

    @_state_locked(ROLE_GOVERNANCE)
    def issue_grant(
        self,
        grant: Mapping[str, Any],
        actor_scope: str | None = None,
        *,
        with_status: bool = False,
    ) -> str | tuple[str, bool]:
        """Issue or replay a grant; optionally return (hash, created).

        Creation is determined inside the state transaction, so HTTP callers
        need not inspect a potentially stale in-memory grant dictionary.
        The default preserves the hash-only SDK result.
        """
        self._assert_integrity()
        self._assert_active()
        self._validate_grant(grant)
        grant_id = grant["grant_id"]
        grant_hash = sha256_hex(grant)
        if grant_id in self.grants:
            if grant_id in self.revoked_grants:
                raise ContractViolation("AUTHORITY_REVOKED", grant_id)
            if sha256_hex(self.grants[grant_id]) == grant_hash:
                return (grant_hash, False) if with_status else grant_hash
            raise ContractViolation("AUTHORITY_ID_CONFLICT", grant_id)
        self.ledger.append(
            "AUTHORITY_GRANTED",
            ROLE_GOVERNANCE,
            grant_id,
            {"grant": copy.deepcopy(dict(grant)), "grant_hash": grant_hash},
        )
        self.grants[grant_id] = copy.deepcopy(dict(grant))
        return (grant_hash, True) if with_status else grant_hash

    @_state_locked(ROLE_GOVERNANCE)
    def revoke_grant(
        self,
        revocation: Mapping[str, Any],
        actor_scope: str | None = None,
    ) -> None:
        self._assert_integrity()
        required = {
            "message_type",
            "grant_id",
            "declaration_hash",
            "revoked_at",
            "revoked_by",
            "reason_code",
            "evidence_ref",
        }
        _require_exact_keys(revocation, required, "REVOCATION_FIELDS")
        if revocation["message_type"] != "authority_revocation":
            raise ContractViolation("REVOCATION_MESSAGE_TYPE")
        grant_id = _require_identifier(revocation["grant_id"], "REVOCATION_GRANT_ID")
        if grant_id not in self.grants:
            raise ContractViolation("AUTHORITY_UNKNOWN", grant_id)
        if _require_sha256(
            revocation["declaration_hash"],
            "REVOCATION_DECLARATION_HASH",
        ) != self.declaration_hash:
            raise ContractViolation("REVOCATION_DECLARATION_MISMATCH")
        revoked_by = _require_identifier(revocation["revoked_by"], "REVOCATION_ACTOR")
        allowed_revokers = {
            self.declaration["governance"]["authority_issuer_id"],
            self.declaration["governance"]["approval_owner_id"],
            *self.declaration["governance"]["revision_authority_ids"],
        }
        if revoked_by not in allowed_revokers:
            raise ContractViolation("REVOCATION_ACTOR_UNAUTHORIZED")
        if (
            parse_utc(revocation["revoked_at"])
            > self._now() + timedelta(seconds=5)
        ):
            raise ContractViolation("REVOCATION_IN_FUTURE")
        _require_identifier(revocation["reason_code"], "REVOCATION_REASON")
        if (
            not isinstance(revocation["evidence_ref"], str)
            or not revocation["evidence_ref"]
        ):
            raise ContractViolation("REVOCATION_EVIDENCE_REQUIRED")
        # Idempotent by STATE, the way a consumed permit's exact replay is:
        # the grant is already revoked, so the caller's request is already
        # true and nothing is recorded again. Every field was still validated
        # above, so a malformed repeat is refused exactly as a first attempt
        # would be. Recording a second AUTHORITY_REVOKED event grew the chain
        # on every retry and, through the release below, overwrote the reason
        # a permit had already been invalidated for.
        if grant_id in self.revoked_grants:
            return
        self.ledger.append(
            "AUTHORITY_REVOKED",
            ROLE_GOVERNANCE,
            grant_id,
            copy.deepcopy(dict(revocation)),
        )
        self.revoked_grants.add(grant_id)
        self._release_reservations(
            lambda record: record.body["authority_grant_id"] == grant_id,
            "AUTHORITY_REVOKED",
        )

    def _validate_intent(self, intent: Mapping[str, Any]) -> None:
        required = {
            "message_type",
            "intent_id",
            "idempotency_key",
            "connector_id",
            "requester_id",
            "authority_grant_id",
            "binding",
            "action_id",
            "target_system_id",
            "scope",
            "resource_claims",
            "received_at",
            "payload_hash",
            "history_summary_hash",
            "state_anchor_hash",
            "prerequisite_results",
            "hard_block_flags",
            "manual_review_flags",
            "ambiguity_flags",
        }
        _require_exact_keys(intent, required, "INTENT_FIELDS")
        if intent["message_type"] != "intent":
            raise ContractViolation("INTENT_MESSAGE_TYPE")
        # The binding's SHAPE is form, and form is refused here - before any
        # event and before the idempotency key is consumed. Only its VALUES
        # are substance: a well-formed binding naming another profile is a
        # refusal with an event, decided later. A non-object binding used to
        # fall through to that refusal, so malformed input became a permanent
        # decision in the signed chain and burned the caller's key.
        binding = _require_mapping(intent["binding"], "INTENT_BINDING")
        _require_exact_keys(binding, set(self._binding()), "INTENT_BINDING")
        for key in {
            "intent_id",
            "idempotency_key",
            "connector_id",
            "requester_id",
            "authority_grant_id",
            "action_id",
            "target_system_id",
        }:
            _require_identifier(intent[key], "INTENT_IDENTIFIER")
        parse_utc(intent["received_at"])
        for key in {"payload_hash", "history_summary_hash", "state_anchor_hash"}:
            _require_sha256(intent[key], "INTENT_HASH")
        scope = _require_mapping(intent["scope"], "INTENT_SCOPE")
        if not scope:
            raise ContractViolation("INTENT_SCOPE")
        for key, value in scope.items():
            _require_identifier(key, "INTENT_SCOPE_DIMENSION")
            if not isinstance(value, str) or not value:
                raise ContractViolation("INTENT_SCOPE")
        claims = _require_mapping(intent["resource_claims"], "RESOURCE_CLAIMS")
        for resource_id, amount in claims.items():
            _require_identifier(resource_id, "RESOURCE_CLAIM_ID")
            _require_non_negative_int(amount, "RESOURCE_CLAIM_AMOUNT")
        controls = self.profile["controls"]
        _bool_map(
            intent["prerequisite_results"],
            set(controls["required_prerequisite_ids"]),
            "PREREQUISITE_RESULTS",
        )
        _bool_map(
            intent["hard_block_flags"],
            set(controls["hard_block_flag_ids"]),
            "HARD_BLOCK_FLAGS",
        )
        _bool_map(
            intent["manual_review_flags"],
            set(controls["manual_review_flag_ids"]),
            "MANUAL_REVIEW_FLAGS",
        )
        _unique_ids(
            intent["ambiguity_flags"],
            "AMBIGUITY_FLAGS",
            allow_empty=True,
        )
        _deep_forbidden_operator_scan(intent, self._forbidden_operator_fields)
        _deep_secret_scan(intent)

    def _resolve_controls(
        self,
        intent: Mapping[str, Any],
        resolved_at: datetime,
    ) -> dict[str, Any]:
        """Return the authoritative control results used as gate inputs.

        Without a `control_resolver`, the reference engine gates on the
        connector-declared intent flags (a documented reference boundary).
        With one, the resolver's derived results REPLACE those flags: the
        three boolean maps must cover exactly the profile-declared flag ids
        the intent carried, and the ambiguity surface must be a unique
        identifier set. Resolver exceptions and malformed output fail closed —
        a connector cannot fall back to its own claims by breaking the
        resolver.
        """
        if self._control_resolver is None:
            return {
                **{
                    field: dict(intent[field])
                    for field in CONTROL_BOOLEAN_FIELDS
                },
                CONTROL_AMBIGUITY_FIELD: list(
                    intent[CONTROL_AMBIGUITY_FIELD]
                ),
            }
        try:
            derived = self._control_resolver(
                copy.deepcopy(dict(intent)),
                resolved_at,
            )
        except Exception as exc:
            raise ContractViolation("CONTROL_RESOLUTION_FAILED") from exc
        if not isinstance(derived, Mapping) or set(derived) != set(
            CONTROL_FIELDS
        ):
            raise ContractViolation("CONTROL_RESOLUTION_INVALID")
        resolved: dict[str, Any] = {}
        for field in CONTROL_BOOLEAN_FIELDS:
            value = derived[field]
            if not isinstance(value, Mapping) or set(value) != set(
                intent[field]
            ):
                raise ContractViolation("CONTROL_RESOLUTION_INVALID")
            if not all(isinstance(flag, bool) for flag in value.values()):
                raise ContractViolation("CONTROL_RESOLUTION_INVALID")
            resolved[field] = dict(value)
        ambiguity = derived[CONTROL_AMBIGUITY_FIELD]
        if not isinstance(ambiguity, list):
            raise ContractViolation("CONTROL_RESOLUTION_INVALID")
        try:
            _unique_ids(ambiguity, "AMBIGUITY_FLAGS", allow_empty=True)
        except ContractViolation as exc:
            raise ContractViolation("CONTROL_RESOLUTION_INVALID") from exc
        resolved[CONTROL_AMBIGUITY_FIELD] = list(ambiguity)
        return resolved

    def _resolve_evidence_bundle(
        self,
        intent: Mapping[str, Any],
        evidence: Mapping[str, Any],
        resolved_at: datetime,
    ) -> dict[str, Any]:
        _deep_secret_scan(evidence)
        if self._evidence_resolver is None:
            return copy.deepcopy(dict(evidence))
        try:
            resolved = self._evidence_resolver(
                copy.deepcopy(dict(intent)),
                copy.deepcopy(dict(evidence)),
                resolved_at,
            )
        except Exception as exc:
            raise ContractViolation("EVIDENCE_RESOLUTION_FAILED") from exc
        if not isinstance(resolved, Mapping):
            raise ContractViolation("EVIDENCE_RESOLUTION_INVALID")
        resolved_bundle = copy.deepcopy(dict(resolved))
        try:
            self._validate_evidence_bundle(resolved_bundle, intent["intent_id"])
        except ContractViolation as exc:
            raise ContractViolation("EVIDENCE_RESOLUTION_INVALID") from exc
        return resolved_bundle

    def _validate_evidence_bundle(
        self,
        evidence: Mapping[str, Any],
        intent_id: str,
    ) -> tuple[set[str], set[str]]:
        _require_exact_keys(
            evidence,
            {"message_type", "intent_id", "collected_at", "items"},
            "EVIDENCE_BUNDLE_FIELDS",
        )
        if evidence["message_type"] != "evidence_bundle":
            raise ContractViolation("EVIDENCE_MESSAGE_TYPE")
        if evidence["intent_id"] != intent_id:
            raise ContractViolation("EVIDENCE_INTENT_MISMATCH")
        parse_utc(evidence["collected_at"])
        if not isinstance(evidence["items"], list) or not evidence["items"]:
            raise ContractViolation("EVIDENCE_ITEMS")
        seen_types: set[str] = set()
        valid_types: set[str] = set()
        invalid_types: set[str] = set()
        allowed_statuses = {"VALID", "INVALID", "REVOKED", "EXPIRED"}
        for raw in evidence["items"]:
            item = _require_mapping(raw, "EVIDENCE_ITEM")
            _require_exact_keys(
                item,
                {"evidence_type", "ref", "sha256", "status"},
                "EVIDENCE_ITEM",
            )
            evidence_type = _require_identifier(
                item["evidence_type"],
                "EVIDENCE_TYPE",
            )
            if evidence_type in seen_types:
                raise ContractViolation("DUPLICATE_EVIDENCE_TYPE", evidence_type)
            seen_types.add(evidence_type)
            if not isinstance(item["ref"], str) or not item["ref"]:
                raise ContractViolation("EVIDENCE_REFERENCE", evidence_type)
            if (
                not isinstance(item["status"], str)
                or item["status"] not in allowed_statuses
            ):
                raise ContractViolation("EVIDENCE_STATUS", evidence_type)
            _require_sha256(item["sha256"], "EVIDENCE_HASH")
            if item["status"] == "VALID":
                valid_types.add(evidence_type)
            else:
                invalid_types.add(evidence_type)
        _deep_secret_scan(evidence)
        return valid_types, invalid_types

    def _required_evidence_types(self, action_id: str) -> set[str]:
        result: set[str] = set()
        for requirement in self.profile["evidence_requirements"]:
            if action_id in requirement["applies_to_action_ids"]:
                result |= set(requirement["required_evidence_types"])
        return result

    def _release_reservations(
        self,
        selects: Callable[["PermitRecord"], bool],
        reason: str,
    ) -> None:
        """Kill the selected unconsumed permits and free their capacity.

        Every revocation path shares this: once a permit provably can never
        commit, the structure reserved for it must come back immediately
        rather than sit until its TTL. Both revocation surfaces route through
        here so the two cannot drift apart again.
        """
        for record in self.permits.values():
            # Only a permit that is still live is killed here. One whose
            # reservation was already released keeps the reason it was
            # released for - a permit expired before its grant was revoked
            # used to be rewritten as revoked, and the first cause was lost.
            if selects(record) and not record.consumed and record.reservation_active:
                record.reservation_active = False
                record.invalidated_reason = reason

    def _purge_expired_reservations(self, now: datetime) -> None:
        for record in self.permits.values():
            if (
                record.reservation_active
                and not record.consumed
                and parse_utc(record.body["expires_at"]) <= now
            ):
                record.reservation_active = False
                record.invalidated_reason = "PERMIT_EXPIRED"

    def _active_structural_reserved(self, now: datetime) -> int:
        self._purge_expired_reservations(now)
        return sum(
            record.body["structural_cost"]
            for record in self.permits.values()
            if record.reservation_active and not record.consumed
        )

    def _active_resource_reserved(self, resource_id: str, now: datetime) -> int:
        self._purge_expired_reservations(now)
        if not self._resources[resource_id]["reservation_required"]:
            # The profile declares that this resource holds no capacity between
            # permit issue and commit. Only committed amounts count against its
            # window limit; an outstanding permit reserves nothing.
            return 0
        return sum(
            record.body["resource_claims"].get(resource_id, 0)
            for record in self.permits.values()
            if record.reservation_active and not record.consumed
        )

    def _committed_resource_in_window(
        self,
        resource_id: str,
        now: datetime,
        window_seconds: int,
    ) -> int:
        start = now - timedelta(seconds=window_seconds)
        return sum(
            claims.get(resource_id, 0)
            for committed_at, claims in self.committed_resources
            if committed_at >= start
        )

    def _effect_gate(
        self,
        action: Mapping[str, Any],
        claims: Mapping[str, Any],
        now: datetime,
    ) -> tuple[bool, str]:
        required_resources = set(action["required_resource_ids"])
        if set(claims) != required_resources:
            return False, "RESOURCE_CLAIM_SET"
        effect = self._effects[action["effect_class_id"]]
        for resource_id in required_resources:
            amount = claims[resource_id]
            resource = self._resources[resource_id]
            rule = resource["claim_rule"]
            if rule == "POSITIVE" and amount <= 0:
                return False, "RESOURCE_MUST_BE_POSITIVE"
            if rule == "ZERO" and amount != 0:
                return False, "RESOURCE_MUST_BE_ZERO"
            if (
                rule == "POSITIVE_IF_EFFECTFUL"
                and effect["mutates_external_state"]
                and amount <= 0
            ):
                return False, "EFFECTFUL_RESOURCE_MUST_BE_POSITIVE"
            # No missing-limit branch: the declaration validator requires a
            # limit for every resource an in-scope action can claim, and only
            # in-scope actions reach this gate, so the lookup cannot miss on
            # any input the constructor accepts. The branch that answered it
            # was unreachable by construction and carried a decision code no
            # run could ever witness; a KeyError here would mean the validator
            # itself regressed, which its own sweep reports by name.
            limit = self._limits[resource_id]
            if amount > limit["max_per_intent"]:
                return False, "RESOURCE_PER_INTENT_LIMIT"
            committed = self._committed_resource_in_window(
                resource_id,
                now,
                limit["window_seconds"],
            )
            reserved = self._active_resource_reserved(resource_id, now)
            if (
                committed + reserved + amount
                > limit["max_committed_per_window"]
            ):
                return False, "RESOURCE_WINDOW_LIMIT"
        return True, "EFFECT_GATE_PASS"

    @staticmethod
    def _public_message_code(disposition: str) -> str:
        try:
            return PUBLIC_MESSAGE_CODE_BY_DISPOSITION[disposition]
        except KeyError as exc:
            raise ContractViolation("UNKNOWN_DISPOSITION") from exc

    @staticmethod
    def _operator_result(
        intent_id: str,
        request_hash: str,
        disposition: str,
        architect_message_code: str,
        permit_hash: str | None = None,
        expires_at: str | None = None,
    ) -> dict[str, Any]:
        if disposition == "ALLOW":
            channel = "OUTPUT"
            if not permit_hash or not expires_at:
                raise ContractViolation("ALLOW_WITHOUT_PERMIT")
        else:
            if disposition not in NON_EXECUTABLE:
                raise ContractViolation("UNKNOWN_DISPOSITION")
            channel = "REFUSAL"
            if permit_hash is not None or expires_at is not None:
                raise ContractViolation("NON_EXECUTABLE_WITH_PERMIT")
        # Checked, then deliberately discarded: what reaches the
        # operator is _public_message_code(disposition). The name now
        # says which vocabulary the caller must supply.
        _require_identifier(architect_message_code, "ARCHITECT_MESSAGE_CODE")
        return {
            "message_type": "operator_result",
            "intent_id": intent_id,
            "request_hash": request_hash,
            "disposition": disposition,
            "channel": channel,
            "message_code": UniversalConnectionLedger._public_message_code(
                disposition
            ),
            "permit_hash": permit_hash,
            "expires_at": expires_at,
        }

    def _record_non_executable(
        self,
        intent: Mapping[str, Any],
        request_hash: str,
        disposition: str,
        code: str,
        gate_engaged: bool,
        structural_gate: bool | None = None,
        effect_gate: bool | None = None,
    ) -> dict[str, Any]:
        result = self._operator_result(
            intent["intent_id"],
            request_hash,
            disposition,
            code,
        )
        decision = {
            "intent_id": intent["intent_id"],
            "request_hash": request_hash,
            "disposition": disposition,
            "message_code": code,
            "gate_engaged": gate_engaged,
            "gate_bit": 0 if gate_engaged else None,
            "structural_gate": structural_gate,
            "effect_gate": effect_gate,
            "recorded_at": utc_text(self._now()),
        }
        self.ledger.append(
            "INTENT_NON_EXECUTABLE",
            ROLE_ARCHITECT,
            intent["intent_id"],
            decision,
        )
        self.decisions[request_hash] = decision
        return result

    @_state_locked(ROLE_OPERATOR)
    def evaluate_intent(
        self,
        intent: Mapping[str, Any],
        evidence_bundle: Mapping[str, Any],
        actor_scope: str | None = None,
    ) -> dict[str, Any]:
        self._assert_integrity()
        self._assert_active()
        self._validate_intent(intent)
        now = self._now()
        if parse_utc(intent["received_at"]) > now + timedelta(seconds=5):
            raise ContractViolation("INTENT_TIME_IN_FUTURE")
        # Validate the submitted evidence bundle's shape and time BEFORE the
        # authorization branches, mirroring the intent checks above. Deferring
        # these caller-controlled contract checks past authorization would let a
        # malformed or future-dated evidence bundle return a contract error only
        # when authorization had already passed, turning the error status into
        # an oracle for the authorization stage. The resolved bundle is
        # re-validated after resolution below.
        self._validate_evidence_bundle(evidence_bundle, intent["intent_id"])
        if parse_utc(evidence_bundle["collected_at"]) > now + timedelta(seconds=5):
            raise ContractViolation("EVIDENCE_TIME_IN_FUTURE")
        # Case-normalized on the DECLARED hash fields, exactly as the executor
        # replay identity is: the wire rule accepts a SHA-256 in either case,
        # so two submissions differing only in the case of a hash are the same
        # request and must replay rather than conflict. Fields the schemas
        # type as identifiers - the idempotency key and the requester among
        # them - are case-sensitive and stay out of that equivalence, so two
        # different principals never share one identity. Normalizing a copy
        # leaves the intent itself untouched for the permit body.
        submitted_request_hash = sha256_hex(
            _normalize_declared_hash_case(
                {
                    "intent": dict(intent),
                    "evidence_bundle": dict(evidence_bundle),
                }
            )
        )
        request_hash = submitted_request_hash
        idempotency_key = intent["idempotency_key"]
        if idempotency_key in self.idempotency:
            old_submitted_hash, old_result = self.idempotency[idempotency_key]
            if old_submitted_hash != submitted_request_hash:
                raise ContractViolation("IDEMPOTENCY_CONFLICT")
            if old_result["disposition"] == "ALLOW":
                permit_hash = old_result["permit_hash"]
                record = self.permits.get(permit_hash)
                if record is None:
                    raise IntegrityViolation("IDEMPOTENCY_PERMIT_MISSING")
                if sha256_hex(record.body) != record.permit_hash:
                    raise IntegrityViolation("PERMIT_HASH_FAILURE")
                self._verify_permit_signature(record)
                self._purge_expired_reservations(self._now())
                if record.consumed:
                    raise ContractViolation("PERMIT_ALREADY_CONSUMED")
                if record.invalidated_reason:
                    raise ContractViolation(record.invalidated_reason)
                _, authority_failure = self._grant_validity(
                    record.body["authority_grant_id"],
                    self._now(),
                )
                if authority_failure is not None:
                    record.reservation_active = False
                    record.invalidated_reason = authority_failure
                    raise ContractViolation(authority_failure)
            return copy.deepcopy(old_result)

        def finish(result: dict[str, Any]) -> dict[str, Any]:
            self.idempotency[idempotency_key] = (
                submitted_request_hash,
                copy.deepcopy(result),
            )
            return result

        if not self._binding_matches(intent["binding"]):
            return finish(
                self._record_non_executable(
                    intent,
                    request_hash,
                    "REFUSAL",
                    "BINDING_MISMATCH",
                    False,
                )
            )
        if intent["connector_id"] != self.declaration["connector"]["connector_id"]:
            return finish(
                self._record_non_executable(
                    intent,
                    request_hash,
                    "REFUSAL",
                    "CONNECTOR_MISMATCH",
                    False,
                )
            )
        grant, authority_failure = self._grant_validity(
            intent["authority_grant_id"],
            now,
        )
        if authority_failure is not None:
            return finish(
                self._record_non_executable(
                    intent,
                    request_hash,
                    "REFUSAL",
                    authority_failure,
                    False,
                )
            )
        if grant is None:
            raise IntegrityViolation("AUTHORITY_LOOKUP_FAILURE")
        if (
            intent["requester_id"] != grant["subject_id"]
            or intent["connector_id"] != grant["connector_id"]
            or not self._binding_matches(grant["binding"])
        ):
            return finish(
                self._record_non_executable(
                    intent,
                    request_hash,
                    "REFUSAL",
                    "AUTHORITY_SUBJECT_MISMATCH",
                    False,
                )
            )
        action_id = intent["action_id"]
        target_id = intent["target_system_id"]
        if (
            action_id not in grant["permitted_action_ids"]
            or action_id not in self.declaration["instance_scope"]["action_ids"]
        ):
            return finish(
                self._record_non_executable(
                    intent,
                    request_hash,
                    "REFUSAL",
                    "ACTION_OUT_OF_SCOPE",
                    False,
                )
            )
        if (
            target_id not in grant["target_system_ids"]
            or target_id not in self.declaration["instance_scope"]["target_system_ids"]
        ):
            return finish(
                self._record_non_executable(
                    intent,
                    request_hash,
                    "REFUSAL",
                    "TARGET_OUT_OF_SCOPE",
                    False,
                )
            )
        action = self._actions[action_id]
        if target_id not in self.declaration["instance_scope"][
            "action_target_bindings"
        ][action_id]:
            return finish(
                self._record_non_executable(
                    intent,
                    request_hash,
                    "REFUSAL",
                    "ACTION_TARGET_MISMATCH",
                    False,
                )
            )
        if (
            action["effect_class_id"]
            not in self.declaration["instance_scope"]["effect_class_ids"]
        ):
            return finish(
                self._record_non_executable(
                    intent,
                    request_hash,
                    "REFUSAL",
                    "EFFECT_OUT_OF_SCOPE",
                    False,
                )
            )
        declared_constraints = self.declaration["instance_scope"][
            "scope_constraints"
        ]
        if set(intent["scope"]) != set(declared_constraints):
            return finish(
                self._record_non_executable(
                    intent,
                    request_hash,
                    "REFUSAL",
                    "SCOPE_DIMENSION_MISMATCH",
                    False,
                )
            )
        if any(
            intent["scope"][dimension] not in allowed
            for dimension, allowed in declared_constraints.items()
        ):
            return finish(
                self._record_non_executable(
                    intent,
                    request_hash,
                    "REFUSAL",
                    "SCOPE_VALUE_OUT_OF_RANGE",
                    False,
                )
            )
        resolved_evidence_bundle = self._resolve_evidence_bundle(
            intent,
            evidence_bundle,
            now,
        )
        evidence_types, invalid_evidence_types = self._validate_evidence_bundle(
            resolved_evidence_bundle,
            intent["intent_id"],
        )
        if parse_utc(resolved_evidence_bundle["collected_at"]) > now + timedelta(seconds=5):
            raise ContractViolation("EVIDENCE_TIME_IN_FUTURE")
        # Authoritative controls: derived (or pass-through) maps are the gate
        # inputs from here on, and they are bound into the PERMIT request hash
        # so the issued permit commits to what was actually gated on. This hash
        # stays internal to the permit body; the operator-facing result and the
        # architect decision are keyed on submitted_request_hash instead, so an
        # operator cannot tell an authorization-stage refusal (which carries the
        # submitted hash) from a control-stage refusal or an ALLOW by comparing
        # the returned request_hash to a locally computed submitted hash.
        resolved_controls = self._resolve_controls(intent, now)
        permit_request_hash = sha256_hex(
            {
                "intent": dict(intent),
                "evidence_bundle": resolved_evidence_bundle,
                "resolved_controls": resolved_controls,
            }
        )

        if invalid_evidence_types:
            return finish(
                self._record_non_executable(
                    intent,
                    request_hash,
                    "REFUSAL",
                    "EVIDENCE_INVALID",
                    False,
                )
            )
        required_evidence = self._required_evidence_types(action_id)
        if not required_evidence <= evidence_types:
            return finish(
                self._record_non_executable(
                    intent,
                    request_hash,
                    "REFUSAL",
                    "EVIDENCE_MISSING",
                    False,
                )
            )
        if resolved_controls["ambiguity_flags"]:
            return finish(
                self._record_non_executable(
                    intent,
                    request_hash,
                    "MANUAL_REVIEW",
                    "AMBIGUOUS_INTENT",
                    False,
                )
            )
        if not all(resolved_controls["prerequisite_results"].values()):
            return finish(
                self._record_non_executable(
                    intent,
                    request_hash,
                    "REFUSAL",
                    "PREREQUISITE_FALSE",
                    False,
                )
            )
        if any(resolved_controls["hard_block_flags"].values()):
            return finish(
                self._record_non_executable(
                    intent,
                    request_hash,
                    "REFUSAL",
                    "HARD_BLOCK",
                    False,
                )
            )
        if any(resolved_controls["manual_review_flags"].values()):
            return finish(
                self._record_non_executable(
                    intent,
                    request_hash,
                    "MANUAL_REVIEW",
                    "MANUAL_REVIEW_REQUIRED",
                    False,
                )
            )

        structural_cost = action["structural_cost"]
        structural_gate = (
            self.structural_remaining
            - self._active_structural_reserved(now)
            >= structural_cost
        )
        effect_gate, effect_code = self._effect_gate(
            action,
            intent["resource_claims"],
            now,
        )
        if not (structural_gate and effect_gate):
            code = (
                "STRUCTURAL_BUDGET_EXHAUSTED"
                if not structural_gate
                else effect_code
            )
            return finish(
                self._record_non_executable(
                    intent,
                    request_hash,
                    "REFUSAL",
                    code,
                    True,
                    structural_gate,
                    effect_gate,
                )
            )

        issued_at = utc_text(now)
        permit_expires_at = min(
            now + timedelta(seconds=self.permit_ttl_seconds),
            parse_utc(self.grants[intent["authority_grant_id"]]["valid_until"]),
            parse_utc(self.declaration["expires_at"]),
        )
        expires_at = utc_text(permit_expires_at)
        # ttl_seconds is the permit's EFFECTIVE lifetime, not the configured
        # nominal: when the grant or the declaration expires earlier than the
        # configured TTL, expires_at is capped and the sealed number must
        # agree with it, so a reader of one signed permit computing
        # issued_at + ttl_seconds lands on expires_at. The difference is
        # rounded UP to whole seconds and never below one: the schema
        # requires an integer of at least 1, and rounding down could make a
        # permit that has a fraction of a second left read as having none.
        # Equality with expires_at therefore holds to the second, not to the
        # microsecond.
        remaining = (permit_expires_at - now).total_seconds()
        effective_ttl_seconds = max(1, int(remaining) + (remaining > int(remaining)))
        permit_body = {
            "message_type": "execution_permit",
            "permit_id": f"permit-{permit_request_hash[:24]}",
            "intent_id": intent["intent_id"],
            "request_hash": permit_request_hash,
            "binding": self._binding(),
            "authority_grant_id": intent["authority_grant_id"],
            "connector_id": intent["connector_id"],
            "action_id": action_id,
            "effect_class_id": action["effect_class_id"],
            "target_system_id": target_id,
            "state_anchor_hash": intent["state_anchor_hash"].upper(),
            "structural_cost": structural_cost,
            "resource_claims": copy.deepcopy(dict(intent["resource_claims"])),
            "reservation_id": f"reservation-{permit_request_hash[:20]}",
            "gate_engaged": True,
            "gate_bit": 1,
            "structural_gate": True,
            "effect_gate": True,
            "issued_at": issued_at,
            "ttl_seconds": effective_ttl_seconds,
            "expires_at": expires_at,
        }
        permit_hash = sha256_hex(permit_body)
        record = PermitRecord(
            body=permit_body,
            permit_hash=permit_hash,
            signature=dict(
                self._permit_signer.sign(permit_hash.encode("ascii"))
            ),
        )
        decision = {
            "intent_id": intent["intent_id"],
            "request_hash": request_hash,
            "disposition": "ALLOW",
            "message_code": "ALLOW_ISSUED",
            "gate_engaged": True,
            "gate_bit": 1,
            "structural_gate": True,
            "effect_gate": True,
            "permit_hash": permit_hash,
            "recorded_at": issued_at,
        }
        self.ledger.append(
            "PERMIT_ISSUED",
            ROLE_ARCHITECT,
            intent["intent_id"],
            {
                "decision": decision,
                "permit_body": copy.deepcopy(permit_body),
                "permit_hash": permit_hash,
                "permit_signature": copy.deepcopy(record.signature),
            },
        )
        self.permits[permit_hash] = record
        # Index the decision under both handles: the submitted hash the operator
        # holds and the permit's own request hash. The operator↔permit hash
        # split (which keeps the gate stage off the operator surface) otherwise
        # leaves an architect who holds only the permit unable to reach its
        # decision, since permit_body.request_hash is the resolved hash. The two
        # hashes never collide (submitted binds two keys, the permit hash three).
        self.decisions[request_hash] = decision
        if permit_request_hash != request_hash:
            self.decisions[permit_request_hash] = decision
        return finish(
            self._operator_result(
                intent["intent_id"],
                request_hash,
                "ALLOW",
                "ALLOW_ISSUED",
                permit_hash,
                expires_at,
            )
        )

    def _validate_execution_request(self, value: Mapping[str, Any]) -> None:
        required = {
            "message_type",
            "permit_hash",
            "connector_id",
            "binding",
            "state_anchor_hash",
            "outcome",
            "downstream_receipt_hash",
            "committed_at",
        }
        _require_exact_keys(value, required, "EXECUTION_FIELDS")
        if value["message_type"] != "execution_request":
            raise ContractViolation("EXECUTION_MESSAGE_TYPE")
        _require_sha256(value["permit_hash"], "EXECUTION_PERMIT_HASH")
        _require_identifier(value["connector_id"], "EXECUTION_CONNECTOR")
        _require_sha256(value["state_anchor_hash"], "EXECUTION_STATE_ANCHOR")
        # Membership first requires a string. A list or a mapping is
        # unhashable, and testing it against a set raises TypeError before the
        # declared refusal can be reached - the same escape as a non-string
        # timestamp, in the other idiom this file uses to validate a value.
        if (
            not isinstance(value["outcome"], str)
            or value["outcome"] not in EXECUTION_OUTCOMES
        ):
            raise ContractViolation("EXECUTION_OUTCOME")
        # A downstream receipt exists only for a COMMITTED execution. FAILED
        # and ABORTED carry an explicit null: forcing a well-formed hash there
        # would make the executor fabricate audit data into the signed ledger.
        if value["outcome"] == "COMMITTED":
            _require_sha256(
                value["downstream_receipt_hash"],
                "DOWNSTREAM_RECEIPT_HASH",
            )
        elif value["downstream_receipt_hash"] is not None:
            raise ContractViolation("DOWNSTREAM_RECEIPT_FORBIDDEN")
        parse_utc(value["committed_at"])
        _deep_secret_scan(value)

    @_state_locked(ROLE_EXECUTOR)
    def commit_execution(
        self,
        execution_request: Mapping[str, Any],
        actor_scope: str | None = None,
        *,
        route_permit_hash: str,
    ) -> dict[str, Any]:
        # route_permit_hash is the transport-path permit hash and is REQUIRED:
        # the path/body binding check must never be silently skipped. An HTTP
        # adapter passes the URL {permit_hash}; a direct caller passes the
        # request's own permit_hash. Omission is a caller error, not fail-open.
        self._assert_integrity()
        self._validate_execution_request(execution_request)
        _require_sha256(route_permit_hash, "EXECUTION_ROUTE_PERMIT_HASH")
        if route_permit_hash.upper() != execution_request["permit_hash"].upper():
            raise ContractViolation("EXECUTION_PERMIT_MISMATCH")
        # The replay identity hash canonicalizes the case of the DECLARED
        # SHA-256 fields, matching the documented "either case" wire rule: a
        # retry differing only in the case of a hash replays instead of
        # conflicting. The nested binding hashes are covered because the
        # inventory is the schemas' own and names them; the request's other
        # keys are not, and that is the point. An earlier comment here argued
        # that shape was safe because EXECUTION_FIELDS closes the key set -
        # measured, that was false: connector_id is typed as an identifier and
        # a hex-shaped value in it collapsed two distinct requests into one
        # identity.
        canonical_execution_request = _normalize_declared_hash_case(
            execution_request
        )
        execution_request_hash = sha256_hex(canonical_execution_request)
        permit_hash = canonical_execution_request["permit_hash"]
        record = self.permits.get(permit_hash)
        if record is not None and record.consumed:
            replay = self.execution_replays.get(permit_hash)
            if replay is None:
                raise IntegrityViolation("EXECUTION_RECEIPT_MISSING")
            old_hash, old_receipt = replay
            if old_hash != execution_request_hash:
                raise ContractViolation("EXECUTION_REPLAY_CONFLICT")
            return copy.deepcopy(old_receipt)
        self._assert_active()
        if record is None:
            raise ContractViolation("PERMIT_UNKNOWN")
        if record.invalidated_reason:
            raise ContractViolation(record.invalidated_reason)
        if not record.reservation_active:
            raise ContractViolation("RESERVATION_INACTIVE")
        now = self._now()
        _, authority_failure = self._grant_validity(
            record.body["authority_grant_id"],
            now,
        )
        if authority_failure is not None:
            record.reservation_active = False
            record.invalidated_reason = authority_failure
            raise ContractViolation(authority_failure)
        if now >= parse_utc(record.body["expires_at"]):
            record.reservation_active = False
            record.invalidated_reason = "PERMIT_EXPIRED"
            raise ContractViolation("PERMIT_EXPIRED")
        if sha256_hex(record.body) != record.permit_hash:
            raise IntegrityViolation("PERMIT_HASH_FAILURE")
        self._verify_permit_signature(record)
        if execution_request["connector_id"] != record.body["connector_id"]:
            raise ContractViolation("EXECUTION_CONNECTOR_MISMATCH")
        if not self._binding_matches(execution_request["binding"]):
            raise ContractViolation("EXECUTION_BINDING_MISMATCH")
        if (
            execution_request["state_anchor_hash"].upper()
            != record.body["state_anchor_hash"]
        ):
            raise ContractViolation("STATE_ANCHOR_CHANGED")
        committed_at = parse_utc(execution_request["committed_at"])
        if committed_at > now + timedelta(seconds=5):
            raise ContractViolation("EXECUTION_TIME_IN_FUTURE")
        if committed_at < parse_utc(record.body["issued_at"]) - timedelta(seconds=5):
            raise ContractViolation("EXECUTION_TIME_PRECEDES_PERMIT")

        outcome = execution_request["outcome"]
        structural_debit = record.body["structural_cost"] if outcome == "COMMITTED" else 0
        resource_debits = (
            copy.deepcopy(record.body["resource_claims"])
            if outcome == "COMMITTED"
            else {key: 0 for key in record.body["resource_claims"]}
        )
        if structural_debit > self.structural_remaining:
            raise IntegrityViolation("STRUCTURAL_DEBIT_UNAVAILABLE")
        if outcome == "COMMITTED":
            for resource_id, amount in sorted(resource_debits.items()):
                limit = self._limits.get(resource_id)
                if limit is None:
                    raise IntegrityViolation("RESOURCE_LIMIT_MISSING_AT_COMMIT")
                committed = self._committed_resource_in_window(
                    resource_id,
                    now,
                    limit["window_seconds"],
                )
                if committed + amount > limit["max_committed_per_window"]:
                    record.reservation_active = False
                    record.invalidated_reason = "RESOURCE_WINDOW_LIMIT"
                    raise ContractViolation("RESOURCE_WINDOW_LIMIT")
        receipt_seed = {
            "message_type": "execution_receipt",
            "receipt_id": f"receipt-{permit_hash[:24]}",
            "permit_hash": permit_hash,
            "intent_id": record.body["intent_id"],
            "outcome": outcome,
            "structural_debit": structural_debit,
            "resource_debits": resource_debits,
            "downstream_receipt_hash": (
                execution_request["downstream_receipt_hash"].upper()
                if execution_request["downstream_receipt_hash"] is not None
                else None
            ),
            "recorded_at": utc_text(now),
        }
        transaction_state = {
            "ledger_events": self.ledger.events_copy(),
            "structural_remaining": self.structural_remaining,
            "committed_resources": copy.deepcopy(list(self.committed_resources)),
            "record_consumed": record.consumed,
            "reservation_active": record.reservation_active,
            "invalidated_reason": record.invalidated_reason,
            "receipt_hashes": copy.deepcopy(list(self.receipt_hashes)),
            "execution_replays": copy.deepcopy(dict(self.execution_replays)),
        }
        try:
            event_hash = self.ledger.append(
                "EXECUTION_RECORDED", ROLE_EXECUTOR, record.body["intent_id"],
                {"execution_request_hash": execution_request_hash, "receipt_seed": receipt_seed},
            )
            receipt = {key: value for key, value in receipt_seed.items() if key != "downstream_receipt_hash"}
            receipt["ledger_event_hash"] = event_hash
            receipt["receipt_hash"] = sha256_hex(receipt)
            if outcome == "COMMITTED":
                self.structural_remaining -= structural_debit
                self.committed_resources.append((now, copy.deepcopy(resource_debits)))
            record.consumed = True
            record.reservation_active = False
            self.receipt_hashes.append(receipt["receipt_hash"])
            self.execution_replays[permit_hash] = (execution_request_hash, copy.deepcopy(receipt))
            return receipt
        except BaseException:
            self.ledger._restore_events(transaction_state["ledger_events"])
            self.structural_remaining = transaction_state["structural_remaining"]
            self.committed_resources = transaction_state["committed_resources"]
            record.consumed = transaction_state["record_consumed"]
            record.reservation_active = transaction_state["reservation_active"]
            record.invalidated_reason = transaction_state["invalidated_reason"]
            self.receipt_hashes = transaction_state["receipt_hashes"]
            self.execution_replays = transaction_state["execution_replays"]
            raise

    @_state_read_locked(ROLE_ARCHITECT)
    def architect_permit(
        self,
        permit_hash: str,
        actor_scope: str | None = None,
    ) -> dict[str, Any]:
        self._assert_integrity()
        record = self.permits.get(_require_sha256(permit_hash, "PERMIT_HASH"))
        if record is None:
            raise ContractViolation("PERMIT_UNKNOWN")
        return {
            "permit_body": copy.deepcopy(record.body),
            "permit_hash": record.permit_hash,
            "signature": copy.deepcopy(record.signature),
            "consumed": record.consumed,
            "reservation_active": record.reservation_active,
            "invalidated_reason": record.invalidated_reason,
        }

    @_state_read_locked(ROLE_ARCHITECT)
    def architect_decision(
        self,
        request_hash: str,
        actor_scope: str | None = None,
    ) -> dict[str, Any]:
        self._assert_integrity()
        decision = self.decisions.get(_require_sha256(request_hash, "REQUEST_HASH"))
        if decision is None:
            raise ContractViolation("DECISION_UNKNOWN")
        return copy.deepcopy(decision)

    @_state_read_locked(ROLE_ARCHITECT)
    def observer_projection(
        self,
        actor_scope: str | None = None,
    ) -> list[dict[str, Any]]:
        self._assert_integrity()
        fields = set(
            self.profile["roles"]["observer_projection_fields"]
        )
        projection: list[dict[str, Any]] = []
        for event in self.ledger.events_copy():
            if event["event_type"] == "PERMIT_ISSUED":
                channel, code = "OUTPUT", "EXECUTION_AUTHORIZED"
            elif event["event_type"] == "INTENT_NON_EXECUTABLE":
                disposition = event["payload"]["disposition"]
                channel = "REFUSAL"
                code = self._public_message_code(disposition)
            elif event["event_type"] == "EXECUTION_RECORDED":
                # Only a COMMITTED execution is surfaced to the observer decision
                # feed as authorized. FAILED and ABORTED are executor-side
                # outcomes that would be indistinguishable from success if
                # projected as EXECUTION_AUTHORIZED; the closed public message-code
                # set carries no execution-outcome code, so their authoritative
                # record stays in the receipt and the architect trace, not this
                # minimal channel.
                if event["payload"]["receipt_seed"]["outcome"] != "COMMITTED":
                    continue
                channel, code = "OUTPUT", "EXECUTION_AUTHORIZED"
            else:
                continue
            if code not in PUBLIC_MESSAGE_CODES:
                raise IntegrityViolation("PUBLIC_MESSAGE_CODE_INVALID")
            record = {
                "channel": channel,
                "message_code": code,
                "event_time": event["event_time"],
                "subject_ref": event["subject_ref"],
            }
            projection.append(
                {
                    key: record[key]
                    for key in (
                        "channel",
                        "message_code",
                        "event_time",
                        "subject_ref",
                    )
                    if key in fields
                }
            )
        return projection

    def _assert_registry_projection(self, record: Mapping[str, Any]) -> None:
        expected_fields = {
            "schema_version", "connector_id", "profile_id", "profile_version",
            "profile_hash", "declaration_id", "declaration_version",
            "declaration_hash", "core_anchor", "status", "activated_at",
            "revoked", "ledger_head_hash", "latest_receipt_root",
        }
        if set(record) != expected_fields:
            raise IntegrityViolation("REGISTRY_DATA_EXPANSION")
        forbidden_path = _find_forbidden_key(
            record,
            set(self.profile["registry_policy"]["forbidden_fields"]),
        )
        if forbidden_path is not None:
            raise IntegrityViolation("REGISTRY_DATA_EXPANSION")
        try:
            if record["schema_version"] != "1.0.0":
                raise ContractViolation("REGISTRY_SCHEMA_VERSION")
            for key in ("connector_id", "profile_id", "declaration_id"):
                _require_identifier(record[key], "REGISTRY_IDENTIFIER")
            for key in ("profile_version", "declaration_version"):
                _require_version(record[key], "REGISTRY_VERSION")
            for key in ("profile_hash", "declaration_hash", "ledger_head_hash"):
                _require_sha256(record[key], "REGISTRY_HASH")
            registry_core_anchor = _require_mapping(
                record["core_anchor"],
                "REGISTRY_CORE_ANCHOR",
            )
            expected_core_anchor = {
                key: CORE_ANCHOR[key]
                for key in ("core_version", "doi", "sha256")
            }
            if dict(registry_core_anchor) != expected_core_anchor:
                raise ContractViolation("REGISTRY_CORE_ANCHOR")
            if not isinstance(record["status"], str) or record["status"] not in {
                "DRAFT", "ACTIVE", "SUSPENDED", "REVOKED", "EXPIRED",
            }:
                raise ContractViolation("REGISTRY_STATUS")
            if record["activated_at"] is not None:
                if not isinstance(record["activated_at"], str):
                    raise ContractViolation("REGISTRY_ACTIVATED_AT")
                parse_utc(record["activated_at"])
            if not isinstance(record["revoked"], bool):
                raise ContractViolation("REGISTRY_REVOKED")
            if record["latest_receipt_root"] is not None:
                _require_sha256(record["latest_receipt_root"], "REGISTRY_RECEIPT_ROOT")
        except ContractViolation as exc:
            raise IntegrityViolation("REGISTRY_PROJECTION_INVALID") from exc

    @_state_read_locked(ROLE_ARCHITECT)
    def registry_record(
        self,
        connector_id: str,
        actor_scope: str | None = None,
    ) -> dict[str, Any]:
        self._assert_integrity()
        active_connector_id = self.declaration["connector"]["connector_id"]
        requested_connector_id = _require_identifier(
            connector_id,
            "REGISTRY_CONNECTOR_ID",
        )
        if requested_connector_id != active_connector_id:
            raise ContractViolation("CONNECTOR_NOT_FOUND", requested_connector_id)
        head = self.ledger.head()
        receipt_root = sha256_hex(self.receipt_hashes) if self.receipt_hashes else None
        record = {
            "schema_version": "1.0.0",
            "connector_id": active_connector_id,
            "profile_id": self.profile["profile_id"],
            "profile_version": self.profile["profile_version"],
            "profile_hash": self.profile_hash,
            "declaration_id": self.declaration["declaration_id"],
            "declaration_version": self.declaration["declaration_version"],
            "declaration_hash": self.declaration_hash,
            "core_anchor": {
                "core_version": CORE_ANCHOR["core_version"],
                "doi": CORE_ANCHOR["doi"],
                "sha256": CORE_ANCHOR["sha256"],
            },
            "status": self.status,
            "activated_at": self.activated_at,
            "revoked": bool(self.revoked_grants),
            "ledger_head_hash": head["head_hash"],
            "latest_receipt_root": receipt_root,
        }
        self._assert_registry_projection(record)
        return record

    @_state_read_locked(ROLE_ARCHITECT)
    def ledger_head(
        self,
        actor_scope: str | None = None,
    ) -> dict[str, Any]:
        self._assert_integrity()
        return self.ledger.head()


def bind_fixture(
    profile: Mapping[str, Any],
    declaration: Mapping[str, Any],
    grant: Mapping[str, Any],
    intent: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Return deep copies with canonical profile and declaration bindings."""

    bound_profile = copy.deepcopy(dict(profile))
    bound_declaration = copy.deepcopy(dict(declaration))
    profile_hash = sha256_hex(bound_profile)
    bound_declaration["profile_binding"]["profile_hash"] = profile_hash
    declaration_hash = sha256_hex(bound_declaration)
    binding = {
        "profile_id": bound_profile["profile_id"],
        "profile_version": bound_profile["profile_version"],
        "profile_hash": profile_hash,
        "declaration_id": bound_declaration["declaration_id"],
        "declaration_version": bound_declaration["declaration_version"],
        "declaration_hash": declaration_hash,
    }
    bound_grant = copy.deepcopy(dict(grant))
    bound_intent = copy.deepcopy(dict(intent))
    bound_grant["binding"] = copy.deepcopy(binding)
    bound_intent["binding"] = copy.deepcopy(binding)
    return bound_profile, bound_declaration, bound_grant, bound_intent
