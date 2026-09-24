"""Disconnected synthetic declaration views and attributed observations.

No engine, network, filesystem writes, execution permits or state transitions.
The caller supplies the SDK import path and the independently pinned view.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sys
from datetime import datetime

_sdk = os.environ.get("NC25_LEDGER_SDK")
if _sdk:
    if not Path(_sdk).is_absolute():
        raise ValueError("SDK_PATH_MUST_BE_ABSOLUTE")
    sys.path.insert(0, _sdk)
from nc25_universal_ledger import canonical_json, sha256_hex

MAX_BYTES = 65536
MAX_DEPTH = 16
DOMAIN = b"NC25OL-PROJECTION-OBJECTION-v1\x00"
BINDING_FIELDS = {"declaration_id", "declaration_version", "declaration_hash",
                  "profile_id", "profile_version", "profile_hash"}
CONDITION_FIELDS = {"action_ids", "effect_class_ids", "target_system_ids",
                    "action_target_bindings", "effective_from", "expires_at"}
PROJECTION_FIELDS = {"message_type", "schema_version", "semantics", "binding",
                     "conditions", "projection_hash"}
OBJECTION_FIELDS = {"message_type", "schema_version", "binding", "projection_hash",
                    "author_id", "objection_id", "code", "text", "mac"}


def _fail(code):
    raise ValueError(code) from None


def _shape(value, fields, code):
    if type(value) is not dict or set(value) != fields:
        _fail(code)


def _text(value, maximum, code):
    if type(value) is not str or not 1 <= len(value) <= maximum:
        _fail(code)
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _fail(code)
    return value


def _identifier(value):
    _text(value, 128, "IDENTIFIER")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None:
        _fail("IDENTIFIER")
    return value


def _version(value):
    _text(value, 32, "VERSION")
    if re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value) is None:
        _fail("VERSION")
    return value


def _digest(value):
    if type(value) is not str or re.fullmatch(r"[0-9A-F]{64}", value) is None:
        _fail("DIGEST")
    return value


def _tree(value, depth=0):
    if depth > MAX_DEPTH:
        _fail("JSON_DEPTH")
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                _fail("JSON_KEY")
            _tree(key, depth + 1)
            _tree(item, depth + 1)
    elif type(value) is list:
        for item in value:
            _tree(item, depth + 1)
    elif type(value) is str:
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            _fail("JSON_STRING")
    elif value is not None and type(value) not in (bool, int):
        # The subset has no numbers. Full source hashing permits finite floats
        # through the SDK; this wire/pinned boundary intentionally does not.
        _fail("JSON_TYPE")


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            _fail("JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _load(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BYTES:
        _fail("JSON_BYTES")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"),
                           object_pairs_hook=_pairs,
                           parse_int=lambda _: _fail("JSON_TYPE"),
                           parse_float=lambda _: _fail("JSON_TYPE"),
                           parse_constant=lambda _: _fail("JSON_NONFINITE"))
    except UnicodeDecodeError:
        _fail("JSON_UTF8")
    except json.JSONDecodeError:
        _fail("JSON_SYNTAX")
    except RecursionError:
        _fail("JSON_DEPTH")
    _tree(value)
    return value


def _binding(value):
    _shape(value, BINDING_FIELDS, "BINDING_FIELDS")
    for name in ("declaration_id", "profile_id"):
        _identifier(value[name])
    for name in ("declaration_version", "profile_version"):
        _version(value[name])
    for name in ("declaration_hash", "profile_hash"):
        _digest(value[name])


def _ids(value):
    if type(value) is not list or not 1 <= len(value) <= 64:
        _fail("IDENTIFIER_LIST")
    for item in value:
        _identifier(item)
    if len(set(value)) != len(value):
        _fail("IDENTIFIER_LIST_DUPLICATE")
    return list(value)


def _timestamp(value):
    _text(value, 40, "TIMESTAMP")
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", value) is None:
        _fail("TIMESTAMP")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail("TIMESTAMP")


def _conditions(value):
    _shape(value, CONDITION_FIELDS, "CONDITION_FIELDS")
    actions = _ids(value["action_ids"])
    _ids(value["effect_class_ids"])
    targets = _ids(value["target_system_ids"])
    bindings = value["action_target_bindings"]
    _shape(bindings, set(actions), "ACTION_TARGET_FIELDS")
    for action in actions:
        if not set(_ids(bindings[action])).issubset(targets):
            _fail("ACTION_TARGET_UNKNOWN")
    if _timestamp(value["effective_from"]) >= _timestamp(value["expires_at"]):
        _fail("TIME_ORDER")


def _checked_projection(value):
    _tree(value)
    _shape(value, PROJECTION_FIELDS, "PROJECTION_FIELDS")
    if (value["message_type"] != "declaration_projection"
            or value["schema_version"] != "1.0.0"
            or value["semantics"] != "subset_not_full_authorisation"):
        _fail("PROJECTION_KIND")
    _binding(value["binding"])
    _conditions(value["conditions"])
    _digest(value["projection_hash"])
    if len(canonical_json(value)) > MAX_BYTES:
        _fail("JSON_BYTES")
    body = {key: item for key, item in value.items() if key != "projection_hash"}
    if sha256_hex(body) != value["projection_hash"]:
        _fail("PROJECTION_HASH")
    return value


def export_projection(declaration: dict, profile: dict) -> dict:
    """Select a synthetic view; validate its syntax, not full authorisation."""
    if type(declaration) is not dict or type(profile) is not dict:
        _fail("SOURCE_OBJECT")
    try:
        full_declaration_hash = sha256_hex(declaration)
        full_profile_hash = sha256_hex(profile)
        profile_binding = declaration["profile_binding"]
        _shape(profile_binding, {"profile_id", "profile_version", "profile_hash"},
               "SOURCE_PROFILE_BINDING")
        if (profile_binding["profile_hash"] != full_profile_hash
                or profile_binding["profile_id"] != profile["profile_id"]
                or profile_binding["profile_version"] != profile["profile_version"]):
            _fail("SOURCE_PROFILE_MISMATCH")
        scope = declaration["instance_scope"]
        if type(scope) is not dict:
            _fail("SOURCE_SCOPE")
        actions = _ids(scope["action_ids"])
        source_targets = scope["action_target_bindings"]
        _shape(source_targets, set(actions), "ACTION_TARGET_FIELDS")
        result = {
            "message_type": "declaration_projection", "schema_version": "1.0.0",
            "semantics": "subset_not_full_authorisation",
            "binding": {
                "declaration_id": declaration["declaration_id"],
                "declaration_version": declaration["declaration_version"],
                "declaration_hash": full_declaration_hash,
                "profile_id": profile["profile_id"],
                "profile_version": profile["profile_version"],
                "profile_hash": full_profile_hash,
            },
            "conditions": {
                "action_ids": actions,
                "effect_class_ids": _ids(scope["effect_class_ids"]),
                "target_system_ids": _ids(scope["target_system_ids"]),
                "action_target_bindings": {action: _ids(source_targets[action]) for action in actions},
                "effective_from": declaration["effective_from"],
                "expires_at": declaration["expires_at"],
            },
        }
        result["projection_hash"] = sha256_hex(result)
        return _checked_projection(result)
    except (KeyError, TypeError, RecursionError, UnicodeError):
        _fail("SOURCE_INVALID")
    except RuntimeError:
        # SDK contract errors can include source details; do not relay them.
        _fail("SOURCE_INVALID")


def read_projection(raw: bytes, pinned: dict) -> dict:
    """Validate wire bytes against an independently supplied exact view."""
    expected = _checked_projection(pinned)
    actual = _checked_projection(_load(raw))
    if canonical_json(actual) != canonical_json(expected):
        _fail("PROJECTION_PIN_MISMATCH")
    return actual


def _key(value):
    if type(value) is not bytes or len(value) < 32:
        _fail("AUTHOR_KEY")
    return value


def _mac(body, key):
    return hmac.new(_key(key), DOMAIN + canonical_json(body), hashlib.sha256).hexdigest().upper()


def _objection(value):
    _tree(value)
    _shape(value, OBJECTION_FIELDS, "OBJECTION_FIELDS")
    if value["message_type"] != "projection_objection" or value["schema_version"] != "1.0.0":
        _fail("OBJECTION_KIND")
    _binding(value["binding"])
    _digest(value["projection_hash"])
    for field in ("author_id", "objection_id", "code"):
        _identifier(value[field])
    _text(value["text"], 4096, "OBJECTION_TEXT")
    _digest(value["mac"])
    if len(canonical_json(value)) > MAX_BYTES:
        _fail("JSON_BYTES")


def make_objection(projection: dict, author_id: str, objection_id: str,
                   code: str, text: str, key: bytes) -> dict:
    """Create an observation with a fixture author key; no execution effect."""
    checked = _checked_projection(projection)
    for item in (author_id, objection_id, code):
        _identifier(item)
    _text(text, 4096, "OBJECTION_TEXT")
    result = {
        "message_type": "projection_objection", "schema_version": "1.0.0",
        "binding": dict(checked["binding"]),
        "projection_hash": checked["projection_hash"],
        "author_id": author_id, "objection_id": objection_id,
        "code": code, "text": text,
    }
    result["mac"] = _mac(result, key)
    _objection(result)
    return result


def read_objection(raw: bytes, pinned: dict, authors: dict[str, bytes]) -> dict:
    """Return authenticated fixture attribution, never truth or authorisation."""
    expected = _checked_projection(pinned)
    actual = _load(raw)
    _objection(actual)
    if (actual["binding"] != expected["binding"]
            or actual["projection_hash"] != expected["projection_hash"]):
        _fail("OBJECTION_BINDING_MISMATCH")
    if type(authors) is not dict or actual["author_id"] not in authors:
        _fail("OBJECTION_AUTHOR_UNKNOWN")
    body = {key: item for key, item in actual.items() if key != "mac"}
    if not hmac.compare_digest(actual["mac"], _mac(body, authors[actual["author_id"]])):
        _fail("OBJECTION_MAC")
    return {"verdict": "attributed_objection", "executable": False, "objection": body}
