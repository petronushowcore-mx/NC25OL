"""Independent verifier for the public NC25OL observer export, version 1.

This module deliberately does not import the ledger engine. It verifies a
separate chain of projected public records, not the engine's private ledger.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


FORMAT = "nc25ol-observer-export/v1"
GENESIS = "0" * 64
MAX_EXPORT_BYTES = 32 * 1024 * 1024
MAX_EVENTS = 100_000
_HEX64 = re.compile(r"[0-9A-F]{64}\Z")
_RECORD_FIELDS = {"channel", "message_code", "event_time", "subject_ref"}
_MESSAGE_CHANNELS = {
    "EXECUTION_AUTHORIZED": "OUTPUT",
    "EXECUTION_COMMITTED": "OUTPUT",
    "EXECUTION_DENIED": "REFUSAL",
    "HUMAN_REVIEW_REQUIRED": "REFUSAL",
}


class ReaderError(ValueError):
    """A stable public refusal code; details are not needed to decide validity."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _object(value: Any, code: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ReaderError(code)
    return value


def _exact(value: Any, fields: set[str], code: str) -> dict[str, Any]:
    obj = _object(value, code)
    if set(obj) != fields:
        raise ReaderError(code)
    return obj


def _hex(value: Any, code: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise ReaderError(code)
    return value


def _text(value: Any, code: str) -> str:
    if type(value) is not str or not value:
        raise ReaderError(code)
    return value


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ReaderError("CANONICAL_JSON_INVALID") from exc


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest().upper()


def _record(value: Any) -> dict[str, Any]:
    record = _exact(value, _RECORD_FIELDS, "RECORD_FIELDS_INVALID")
    actual_channel = _text(record["channel"], "RECORD_DECISION_INVALID")
    actual_message = _text(record["message_code"], "RECORD_DECISION_INVALID")
    if _MESSAGE_CHANNELS.get(actual_message) != actual_channel:
        raise ReaderError("RECORD_DECISION_INVALID")
    _text(record["event_time"], "RECORD_TIME_INVALID")
    _text(record["subject_ref"], "RECORD_SUBJECT_INVALID")
    return record


def _key(value: Any, expected_fingerprint: str | None) -> tuple[dict[str, Any], bytes]:
    key = _exact(
        value,
        {"algorithm", "key_id", "raw_base64", "fingerprint_sha256"},
        "PUBLIC_KEY_FIELDS_INVALID",
    )
    if key["algorithm"] != "Ed25519":
        raise ReaderError("PUBLIC_KEY_ALGORITHM_INVALID")
    _text(key["key_id"], "PUBLIC_KEY_ID_INVALID")
    _hex(key["fingerprint_sha256"], "KEY_FINGERPRINT_INVALID")
    try:
        raw = base64.b64decode(key["raw_base64"], validate=True)
    except (TypeError, ValueError, binascii.Error) as exc:
        raise ReaderError("PUBLIC_KEY_BYTES_INVALID") from exc
    if len(raw) != 32:
        raise ReaderError("PUBLIC_KEY_BYTES_INVALID")
    if hashlib.sha256(raw).hexdigest().upper() != key["fingerprint_sha256"]:
        raise ReaderError("KEY_FINGERPRINT_MISMATCH")
    if expected_fingerprint is not None:
        if type(expected_fingerprint) is not str:
            raise ReaderError("EXPECTED_FINGERPRINT_INVALID")
        expected = _hex(expected_fingerprint.upper(), "EXPECTED_FINGERPRINT_INVALID")
        if key["fingerprint_sha256"] != expected:
            raise ReaderError("KEY_UNEXPECTED")
    return key, raw


def verify_export(
    value: Any, *, expected_fingerprint: str | None = None
) -> dict[str, Any]:
    """Verify the projected chain and signed head; return public counts only.

    A caller must pin expected_fingerprint out of band to authenticate a known
    operator key. Without that pin, this proves only control of the included key.
    """
    bundle = _exact(
        value, {"format", "events", "head", "public_key", "signature"},
        "EXPORT_FIELDS_INVALID",
    )
    if bundle["format"] != FORMAT:
        raise ReaderError("FORMAT_UNSUPPORTED")
    key, raw_key = _key(bundle["public_key"], expected_fingerprint)
    head = _exact(bundle["head"], {"event_count", "head_hash"}, "HEAD_FIELDS_INVALID")
    count = head["event_count"]
    if type(count) is not int or count < 0 or count > MAX_EVENTS:
        raise ReaderError("HEAD_COUNT_INVALID")
    _hex(head["head_hash"], "HEAD_HASH_INVALID")
    events = bundle["events"]
    if type(events) is not list:
        raise ReaderError("EVENTS_INVALID")
    if len(events) != count:
        raise ReaderError("EVENT_COUNT_MISMATCH")
    indexes = []
    for event in events:
        item = _exact(
            event, {"index", "previous_hash", "record", "event_hash"},
            "EVENT_FIELDS_INVALID",
        )
        if type(item["index"]) is not int or item["index"] < 0:
            raise ReaderError("EVENT_INDEX_INVALID")
        indexes.append(item["index"])
    if indexes != list(range(count)):
        if sorted(indexes) == list(range(count)):
            raise ReaderError("EVENT_ORDER_INVALID")
        raise ReaderError("EVENT_INDEX_INVALID")

    previous = GENESIS
    codes: Counter[str] = Counter()
    for event in events:
        record = _record(event["record"])
        _hex(event["previous_hash"], "EVENT_PREVIOUS_HASH_INVALID")
        _hex(event["event_hash"], "EVENT_HASH_INVALID")
        if event["previous_hash"] != previous:
            raise ReaderError("EVENT_LINK_MISMATCH")
        body = {
            "index": event["index"],
            "previous_hash": event["previous_hash"],
            "record": record,
        }
        if event["event_hash"] != _sha(body):
            raise ReaderError("EVENT_HASH_MISMATCH")
        previous = event["event_hash"]
        codes[record["message_code"]] += 1
    if head["head_hash"] != previous:
        raise ReaderError("HEAD_HASH_MISMATCH")

    envelope = _exact(
        bundle["signature"], {"version", "algorithm", "key_id", "signature"},
        "SIGNATURE_FIELDS_INVALID",
    )
    if (envelope["version"] != "1" or envelope["algorithm"] != "Ed25519"
            or envelope["key_id"] != key["key_id"]):
        raise ReaderError("SIGNATURE_IDENTITY_INVALID")
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
    except (TypeError, ValueError, binascii.Error) as exc:
        raise ReaderError("SIGNATURE_BYTES_INVALID") from exc
    if len(signature) != 64:
        raise ReaderError("SIGNATURE_BYTES_INVALID")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise ReaderError("CRYPTO_UNAVAILABLE") from exc
    statement = {"format": FORMAT, "head": head, "public_key": key}
    try:
        Ed25519PublicKey.from_public_bytes(raw_key).verify(
            signature, _canonical(statement)
        )
    except (InvalidSignature, ValueError) as exc:
        raise ReaderError("HEAD_SIGNATURE_INVALID") from exc
    return {
        "signature_valid": True,
        "verified": expected_fingerprint is not None,
        "format": FORMAT,
        "event_count": count,
        "head_hash": previous,
        "key_fingerprint_sha256": key["fingerprint_sha256"],
        "authorized": codes["EXECUTION_AUTHORIZED"],
        "executed": codes["EXECUTION_COMMITTED"],
        "refused_by_code": {
            code: codes[code] for code in ("EXECUTION_DENIED", "HUMAN_REVIEW_REQUIRED")
            if codes[code]
        },
    }


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReaderError("JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ReaderError("JSON_CONSTANT_INVALID")


def read_export(
    path: str | Path, *, expected_fingerprint: str | None = None
) -> dict[str, Any]:
    source = Path(path)
    if source.stat().st_size > MAX_EXPORT_BYTES:
        raise ReaderError("EXPORT_TOO_LARGE")
    with source.open("rb") as stream:
        raw = stream.read(MAX_EXPORT_BYTES + 1)
    if len(raw) > MAX_EXPORT_BYTES:
        raise ReaderError("EXPORT_TOO_LARGE")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except ReaderError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ReaderError("JSON_INVALID") from exc
    return verify_export(value, expected_fingerprint=expected_fingerprint)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("--expect-fingerprint", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(read_export(
            args.export, expected_fingerprint=args.expect_fingerprint
        ), sort_keys=True))
        return 0
    except (ReaderError, OSError) as exc:
        code = exc.code if isinstance(exc, ReaderError) else "EXPORT_READ_FAILED"
        print(json.dumps({"verified": False, "code": code}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
