"""OTCS execution bridge for NC25OL.

NC2.5 owns the admissibility atmosphere.  The OTCS side contributes typed
facts (rights receipts, the current project head, and content-addressed
objects) and performs the downstream compare-and-swap append only after the
NC2.5 engine has issued a permit.  No OTCS field named ``allowed`` or
equivalent is accepted by this bridge.

The bridge deliberately keeps two authority classes separate:

* ``authority_grant_id`` in an NC2.5 intent is the operational grant used by
  the local admission engine;
* OTCS entry-content rights, Registry Operating Grant, consent, and mark
  permission are evidence receipts required by the OTCS domain profile.

OTCS hash references are opaque.  Their declared RFC 8785 digest is normalized
to upper case for comparison and never recomputed with NC2.5 canonical JSON.  NC2.5 canonical hashing is
used only for the bridge's own local operation and replay identities.

The SQLite outbox closes the ordinary crash seams around a non-transactional
downstream call. Each recovered operation and its original intent/evidence
snapshot must match an authenticated submitted admission decision in the durable
engine. Snapshots returned by transitions are checked before use, and the local
admission snapshot never crosses the OTCS wire. Legacy rows without it are
refused; this is not a MAC over all outbox state or a downstream receipt seal.  A PREPARED row revalidates its engine binding and permit
before OTCS is called; a dead permit becomes NOT_EXECUTED.  While the permit is
still live, an ambiguous retry can re-issue the same OTCS request, and
project-scoped OTCS idempotency must replay the original receipt so a second
external effect cannot occur.  Recovery of a CALLING or AMBIGUOUS row whose
permit has stopped being live is refused instead: neither state proves the
request ever left the machine, so re-driving it could be a FIRST effect under a
dead permit.  If OTCS has committed and the NC2.5 permit can no longer be
finalized, the row becomes RECONCILIATION_REQUIRED; the bridge does not invent
a late authorization.
"""

from __future__ import annotations

import copy
import json
import math
from contextlib import closing, contextmanager
import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from nc25_universal_ledger import (
    ContractViolation,
    MAX_NESTING_DEPTH,
    columns_detail,
    refuse_stored_artefact,
    refuse_unreadable_database,
    _decode_stored_text,
    _normalize_declared_hash_case,
    IntegrityViolation,
    ROLE_EXECUTOR,
    ROLE_ARCHITECT,
    ROLE_OPERATOR,
    UniversalConnectionLedger,
    parse_utc,
    sha256_hex,
    utc_text,
)


OTCS_BRIDGE_VERSION = "1.0.0"
OTCS_HASH_PROFILE = "RFC8785_SHA256"
OTCS_APPEND_ACTION_ID = "OTCS_APPEND_EVENT"
OTCS_HEAD_EVIDENCE_TYPE = "OTCS_EXPECTED_HEAD"
OTCS_OPERATION_EVIDENCE_TYPE = "NC25_OTCS_BRIDGE_OPERATION"
"""The bridge's own refusal vocabulary, declared where it is raised.

The engine declares `PUBLIC_MESSAGE_CODES` and `ARCHITECT_DECISION_CODES`
the same way, and for the same reason: a caller reads the declaration, not
a reader's scan of the source. The failure-surface ratchet holds the two
in step and reddens in EITHER direction, so a code added to the bridge
without being added here fails acceptance, and a name here that no site
raises fails it too.

🔴 These codes do NOT travel the adapter's wire and are absent from
`Error.code` on purpose. Measured: the adapter mentions OTCS zero times,
the OpenAPI contract zero times. A bridge refusal is raised in-process to
the Python caller that imported this module; publishing it as a wire code
would promise an HTTP client something no response can carry.

🔴 NAMED LIMIT, stated because a partner meets it first: the bridge has no
wire schema at all - neither `otcs_append_request` nor the receipt is
described in the contract or in `core/schemas/`. This vocabulary says WHAT
can refuse; it does not say what the message looks like.
"""
OTCS_REFUSAL_CODES = frozenset(
    {
        "OTCS_BRIDGE_JSON",
        "OTCS_BRIDGE_VERSION",
        "OTCS_CLIENT_INVALID",
        "OTCS_DURABLE_ENGINE_REQUIRED",
        "OTCS_EVENT_ID_NOT_SUCCESSOR",
        "OTCS_EVIDENCE_BINDING",
        "OTCS_EVIDENCE_DUPLICATE",
        "OTCS_GOVERNING_OBJECT_MISMATCH",
        "OTCS_HASH_DIGEST",
        "OTCS_HASH_OBJECT_ID",
        "OTCS_HASH_OBJECT_KIND",
        "OTCS_HASH_PROFILE",
        "OTCS_HASH_REF_FIELDS",
        "OTCS_HEAD_EVENT_ID",
        "OTCS_HEAD_EVENT_REF_MISMATCH",
        "OTCS_HEAD_FIELDS",
        "OTCS_HEAD_GOVERNING_KIND_MISMATCH",
        "OTCS_HEAD_HISTORY_KIND",
        "OTCS_HEAD_OBJECT_KIND",
        "OTCS_HEAD_PROJECT_ID",
        "OTCS_HEAD_PROJECT_MISMATCH",
        "OTCS_HEAD_SEQUENCE",
        "OTCS_IDEMPOTENCY_CONFLICT",
        "OTCS_INTENT_BINDING",
        "OTCS_INTENT_SCOPE",
        "OTCS_LEGAL_EVIDENCE_FIELDS",
        "OTCS_LOCAL_FINALIZATION_REFUSED",
        "OTCS_OPERATION_EFFECTIVE_AT",
        "OTCS_OPERATION_EVENT_ID",
        "OTCS_OPERATION_EVENT_TYPE",
        "OTCS_OPERATION_FIELDS",
        "OTCS_OPERATION_IDEMPOTENCY_KEY",
        "OTCS_OPERATION_PROJECT_ID",
        "OTCS_OPERATION_SEQUENCE",
        "OTCS_OPERATION_TARGET",
        "OTCS_OUTBOX_COLUMNS",
        "OTCS_OUTBOX_CONFLICT",
        "OTCS_OUTBOX_CONNECTOR_ID",
        "OTCS_OUTBOX_ENGINE_BINDING",
        "OTCS_OUTBOX_EXECUTION_REQUEST",
        "OTCS_OUTBOX_MISSING",
        "OTCS_OUTBOX_PERMIT",
        "OTCS_OUTBOX_PERMIT_BINDING",
        "OTCS_OUTBOX_PERMIT_HASH",
        "OTCS_OUTBOX_ADMISSION",
        "OTCS_OUTBOX_REQUEST",
        "OTCS_OUTBOX_RESULT_STATE",
        "OTCS_OUTBOX_ROW_JSON",
        "OTCS_OUTBOX_ROW_TEXT",
        "OTCS_OUTBOX_STATE",
        "OTCS_OUTBOX_TRANSITION",
        "OTCS_RECEIPT_DIGEST_REF_MISMATCH",
        "OTCS_RECEIPT_EFFECTIVE_AT",
        "OTCS_RECEIPT_EPOCH",
        "OTCS_RECEIPT_EVENT_ID",
        "OTCS_RECEIPT_EVENT_REF_MISMATCH",
        "OTCS_RECEIPT_FIELDS",
        "OTCS_RECEIPT_ID",
        "OTCS_RECEIPT_IDEMPOTENCY_KEY",
        "OTCS_RECEIPT_ISSUER",
        "OTCS_RECEIPT_KEY_ID",
        "OTCS_RECEIPT_LOG_ROOT_KIND",
        "OTCS_RECEIPT_MISMATCH",
        "OTCS_RECEIPT_PROJECT_ID",
        "OTCS_RECEIPT_PROOF_REF",
        "OTCS_RECEIPT_SEQUENCE",
        "OTCS_RECEIPT_SIGNATURE_REF",
        "OTCS_PERMIT_NOT_LIVE_ON_RECOVERY",
        "OTCS_RECEIPT_UNUSABLE",
        "OTCS_RECONCILIATION_REQUIRED",
        "OTCS_RECOVERY_REQUIRED",
        "OTCS_REGISTRY_MODE",
        "OTCS_SEQUENCE_NOT_SUCCESSOR",
    }
)

# The subset whose guard answers only from inside: on every public path an
# earlier guard speaks first, so a caller cannot receive these however the
# input is shaped. They are witnessed by the suite anyway - a guard that
# can fire deserves a witness - and named here so the vocabulary is not
# read as a promise about the surface.
#   OTCS_OUTBOX_RESULT_STATE   no public path hands a non-terminal row
#                              to result construction
#   OTCS_OUTBOX_CONNECTOR_ID   OTCS_OUTBOX_ENGINE_BINDING always answers
#                              first on every public route
#   OTCS_RECEIPT_MISMATCH      its only producer, _validate_receipt, has
#                              exactly one call site, and that site reissues
#                              every bridge error as OTCS_RECEIPT_UNUSABLE:
#                              the caller sees this code as the DETAIL of the
#                              wrapper, never as the code. Counted here on
#                              that measurement, not on a reading.
#
# OTCS_OUTBOX_STATE was here and is NOT. Its reason was "the module's state set
# and the table's CHECK constraint are the same set" -- true only while this
# module created the table. A deployment that hands the bridge a pre-existing
# database with a table of the right shape and no CHECK breaks the assumption,
# and the PUBLIC read then raises the code directly. A
# row in an unknown state reaches it through outbox_record/get with no
# earlier guard in the way. The two remaining reasons were driven the same way
# and were not reached BY THAT ROUTE -- which is weaker than unreachable, and
# is written that way on purpose.
OTCS_INTERNAL_ONLY_CODES = frozenset(
    {
        "OTCS_OUTBOX_RESULT_STATE",
        "OTCS_OUTBOX_CONNECTOR_ID",
        "OTCS_RECEIPT_MISMATCH",
    }
)

OTCS_LEGAL_EVIDENCE_TYPES = (
    "OTCS_ENTRY_CONTENT_RIGHTS",
    "OTCS_REGISTRY_OPERATING_GRANT",
    "OTCS_CONSENT_RECORD",
    "OTCS_MARK_PERMISSION",
)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{1,127}$")
_SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
_REGISTRY_MODES = frozenset({"full_snapshot", "reference_only"})
_OUTBOX_COLUMNS = frozenset(
    {
        "project_id",
        "idempotency_key",
        "operation_hash",
        "permit_hash",
        "request_json",
        "state",
        "receipt_json",
        "execution_request_json",
        "local_receipt_json",
        "rejection_code",
        "last_error",
        "updated_at",
    }
)
# The columns the create statement names in its PRIMARY KEY, in the same spirit: the pair
# that makes a row idempotent. A stored table is asked for it beside the column names.
_OUTBOX_KEY = frozenset({"project_id", "idempotency_key"})
# The declared columns as a SELECT names them, sorted so the statement text is the same on
# every run. The reads used `SELECT *`, which asks the table for whatever it has: the column
# guard runs on its own connection and the row statements on another, so a schema changed
# between the two - by a second process, which this module's lock does not reach - was read
# back in full. A statement that names its columns cannot be handed a thirteenth, and a
# column that has gone becomes a driver error the row guard already translates by name. The
# window between the check and the read is not closed by this and is not claimed to be.
_OUTBOX_PROJECTION = ", ".join(sorted(_OUTBOX_COLUMNS))
# The columns the create statement declares without NOT NULL, read off it rather than
# chosen: the decoder admits NULL in these and refuses it in the other seven, so a stored
# table that dropped a NOT NULL cannot hand back a record with a hole the schema forbids.
_OUTBOX_NULLABLE = frozenset(
    {
        "receipt_json",
        "execution_request_json",
        "local_receipt_json",
        "rejection_code",
        "last_error",
    }
)
_OUTBOX_STATES = frozenset(
    {
        "PREPARED",
        "CALLING",
        "AMBIGUOUS",
        "DOWNSTREAM_COMMITTED",
        "DOWNSTREAM_REJECTED",
        "LOCAL_COMMITTED",
        "LOCAL_FAILED",
        "NOT_EXECUTED",
        "RECONCILIATION_REQUIRED",
    }
)


class OTCSBridgeError(Exception):
    """A stable bridge failure with a machine-readable code."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


class OTCSAppendRejected(OTCSBridgeError):
    """A definitive OTCS refusal known to have produced no external effect."""


class OTCSReconciliationRequired(OTCSBridgeError):
    """OTCS may have committed, but the local receipt cannot be finalized."""


class OTCSClient(Protocol):
    """Verified downstream port with project-scoped idempotent replay."""

    def append_event(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """CAS-append or raise ``OTCSAppendRejected`` before any effect.

        A successful return must already have passed OTCS signature and
        inclusion-proof verification against the deployment trust policy.
        """


def _mapping(value: Any, code: str) -> dict[str, Any]:
    # A plain copy, not `dict(value)`: the copy is what every later question is asked
    # of, and `dict(value)` of a dict subclass runs its own iteration. See `_plain_copy`.
    copied = _plain_copy(value, code)
    if type(copied) is not dict:
        raise OTCSBridgeError(code, "expected object")
    return copied


def _closed(value: Mapping[str, Any], fields: set[str], code: str) -> dict[str, Any]:
    mapped = _mapping(value, code)
    if set(mapped) != fields:
        raise OTCSBridgeError(
            code,
            f"expected={sorted(fields)} actual={sorted(mapped)}",
        )
    return mapped


# Every helper below that admits a string converts it to a PLAIN `str` first, with the base
# implementation, before asking it anything. `isinstance(value, str)` admits a subclass, and
# every question asked of the object afterwards - `len`, truthiness, `fullmatch`, `upper`,
# a parse - can run the object's own code. Without normalisation in `_text`, a subclass
# whose `__len__` raises can interrupt receipt admission after the downstream effect. The same
# normalisation `_stored_reason` makes, applied at every door that takes a string, so the
# answer is about the characters. `_integer` does the same for numbers with `int.__index__`.
#
# The answer is also what gets KEPT. The value objects below store each helper's return in
# place of what they were handed, and admit a nested reference only as the exact class, so
# every later comparison - `!=` between two references, a receipt against its operation -
# is between plain values. Until that, the helpers asked the right question and the objects
# kept the original anyway. Measured: a subclass that says it equals everything passed the
# event-reference check and was stored as itself, `hash_profile` admitted any object whose
# `__ne__` answered False, and an int whose `__lt__` lied put a negative sequence past a
# minimum of one.
#
# And the question "is this a string" is asked of the value's REAL type, `type(value)`, not
# through `isinstance`. `isinstance` consults the object's `__class__`, which a property on
# its class can answer with anything: measured, an object that is no string at all but
# says it is one passed `isinstance(value, str)` at every door, and the base normalisation
# after it then raised TypeError under no code - on the rejection path, after the
# downstream effect, with the row left CALLING. `type(value)` is the type the object
# actually has - the one the base methods check before they run - and a `__class__`
# property cannot fake it.


def _plain_text(value: str) -> str:
    return str.__str__(value)


def _is(value: Any, kind: type) -> bool:
    """`isinstance` by the value's real type: see the note above `_plain_text`."""
    return issubclass(type(value), kind)


def _identifier(value: Any, code: str) -> str:
    if not _is(value, str):
        raise OTCSBridgeError(code, "invalid identifier")
    value = _plain_text(value)
    if _IDENTIFIER_RE.fullmatch(value) is None:
        raise OTCSBridgeError(code, "invalid identifier")
    return value


def _storable_text(value: str) -> bool:
    """Can this string be written into a TEXT column and read back as itself?

    One home, because the question is asked twice: on the way IN by `_text`, which admits
    a receipt's free text, and on the way OUT by the decoder's walk over a stored row.
    Asking it in one place only was the defect: a lone surrogate in a receipt field passed
    admission, and the INSERT then died at the binding with a raw UnicodeEncodeError, after
    the downstream effect.

    The test is the round trip rather than `isascii`, for the same reason the decoder gives:
    its subject is the write-back, so it must refuse exactly what cannot be written and
    nothing else. A string of ordinary non-ASCII text encodes and passes.

    `str.encode(value, ...)` and not `value.encode(...)`: `isinstance(value, str)` admits a
    SUBCLASS, whose `encode` is the object's own code and may raise anything at all, and
    the clause below catches one exception type. No caller hands one over any more: both
    `_stored_reason` and `_text` normalise to a plain string before calling this, and the
    decoder's walk gets exact strings from `json.loads`. The base call stays so the
    predicate is right for a caller that does not normalise, and it is said here that it
    is no longer load-bearing - the break that removed it reddened a case while `_text`
    called this on the object, and reddens nothing now. The case that reddens when `_text`
    stops normalising is the value-object case, which builds a receipt directly; a receipt
    through `execute` reaches `_text` already plain, because the mapping door copies it.
    Measured when it carried the class, with
    the controls in both directions: a subclass whose `encode` raises fires on a normal
    call and not through the base method; an ordinary string still encodes; a lone
    surrogate is still refused.
    """
    try:
        str.encode(value, "utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _stored_reason(value: Any, maximum: int = 500) -> str:
    """Render a downstream reason so it can be stored, without inventing one.

    Used for the code a downstream sends with a definitive rejection. That rejection is,
    by the client contract, known to have produced no effect, so refusing to record it
    would leave the row mid-call over a fact that is settled; and the module does not
    invent a reason, so the downstream's own word is kept wherever it can be. Measured,
    two forms could not be: a lone surrogate died at the binding as a raw
    UnicodeEncodeError, and a code that is not a string at all died there as a raw
    ProgrammingError.

    Also used for the detail of a refusal whose value may not be a string at all - a bridge
    version, a registry mode, a hash profile - because an f-string built from the value
    itself would run its own `__bool__` and `__format__`.

    So a string keeps its characters where they can be stored and carries the escape
    `backslashreplace` writes where they cannot; anything that is not a string is
    rendered by `repr`, then normalised to a plain string before use. If rendering
    fails, `<unrenderable NAME>` records that, with the name of the value's type - read
    so that neither the value nor its metaclass runs.

    Truncated at the same bound `_text` uses, and truncated rather than refused, which is
    the difference between the two: `_text` guards what a caller MAY submit, so it says no;
    this records what a downstream ALREADY did, so it keeps as much as it can hold. The
    length of what a downstream sends is its choice, and this row is not the place to
    argue with it.
    """
    if _is(value, str):
        # A PLAIN string of the same characters, and not the object itself. `isinstance`
        # admits a subclass, and every operation below then runs the subclass's code:
        # `encode` inside `_storable_text` - which is the finding that started this - and
        # `__getitem__` in the truncation three lines down, whose override could return
        # anything at all, including a value sqlite cannot bind, which is the raw driver
        # error this function exists to prevent. One normalisation closes the whole class
        # rather than the method that was reported. `str.__str__` is the base
        # implementation, so it runs nothing the subclass defines; measured against a
        # plant overriding `__str__`, `__repr__`, `__getitem__`, `__add__`, `__iter__`
        # and `encode` - it returns an exact `str`, and a lone surrogate survives it, so
        # the storability question below is still asked of the same characters.
        text = str.__str__(value)
    else:
        try:
            text = _plain_text(repr(value))
        except Exception:
            # `repr` is not a safe operation on a value from outside: it runs the
            # object's own code. Measured, with a well-behaved object as the control: an
            # object whose `__repr__` raises sends that exception out of this function,
            # and this function is called from inside the handler for a definitive
            # rejection - so the row is left mid-call over a fact the client contract
            # says is already settled, which is the exact outcome this function exists
            # to prevent. What is still known about a value that will not describe itself
            # is its type, and the name is read through `type`'s own descriptor: the
            # attribute `type(value).__name__` goes through the metaclass, which a caller's
            # class can override, and a class's name may itself be a str subclass - both
            # measured, so the name is taken by the base descriptor and made plain.
            name = _plain_text(type.__dict__["__name__"].__get__(type(value), type))
            text = "<unrenderable %s>" % name
    if not _storable_text(text):
        # Base method for the same reason as everywhere else in this function, though on
        # this path it can no longer matter: the normalisation above makes `text` a plain
        # string before anything here runs. Written this way so the line stays right if
        # the normalisation is ever moved, and said plainly rather than left as a comment
        # about a subclass that cannot reach it - an earlier draft of this sentence
        # claimed exactly that, three lines under the fix that made it false.
        text = str.encode(text, "utf-8", "backslashreplace").decode("utf-8")
    return text[:maximum]


def _text(value: Any, code: str, maximum: int = 500) -> str:
    if not _is(value, str):
        raise OTCSBridgeError(code, "invalid text")
    value = _plain_text(value)
    if not value or len(value) > maximum:
        raise OTCSBridgeError(code, "invalid text")
    # Shape is not storability, and this admitted text the store could not keep. The
    # detail says which of the two refused, because "invalid text" for a string of the
    # right length and the wrong characters sends a reader looking at the length.
    if not _storable_text(value):
        raise OTCSBridgeError(code, "unwritable text")
    return value


def _sha256(value: Any, code: str) -> str:
    if not _is(value, str):
        raise OTCSBridgeError(code, "invalid SHA-256")
    value = _plain_text(value)
    if _SHA256_RE.fullmatch(value) is None:
        raise OTCSBridgeError(code, "invalid SHA-256")
    return value.upper()


def _integer(value: Any, code: str, minimum: int = 0) -> int:
    if type(value) is bool or not _is(value, int):
        raise OTCSBridgeError(code, "invalid integer")
    value = int.__index__(value)
    if value < minimum:
        raise OTCSBridgeError(code, "invalid integer")
    return value


def _exact(value: Any, kind: type, code: str) -> Any:
    """Admit a nested reference only as the class itself.

    Its own `__post_init__` is what made its fields plain, and references are compared
    with `!=`, which a subclass or a look-alike answers with its own code.
    """
    if type(value) is not kind:
        raise OTCSBridgeError(code, "expected " + kind.__name__)
    return value


def _plain_copy(value: Any, code: str, depth: int = 0) -> Any:
    """A caller's value as plain data, read by base implementations wherever there is one.

    `execute` hands what it is given to comparisons, to a hash and to the engine, and each
    of those asks the object: `!=` and `upper` run a subclass's own methods, and so does
    iterating a dict subclass. Measured, each against the same wrong value as a plain
    string: a scope field of other characters whose `__ne__` said equal, and an evidence
    digest of other characters whose `upper` answered with the right one, both passed the
    binding and reached the downstream. So the value is copied once, at the door: strings,
    integers and floats through their base implementations, dicts, lists and tuples as the
    same kinds of plain container read by the base iterators. Any other mapping has no
    base reading, so it is copied once by its own methods - the one place the caller's
    code runs - and a failure of that copy is refused under `code`. A key is made plain too, two
    keys that become the same string are refused rather than collapsed into whichever
    came last, and a key that is not a string is refused: no document here has one, and
    left in place it escaped as a raw TypeError from the sorted detail of `_closed` -
    measured, an integer key beside a string one.

    Anything else is left as it is, for the checks that refuse it by name, so a value this
    copy does not recognise meets the code it met before - which holds only while every
    reader before those checks asks the value's real type. Some did not: an object whose
    `__class__` said str or list reached a hash-case normaliser or a binding check first
    and left raw. They ask the real type now, and a sweep in the bridge suite plants such
    objects at every place of the three documents.

    Past the nesting limit the value is refused here, under `code`, before anything is
    asked of it. It used to be left uncopied for the engine's depth guard to answer, and
    that guard is not the first reader: the replay identity's hash-case normaliser walks
    the whole document before the hash reaches it, with no bound, and so does the binding
    check before that. Measured: a plain list nested 3000 deep left `execute` as a raw
    RecursionError, and a str or dict subclass past the limit ran its own `upper` or
    `items` and left as whatever that raised. Counted by CONTAINERS - the top-level value
    at depth zero, and a container entered at depth MAX_NESTING_DEPTH or deeper refused -
    which is how the wire's bracket scan and the stored-row walk count, so no document this
    door admits is refused for its depth on read-back. The engine's own walk counts values instead
    and admits one container more when the innermost is empty; the door does not inherit
    that. Counting as the engine did, it let such a document through here, and the walk
    refuses that document when it reads a row back - which the door case's boundary row
    and the stored-document case pin between them.
    """
    kind = type(value)
    if value is None or kind is bool:
        return value
    if issubclass(kind, str):
        return str.__str__(value)
    if issubclass(kind, int):
        return int.__index__(value)
    if issubclass(kind, float):
        return float.__float__(value)
    if issubclass(kind, (list, tuple, Mapping)) and depth >= MAX_NESTING_DEPTH:
        raise OTCSBridgeError(code, "nested past %d" % MAX_NESTING_DEPTH)
    if issubclass(kind, list):
        return [_plain_copy(item, code, depth + 1) for item in list.__iter__(value)]
    if issubclass(kind, tuple):
        return tuple(_plain_copy(item, code, depth + 1) for item in tuple.__iter__(value))
    if issubclass(kind, dict):
        pairs = list(dict.items(value))
    elif issubclass(kind, Mapping):
        try:
            pairs = list(dict(value).items())
        except Exception as exc:
            raise OTCSBridgeError(code, "unreadable mapping") from exc
    else:
        return value
    copied: dict[Any, Any] = {}
    for key, item in pairs:
        if not issubclass(type(key), str):
            raise OTCSBridgeError(code, "a key that is not text")
        key = str.__str__(key)
        if key in copied:
            raise OTCSBridgeError(code, "a key named twice")
        copied[key] = _plain_copy(item, code, depth + 1)
    return copied


def _time(value: Any, code: str) -> str:
    if not _is(value, str):
        raise OTCSBridgeError(code, "invalid timestamp")
    value = _plain_text(value)
    try:
        parse_utc(value)
    except (ContractViolation, ValueError) as exc:
        raise OTCSBridgeError(code, "invalid timestamp") from exc
    return value


def _canonical_text(value: Mapping[str, Any]) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise OTCSBridgeError("OTCS_BRIDGE_JSON", "not canonicalizable") from exc


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


@dataclass(frozen=True)
class OTCSHashRef:
    """A typed OTCS digest.  ``digest`` is accepted as an opaque OTCS fact."""

    object_kind: str
    object_id: str
    hash_profile: str
    digest: str

    def __post_init__(self) -> None:
        # Every field is kept as the helper's answer: see the note above `_plain_text`.
        object.__setattr__(
            self, "object_kind", _identifier(self.object_kind, "OTCS_HASH_OBJECT_KIND"))
        object.__setattr__(self, "object_id", _text(self.object_id, "OTCS_HASH_OBJECT_ID"))
        if (
            not _is(self.hash_profile, str)
            or _plain_text(self.hash_profile) != OTCS_HASH_PROFILE
        ):
            raise OTCSBridgeError("OTCS_HASH_PROFILE", _stored_reason(self.hash_profile))
        object.__setattr__(self, "hash_profile", OTCS_HASH_PROFILE)
        object.__setattr__(self, "digest", _sha256(self.digest, "OTCS_HASH_DIGEST"))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "OTCSHashRef":
        mapped = _closed(
            value,
            {"object_kind", "object_id", "hash_profile", "digest"},
            "OTCS_HASH_REF_FIELDS",
        )
        return cls(**mapped)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "object_kind": self.object_kind,
            "object_id": self.object_id,
            "hash_profile": self.hash_profile,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class OTCSHeadRef:
    """The exact OTCS project head against which the append must CAS."""

    project_id: str
    governing_object_kind: str
    governing_digest: OTCSHashRef
    project_sequence: int
    event_id: str
    event_digest: OTCSHashRef
    history_digest: OTCSHashRef

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "project_id", _identifier(self.project_id, "OTCS_HEAD_PROJECT_ID"))
        object.__setattr__(
            self,
            "governing_object_kind",
            _identifier(self.governing_object_kind, "OTCS_HEAD_OBJECT_KIND"),
        )
        object.__setattr__(
            self, "project_sequence", _integer(self.project_sequence, "OTCS_HEAD_SEQUENCE"))
        object.__setattr__(self, "event_id", _identifier(self.event_id, "OTCS_HEAD_EVENT_ID"))
        _exact(self.governing_digest, OTCSHashRef, "OTCS_HASH_REF_FIELDS")
        _exact(self.event_digest, OTCSHashRef, "OTCS_HASH_REF_FIELDS")
        _exact(self.history_digest, OTCSHashRef, "OTCS_HASH_REF_FIELDS")
        if self.governing_digest.object_kind != self.governing_object_kind:
            raise OTCSBridgeError("OTCS_HEAD_GOVERNING_KIND_MISMATCH")
        if (
            self.event_digest.object_kind != "project_event"
            or self.event_digest.object_id != self.event_id
        ):
            raise OTCSBridgeError("OTCS_HEAD_EVENT_REF_MISMATCH")
        if self.history_digest.object_kind != "project_history":
            raise OTCSBridgeError("OTCS_HEAD_HISTORY_KIND")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "OTCSHeadRef":
        mapped = _closed(
            value,
            {
                "project_id",
                "governing_object_kind",
                "governing_digest",
                "project_sequence",
                "event_id",
                "event_digest",
                "history_digest",
            },
            "OTCS_HEAD_FIELDS",
        )
        return cls(
            project_id=mapped["project_id"],
            governing_object_kind=mapped["governing_object_kind"],
            governing_digest=OTCSHashRef.from_mapping(mapped["governing_digest"]),
            project_sequence=mapped["project_sequence"],
            event_id=mapped["event_id"],
            event_digest=OTCSHashRef.from_mapping(mapped["event_digest"]),
            history_digest=OTCSHashRef.from_mapping(mapped["history_digest"]),
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "governing_object_kind": self.governing_object_kind,
            "governing_digest": self.governing_digest.to_mapping(),
            "project_sequence": self.project_sequence,
            "event_id": self.event_id,
            "event_digest": self.event_digest.to_mapping(),
            "history_digest": self.history_digest.to_mapping(),
        }


@dataclass(frozen=True)
class OTCSAppendOperation:
    """One candidate OTCS event, before NC2.5 admission."""

    bridge_version: str
    project_id: str
    event_id: str
    event_type: str
    project_sequence: int
    idempotency_key: str
    effective_at: str
    target_system_id: str
    registry_mode: str
    governing_object: OTCSHashRef
    payload: OTCSHashRef
    expected_head: OTCSHeadRef
    legal_evidence: tuple[tuple[str, OTCSHashRef], ...]

    def __post_init__(self) -> None:
        keep = object.__setattr__
        if (
            not _is(self.bridge_version, str)
            or _plain_text(self.bridge_version) != OTCS_BRIDGE_VERSION
        ):
            raise OTCSBridgeError("OTCS_BRIDGE_VERSION", _stored_reason(self.bridge_version))
        keep(self, "bridge_version", OTCS_BRIDGE_VERSION)
        # In the order the fields were always checked, so a value wrong in two places is
        # refused under the same code as before.
        keep(self, "project_id", _identifier(self.project_id, "OTCS_OPERATION_PROJECT_ID"))
        keep(self, "event_id", _identifier(self.event_id, "OTCS_OPERATION_EVENT_ID"))
        keep(self, "event_type", _identifier(self.event_type, "OTCS_OPERATION_EVENT_TYPE"))
        keep(
            self,
            "project_sequence",
            _integer(self.project_sequence, "OTCS_OPERATION_SEQUENCE", 1),
        )
        keep(
            self,
            "idempotency_key",
            _identifier(self.idempotency_key, "OTCS_OPERATION_IDEMPOTENCY_KEY"),
        )
        keep(self, "effective_at", _time(self.effective_at, "OTCS_OPERATION_EFFECTIVE_AT"))
        keep(
            self, "target_system_id", _identifier(self.target_system_id, "OTCS_OPERATION_TARGET"))
        if (
            not _is(self.registry_mode, str)
            or _plain_text(self.registry_mode) not in _REGISTRY_MODES
        ):
            raise OTCSBridgeError("OTCS_REGISTRY_MODE", _stored_reason(self.registry_mode))
        keep(self, "registry_mode", _plain_text(self.registry_mode))
        _exact(self.governing_object, OTCSHashRef, "OTCS_HASH_REF_FIELDS")
        _exact(self.payload, OTCSHashRef, "OTCS_HASH_REF_FIELDS")
        _exact(self.expected_head, OTCSHeadRef, "OTCS_HEAD_FIELDS")
        # The evidence pairs are read as an exact tuple of exact pairs, so iterating them
        # runs nothing of the caller's, and a key named twice is refused rather than
        # collapsed by `dict` into whichever came last.
        if type(self.legal_evidence) is not tuple:
            raise OTCSBridgeError("OTCS_LEGAL_EVIDENCE_FIELDS", "expected a tuple of pairs")
        pairs = []
        for pair in self.legal_evidence:
            if type(pair) is not tuple or len(pair) != 2 or not _is(pair[0], str):
                raise OTCSBridgeError("OTCS_LEGAL_EVIDENCE_FIELDS", "expected a tuple of pairs")
            pairs.append(
                (
                    _plain_text(pair[0]),
                    _exact(pair[1], OTCSHashRef, "OTCS_LEGAL_EVIDENCE_FIELDS"),
                )
            )
        if len({key for key, _ in pairs}) != len(pairs):
            raise OTCSBridgeError("OTCS_LEGAL_EVIDENCE_FIELDS", "a type named twice")
        keep(self, "legal_evidence", tuple(pairs))
        if self.expected_head.project_id != self.project_id:
            raise OTCSBridgeError("OTCS_HEAD_PROJECT_MISMATCH")
        if self.project_sequence != self.expected_head.project_sequence + 1:
            raise OTCSBridgeError("OTCS_SEQUENCE_NOT_SUCCESSOR")
        if self.event_id == self.expected_head.event_id:
            raise OTCSBridgeError("OTCS_EVENT_ID_NOT_SUCCESSOR")
        if self.governing_object != self.expected_head.governing_digest:
            raise OTCSBridgeError("OTCS_GOVERNING_OBJECT_MISMATCH")
        legal = dict(self.legal_evidence)
        if set(legal) != set(OTCS_LEGAL_EVIDENCE_TYPES):
            raise OTCSBridgeError(
                "OTCS_LEGAL_EVIDENCE_FIELDS",
                f"expected={sorted(OTCS_LEGAL_EVIDENCE_TYPES)} actual={sorted(legal)}",
            )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "OTCSAppendOperation":
        mapped = _closed(
            value,
            {
                "bridge_version",
                "project_id",
                "event_id",
                "event_type",
                "project_sequence",
                "idempotency_key",
                "effective_at",
                "target_system_id",
                "registry_mode",
                "governing_object",
                "payload",
                "expected_head",
                "legal_evidence",
            },
            "OTCS_OPERATION_FIELDS",
        )
        legal = _mapping(mapped["legal_evidence"], "OTCS_LEGAL_EVIDENCE_FIELDS")
        return cls(
            bridge_version=mapped["bridge_version"],
            project_id=mapped["project_id"],
            event_id=mapped["event_id"],
            event_type=mapped["event_type"],
            project_sequence=mapped["project_sequence"],
            idempotency_key=mapped["idempotency_key"],
            effective_at=mapped["effective_at"],
            target_system_id=mapped["target_system_id"],
            registry_mode=mapped["registry_mode"],
            governing_object=OTCSHashRef.from_mapping(mapped["governing_object"]),
            payload=OTCSHashRef.from_mapping(mapped["payload"]),
            expected_head=OTCSHeadRef.from_mapping(mapped["expected_head"]),
            legal_evidence=tuple(
                (key, OTCSHashRef.from_mapping(legal[key]))
                for key in sorted(legal)
            ),
        )

    def legal_evidence_mapping(self) -> dict[str, OTCSHashRef]:
        return dict(self.legal_evidence)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "bridge_version": self.bridge_version,
            "project_id": self.project_id,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "project_sequence": self.project_sequence,
            "idempotency_key": self.idempotency_key,
            "effective_at": self.effective_at,
            "target_system_id": self.target_system_id,
            "registry_mode": self.registry_mode,
            "governing_object": self.governing_object.to_mapping(),
            "payload": self.payload.to_mapping(),
            "expected_head": self.expected_head.to_mapping(),
            "legal_evidence": {
                key: value.to_mapping() for key, value in self.legal_evidence
            },
        }


@dataclass(frozen=True)
class OTCSReceiptRef:
    """Content-addressed receipt returned by a successful OTCS append."""

    receipt_id: str
    project_id: str
    event_id: str
    project_sequence: int
    idempotency_key: str
    previous_head: OTCSHeadRef
    event_digest: OTCSHashRef
    receipt_digest: OTCSHashRef
    issuer_id: str
    operator_epoch: str
    key_id: str
    effective_at: str
    signature_ref: str
    log_root: OTCSHashRef
    inclusion_proof_ref: str

    def __post_init__(self) -> None:
        # Each field is kept as the helper's answer, so a receipt compared with its
        # operation is compared by characters: see the note above `_plain_text`.
        keep = object.__setattr__
        for name, code in (
            ("receipt_id", "OTCS_RECEIPT_ID"),
            ("project_id", "OTCS_RECEIPT_PROJECT_ID"),
            ("event_id", "OTCS_RECEIPT_EVENT_ID"),
            ("idempotency_key", "OTCS_RECEIPT_IDEMPOTENCY_KEY"),
            ("issuer_id", "OTCS_RECEIPT_ISSUER"),
            ("operator_epoch", "OTCS_RECEIPT_EPOCH"),
            ("key_id", "OTCS_RECEIPT_KEY_ID"),
        ):
            keep(self, name, _identifier(getattr(self, name), code))
        keep(
            self,
            "project_sequence",
            _integer(self.project_sequence, "OTCS_RECEIPT_SEQUENCE", 1),
        )
        keep(self, "effective_at", _time(self.effective_at, "OTCS_RECEIPT_EFFECTIVE_AT"))
        keep(self, "signature_ref", _text(self.signature_ref, "OTCS_RECEIPT_SIGNATURE_REF"))
        keep(
            self,
            "inclusion_proof_ref",
            _text(self.inclusion_proof_ref, "OTCS_RECEIPT_PROOF_REF"),
        )
        _exact(self.previous_head, OTCSHeadRef, "OTCS_HEAD_FIELDS")
        _exact(self.event_digest, OTCSHashRef, "OTCS_HASH_REF_FIELDS")
        _exact(self.receipt_digest, OTCSHashRef, "OTCS_HASH_REF_FIELDS")
        _exact(self.log_root, OTCSHashRef, "OTCS_HASH_REF_FIELDS")
        if (
            self.event_digest.object_kind != "project_event"
            or self.event_digest.object_id != self.event_id
        ):
            raise OTCSBridgeError("OTCS_RECEIPT_EVENT_REF_MISMATCH")
        if (
            self.receipt_digest.object_kind != "append_receipt"
            or self.receipt_digest.object_id != self.receipt_id
        ):
            raise OTCSBridgeError("OTCS_RECEIPT_DIGEST_REF_MISMATCH")
        if self.log_root.object_kind != "transparency_log_root":
            raise OTCSBridgeError("OTCS_RECEIPT_LOG_ROOT_KIND")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "OTCSReceiptRef":
        mapped = _closed(
            value,
            {
                "receipt_id",
                "project_id",
                "event_id",
                "project_sequence",
                "idempotency_key",
                "previous_head",
                "event_digest",
                "receipt_digest",
                "issuer_id",
                "operator_epoch",
                "key_id",
                "effective_at",
                "signature_ref",
                "log_root",
                "inclusion_proof_ref",
            },
            "OTCS_RECEIPT_FIELDS",
        )
        return cls(
            receipt_id=mapped["receipt_id"],
            project_id=mapped["project_id"],
            event_id=mapped["event_id"],
            project_sequence=mapped["project_sequence"],
            idempotency_key=mapped["idempotency_key"],
            previous_head=OTCSHeadRef.from_mapping(mapped["previous_head"]),
            event_digest=OTCSHashRef.from_mapping(mapped["event_digest"]),
            receipt_digest=OTCSHashRef.from_mapping(mapped["receipt_digest"]),
            issuer_id=mapped["issuer_id"],
            operator_epoch=mapped["operator_epoch"],
            key_id=mapped["key_id"],
            effective_at=mapped["effective_at"],
            signature_ref=mapped["signature_ref"],
            log_root=OTCSHashRef.from_mapping(mapped["log_root"]),
            inclusion_proof_ref=mapped["inclusion_proof_ref"],
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "project_id": self.project_id,
            "event_id": self.event_id,
            "project_sequence": self.project_sequence,
            "idempotency_key": self.idempotency_key,
            "previous_head": self.previous_head.to_mapping(),
            "event_digest": self.event_digest.to_mapping(),
            "receipt_digest": self.receipt_digest.to_mapping(),
            "issuer_id": self.issuer_id,
            "operator_epoch": self.operator_epoch,
            "key_id": self.key_id,
            "effective_at": self.effective_at,
            "signature_ref": self.signature_ref,
            "log_root": self.log_root.to_mapping(),
            "inclusion_proof_ref": self.inclusion_proof_ref,
        }


class SQLiteOTCSOutbox:
    """Small durable state machine around the OTCS/NC2.5 commit seam."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        # Under the lock, as every other connection in this class is taken - for that
        # discipline and nothing more. The lock is this instance's own, made on the line
        # above, so during construction no other thread can hold it, and two
        # constructions on one path each take their own: it serialises nothing between
        # them, in one block or in two. What keeps two racing constructions harmless is
        # `IF NOT EXISTS`. A statement outside the lock would be one nobody reading the
        # rest of the class expects, which is the whole reason it is inside.
        with self._lock, closing(self._connect(require_table=False)) as connection:
            # Under the same classifier as the header read in `_connect`. That read was
            # described as running "before anything else on this connection", and this
            # create ran on the same connection outside any guard: measured, a file whose
            # hundred-byte header is valid and whose schema page is overwritten passes the
            # read and raises `database disk image is malformed` HERE, past this module.
            # Through `_translate`, for the reason the engine's constructor gives at the
            # same place: `refuse_unreadable_database` answers None for the CONSTRAINT
            # class by design, so an `IntegrityError` raised INSIDE
            # `refuse_stored_artefact` - by `connection.execute(CREATE)` - would leave this
            # module as the driver's own exception WITHOUT this wrapper; with it, the
            # translator names it. Defensive, and said as such: this said
            # the error "left", as if observed, while the engine's own measurement holds
            # here too - a `CREATE TABLE IF NOT EXISTS` over a foreign table raises
            # nothing, and DDL reaches the constraint class only by building a unique index
            # over rows that already hold duplicates. This schema's primary key does build
            # one - `sqlite_autoindex_otcs_bridge_outbox_1`, measured - but only with the
            # table, over no rows, and `IF NOT EXISTS` builds nothing over a table already
            # there; an earlier form of this said the schema built none. Should an index over
            # stored rows ever be added, the translator's
            # detail is worded for a ROW write and would need its own. That is what the
            # wrapper covers, and all it covers: the `raise` below stands outside the
            # `_translate` block - still inside the lock and the connection - so on the
            # artefact path, a driver error the classifier attributes to the stored file,
            # which the helper returns rather than raises, the refusal is named because this
            # code re-raises it by hand, not because the translator answered. Two paths, two
            # namers: a constraint by the translator, an artefact by the line below.
            with self._translate():
                refusal = refuse_stored_artefact(
                    connection,
                    (
                    """
                CREATE TABLE IF NOT EXISTS otcs_bridge_outbox (
                    project_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    operation_hash TEXT NOT NULL,
                    permit_hash TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    receipt_json TEXT,
                    execution_request_json TEXT,
                    local_receipt_json TEXT,
                    rejection_code TEXT,
                    last_error TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (project_id, idempotency_key),
                    CHECK (state IN (
                        'PREPARED', 'CALLING', 'AMBIGUOUS',
                        'DOWNSTREAM_COMMITTED', 'DOWNSTREAM_REJECTED',
                        'NOT_EXECUTED',
                        'LOCAL_COMMITTED', 'LOCAL_FAILED',
                        'RECONCILIATION_REQUIRED'
                    ))
                )
                """,
                ),
            )
            if refusal is not None:
                detail, cause = refusal
                raise OTCSBridgeError("OTCS_OUTBOX_COLUMNS", detail) from cause
            # The last statement of the construction, under the same translation as the
            # create it finishes. It was outside every guard while the statements around
            # it were inside - found by reading the list this file's own comment gives.
            with self._translate():
                connection.commit()
        # The subject here is the table of THIS name, not the file: a database already
        # holding other tables is adopted, and the create adds ours beside them. Measured -
        # a file carrying one unrelated table is accepted and comes back carrying two.
        # Nothing in this module claims the file exclusively, and refusing a shared one
        # would forbid co-locating this outbox with the engine's own state.
        # The create connection above skips the column guard, because the table may not
        # exist yet - and `CREATE TABLE IF NOT EXISTS` does nothing when a foreign table is
        # already there. Without this checked open, a table missing a column was refused
        # only at the first public read, and a table with an undeclared column was not
        # refused anywhere.
        with self._lock:
            self._connect().close()

    def _connect(self, *, require_table: bool = True) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        # The FIRST statement that touches the file, guarded. It is not the only guarded
        # one, and this comment used to say it ran "before anything else on this
        # connection", which read as a promise that everything after it was covered: the
        # create the constructor performs ran on this same connection outside any guard.
        # Measured both halves. Without this prologue the bridge escaped with
        # sqlite3.DatabaseError on a path that is not a database, while the state store,
        # whose own prologue was already guarded, refused by name. And with the prologue
        # but without a guard on the create, a file whose hundred-byte header is valid and
        # whose schema page is overwritten PASSES here and raises `database disk image is
        # malformed` out of the create.
        #
        # What is guarded, said as a list rather than as "every statement", which is what
        # stood here and was never true. The guards in this file, each named by what it
        # wraps: this prologue, inline, just below; the COLUMN read further down, which has
        # its own try/except and was folded into "the prologue" by an earlier form of this
        # list; the create, in the constructor, through `refuse_stored_artefact` under its
        # own `_translate`; the COMMIT that finishes it, under a `_translate` of its own; and
        # `_rows`, one guard around every statement a public call runs against ROWS. A guard
        # wraps one statement or many - the create is one, `_rows` is all of a call's - and
        # the list counts guards, not statements. It is named rather than counted: its
        # figure went stale once already, when the create and the commit stopped sharing a
        # wrapper and the number beside the list did not move. The list is of the FILE, not
        # of one connection: each connection passes the guards on its own path, and the
        # constructor's create connection, opened with `require_table=False`, never runs
        # the column read - the checked connection the constructor opens after the create
        # does.
        #
        # What each one consults, said per failure, because "every guard asks the
        # classifier" stood here and was true of one failure only. For a driver error that
        # is NOT a constraint failure, every one of them consults `refuse_unreadable_database`,
        # the one home for that classification. A constraint failure is the one thing that
        # function answers None for, on purpose, and `_translate` answers it itself, by the
        # exception's class rather than by the code, as a column refusal: on this module's
        # own writes a constraint can only be one the stored table carries. So the guards
        # that go through `_translate` - the create, the commit, and `_rows` - answer both,
        # and the inline handlers - the prologue and the column read - answer only the
        # first, because the statements they run read and never write. The create asked the
        # classifier, got None for a constraint, and was re-raised raw until it too ran
        # through `_translate`: asking is not being answered.
        # The row guard was added after a measurement:
        # a corrupt DATA page under an intact schema page passes both reads here and left
        # a raw driver error out of a public read.
        try:
            # `schema_version` reads the database header; a connection-level setting such
            # as `busy_timeout` does not touch the file at all and would guard nothing.
            connection.execute("PRAGMA schema_version")
        except sqlite3.DatabaseError as exc:
            unreadable = refuse_unreadable_database(exc)
            connection.close()
            if unreadable is None:
                raise
            raise OTCSBridgeError("OTCS_OUTBOX_COLUMNS", unreadable) from exc
        # Same reason as the engine's state store, which is where the factory lives: a
        # TEXT column that is not valid UTF-8 fails inside the driver at the fetch, before
        # the decoder can refuse it, and no bridge code names that. Decoded this way the
        # value reaches `_decoded`, which refuses it as an unreadable row.
        connection.text_factory = _decode_stored_text
        if require_table:
            # The bridge accepts an outbox table it did not create, so the
            # table's columns are checked before any statement names one: a
            # missing column raised sqlite3.OperationalError from the query or
            # KeyError from the row decoder, past the bridge vocabulary.
            # The comparison is in BOTH directions. A table carrying every
            # declared column plus others used to pass, because only
            # `declared - present` was taken, and `SELECT *` then carried the
            # undeclared values into the decoded record and out through
            # `outbox_record`: a shape no declared reading describes.
            # The reading statement is itself a statement: a path holding bytes that are
            # not a SQLite database makes it raise before any guard here runs, which is
            # this module's own class one layer up. The engine's helper decides which
            # driver errors mean "not our store" and which are transient.
            try:
                columns = list(connection.execute("PRAGMA table_xinfo(otcs_bridge_outbox)"))
                # Read the actual key index, not its SQL spelling. Column collations and
                # index collations can differ; only a binary key preserves exact identifiers.
                key_collations = list(connection.execute(
                    "SELECT k.name, k.coll FROM pragma_index_list('otcs_bridge_outbox') AS i "
                    "JOIN pragma_index_xinfo(i.name) AS k WHERE i.origin = 'pk' AND k.key = 1"
                ))
            except sqlite3.DatabaseError as exc:
                unreadable = refuse_unreadable_database(exc)
                connection.close()
                if unreadable is None:
                    raise
                raise OTCSBridgeError("OTCS_OUTBOX_COLUMNS", unreadable) from exc
            detail = columns_detail(_OUTBOX_COLUMNS, {row[1] for row in columns})
            if detail:
                connection.close()
                raise OTCSBridgeError("OTCS_OUTBOX_COLUMNS", detail)
            # The declared shape includes its KEY, and the names alone did not ask for it.
            # The create statement does nothing when a foreign table of that name is already
            # there, and a constraint is not retrofitted: a table carrying exactly our
            # twelve columns and no primary key was admitted, two rows sharing a project and
            # an idempotency key lived in it, and `get` answered with whichever the driver
            # reached first - measured, against our own table, which refuses the second row
            # itself. Idempotency is what that key carries, so a table without it is not
            # this outbox whatever its columns are called. The same rows already read
            # report the key: `table_xinfo` gives each column's position in it, zero for a
            # column outside it. The detail names the key that IS there, since the one that
            # should be is this module's own declaration.
            key = {row[1] for row in columns if row[5]}
            if key != _OUTBOX_KEY:
                connection.close()
                raise OTCSBridgeError(
                    "OTCS_OUTBOX_COLUMNS",
                    "primary key %s" % (", ".join(sorted(key)) if key else "absent"))
            if ({row[0] for row in key_collations} != _OUTBOX_KEY
                    or any(row[1].upper() != "BINARY" for row in key_collations)):
                connection.close()
                raise OTCSBridgeError("OTCS_OUTBOX_COLUMNS", "primary key collation is not BINARY")
        return connection

    @contextmanager
    def _rows(self):
        """Open the outbox for statements that read and write rows, refusing by name.

        The prologue and the create are guarded where they stand; these are the rest, and
        until this existed they were the layer where a stored artefact still left raw.
        Measured: a corrupt data page under an intact schema page passes the header read
        and the column read, and the SELECT then raised `database disk image is malformed`
        out of `get`.

        A constraint failure is answered separately and deliberately. This module's writes
        satisfy this module's declaration by construction - `transition` refuses a state
        outside `_OUTBOX_STATES` before it writes, and `prepare` inserts under
        BEGIN IMMEDIATE after finding no row - so a constraint that fires is one the stored
        table carries and this store did not declare. Measured: a table with our twelve
        names and `receipt_json TEXT NOT NULL` is accepted by the name guard, because that
        guard compares names by design, and the first INSERT then left a raw IntegrityError.
        """
        with self._lock, closing(self._connect()) as connection:
            with self._translate():
                yield connection

    @contextmanager
    def _translate(self):
        """The translation alone, without opening anything.

        Split out so the CONSTRUCTOR can use it: its commit runs on a connection this class
        already holds, and it was the one statement on a stored file left outside. Splitting
        rather than repeating keeps one body for the decision - a second copy of these two
        branches is how the two halves of a question drift apart.
        """
        try:
            yield
        except sqlite3.IntegrityError as exc:
            raise OTCSBridgeError(
                "OTCS_OUTBOX_COLUMNS",
                "constraint not declared by this store",
            ) from exc
        except sqlite3.DatabaseError as exc:
            unreadable = refuse_unreadable_database(exc)
            if unreadable is None:
                raise
            raise OTCSBridgeError("OTCS_OUTBOX_COLUMNS", unreadable) from exc

    @staticmethod
    def _decoded(row: sqlite3.Row | None) -> dict[str, Any] | None:
        def _refuse_unwritable(value: Any, field: str) -> None:
            """Refuse what in `value` cannot be written back, naming its column.

            Three things: a string that will not encode, a number the canonical form
            refuses, a value nested past the engine's limit. One home, because the question
            is asked twice - of the stored text and of what the parse produced - and the two
            must not drift. Keys as well as values: a surrogate in a key is written back
            with the rest of the object.

            The first of its two call sites hands it only the raw columns that are STRINGS.
            Raw values are flat - the driver returns scalars - but they need not be strings:
            the column guard compares NAMES, so a stored table declaring those names with
            other types, or with none, passes it. Measured under this connection's own text
            factory, with TEXT as the control: a declared type's affinity converts on the
            way in - TEXT turns a stored number into a str, INTEGER and REAL turn numeric
            text into numbers and leave other text a str - and BLOB, or no declared type,
            converts nothing, so a value comes back as what was stored: a str, an int, a
            float or bytes. This said BLOB and no type return bytes, which the bridge's own
            typeless sweep table contradicts, since its stored strings come back as strings.
            The non-strings are not this walk's to judge, and handing them to it was a
            defect: its float branch, which exists for what the parse produces, refused a
            non-finite REAL in a plain column as OTCS_OUTBOX_ROW_JSON, while a finite one in
            the same column met the shape check as OTCS_OUTBOX_ROW_TEXT - two codes for one
            fact. They are refused further on: in a JSON column as OTCS_OUTBOX_ROW_JSON
            before the parse; in `state` as OTCS_OUTBOX_STATE by the state check, which runs
            first and which the shape check then skips; in every other plain column as
            OTCS_OUTBOX_ROW_TEXT by the shape check. Named here because what this walk
            leaves alone is refused elsewhere, and a sentence calling that self-evident
            would survive those checks' removal.

            Walked with an explicit stack rather than by recursion, and the reason belongs
            to the SECOND call site, which walks what the parse produced. That one runs
            OUTSIDE the `except` that turns a
            RecursionError from the parse into a refusal, and on 3.12 the parser's C limit
            (1500) is above the interpreter's Python limit (1000): a stored array nested
            between the two parses and would then exhaust the stack HERE, leaving as a bare
            RecursionError under no code of ours. An explicit stack removes the failure
            rather than catching it.

            The stack alone was NOT enough, and the sentence here said it was. A value
            deep enough to exhaust `copy.deepcopy` in the public read - roughly two frames
            per level against a 1000-frame limit - but shallow enough for the parser still
            parsed, walked and returned, and died two calls later under no code of ours.
            So the walk also applies the engine's MAX_NESTING_DEPTH to the parsed
            structure: the same limit a submitted document meets, read from the same place,
            and - since the boundary was measured - applied at the same level. The first
            form of this seeded the top-level value at 1 and so refused a document of
            exactly MAX containers that the wire admits, which would have made a row the
            engine accepts unreadable by every public call. Only with both does the answer stop depending on which of the
            interpreter's limits is smaller.
            """
            # Seeded at 0, so the bound here is the bound on the wire and not one level
            # stricter. Measured at the boundary with MAX_NESTING_DEPTH = 64: with the
            # top-level value seeded at 1, a document of exactly 64 containers was ADMITTED
            # by the adapter's scan and REFUSED here, so a row the engine accepts through
            # the wire could not be read back through any public call and nothing repaired
            # it. The adapter counts opening brackets from zero; counting values from one
            # visits a scalar inside N containers at N+1. At 63 and at 65 the two agreed,
            # which is why only a case at exactly the limit shows it.
            pending = [(value, 0)]
            while pending:
                item, depth = pending.pop()
                # Depth is carried because this walk is the only place that visits every
                # node of the parsed value, and the engine's limit has to be applied to a
                # STORED structure as well as to a submitted one. Without it a value in
                # the band between the parser's own limit and the interpreter's recursion
                # limit parses here, passes every guard, and then dies in the
                # `copy.deepcopy` of the public read - a bare RecursionError under no code
                # of ours, which is the class this decoder exists to close, one layer
                # further out. Measured: at 400 levels the value parses and copies; at
                # 600 it parses and the copy raises.
                if isinstance(item, (Mapping, list, tuple)) and depth >= MAX_NESTING_DEPTH:
                    # Counted on ENTERING a container, because that is what the wire
                    # counts: its scan counts opening brackets, so its depth is the number
                    # of containers. Counting visited NODES agreed only for values whose
                    # deepest node is a scalar - a container's own depth is one less than
                    # its members', so a value ending in an EMPTY container has no node at
                    # the depth its bracket count implies. The earlier node count did
                    # exactly that: at one past the limit with a scalar inside both
                    # refused, while with the innermost container empty the wire refused
                    # and the walk admitted. The two now agree on every shape measured -
                    # 63, 64 and 65 containers with a scalar at the bottom, 64 and 65 with
                    # an empty container at the bottom - and the stored-document case holds
                    # both to those shapes, 63 with an empty bottom added.
                    raise OTCSBridgeError(
                        "OTCS_OUTBOX_ROW_JSON",
                        "%s: nested past %d" % (field, MAX_NESTING_DEPTH))
                if isinstance(item, str):
                    # The same predicate admission asks, and for the same reason: this
                    # decides whether the value can be written back, and admission decides
                    # whether it should ever have been written at all.
                    if not _storable_text(item):
                        raise OTCSBridgeError("OTCS_OUTBOX_ROW_TEXT", field)
                elif isinstance(item, float) and not math.isfinite(item):
                    # The same question as the line above, asked of a number. A float is
                    # not a string, so it matched no branch of this walk and was never
                    # examined: `json.loads` admits the bare tokens NaN, Infinity and
                    # -Infinity, and this module's canonical dump passes allow_nan=False,
                    # so such a value travelled the whole recovery path and died at the
                    # LAST step - after the engine-side effect was committed, under no
                    # code of ours. Refused here, before the effect, which is the same
                    # reason the text check stands where it stands.
                    #
                    # The predicate is finiteness rather than a test for NaN, because the
                    # rule it must agree with is the dump's own: allow_nan=False refuses
                    # exactly the non-finite. Three tokens were measured; naming them
                    # would have closed three shapes and left the class open.
                    #
                    # The code is the JSON one and not a new name: the family is already
                    # "the stored JSON carries what our canonical form cannot express",
                    # which is what that code says, and the detail carries the rest.
                    raise OTCSBridgeError(
                        "OTCS_OUTBOX_ROW_JSON",
                        "%s: not a finite number" % field)
                elif isinstance(item, Mapping):
                    for key, member in item.items():
                        pending.append((key, depth + 1))
                        pending.append((member, depth + 1))
                elif isinstance(item, (list, tuple)):
                    pending.extend((member, depth + 1) for member in item)

        if row is None:
            return None
        result = dict(row)
        # A stored TEXT column that is not valid UTF-8 arrives here as lone surrogates,
        # because the connection decodes with surrogateescape rather than letting the
        # driver fail at the fetch. Such a value survives json.dumps and dies at the first
        # encode, under no code of ours. Traced, not inferred: the sweep's recovery case
        # went recover -> _advance -> transition -> connection.execute, and raised
        # UnicodeEncodeError where the driver encodes the parameter on the way BACK into
        # the database - a value read two calls earlier killing a write.
        # It is refused here, where the column has a name to put in the detail. The test is
        # the round trip rather than `isascii` because its subject is the write-back - it
        # refuses exactly what cannot be stored again. Measured, and no live difference:
        # every value this module writes into `last_error` is a refusal code or an
        # exception's type name, both ASCII, and swapping the round trip for an ASCII test
        # leaves the whole bridge suite green. The round trip is the one that stays right
        # if a future writer stores text. Strings only: see the walk's docstring for why a
        # raw number or BLOB is left to the checks that name its column's shape.
        for field, value in result.items():
            if type(value) is str:
                _refuse_unwritable(value, field)
        # Which JSON columns were NULL in the store, kept because the parse erases it: the
        # text `null` parses to None as well, and the shape check below saw one value for
        # two different stored things and named both "null". Consulted where a null is
        # refused, which is `request_json` alone. In the three nullable columns both read as
        # absence, deliberately: this module writes NULL there for "none", so a stored
        # `null` is foreign text that means the same thing, and nothing downstream could
        # tell the two apart if it were kept.
        sql_null = set()
        for field in (
            "request_json",
            "receipt_json",
            "execution_request_json",
            "local_receipt_json",
        ):
            raw = result.pop(field)
            # Recorded only where a null is refused, which is the one place it is read:
            # the nullable columns are let through before the set is asked.
            if raw is None and field not in _OUTBOX_NULLABLE:
                sql_null.add(field)
            # Text first, and refused as text: `json.loads` accepts BYTES, so a BLOB of
            # valid JSON in a column the schema declares TEXT parsed and came back as the
            # record - measured on a typeless table, the row's own document stored as a
            # BLOB, with invalid bytes and an integer as controls, which the parse did
            # refuse. The driver hands a TEXT column back as an exact `str`.
            if raw is not None and type(raw) is not str:
                raise OTCSBridgeError("OTCS_OUTBOX_ROW_JSON", "%s: not text" % field)
            # The outbox is plain SQLite and carries no MAC, and a deployment
            # may hand the bridge a table this module did not create. A stored
            # column that does not parse - invalid text, an integer literal
            # past the digit limit, an array nested past the interpreter's
            # recursion limit - is refused with its own code; json.loads raised
            # it past the bridge vocabulary before. RecursionError is not a
            # ValueError, and no nesting scan runs here as it does before the
            # wire adapter's parse. A value that is not text never gets here -
            # it is refused just above - so the parse is handed a str or None,
            # and a TypeError, which is what it raised on a number (bytes it
            # parsed), is no longer one of its answers.
            try:
                result[field.removesuffix("_json")] = (
                    json.loads(raw) if raw is not None else None
                )
            except (ValueError, RecursionError) as exc:
                raise OTCSBridgeError("OTCS_OUTBOX_ROW_JSON", field) from exc
            # And whether what parsed is a DOCUMENT. Every value this module writes into
            # these four columns is an object; the parse admits any JSON value, so a stored
            # `[]` came back as the record's `request` and `7` came back as `request=7` -
            # measured, with an object as the control - and `outbox_record` handed both to a
            # caller that has no such shape to read. Asked before the walk below, because
            # whether this is a document at all comes before what its values are made of.
            parsed = result[field.removesuffix("_json")]
            if parsed is not None and type(parsed) is not dict:
                raise OTCSBridgeError(
                    "OTCS_OUTBOX_ROW_JSON", "%s: not an object" % field)
            # And again over what the parse produced. The loop above proves only that the
            # STORED text encodes: a JSON column whose text is pure ASCII can carry the
            # escape `\udXXX`, which parses into a lone surrogate, and that value is then
            # written back verbatim - the receipt is, having no shape check on the recovery
            # path - so the same driver encode dies, after the engine-side effect and under
            # no code. The first loop cannot see it, because the bytes it examines are
            # innocent.
            _refuse_unwritable(result[field.removesuffix("_json")], field)
        # The stored value is the detail only when it is text: `detail` is a string by its
        # declaration, and a BLOB here - which the shape check below never sees, because
        # it skips the column this line answers - handed the refusal raw bytes. Anything
        # else is said the way the shape check says it for every other column: NULL as
        # null, and every other value that is not text - bytes or a number - as not text.
        state = result["state"]
        if state not in _OUTBOX_STATES:
            detail = (state if type(state) is str
                      else "state: null" if state is None else "state: not text")
            raise OTCSBridgeError("OTCS_OUTBOX_STATE", detail)
        # And the SHAPE the schema declares, which the storability walk never asked: it
        # tests strings and passes every non-string through. Measured on a stored table
        # with the module's names and no types, the unmodified row as control: a BLOB or an
        # integer in `last_error`, `operation_hash`, `permit_hash`, `rejection_code` or
        # `updated_at` came back from `outbox_record` as `bytes` or `int` - a record no
        # declared reading describes, the same reason the undeclared column is refused. The
        # sweep saw it and passed, because it counted only exceptions that left the
        # vocabulary; an answer of the wrong shape counted as an answer. Every plain column
        # is text, or NULL where the schema allows it. The JSON columns are asked only
        # whether NULL is allowed, under their own code - a non-text value there was
        # refused before the parse - and of the four only `request_json` is declared NOT
        # NULL, so it is the one this can refuse.
        # Asked AFTER the state check, and the order is a decision: a row with an unknown
        # state is answered by the more specific code, which two cases pin, and the
        # question here still reaches every row whose state is one of the nine.
        for field, value in result.items():
            if field == "state":
                continue
            stored = field + "_json" if field + "_json" in _OUTBOX_COLUMNS else field
            if value is None:
                if stored in _OUTBOX_NULLABLE:
                    continue
                # Two literal raises and not one with a chosen code: the vocabulary is
                # read statically, and a raise whose code is an expression is one no
                # scanner of this tree can classify.
                if stored.endswith("_json"):
                    raise OTCSBridgeError(
                        "OTCS_OUTBOX_ROW_JSON",
                        "%s: %s" % (stored, "null" if stored in sql_null else "JSON null"))
                raise OTCSBridgeError("OTCS_OUTBOX_ROW_TEXT", "%s: null" % stored)
            if not stored.endswith("_json") and not isinstance(value, str):
                raise OTCSBridgeError("OTCS_OUTBOX_ROW_TEXT", "%s: not text" % stored)
        return result

    def get(self, project_id: str, idempotency_key: str) -> dict[str, Any] | None:
        # Every key predicate explicitly selects binary equality. An adopted table may
        # give its columns NOCASE while its primary key correctly uses BINARY.
        with self._rows() as connection:
            row = connection.execute(
                "SELECT " + _OUTBOX_PROJECTION + " FROM otcs_bridge_outbox "
                "WHERE project_id COLLATE BINARY = ? AND idempotency_key COLLATE BINARY = ?",
                (project_id, idempotency_key),
            ).fetchone()
        return self._decoded(row)

    def prepare(
        self,
        operation: OTCSAppendOperation,
        operation_hash: str,
        permit_hash: str,
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        request_text = _canonical_text(request)
        with self._rows() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT " + _OUTBOX_PROJECTION + " FROM otcs_bridge_outbox "
                "WHERE project_id COLLATE BINARY = ? AND idempotency_key COLLATE BINARY = ?",
                (operation.project_id, operation.idempotency_key),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO otcs_bridge_outbox "
                    "(project_id, idempotency_key, operation_hash, permit_hash, "
                    "request_json, state, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        operation.project_id,
                        operation.idempotency_key,
                        operation_hash,
                        permit_hash,
                        request_text,
                        "PREPARED",
                        _utc_now(),
                    ),
                )
            else:
                existing = self._decoded(row)
                if (
                    existing is None
                    or existing["operation_hash"] != operation_hash
                    or existing["permit_hash"] != permit_hash
                    or _canonical_text(existing["request"]) != request_text
                ):
                    raise OTCSBridgeError("OTCS_IDEMPOTENCY_CONFLICT")
            connection.commit()
        record = self.get(operation.project_id, operation.idempotency_key)
        if record is None:
            raise OTCSBridgeError("OTCS_OUTBOX_MISSING")
        return record

    def transition(
        self,
        project_id: str,
        idempotency_key: str,
        expected_states: set[str],
        new_state: str,
        *,
        receipt: Mapping[str, Any] | None = None,
        execution_request: Mapping[str, Any] | None = None,
        local_receipt: Mapping[str, Any] | None = None,
        rejection_code: str | None = None,
        last_error: str | None = None,
    ) -> dict[str, Any]:
        if new_state not in _OUTBOX_STATES or not expected_states <= _OUTBOX_STATES:
            raise OTCSBridgeError("OTCS_OUTBOX_TRANSITION")
        with self._rows() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT state FROM otcs_bridge_outbox "
                "WHERE project_id COLLATE BINARY = ? AND idempotency_key COLLATE BINARY = ?",
                (project_id, idempotency_key),
            ).fetchone()
            if row is None:
                raise OTCSBridgeError("OTCS_OUTBOX_MISSING")
            if row["state"] not in expected_states:
                raise OTCSBridgeError(
                    "OTCS_OUTBOX_CONFLICT",
                    f"expected={sorted(expected_states)} actual={row['state']}",
                )
            connection.execute(
                "UPDATE otcs_bridge_outbox SET state = ?, receipt_json = ?, "
                "execution_request_json = ?, local_receipt_json = ?, "
                "rejection_code = ?, last_error = ?, updated_at = ? "
                "WHERE project_id COLLATE BINARY = ? AND idempotency_key COLLATE BINARY = ?",
                (
                    new_state,
                    _canonical_text(receipt) if receipt is not None else None,
                    _canonical_text(execution_request)
                    if execution_request is not None
                    else None,
                    _canonical_text(local_receipt)
                    if local_receipt is not None
                    else None,
                    rejection_code,
                    last_error,
                    _utc_now(),
                    project_id,
                    idempotency_key,
                ),
            )
            connection.commit()
        record = self.get(project_id, idempotency_key)
        if record is None:
            raise OTCSBridgeError("OTCS_OUTBOX_MISSING")
        return record


class OTCSBridge:
    """Coordinate NC2.5 admission, one OTCS append, and local finalization."""

    def __init__(
        self,
        engine: UniversalConnectionLedger,
        client: OTCSClient,
        outbox_path: str | Path,
        *,
        _fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        """Attach the bridge to a durable engine and a project-idempotent client.

        Both arguments are refused rather than coerced: an engine constructed
        without ``state_path`` cannot survive the crash seam this bridge exists
        to close, and a client without ``append_event`` is not the port.

        ``_fault_hook`` is NOT part of the offered surface.  It is the seam the
        outbox regression tests use to stop the process at a named point and
        prove that recovery re-drives the row without a second downstream
        effect.  The leading underscore is the whole contract: production code
        passes nothing here.
        """
        if getattr(engine, "_state_store", None) is None:
            raise OTCSBridgeError(
                "OTCS_DURABLE_ENGINE_REQUIRED",
                "construct the ledger with state_path before attaching the bridge",
            )
        append = getattr(client, "append_event", None)
        if not callable(append):
            raise OTCSBridgeError("OTCS_CLIENT_INVALID")
        self._engine = engine
        self._client = client
        self._outbox = SQLiteOTCSOutbox(outbox_path)
        self._fault_hook = _fault_hook

    def execute(
        self,
        operation: Mapping[str, Any],
        intent: Mapping[str, Any],
        evidence_bundle: Mapping[str, Any],
    ) -> dict[str, Any]:
        # Copied once, here, and only the copies are used below: the validators, the
        # replay identity and the engine all read the same plain data. Validating a copy
        # and then handing on the original would let the two answer differently - a dict
        # subclass iterates by its own code when `dict()` copies it. See `_plain_copy`.
        operation = _plain_copy(operation, "OTCS_OPERATION_FIELDS")
        intent = _plain_copy(intent, "OTCS_INTENT_BINDING")
        evidence_bundle = _plain_copy(evidence_bundle, "OTCS_EVIDENCE_BINDING")
        candidate = OTCSAppendOperation.from_mapping(operation)
        self._validate_intent_binding(candidate, intent)
        self._validate_evidence_binding(candidate, evidence_bundle)
        operation_hash = self._submission_hash(candidate, intent, evidence_bundle)
        admission_evidence = self._admission_evidence(candidate, evidence_bundle)
        existing = self._outbox.get(candidate.project_id, candidate.idempotency_key)
        if existing is not None:
            if existing["operation_hash"] != operation_hash:
                raise OTCSBridgeError("OTCS_IDEMPOTENCY_CONFLICT")
            return self._advance(existing, recovery=False)

        # This is the only admissibility decision.  OTCS has supplied facts;
        # NC2.5 now applies the active profile/declaration and issues (or does
        # not issue) the permit before any downstream call can occur.
        operator_result = self._engine.evaluate_intent(
            intent,
            admission_evidence,
            actor_scope=ROLE_OPERATOR,
        )
        if operator_result["disposition"] != "ALLOW":
            return {
                "status": "NOT_ADMISSIBLE",
                "operator_result": copy.deepcopy(operator_result),
                "otcs_receipt": None,
                "ledger_receipt": None,
            }

        permit_hash = operator_result["permit_hash"]
        request = {
            "message_type": "otcs_append_request",
            "bridge_version": OTCS_BRIDGE_VERSION,
            "operation": candidate.to_mapping(),
            # Local recovery witness; removed from the downstream wire copy.
            "admission": {
                "intent": copy.deepcopy(intent),
                "evidence_bundle": copy.deepcopy(evidence_bundle),
            },
            "nc25_permit": {
                "permit_hash": permit_hash,
                "profile_hash": self._engine.profile_hash,
                "declaration_hash": self._engine.declaration_hash,
                "intent_id": intent["intent_id"],
                "connector_id": intent["connector_id"],
                # Only the compact declared-hash binding crosses the boundary;
                # the full NC2.5 profile and declaration remain local.
                "binding": copy.deepcopy(dict(intent["binding"])),
            },
        }
        row = self._outbox.prepare(
            candidate,
            operation_hash,
            permit_hash,
            request,
        )
        self._fault("after_prepare")
        result = self._advance(row, recovery=False)
        result["operator_result"] = copy.deepcopy(operator_result)
        return result

    def recover(self, project_id: str, idempotency_key: str) -> dict[str, Any]:
        """Resume an exact stored operation.

        CALLING and AMBIGUOUS both leave transmission uncertain. Either may
        replay the exact request by key only while its permit remains live.
        A dead permit refuses with OTCS_PERMIT_NOT_LIVE_ON_RECOVERY and leaves
        RECONCILIATION_REQUIRED, because absence of a downstream effect cannot
        be established from either state.

        A stored downstream receipt resumes local finalization without another
        OTCS call. The ledger still enforces the permit at finalization.
        """

        project_id = _identifier(project_id, "OTCS_OPERATION_PROJECT_ID")
        idempotency_key = _identifier(idempotency_key, "OTCS_OPERATION_IDEMPOTENCY_KEY")
        row = self._outbox.get(project_id, idempotency_key)
        if row is None:
            raise OTCSBridgeError("OTCS_OUTBOX_MISSING")
        return self._advance(row, recovery=True)

    def outbox_record(
        self, project_id: str, idempotency_key: str
    ) -> dict[str, Any] | None:
        """Return a defensive copy of one bridge recovery record.

        The same two identifiers are admitted the same way as at every other public door.
        They went straight to the store here while `recover`, one method above and taking
        exactly the same pair, refused a malformed one by name - so the shape a caller had
        to satisfy depended on which method it called. A door is not made safe by the
        door beside it.
        """

        project_id = _identifier(project_id, "OTCS_OPERATION_PROJECT_ID")
        idempotency_key = _identifier(idempotency_key, "OTCS_OPERATION_IDEMPOTENCY_KEY")
        record = self._outbox.get(project_id, idempotency_key)
        return copy.deepcopy(record)

    @staticmethod
    def _validate_intent_binding(
        operation: OTCSAppendOperation,
        intent: Mapping[str, Any],
    ) -> None:
        mapped = _mapping(intent, "OTCS_INTENT_BINDING")
        comparisons = {
            "action_id": OTCS_APPEND_ACTION_ID,
            "idempotency_key": operation.idempotency_key,
            "target_system_id": operation.target_system_id,
            "payload_hash": operation.payload.digest,
            "history_summary_hash": operation.expected_head.history_digest.digest,
            "state_anchor_hash": operation.expected_head.event_digest.digest,
        }
        # The real type and the base `upper`: the door leaves a value it does not recognise
        # for the checks that refuse it by name, and this one meets it first. A value whose
        # `__class__` says str passed `isinstance` here and had no `upper` - measured, it
        # left `execute` as a raw AttributeError. See the note above `_plain_text`.
        for field, expected in comparisons.items():
            actual = mapped.get(field)
            if field.endswith("_hash") and _is(actual, str):
                actual = str.upper(actual)
            if actual != expected:
                raise OTCSBridgeError("OTCS_INTENT_BINDING", field)
        scope = _mapping(mapped.get("scope"), "OTCS_INTENT_SCOPE")
        expected_scope = {
            "project_id": operation.project_id,
            "event_type": operation.event_type,
            "registry_mode": operation.registry_mode,
            "governing_object_kind": operation.governing_object.object_kind,
        }
        for field, expected in expected_scope.items():
            if scope.get(field) != expected:
                raise OTCSBridgeError("OTCS_INTENT_SCOPE", field)

    @staticmethod
    def _validate_evidence_binding(
        operation: OTCSAppendOperation,
        evidence_bundle: Mapping[str, Any],
    ) -> None:
        bundle = _mapping(evidence_bundle, "OTCS_EVIDENCE_BINDING")
        items = bundle.get("items")
        # Real types throughout, for the reason `_validate_intent_binding` gives.
        if not _is(items, list):
            raise OTCSBridgeError("OTCS_EVIDENCE_BINDING", "items")
        by_type: dict[str, Mapping[str, Any]] = {}
        for raw in items:
            item = _mapping(raw, "OTCS_EVIDENCE_BINDING")
            evidence_type = item.get("evidence_type")
            if not _is(evidence_type, str):
                raise OTCSBridgeError("OTCS_EVIDENCE_BINDING", "evidence_type")
            if evidence_type in by_type:
                raise OTCSBridgeError("OTCS_EVIDENCE_DUPLICATE", evidence_type)
            by_type[evidence_type] = item
        expected = {
            key: value.digest
            for key, value in operation.legal_evidence_mapping().items()
        }
        expected[OTCS_HEAD_EVIDENCE_TYPE] = operation.expected_head.event_digest.digest
        for evidence_type, digest in expected.items():
            item = by_type.get(evidence_type)
            if item is None:
                raise OTCSBridgeError("OTCS_EVIDENCE_BINDING", evidence_type)
            actual = item.get("sha256")
            if not _is(actual, str) or str.upper(actual) != digest:
                raise OTCSBridgeError("OTCS_EVIDENCE_BINDING", evidence_type)

    @staticmethod
    def _operation_from_row(row: Mapping[str, Any]) -> OTCSAppendOperation:
        request = _mapping(row.get("request"), "OTCS_OUTBOX_REQUEST")
        operation = request.get("operation")
        return OTCSAppendOperation.from_mapping(
            _mapping(operation, "OTCS_OUTBOX_REQUEST")
        )

    @staticmethod
    def _submission_hash(operation, intent, evidence_bundle) -> str:
        return sha256_hex(_normalize_declared_hash_case({
            "identity_profile": "NC25_OTCS_BRIDGE_SUBMISSION_V1",
            "operation": operation.to_mapping(),
            "intent": dict(intent),
            "evidence_bundle": dict(evidence_bundle),
        }))

    @staticmethod
    def _admission_evidence(operation, evidence_bundle) -> dict[str, Any]:
        evidence = copy.deepcopy(dict(evidence_bundle))
        items = evidence.get("items")
        if not isinstance(items, list) or any(
            not isinstance(item, Mapping)
            or item.get("evidence_type") == OTCS_OPERATION_EVIDENCE_TYPE
            for item in items
        ):
            raise OTCSBridgeError("OTCS_EVIDENCE_BINDING", "reserved operation evidence")
        # This records which operation was submitted, not an OTCS rights grant.
        items.append({
            "evidence_type": OTCS_OPERATION_EVIDENCE_TYPE,
            "ref": "urn:nc25:otcs:submitted-operation:v1",
            "sha256": sha256_hex(operation.to_mapping()),
            "status": "VALID",
        })
        return evidence

    def _validate_row_admission(self, row: Mapping[str, Any]) -> OTCSAppendOperation:
        request = _mapping(row.get("request"), "OTCS_OUTBOX_REQUEST")
        # A legacy row cannot prove this binding. Never issue it a replacement permit.
        admission = _closed(
            request.get("admission"), {"intent", "evidence_bundle"},
            "OTCS_OUTBOX_ADMISSION",
        )
        intent = _mapping(admission["intent"], "OTCS_OUTBOX_ADMISSION")
        evidence = _mapping(admission["evidence_bundle"], "OTCS_OUTBOX_ADMISSION")
        operation = self._operation_from_row(row)
        if (row.get("project_id"), row.get("idempotency_key")) != (
            operation.project_id, operation.idempotency_key,
        ):
            raise OTCSBridgeError("OTCS_OUTBOX_ADMISSION", "row selectors")
        if row.get("operation_hash") != self._submission_hash(operation, intent, evidence):
            raise OTCSBridgeError("OTCS_OUTBOX_ADMISSION", "submission identity")
        submitted_hash = sha256_hex(_normalize_declared_hash_case({
            "intent": dict(intent),
            "evidence_bundle": self._admission_evidence(operation, evidence),
        }))
        # The durable engine authenticates this submitted decision independently
        # of the outbox. Recomputing an outbox hash cannot create an admission.
        try:
            decision = self._engine.architect_decision(
                submitted_hash, actor_scope=ROLE_ARCHITECT,
            )
        except IntegrityViolation:
            raise
        except ContractViolation as exc:
            if exc.code != "DECISION_UNKNOWN":
                raise
            raise OTCSBridgeError("OTCS_OUTBOX_ADMISSION", "unknown submission") from exc
        nc25 = _mapping(request.get("nc25_permit"), "OTCS_OUTBOX_REQUEST")
        if (decision.get("disposition") != "ALLOW"
                or decision.get("request_hash") != submitted_hash
                or decision.get("permit_hash") != _sha256(row.get("permit_hash"), "OTCS_OUTBOX_REQUEST")
                or decision.get("intent_id") != intent.get("intent_id")
                or nc25.get("intent_id") != intent.get("intent_id")):
            raise OTCSBridgeError("OTCS_OUTBOX_ADMISSION", "decision binding")
        # Direct engine submissions also need the bridge's cross-object contract.
        self._validate_intent_binding(operation, intent)
        self._validate_evidence_binding(operation, evidence)
        return operation

    def _validate_row_engine_binding(self, row: Mapping[str, Any]) -> None:
        if "admission" not in _mapping(row.get("request"), "OTCS_OUTBOX_REQUEST"):
            raise OTCSBridgeError("OTCS_OUTBOX_ADMISSION", "legacy row has no admission")
        request = _closed(
            row.get("request"),
            {
                "message_type",
                "bridge_version",
                "operation",
                "nc25_permit",
                "admission",
            },
            "OTCS_OUTBOX_REQUEST",
        )
        if request["message_type"] != "otcs_append_request":
            raise OTCSBridgeError(
                "OTCS_OUTBOX_ENGINE_BINDING",
                "message_type",
            )
        if request["bridge_version"] != OTCS_BRIDGE_VERSION:
            raise OTCSBridgeError(
                "OTCS_OUTBOX_ENGINE_BINDING",
                "bridge_version",
            )
        nc25 = _closed(
            request.get("nc25_permit"),
            {
                "permit_hash",
                "profile_hash",
                "declaration_hash",
                "intent_id",
                "connector_id",
                "binding",
            },
            "OTCS_OUTBOX_REQUEST",
        )
        row_permit_hash = _sha256(
            row.get("permit_hash"),
            "OTCS_OUTBOX_PERMIT_HASH",
        )
        request_permit_hash = _sha256(
            nc25.get("permit_hash"),
            "OTCS_OUTBOX_PERMIT_HASH",
        )
        if row_permit_hash != request_permit_hash:
            raise OTCSBridgeError(
                "OTCS_OUTBOX_ENGINE_BINDING",
                "permit_hash",
            )
        expected_binding = {
            "profile_id": self._engine.profile["profile_id"],
            "profile_version": self._engine.profile["profile_version"],
            "profile_hash": self._engine.profile_hash,
            "declaration_id": self._engine.declaration["declaration_id"],
            "declaration_version": self._engine.declaration[
                "declaration_version"
            ],
            "declaration_hash": self._engine.declaration_hash,
        }
        binding = _closed(
            nc25.get("binding"),
            set(expected_binding),
            "OTCS_OUTBOX_REQUEST",
        )
        if _normalize_declared_hash_case(binding) != expected_binding:
            raise OTCSBridgeError(
                "OTCS_OUTBOX_ENGINE_BINDING",
                "binding",
            )
        comparisons = {
            "profile_hash": self._engine.profile_hash,
            "declaration_hash": self._engine.declaration_hash,
            "connector_id": self._engine.declaration["connector"][
                "connector_id"
            ],
        }
        for field, expected in comparisons.items():
            actual = nc25.get(field)
            if field.endswith("_hash") and isinstance(actual, str):
                actual = actual.upper()
            if actual != expected:
                raise OTCSBridgeError(
                    "OTCS_OUTBOX_ENGINE_BINDING",
                    field,
                )

    def _permit_not_live_reason(
        self,
        row: Mapping[str, Any],
        operation: OTCSAppendOperation,
    ) -> str | None:
        try:
            permit = self._engine.architect_permit(
                row["permit_hash"],
                actor_scope=ROLE_ARCHITECT,
            )
        except IntegrityViolation:
            # A broken seal, chain or persisted state is the engine reporting
            # that it cannot vouch for itself.  That is not "the permit is not
            # live": turning it into a reason string would terminate the row as
            # NOT_EXECUTED under a false rejection code, and nothing here
            # constrains rejection_code, so the falsehood would persist.
            raise
        except ContractViolation as exc:
            return exc.code
        permit_hash = _sha256(
            permit.get("permit_hash"),
            "OTCS_OUTBOX_PERMIT_HASH",
        )
        if permit_hash != _sha256(
            row.get("permit_hash"),
            "OTCS_OUTBOX_PERMIT_HASH",
        ):
            raise OTCSBridgeError(
                "OTCS_OUTBOX_PERMIT_BINDING",
                "permit_hash",
            )
        request = _mapping(row.get("request"), "OTCS_OUTBOX_REQUEST")
        nc25 = _mapping(request.get("nc25_permit"), "OTCS_OUTBOX_REQUEST")
        body = _mapping(permit.get("permit_body"), "OTCS_OUTBOX_PERMIT")
        comparisons = {
            "intent_id": nc25.get("intent_id"),
            "connector_id": nc25.get("connector_id"),
            "action_id": OTCS_APPEND_ACTION_ID,
            "target_system_id": operation.target_system_id,
            "state_anchor_hash": operation.expected_head.event_digest.digest,
            "binding": nc25.get("binding"),
        }
        for field, expected in comparisons.items():
            actual = body.get(field)
            if field == "state_anchor_hash" and isinstance(actual, str):
                actual = actual.upper()
            if field == "binding" and isinstance(actual, Mapping):
                actual = _normalize_declared_hash_case(dict(actual))
                expected = _normalize_declared_hash_case(
                    _mapping(expected, "OTCS_OUTBOX_PERMIT")
                )
            if actual != expected:
                raise OTCSBridgeError(
                    "OTCS_OUTBOX_PERMIT_BINDING",
                    field,
                )
        if permit.get("consumed") is True:
            return "PERMIT_ALREADY_CONSUMED"
        invalidated_reason = permit.get("invalidated_reason")
        if isinstance(invalidated_reason, str) and invalidated_reason:
            return invalidated_reason
        if permit.get("reservation_active") is not True:
            return "RESERVATION_INACTIVE"
        if self._engine.status != "ACTIVE":
            return "DECLARATION_NOT_ACTIVE"
        now = self._engine.clock.now()
        if not (
            parse_utc(self._engine.declaration["effective_from"])
            <= now
            < parse_utc(self._engine.declaration["expires_at"])
        ):
            return "DECLARATION_OUTSIDE_VALIDITY"
        if now >= parse_utc(body["expires_at"]):
            return "PERMIT_EXPIRED"
        return None

    def _fault(self, point: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(point)

    def _advance(
        self,
        row: Mapping[str, Any],
        *,
        recovery: bool,
    ) -> dict[str, Any]:
        self._validate_row_engine_binding(row)
        operation = self._validate_row_admission(row)

        def transition(*args, **kwargs):
            # transition() re-reads SQLite. Admit that new snapshot before using it.
            changed = self._outbox.transition(*args, **kwargs)
            self._validate_row_engine_binding(changed)
            self._validate_row_admission(changed)
            return changed

        state = row["state"]
        if state in {"LOCAL_COMMITTED", "LOCAL_FAILED", "NOT_EXECUTED"}:
            return self._result(row)
        if state == "RECONCILIATION_REQUIRED":
            raise OTCSReconciliationRequired(
                "OTCS_RECONCILIATION_REQUIRED",
                row.get("last_error") or "stored reconciliation state",
            )

        project_id = operation.project_id
        idempotency_key = operation.idempotency_key
        if state == "PREPARED":
            reason = self._permit_not_live_reason(row, operation)
            if reason is not None:
                row = transition(
                    project_id,
                    idempotency_key,
                    {"PREPARED"},
                    "NOT_EXECUTED",
                    rejection_code=reason,
                    last_error=reason,
                )
                return self._result(row)
        if state in {"CALLING", "AMBIGUOUS"} and not recovery:
            raise OTCSBridgeError("OTCS_RECOVERY_REQUIRED", state)
        if state in {"CALLING", "AMBIGUOUS"}:
            # NEITHER state proves the request left the machine, so neither may
            # be re-driven once the permit stops being live.
            #
            # AMBIGUOUS includes append failures other than OTCSAppendRejected.
            # A client raising ConnectionRefusedError before a single byte is
            # sent lands here with effects still zero. Re-driving it could
            # therefore produce a first downstream effect under a dead permit.
            #
            # Refusing costs nothing that was available anyway: a row whose
            # permit is dead cannot be finalized locally either way, so the
            # downstream call before that refusal buys a wasted replay at best
            # and an unauthorised effect at worst.
            #
            # The terminal state is RECONCILIATION_REQUIRED rather than
            # NOT_EXECUTED because "nothing happened" is a fact this bridge
            # cannot establish for either state; it can only assume it. The row
            # is handed to a human with the effect status honestly unknown.
            reason = self._permit_not_live_reason(row, operation)
            if reason is not None:
                transition(
                    project_id,
                    idempotency_key,
                    {state},
                    "RECONCILIATION_REQUIRED",
                    rejection_code=reason,
                    last_error=reason,
                )
                # Named for the CLASS, not one member of it:
                # _permit_not_live_reason answers with any of seven reasons
                # (consumed, reservation inactive, declaration not active or
                # outside validity, expired, a stored invalidation reason, or a
                # refusal code from the lookup itself). An earlier name said
                # EXPIRED and covered one of the seven.
                raise OTCSReconciliationRequired(
                    "OTCS_PERMIT_NOT_LIVE_ON_RECOVERY", reason
                )
        if state in {"PREPARED", "CALLING", "AMBIGUOUS"}:
            allowed = {"PREPARED"} if not recovery else {"PREPARED", "CALLING", "AMBIGUOUS"}
            row = transition(
                project_id,
                idempotency_key,
                allowed,
                "CALLING",
            )
            wire_request = copy.deepcopy(row["request"])
            del wire_request["admission"]
            try:
                raw_receipt = self._client.append_event(wire_request)
            except OTCSAppendRejected as exc:
                execution_request = self._execution_request(
                    row,
                    operation,
                    outcome="FAILED",
                    downstream_receipt_hash=None,
                    committed_at=utc_text(self._engine.clock.now()),
                )
                row = transition(
                    project_id,
                    idempotency_key,
                    {"CALLING"},
                    "DOWNSTREAM_REJECTED",
                    execution_request=execution_request,
                    rejection_code=_stored_reason(exc.code),
                )
            except BaseException as exc:
                transition(
                    project_id,
                    idempotency_key,
                    {"CALLING"},
                    "AMBIGUOUS",
                    last_error=type(exc).__name__,
                )
                raise
            else:
                try:
                    receipt = OTCSReceiptRef.from_mapping(raw_receipt)
                    self._validate_receipt(operation, receipt)
                except OTCSBridgeError as exc:
                    transition(
                        project_id,
                        idempotency_key,
                        {"CALLING"},
                        "RECONCILIATION_REQUIRED",
                        last_error=exc.code,
                    )
                    raise OTCSReconciliationRequired(
                        "OTCS_RECEIPT_UNUSABLE", exc.code
                    ) from exc
                except Exception as exc:  # noqa: BLE001 - the class, not a list of it
                    # The receipt is admitted AFTER the downstream effect, so an exception
                    # that is not ours used to leave this `try` with the row CALLING over an
                    # effect that happened: the receipt object's own code, run while it was
                    # read - a mapping whose `keys` raised, a value whose methods did. Those
                    # shapes are read by `_plain_copy` now, which runs none of the object's
                    # code and refuses an unreadable mapping by name, so they arrive above
                    # as OTCS_RECEIPT_FIELDS. What is left for this clause is what no copy
                    # sees - a fault in this module's own receipt code - and the answer is the
                    # one the bridge already has for a receipt it cannot use:
                    # RECONCILIATION_REQUIRED, which asks an operator rather than guessing.
                    # Fail-closed by design, and witnessed by a case that injects that fault.
                    transition(
                        project_id,
                        idempotency_key,
                        {"CALLING"},
                        "RECONCILIATION_REQUIRED",
                        last_error=type(exc).__name__,
                    )
                    raise OTCSReconciliationRequired(
                        "OTCS_RECEIPT_UNUSABLE", type(exc).__name__
                    ) from exc
                try:
                    self._fault("after_downstream_response")
                except BaseException as exc:
                    transition(
                        project_id,
                        idempotency_key,
                        {"CALLING"},
                        "AMBIGUOUS",
                        last_error=type(exc).__name__,
                    )
                    raise
                execution_request = self._execution_request(
                    row,
                    operation,
                    outcome="COMMITTED",
                    downstream_receipt_hash=receipt.receipt_digest.digest,
                    committed_at=receipt.effective_at,
                )
                row = transition(
                    project_id,
                    idempotency_key,
                    {"CALLING"},
                    "DOWNSTREAM_COMMITTED",
                    receipt=receipt.to_mapping(),
                    execution_request=execution_request,
                )
                self._fault("after_downstream_persisted")

        if row["state"] not in {"DOWNSTREAM_COMMITTED", "DOWNSTREAM_REJECTED"}:
            row = self._outbox.get(project_id, idempotency_key)
            if row is None:
                raise OTCSBridgeError("OTCS_OUTBOX_MISSING")
        self._validate_row_admission(row)
        self._validate_row_engine_binding(row)
        execution_request = row.get("execution_request")
        if not isinstance(execution_request, Mapping):
            raise OTCSBridgeError("OTCS_OUTBOX_EXECUTION_REQUEST")
        try:
            local_receipt = self._engine.commit_execution(
                execution_request,
                actor_scope=ROLE_EXECUTOR,
                route_permit_hash=row["permit_hash"],
            )
        except IntegrityViolation:
            # Preserve the exact request and downstream receipt.  A repaired
            # local integrity fault can retry without touching OTCS again.
            #
            # This clause stands FIRST on purpose: IntegrityViolation subclasses
            # ContractViolation, so written second it is unreachable and the
            # sentence above is false — the row went to RECONCILIATION_REQUIRED,
            # which _advance then refuses forever.  The engine orders the same
            # two handlers this way in _state_locked for the same reason.
            raise
        except ContractViolation as exc:
            if row["state"] == "DOWNSTREAM_COMMITTED":
                transition(
                    project_id,
                    idempotency_key,
                    {"DOWNSTREAM_COMMITTED"},
                    "RECONCILIATION_REQUIRED",
                    receipt=row.get("receipt"),
                    execution_request=execution_request,
                    last_error=exc.code,
                )
                raise OTCSReconciliationRequired(
                    "OTCS_LOCAL_FINALIZATION_REFUSED", exc.code
                ) from exc
            raise
        self._fault("after_local_commit")
        final_state = (
            "LOCAL_COMMITTED"
            if row["state"] == "DOWNSTREAM_COMMITTED"
            else "LOCAL_FAILED"
        )
        row = transition(
            project_id,
            idempotency_key,
            {row["state"]},
            final_state,
            receipt=row.get("receipt"),
            execution_request=execution_request,
            local_receipt=local_receipt,
            rejection_code=row.get("rejection_code"),
        )
        return self._result(row)

    @staticmethod
    def _execution_request(
        row: Mapping[str, Any],
        operation: OTCSAppendOperation,
        *,
        outcome: str,
        downstream_receipt_hash: str | None,
        committed_at: str,
    ) -> dict[str, Any]:
        request = _mapping(row["request"], "OTCS_OUTBOX_REQUEST")
        nc25 = _mapping(request.get("nc25_permit"), "OTCS_OUTBOX_REQUEST")
        binding = _mapping(nc25.get("binding"), "OTCS_OUTBOX_REQUEST")
        return {
            "message_type": "execution_request",
            "permit_hash": row["permit_hash"],
            "connector_id": _identifier(
                nc25.get("connector_id"),
                "OTCS_OUTBOX_CONNECTOR_ID",
            ),
            # The same compact declared-hash binding the outbox row carries,
            # copied so the stored request cannot be mutated through this
            # object. This request does not leave the process: it is the
            # engine's own execution request.
            "binding": copy.deepcopy(binding),
            "state_anchor_hash": operation.expected_head.event_digest.digest,
            "outcome": outcome,
            "downstream_receipt_hash": downstream_receipt_hash,
            "committed_at": committed_at,
        }

    def _validate_receipt(
        self,
        operation: OTCSAppendOperation,
        receipt: OTCSReceiptRef,
    ) -> None:
        expected = {
            "project_id": operation.project_id,
            "event_id": operation.event_id,
            "project_sequence": operation.project_sequence,
            "idempotency_key": operation.idempotency_key,
        }
        for field, value in expected.items():
            if getattr(receipt, field) != value:
                raise OTCSBridgeError("OTCS_RECEIPT_MISMATCH", field)
        if receipt.previous_head != operation.expected_head:
            raise OTCSBridgeError("OTCS_RECEIPT_MISMATCH", "previous_head")

    @staticmethod
    def _result(row: Mapping[str, Any]) -> dict[str, Any]:
        statuses = {
            "LOCAL_COMMITTED": "COMMITTED",
            "LOCAL_FAILED": "DOWNSTREAM_REJECTED",
            "NOT_EXECUTED": "NOT_EXECUTED",
        }
        status = statuses.get(row["state"])
        if status is None:
            raise OTCSBridgeError("OTCS_OUTBOX_RESULT_STATE", row["state"])
        return {
            "status": status,
            "permit_hash": row["permit_hash"],
            "otcs_receipt": copy.deepcopy(row.get("receipt")),
            "ledger_receipt": copy.deepcopy(row.get("local_receipt")),
            "rejection_code": row.get("rejection_code"),
        }
