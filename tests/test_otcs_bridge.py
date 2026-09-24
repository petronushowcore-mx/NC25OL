from __future__ import annotations

import copy
from contextlib import closing
from datetime import datetime, timezone
import json
import sqlite3
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python"))

from nc25_otcs_bridge import (  # noqa: E402
    OTCS_BRIDGE_VERSION,
    _canonical_text,
    OTCSAppendOperation,
    OTCSAppendRejected,
    OTCSBridge,
    OTCSBridgeError,
    OTCSReceiptRef,
    OTCSReconciliationRequired,
    SQLiteOTCSOutbox,
    _OUTBOX_NULLABLE,
    _plain_copy,
)
from nc25_universal_ledger import (  # noqa: E402
    ContractViolation,
    FixedClock,
    IntegrityViolation,
    ROLE_GOVERNANCE,
    ROLE_OPERATOR,
    UniversalConnectionLedger,
    bind_fixture,
    refuse_unreadable_database,
    sha256_hex,
    _normalize_declared_hash_case,
)


class FakeOTCSClient:
    """Project-idempotent downstream used to exercise the bridge seam."""

    def __init__(
        self,
        receipt: dict,
        *,
        reject_code: str | None = None,
        add_allowed_field: bool = False,
    ) -> None:
        self.receipt = copy.deepcopy(receipt)
        self.reject_code = reject_code
        self.add_allowed_field = add_allowed_field
        self.calls = 0
        self.effects = 0
        self.requests: list[dict] = []
        self._replays: dict[tuple[str, str], tuple[str, dict]] = {}

    def append_event(self, request) -> dict:
        self.calls += 1
        captured = copy.deepcopy(dict(request))
        self.requests.append(captured)
        if self.reject_code is not None:
            raise OTCSAppendRejected(self.reject_code)
        operation = captured["operation"]
        key = (operation["project_id"], operation["idempotency_key"])
        request_text = json.dumps(captured, sort_keys=True, separators=(",", ":"))
        if key in self._replays:
            original_text, original_receipt = self._replays[key]
            if request_text != original_text:
                raise AssertionError("FAKE_OTCS_IDEMPOTENCY_CONFLICT")
            return copy.deepcopy(original_receipt)
        response = copy.deepcopy(self.receipt)
        if self.add_allowed_field:
            response["allowed"] = False
        self._replays[key] = (request_text, copy.deepcopy(response))
        self.effects += 1
        return response


class _AgreesWithEverything(str):
    """A string whose comparisons all answer "equal", whatever its characters are."""

    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False

    __hash__ = str.__hash__


class _UpperAnswers(str):
    """A string whose `upper` answers with a value it was given, not with its characters."""

    def __new__(cls, characters, answer):
        value = super().__new__(cls, characters)
        value.answer = answer
        return value

    def upper(self):
        return self.answer


class _TwoFacedDict(dict):
    """Stores one document and answers every reading method with another."""

    def __init__(self, stored, shown):
        super().__init__(stored)
        self.shown = shown

    def items(self):
        return self.shown.items()

    def keys(self):
        return self.shown.keys()

    def __iter__(self):
        return iter(self.shown)

    def __getitem__(self, key):
        return self.shown[key]

    def get(self, key, default=None):
        return self.shown.get(key, default)


class _ClaimsToBeAString:
    """No string at all, and `isinstance(value, str)` says it is one: `__class__` is asked."""

    @property
    def __class__(self):
        return str


class _ClaimsToBeAnInteger:
    @property
    def __class__(self):
        return int


class _ClaimsToBeAMapping:
    @property
    def __class__(self):
        return dict


class _ClaimsToBeAList:
    @property
    def __class__(self):
        return list


class OTCSBridgeRegressions(unittest.TestCase):
    def setUp(self) -> None:
        self.bundle = json.loads(
            (ROOT / "profiles" / "otcs" / "reference-connection.json").read_text(
                encoding="utf-8"
            )
        )
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.temporary_root = Path(self.temporary.name)
        self.clock = FixedClock(
            datetime(2026, 8, 1, 10, 0, tzinfo=timezone.utc)
        )
        self.engine = UniversalConnectionLedger(
            self.bundle["profile"],
            self.bundle["declaration"],
            signing_key=b"synthetic-reference-signing-key",
            clock=self.clock,
            state_path=self.temporary_root / "ledger.sqlite",
        )
        self.engine.activate(
            self.bundle["declaration"]["governance"]["approval_owner_id"],
            "evidence://synthetic/otcs/declaration-activation",
            actor_scope=ROLE_GOVERNANCE,
        )
        self.engine.issue_grant(
            self.bundle["grant"],
            actor_scope=ROLE_GOVERNANCE,
        )
        self.outbox_path = self.temporary_root / "otcs-outbox.sqlite"

    def bridge(self, client, *, fault_hook=None) -> OTCSBridge:
        return OTCSBridge(
            self.engine,
            client,
            self.outbox_path,
            _fault_hook=fault_hook,
        )

    def test_nc25_refusal_prevents_any_otcs_call(self) -> None:
        client = FakeOTCSClient(self.bundle["downstream_receipt"])
        intent = copy.deepcopy(self.bundle["intent"])
        intent["hard_block_flags"]["RIGHTS_REVOKED"] = True

        result = self.bridge(client).execute(
            self.bundle["bridge_operation"],
            intent,
            self.bundle["evidence"],
        )

        self.assertEqual(result["status"], "NOT_ADMISSIBLE")
        self.assertEqual(result["operator_result"]["disposition"], "REFUSAL")
        self.assertIsNone(result["operator_result"]["permit_hash"])
        self.assertEqual(client.calls, 0)
        self.assertIsNone(
            self.bridge(client).outbox_record(
                self.bundle["bridge_operation"]["project_id"],
                self.bundle["bridge_operation"]["idempotency_key"],
            )
        )

    def test_otcs_receives_permit_and_facts_not_admissibility(self) -> None:
        client = FakeOTCSClient(self.bundle["downstream_receipt"])
        result = self.bridge(client).execute(
            self.bundle["bridge_operation"],
            self.bundle["intent"],
            self.bundle["evidence"],
        )

        self.assertEqual(result["status"], "COMMITTED")
        self.assertEqual(client.calls, 1)
        request = client.requests[0]
        keys: set[str] = set()
        stack = [request]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                keys.update(str(key).lower() for key in value)
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
        self.assertNotIn("allowed", keys)
        self.assertEqual(request["operation"], self.bundle["bridge_operation"])
        self.assertEqual(
            request["nc25_permit"]["permit_hash"],
            result["permit_hash"],
        )
        self.assertEqual(
            request["nc25_permit"]["binding"],
            self.bundle["intent"]["binding"],
        )
        self.assertNotIn("profile", request)
        self.assertNotIn("declaration", request)

        evidence_by_type = {
            item["evidence_type"]: item
            for item in self.bundle["evidence"]["items"]
        }
        legal_grant = request["operation"]["legal_evidence"][
            "OTCS_REGISTRY_OPERATING_GRANT"
        ]
        self.assertEqual(
            legal_grant["digest"],
            evidence_by_type["OTCS_REGISTRY_OPERATING_GRANT"]["sha256"],
        )
        self.assertEqual(
            self.bundle["intent"]["authority_grant_id"],
            self.bundle["grant"]["grant_id"],
        )
        self.assertNotIn("authority_grant_id", request["operation"]["legal_evidence"])

    def test_otcs_receipt_digest_is_bound_into_the_ledger_event(self) -> None:
        client = FakeOTCSClient(self.bundle["downstream_receipt"])
        result = self.bridge(client).execute(
            self.bundle["bridge_operation"],
            self.bundle["intent"],
            self.bundle["evidence"],
        )

        recorded = [
            event
            for event in self.engine.ledger.events_copy()
            if event["event_type"] == "EXECUTION_RECORDED"
        ]
        self.assertEqual(len(recorded), 1)
        event = recorded[0]
        self.assertEqual(
            event["payload"]["receipt_seed"]["downstream_receipt_hash"],
            self.bundle["downstream_receipt"]["receipt_digest"]["digest"],
        )
        self.assertEqual(
            result["ledger_receipt"]["ledger_event_hash"],
            event["event_hash"],
        )

    def test_ambiguous_retry_reissues_request_but_not_effect(self) -> None:
        client = FakeOTCSClient(self.bundle["downstream_receipt"])

        def crash_after_response(point: str) -> None:
            if point == "after_downstream_response":
                raise RuntimeError("SYNTHETIC_RESPONSE_LOSS")

        with self.assertRaisesRegex(RuntimeError, "^SYNTHETIC_RESPONSE_LOSS$"):
            self.bridge(client, fault_hook=crash_after_response).execute(
                self.bundle["bridge_operation"],
                self.bundle["intent"],
                self.bundle["evidence"],
            )
        stored = self.bridge(client).outbox_record(
            self.bundle["bridge_operation"]["project_id"],
            self.bundle["bridge_operation"]["idempotency_key"],
        )
        self.assertEqual(stored["state"], "AMBIGUOUS")

        result = self.bridge(client).recover(
            self.bundle["bridge_operation"]["project_id"],
            self.bundle["bridge_operation"]["idempotency_key"],
        )
        self.assertEqual(result["status"], "COMMITTED")
        self.assertEqual(client.calls, 2)
        self.assertEqual(client.effects, 1)
        self.assertEqual(client.requests[0], client.requests[1])

    def test_prepared_expired_permit_never_calls_otcs(self) -> None:
        client = FakeOTCSClient(self.bundle["downstream_receipt"])

        def crash_after_prepare(point: str) -> None:
            if point == "after_prepare":
                raise RuntimeError("SYNTHETIC_PREPARED_PAUSE")

        with self.assertRaisesRegex(RuntimeError, "^SYNTHETIC_PREPARED_PAUSE$"):
            self.bridge(client, fault_hook=crash_after_prepare).execute(
                self.bundle["bridge_operation"],
                self.bundle["intent"],
                self.bundle["evidence"],
            )
        self.assertEqual(client.calls, 0)
        self.clock.advance(seconds=301)

        bridge = self.bridge(client)
        result = bridge.recover(
            self.bundle["bridge_operation"]["project_id"],
            self.bundle["bridge_operation"]["idempotency_key"],
        )

        self.assertEqual(result["status"], "NOT_EXECUTED")
        self.assertEqual(result["rejection_code"], "PERMIT_EXPIRED")
        self.assertIsNone(result["otcs_receipt"])
        self.assertIsNone(result["ledger_receipt"])
        self.assertEqual(client.calls, 0)
        self.assertEqual(client.effects, 0)
        stored = bridge.outbox_record(
            self.bundle["bridge_operation"]["project_id"],
            self.bundle["bridge_operation"]["idempotency_key"],
        )
        self.assertEqual(stored["state"], "NOT_EXECUTED")
        self.assertFalse(
            any(
                event["event_type"] == "EXECUTION_RECORDED"
                for event in self.engine.ledger.events_copy()
            )
        )

    def test_mid_call_row_with_a_dead_permit_is_not_re_driven(self) -> None:
        """A CALLING row cannot be re-driven under a dead permit.

        CALLING carries no proof that the request left. Re-driving it after
        expiry could create a first downstream effect under a dead permit.
        The same restriction for both AMBIGUOUS shapes is exercised by
        test_dead_permit_refuses_recovery_in_both_ambiguous_shapes.

        The row is left RECONCILIATION_REQUIRED rather than NOT_EXECUTED
        because "nothing happened" is not a fact the bridge can establish here.
        """
        client = FakeOTCSClient(self.bundle["downstream_receipt"])

        def crash_after_prepare(point: str) -> None:
            if point == "after_prepare":
                raise RuntimeError("SYNTHETIC_PREPARED_PAUSE")

        with self.assertRaisesRegex(RuntimeError, "^SYNTHETIC_PREPARED_PAUSE$"):
            self.bridge(client, fault_hook=crash_after_prepare).execute(
                self.bundle["bridge_operation"],
                self.bundle["intent"],
                self.bundle["evidence"],
            )
        self.assertEqual(client.calls, 0)

        # There is no fault point between the CALLING transition and the
        # downstream call, so the state a crash would leave is constructed
        # through the same outbox API the bridge itself uses.
        bridge = self.bridge(client)
        project_id = self.bundle["bridge_operation"]["project_id"]
        idempotency_key = self.bundle["bridge_operation"]["idempotency_key"]
        bridge._outbox.transition(
            project_id, idempotency_key, {"PREPARED"}, "CALLING"
        )
        self.clock.advance(seconds=301)

        with self.assertRaisesRegex(
            OTCSReconciliationRequired, r"^OTCS_PERMIT_NOT_LIVE_ON_RECOVERY(:|$)"
        ):
            bridge.recover(project_id, idempotency_key)

        # The point of refusing: OTCS was never called, so no effect was
        # created under the dead permit.
        self.assertEqual(client.calls, 0)
        self.assertEqual(client.effects, 0)
        stored = bridge.outbox_record(project_id, idempotency_key)
        self.assertEqual(stored["state"], "RECONCILIATION_REQUIRED")
        self.assertEqual(stored["rejection_code"], "PERMIT_EXPIRED")
        self.assertFalse(
            any(
                event["event_type"] == "EXECUTION_RECORDED"
                for event in self.engine.ledger.events_copy()
            )
        )

        # Each short recovery instruction must name the live-permit condition
        # and the reconciliation outcome. This checks the declared terms;
        # the cases here establish dead-permit refusal; the live-retry test
        # separately establishes re-send without a second downstream effect.
        import ast
        import re
        runbook = (ROOT / "UNIVERSAL-CONNECTION-RUNBOOK.md").read_text(encoding="utf-8")
        paragraphs = re.findall(r"7\. On an ambiguous response,.*?(?=\n8\.)", runbook, re.S)
        tree = ast.parse((ROOT / "tools/build_universal_specification.py").read_text(encoding="utf-8"))
        paragraphs.extend(n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)
                          and isinstance(n.value, str)
                          and n.value.startswith(("A dead PREPARED permit", "After an ambiguous CALLING state")))
        self.assertEqual(len(paragraphs), 3)
        for paragraph in paragraphs:
            with self.subTest(recovery_instruction=paragraph[:55]):
                self.assertIn("live permit", paragraph)
                self.assertIn("RECONCILIATION_REQUIRED", paragraph)

    def test_mid_call_row_with_a_live_permit_resumes_once(self) -> None:
        client = FakeOTCSClient(self.bundle["downstream_receipt"])
        def pause(point: str) -> None:
            if point == "after_prepare":
                raise RuntimeError("SYNTHETIC_PREPARED_PAUSE")
        with self.assertRaisesRegex(RuntimeError, "^SYNTHETIC_PREPARED_PAUSE$"):
            self.bridge(client, fault_hook=pause).execute(
                self.bundle["bridge_operation"], self.bundle["intent"], self.bundle["evidence"])
        bridge = self.bridge(client)
        project_id = self.bundle["bridge_operation"]["project_id"]
        key = self.bundle["bridge_operation"]["idempotency_key"]
        bridge._outbox.transition(project_id, key, {"PREPARED"}, "CALLING")
        result = bridge.recover(project_id, key)
        self.assertEqual(result["status"], "COMMITTED", "LIVE_CALLING_RESUMES")
        self.assertEqual(client.calls, 1)
        self.assertEqual(client.effects, 1)
        bridge.recover(project_id, key)
        self.assertEqual(client.calls, 1)
        self.assertEqual(client.effects, 1)

    def test_dead_permit_refuses_recovery_in_both_ambiguous_shapes(self) -> None:
        """AMBIGUOUS does not prove transmission, so it gets no exemption.

        AMBIGUOUS is everything that goes wrong around the append except an
        OTCSAppendRejected. It is reached two ways, and only one of them means
        the request left the machine:

          * the response was lost AFTER the client returned a receipt;
          * the client raised before a single byte was sent -- a refused
            connection, a failed handshake, a marshalling error.

        The second shape is why recovery must check the permit here as well.
        An earlier version of this guard exempted AMBIGUOUS on the ground that
        it "records that the request left"; driven, that produced a FIRST
        downstream effect under a dead permit.

        Both shapes are instantiated below, because a witness that only builds
        the half where the claim holds certifies nothing about the other half.
        The live-permit replay that this guard must NOT block is witnessed
        separately by test_ambiguous_retry_reissues_request_but_not_effect.
        """
        class RefusesBeforeSending:
            """No bytes leave the machine; the row still lands in AMBIGUOUS."""

            def __init__(self) -> None:
                self.calls = 0
                self.effects = 0

            def append_event(self, request):
                self.calls += 1
                raise ConnectionRefusedError("SYNTHETIC_NO_ROUTE_TO_HOST")

        project_id = self.bundle["bridge_operation"]["project_id"]
        idempotency_key = self.bundle["bridge_operation"]["idempotency_key"]

        for shape in ("response lost after the client returned", "never sent"):
            with self.subTest(shape=shape):
                self.setUp()
                if shape == "never sent":
                    client = RefusesBeforeSending()
                    with self.assertRaises(ConnectionRefusedError):
                        self.bridge(client).execute(
                            self.bundle["bridge_operation"],
                            self.bundle["intent"],
                            self.bundle["evidence"],
                        )
                else:
                    client = FakeOTCSClient(self.bundle["downstream_receipt"])

                    def crash_after_response(point: str) -> None:
                        if point == "after_downstream_response":
                            raise RuntimeError("SYNTHETIC_RESPONSE_LOSS")

                    with self.assertRaisesRegex(
                        RuntimeError, "^SYNTHETIC_RESPONSE_LOSS$"
                    ):
                        self.bridge(client, fault_hook=crash_after_response).execute(
                            self.bundle["bridge_operation"],
                            self.bundle["intent"],
                            self.bundle["evidence"],
                        )

                bridge = self.bridge(client)
                self.assertEqual(
                    bridge.outbox_record(project_id, idempotency_key)["state"],
                    "AMBIGUOUS",
                )
                calls_before = client.calls
                self.clock.advance(seconds=301)

                with self.assertRaisesRegex(
                    OTCSReconciliationRequired,
                    r"^OTCS_PERMIT_NOT_LIVE_ON_RECOVERY(:|$)",
                ):
                    bridge.recover(project_id, idempotency_key)

                # The point of refusing: nothing further reached OTCS.
                self.assertEqual(client.calls, calls_before)
                stored = bridge.outbox_record(project_id, idempotency_key)
                self.assertEqual(stored["state"], "RECONCILIATION_REQUIRED")
                self.assertEqual(stored["rejection_code"], "PERMIT_EXPIRED")

    def test_an_unknown_stored_state_is_reachable_through_the_public_read(
        self,
    ) -> None:
        """Pins the measurement that moved a code out of the internal-only set.

        The module used to declare OTCS_OUTBOX_STATE unreachable from any
        public path, on the ground that its state set and the table's CHECK
        constraint are the same set. That holds only while this module creates
        the table. A deployment that hands the bridge an existing database of
        the right shape and no CHECK breaks it.

        Without this test the retraction rested on a one-off probe that shipped
        with nothing, and the next reader would have had only prose to trust.
        """
        import sqlite3

        foreign = self.temporary_root / "foreign-outbox.sqlite"
        connection = sqlite3.connect(foreign)
        connection.execute(
            "CREATE TABLE otcs_bridge_outbox ("
            " project_id TEXT NOT NULL, idempotency_key TEXT NOT NULL,"
            " operation_hash TEXT NOT NULL, permit_hash TEXT,"
            " state TEXT NOT NULL, request_json TEXT, receipt_json TEXT,"
            " execution_request_json TEXT, local_receipt_json TEXT,"
            " rejection_code TEXT, last_error TEXT, updated_at TEXT NOT NULL,"
            " PRIMARY KEY (project_id, idempotency_key))"
        )
        connection.execute(
            "INSERT INTO otcs_bridge_outbox (project_id, idempotency_key,"
            " operation_hash, state, updated_at) VALUES (?,?,?,?,?)",
            ("p-1", "k-1", "0" * 64, "SHIPPED", "2026-09-07T00:00:00Z"),
        )
        connection.commit()
        connection.close()

        outbox = SQLiteOTCSOutbox(foreign)
        with self.assertRaisesRegex(OTCSBridgeError, r"^OTCS_OUTBOX_STATE(:|$)"):
            outbox.get("p-1", "k-1")

        # Control: an outbox this module created answers the same public read
        # without refusing, so the refusal above belongs to the planted row and
        # not to the read itself.
        own = SQLiteOTCSOutbox(self.temporary_root / "own-outbox.sqlite")
        self.assertIsNone(own.get("p-1", "k-1"))

    def test_a_database_that_lost_its_table_is_refused_as_absent_not_as_malformed(
        self,
    ) -> None:
        """One refusal code, two facts, and the detail has to say which.

        `PRAGMA table_xinfo`, the guard's read, answers a table that is not there
        with no rows at all, so the guard's `present` came back empty and every declared name
        fell into "missing": the caller was handed a sentence describing a
        table with the wrong columns, for a database that had none. The code
        stays what it was - this is still not our table - and the detail is
        what changes.

        Reachable because the bridge opens a connection per call: a file
        deleted or replaced between calls is recreated empty by `sqlite3`.
        """
        import sqlite3

        path = self.temporary_root / "vanishing-outbox.sqlite"
        outbox = SQLiteOTCSOutbox(path)
        self.assertIsNone(outbox.get("p-1", "k-1"))
        path.unlink()

        with self.assertRaisesRegex(OTCSBridgeError, r"^OTCS_OUTBOX_COLUMNS: table absent$"):
            outbox.get("p-1", "k-1")

        # Control, the other direction: a table that IS there and is wrong must still name
        # its columns, so the new branch cannot swallow the one it was carved out of.
        wrong = self.temporary_root / "wrong-columns-outbox.sqlite"
        connection = sqlite3.connect(wrong)
        connection.execute("CREATE TABLE otcs_bridge_outbox (project_id TEXT)")
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(OTCSBridgeError, r"^OTCS_OUTBOX_COLUMNS: missing "):
            SQLiteOTCSOutbox(wrong)

        # A third fact under the same code, and the one the guard itself used to leak: the
        # statements that read the schema are statements, so a path holding bytes that are
        # not a SQLite database made the FIRST of them raise sqlite3.DatabaseError - past
        # this module, and at construction, because the store takes a checked connection as
        # it opens. Measured before the guard: `escaped:sqlite3.DatabaseError` from both
        # stores; after it, each refuses by its own code.
        prose = self.temporary_root / "not-a-database.sqlite"
        prose.write_bytes(b"this file is a hundred bytes of ordinary prose, not a database.")
        with self.assertRaisesRegex(OTCSBridgeError, r"^OTCS_OUTBOX_COLUMNS: not a database$"):
            SQLiteOTCSOutbox(prose)

        # A fourth, and the one that showed the classifier was too coarse: a real database
        # whose outbox NAME is a virtual table of a module this build lacks. `PRAGMA
        # table_xinfo` does not answer it with no rows - it RAISES, as sqlite3.OperationalError
        # - and while every OperationalError was treated as transient and re-raised, that
        # error left the module as a raw driver exception. It is not transient: it is a
        # permanent property of that file against this build. Measured on this build, the
        # driver names it SQLITE_ERROR, while a locked database is SQLITE_BUSY - which is
        # what lets the transient class be named positively instead of by exception type.
        # Written through `writable_schema` because there is no other way to put such a row
        # in a database from a build that lacks the module.
        alien = self.temporary_root / "unknown-module.sqlite"
        connection = sqlite3.connect(alien)
        connection.execute("CREATE TABLE placeholder (x)")
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            "UPDATE sqlite_master SET type='table', name='otcs_bridge_outbox', "
            "tbl_name='otcs_bridge_outbox', "
            "sql='CREATE VIRTUAL TABLE otcs_bridge_outbox USING no_such_module(x)' "
            "WHERE name='placeholder'")
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(
                OTCSBridgeError, r"^OTCS_OUTBOX_COLUMNS: unreadable: SQLITE_ERROR$"):
            SQLiteOTCSOutbox(alien)

        # A fifth: a valid header over a schema page that is not. The guarded statement was
        # the header read, described as running before anything else on the connection -
        # and the create ran on that same connection outside any guard. Measured: this file
        # PASSES `PRAGMA schema_version` and used to raise `database disk image is
        # malformed` out of the create, past this module. Built by overwriting page one
        # after its hundred-byte header, which is the only way to make a file whose header
        # is honest and whose schema is not.
        readable_header = self.temporary_root / "corrupt-schema.sqlite"
        connection = sqlite3.connect(readable_header)
        connection.execute("CREATE TABLE something (a TEXT, b TEXT, c TEXT)")
        connection.execute("INSERT INTO something VALUES ('x','y','z')")
        connection.commit()
        connection.close()
        raw = bytearray(readable_header.read_bytes())
        self.assertEqual(bytes(raw[:15]), b"SQLite format 3", "the fixture is not a database")
        for offset in range(100, min(len(raw), 512)):
            raw[offset] = 0xFF
        readable_header.write_bytes(bytes(raw))
        probe = sqlite3.connect(readable_header)
        try:
            probe.execute("PRAGMA schema_version").fetchone()  # the header read still passes
        finally:
            probe.close()
        with self.assertRaisesRegex(
                OTCSBridgeError, r"^OTCS_OUTBOX_COLUMNS: malformed database$"):
            SQLiteOTCSOutbox(readable_header)

        # And the other side of that classifier, by code, because it moved three times.
        # First it re-raised every OperationalError as transient, which let a database
        # naming an unknown module escape as a raw driver error. Then it named the
        # transient class positively and treated the COMPLEMENT as the artefact - and a
        # full disk, a failed read, an interrupted statement all became permanent verdicts
        # that this table's columns are not ours. Now it keys on the driver's BASE code,
        # because the driver reports EXTENDED ones: measured, a primary-key violation
        # arrives as SQLITE_CONSTRAINT_PRIMARYKEY, 1555, and SQLite builds an extended code
        # from its base, so the low byte is the base. What belongs to neither list keeps
        # its own type: a fault the store cannot attribute to the stored artefact is not a
        # statement about the stored artefact.
        #
        # Every row carries the CLASS, the CODE and the NAME the driver gives that case,
        # because a fixture must repeat its producer - the name is carried even though the
        # function no longer reads it, for the same reason. Which of the two grounds each
        # row stands on, said rather than blurred, and the two lists together account for
        # every name the loops drive: SQLITE_BUSY, SQLITE_CANTOPEN, SQLITE_FULL,
        # SQLITE_ERROR, SQLITE_NOTADB, SQLITE_CORRUPT and SQLITE_CONSTRAINT were produced
        # and read on this build; SQLITE_LOCKED, SQLITE_IOERR, SQLITE_INTERRUPT,
        # SQLITE_PROTOCOL, SQLITE_FORMAT and SQLITE_SCHEMA are taken from the module's
        # documented mapping of result codes to exception classes, because no test here can
        # provoke them. An earlier form of this comment listed twelve and left
        # SQLITE_INTERRUPT in neither list while the loop went on pinning it.
        # The rows were built by side before - transient
        # ones as OperationalError, artefact ones as DatabaseError - and that hid the whole
        # point: SQLITE_ERROR is raised BY THE DRIVER as an OperationalError, so it is an
        # artefact code wearing the transient class, and a row that builds it as a
        # DatabaseError passes under a plain type test too. SQLITE_NOMEM is absent for the
        # same reason in reverse: the driver answers it with MemoryError, which no
        # `except sqlite3.DatabaseError` catches, so asking what this function says about
        # it asks about a shape that never reaches it.
        for name, exception in (
            ("SQLITE_BUSY", sqlite3.OperationalError),
            ("SQLITE_LOCKED", sqlite3.OperationalError),
            ("SQLITE_CANTOPEN", sqlite3.OperationalError),
            ("SQLITE_IOERR", sqlite3.OperationalError),
            ("SQLITE_FULL", sqlite3.OperationalError),
            ("SQLITE_INTERRUPT", sqlite3.OperationalError),
            ("SQLITE_PROTOCOL", sqlite3.OperationalError),
            ("SQLITE_CONSTRAINT", sqlite3.IntegrityError),
            # Was on the artefact side, unmeasured: it says the schema changed under a
            # statement the driver had already re-prepared, not whose table this is.
            ("SQLITE_SCHEMA", sqlite3.OperationalError),
        ):
            error = exception(name.lower())
            error.sqlite_errorname = name
            error.sqlite_errorcode = getattr(sqlite3, name)
            self.assertIsNone(
                refuse_unreadable_database(error),
                f"{name} is not a verdict about the stored table and must keep its type")
        for name, exception, detail in (
            ("SQLITE_NOTADB", sqlite3.DatabaseError, "not a database"),
            ("SQLITE_CORRUPT", sqlite3.DatabaseError, "malformed database"),
            ("SQLITE_ERROR", sqlite3.OperationalError, "unreadable: SQLITE_ERROR"),
            ("SQLITE_FORMAT", sqlite3.DatabaseError, "unreadable: SQLITE_FORMAT"),
        ):
            error = exception(name.lower())
            error.sqlite_errorname = name
            error.sqlite_errorcode = getattr(sqlite3, name)
            self.assertEqual(
                refuse_unreadable_database(error), detail,
                f"{name} is a property of the stored artefact and must be refused by name")
        # The two forms the move to base codes was made for. An EXTENDED artefact code is
        # the base with high bits set - SQLITE_CORRUPT_INDEX is 779, whose low byte is
        # SQLITE_CORRUPT - and under the old name table it would have kept its type.
        extended = sqlite3.DatabaseError("corrupt index")
        extended.sqlite_errorname = "SQLITE_CORRUPT_INDEX"
        extended.sqlite_errorcode = sqlite3.SQLITE_CORRUPT_INDEX
        self.assertEqual(
            refuse_unreadable_database(extended), "malformed database",
            "an extended artefact code is the base code with high bits set")
        # And the other half of that decision, which the fold hid while it was general.
        # These extend SQLITE_ERROR, so their low byte is 1 and the fold published every
        # one of them as 'unreadable: SQLITE_ERROR' - a permanent verdict about the file.
        # SQLITE_ERROR_RETRY says to run the statement again and SQLITE_ERROR_SNAPSHOT
        # says a WAL snapshot has moved on: neither says the stored table is not ours, and
        # a caller told otherwise loses the exception type that would have made it retry.
        for name, exception in (
            ("SQLITE_ERROR_RETRY", sqlite3.OperationalError),
            ("SQLITE_ERROR_SNAPSHOT", sqlite3.OperationalError),
        ):
            error = exception(name.lower())
            error.sqlite_errorname = name
            error.sqlite_errorcode = getattr(sqlite3, name)
            self.assertEqual(getattr(sqlite3, name) & 0xFF, sqlite3.SQLITE_ERROR)
            self.assertIsNone(
                refuse_unreadable_database(error),
                f"{name} extends SQLITE_ERROR without carrying its meaning")
        # Their sibling is not one of them, and this row is the second decision on it. A
        # stored table declared with a collation this build does not register cannot be
        # read here by any retry - the family is not foldable, so the member is named on
        # its own. Measured rather than argued: a table created with a custom collation
        # and reopened on a connection that does not register it answers `no such
        # collation sequence` as an OperationalError carrying this code, and while the
        # classifier said None the store re-raised that driver error out of a public call.
        # The row drives the code the driver gives, like the others here.
        collation = sqlite3.OperationalError("no such collation sequence: MYCOLL")
        collation.sqlite_errorname = "SQLITE_ERROR_MISSING_COLLSEQ"
        collation.sqlite_errorcode = sqlite3.SQLITE_ERROR_MISSING_COLLSEQ
        self.assertEqual(sqlite3.SQLITE_ERROR_MISSING_COLLSEQ & 0xFF, sqlite3.SQLITE_ERROR)
        self.assertEqual(
            refuse_unreadable_database(collation), "unreadable: missing collation",
            "a collation the build lacks is a property of the stored schema, not a retry")
        # And an error the MODULE raises, with no SQLite code behind it at all. Measured on
        # this build: a statement on a closed connection and a wrong binding count are
        # ProgrammingError with no code, and the fallback they used to meet answered both
        # 'not a database' - a fault in the caller published as a verdict about the file.
        uncoded = sqlite3.ProgrammingError("Cannot operate on a closed database.")
        self.assertIsNone(
            refuse_unreadable_database(uncoded),
            "an error the driver did not code is not a verdict about the stored artefact")

    def test_a_corrupt_row_page_is_refused_by_name(self) -> None:
        """Past the schema, into the rows: both shape reads pass and the row read does not.

        The header read and the column read are guarded and both see an intact page one.
        Overwriting page TWO leaves them passing and breaks where the rows are, which is
        the layer that left a raw driver error out of a public read until `_rows` existed.
        """
        import sqlite3

        client = FakeOTCSClient(self.bundle["downstream_receipt"])
        operation = self.bundle["bridge_operation"]
        result = self.bridge(client).execute(
            operation, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])
        self.assertEqual(result["status"], "COMMITTED")
        record = self.bridge(client).outbox_record(
            operation["project_id"], operation["idempotency_key"])
        self.assertEqual(record["state"], "LOCAL_COMMITTED")

        raw = bytearray(self.outbox_path.read_bytes())
        page_size = int.from_bytes(raw[16:18], "big") or 65536
        self.assertGreaterEqual(
            len(raw), 2 * page_size, "the outbox has no second page to corrupt")
        for offset in range(page_size + 8, min(len(raw), 2 * page_size)):
            raw[offset] = 0xFF
        self.outbox_path.write_bytes(bytes(raw))
        # The two guarded shape reads still pass on this file - that is what makes the row
        # read the case under test rather than a repeat of the schema cases.
        with closing(sqlite3.connect(self.outbox_path)) as probe:
            probe.execute("PRAGMA schema_version").fetchone()
            probe.execute("PRAGMA table_xinfo(otcs_bridge_outbox)").fetchall()
        with self.assertRaisesRegex(
                OTCSBridgeError, r"^OTCS_OUTBOX_COLUMNS: malformed database$"):
            self.bridge(client).outbox_record(
                operation["project_id"], operation["idempotency_key"])

    def test_a_constraint_this_store_did_not_declare_is_refused_by_name(self) -> None:
        """The name guard admits it by design; the first write is where it shows.

        Column NAMES are all the open compares, on purpose: the value guards downstream
        meet every storage class, so a table declaring these names with other types is
        readable. A constraint is not a type - this module's writes satisfy this module's
        declaration by construction, so one that fires belongs to the stored table.
        """
        import sqlite3

        with closing(sqlite3.connect(self.outbox_path)) as connection:
            connection.execute(
                "CREATE TABLE otcs_bridge_outbox ("
                "project_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, "
                "operation_hash TEXT NOT NULL, permit_hash TEXT NOT NULL, "
                "request_json TEXT NOT NULL, state TEXT NOT NULL, "
                "receipt_json TEXT NOT NULL, execution_request_json TEXT, "
                "local_receipt_json TEXT, rejection_code TEXT, last_error TEXT, "
                "updated_at TEXT NOT NULL, "
                "PRIMARY KEY (project_id, idempotency_key))"
            )
            connection.commit()
        client = FakeOTCSClient(self.bundle["downstream_receipt"])
        # Construction is NOT the refusal: the names are ours, and that is the design.
        bridge = self.bridge(client)
        with self.assertRaisesRegex(
                OTCSBridgeError,
                r"^OTCS_OUTBOX_COLUMNS: constraint not declared by this store$"):
            bridge.execute(
                self.bundle["bridge_operation"],
                copy.deepcopy(self.bundle["intent"]),
                self.bundle["evidence"],
            )
        # Before the downstream: the refusal is on our own first write.
        self.assertEqual(client.calls, 0)

    def test_a_stored_number_the_canonical_form_refuses_is_caught_by_the_read(self) -> None:
        """The walk asked its question of strings only, and a number is not a string.

        `json.loads` admits the bare tokens NaN, Infinity and -Infinity; this module's
        canonical dump passes `allow_nan=False` and refuses them. Between those two facts
        sat the decoder's walk, which examined every string it met and matched no branch at
        all for a float - so such a value travelled the whole recovery path and died at the
        LAST step, after the engine-side effect was already committed, under no code of
        ours. That is the class the text check exists to close, in the one shape it could
        not see.

        Planted as `Infinity` rather than as the `NaN` the defect was found with, on
        purpose: the fix is finiteness, and a fix written for the token it was reported
        with would let this plant through.
        """
        import sqlite3

        client = FakeOTCSClient(self.bundle["downstream_receipt"])
        operation = self.bundle["bridge_operation"]
        result = self.bridge(client).execute(
            operation, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])
        self.assertEqual(result["status"], "COMMITTED")

        with closing(sqlite3.connect(self.outbox_path)) as store:
            stored = store.execute(
                "SELECT receipt_json FROM otcs_bridge_outbox "
                "WHERE project_id = ? AND idempotency_key = ?",
                (operation["project_id"], operation["idempotency_key"])).fetchone()[0]
            self.assertNotIn("Infinity", stored, "the fixture already carries the plant")
            store.execute(
                "UPDATE otcs_bridge_outbox SET receipt_json = ? "
                "WHERE project_id = ? AND idempotency_key = ?",
                (stored.rstrip().rstrip("}") + ', "planted_amount": Infinity}',
                 operation["project_id"], operation["idempotency_key"]))
            store.commit()

        with self.assertRaisesRegex(
                OTCSBridgeError,
                r"^OTCS_OUTBOX_ROW_JSON: receipt_json: not a finite number$"):
            self.bridge(client).outbox_record(
                operation["project_id"], operation["idempotency_key"])
        # No second effect: the refusal is on the READ of a stored row, and the row is
        # what it was. Without this the case would not distinguish "refused before acting"
        # from "acted, then refused", which is the whole subject.
        self.assertEqual(client.effects, 1)

    def test_a_stored_ordinary_number_is_read_back_unharmed(self) -> None:
        """The control the case above needs, and it is not decoration.

        A walk that refused every number would pass the accusation case exactly as a
        correct one does. This plants a number of the same kind in the same field of the
        same row and requires the read to succeed.
        """
        import sqlite3

        client = FakeOTCSClient(self.bundle["downstream_receipt"])
        operation = self.bundle["bridge_operation"]
        self.bridge(client).execute(
            operation, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])

        with closing(sqlite3.connect(self.outbox_path)) as store:
            stored = store.execute(
                "SELECT receipt_json FROM otcs_bridge_outbox "
                "WHERE project_id = ? AND idempotency_key = ?",
                (operation["project_id"], operation["idempotency_key"])).fetchone()[0]
            store.execute(
                "UPDATE otcs_bridge_outbox SET receipt_json = ? "
                "WHERE project_id = ? AND idempotency_key = ?",
                (stored.rstrip().rstrip("}") + ', "planted_amount": 1.5}',
                 operation["project_id"], operation["idempotency_key"]))
            store.commit()

        record = self.bridge(client).outbox_record(
            operation["project_id"], operation["idempotency_key"])
        self.assertEqual(record["receipt"]["planted_amount"], 1.5)

    def test_a_receipt_field_that_cannot_be_stored_forces_reconciliation(self) -> None:
        """Admission asks what the decoder asks, and it asks BEFORE the write.

        A lone surrogate is a string Python holds and UTF-8 cannot encode. It passed the
        shape test, and the INSERT then died at the binding with a raw UnicodeEncodeError -
        after the downstream effect, leaving the row in CALLING. The receipt is unusable,
        which the bridge already has an answer for, and now reaches it.
        """
        receipt = copy.deepcopy(self.bundle["downstream_receipt"])
        receipt["signature_ref"] = "\ud800"
        client = FakeOTCSClient(receipt)
        operation = self.bundle["bridge_operation"]
        with self.assertRaisesRegex(
                OTCSReconciliationRequired,
                r"^OTCS_RECEIPT_UNUSABLE: OTCS_RECEIPT_SIGNATURE_REF$"):
            self.bridge(client).execute(
                operation, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])
        # The effect downstream HAPPENED - that is why the answer is reconciliation and
        # not a rejection - and the row says so where an operator will look.
        self.assertEqual(client.effects, 1)
        record = self.bridge(client).outbox_record(
            operation["project_id"], operation["idempotency_key"])
        self.assertEqual(record["state"], "RECONCILIATION_REQUIRED")
        self.assertEqual(record["last_error"], "OTCS_RECEIPT_SIGNATURE_REF")


    def test_a_receipt_field_that_is_a_hostile_subclass_is_refused_by_name(self) -> None:
        """The same door as the case above, asked by an OBJECT rather than by a character.

        A str subclass whose own `encode` raises, carrying a lone surrogate. What this
        names is the outcome at the receipt door: a NAMED refusal and the row taken to
        RECONCILIATION_REQUIRED, rather than the subclass's exception leaving the admission
        and the row left mid-call. It does not observe which layer holds that. The mapping
        door copies the receipt to plain strings before any field helper runs, `_text`
        normalises again, and `_storable_text` encodes through the base method - three
        layers, and a break of any one of them leaves this case green, measured. The case
        that reddens when `_text` alone stops normalising is the value-object case, which
        builds a receipt directly.

        Its own method, not a second drive in the case above: that store keeps the row the
        first drive leaves, the intent binds the idempotency key and the receipt carries it
        too, so a second drive there has to move four things together and ends up measuring
        whichever guard notices first - measured, twice, before this was split out.
        """
        class RefusesToBeEncoded(str):
            def encode(self, *arguments: object, **keywords: object) -> bytes:
                raise RuntimeError("this field will not be encoded")

        receipt = copy.deepcopy(self.bundle["downstream_receipt"])
        receipt["signature_ref"] = RefusesToBeEncoded("\ud800")
        client = FakeOTCSClient(receipt)
        operation = self.bundle["bridge_operation"]
        with self.assertRaisesRegex(
                OTCSReconciliationRequired,
                r"^OTCS_RECEIPT_UNUSABLE: OTCS_RECEIPT_SIGNATURE_REF$"):
            self.bridge(client).execute(
                operation, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])
        record = self.bridge(client).outbox_record(
            operation["project_id"], operation["idempotency_key"])
        self.assertEqual(record["state"], "RECONCILIATION_REQUIRED")
        self.assertEqual(record["last_error"], "OTCS_RECEIPT_SIGNATURE_REF")

    def test_a_receipt_field_that_is_an_ordinary_subclass_is_admitted(self) -> None:
        """The control the case above needs: the guard must not refuse every subclass.

        The SAME characters the fixture carries, wearing the same hostile type. A
        different value here would be a different receipt and would be refused as
        OTCS_RECEIPT_MISMATCH - measured - which is a guard answering about something
        else. The type moves and nothing else does.
        """
        class RefusesToBeEncoded(str):
            def encode(self, *arguments: object, **keywords: object) -> bytes:
                raise RuntimeError("this field will not be encoded")

        receipt = copy.deepcopy(self.bundle["downstream_receipt"])
        receipt["signature_ref"] = RefusesToBeEncoded(
            self.bundle["downstream_receipt"]["signature_ref"])
        client = FakeOTCSClient(receipt)
        operation = self.bundle["bridge_operation"]
        self.assertEqual(
            self.bridge(client).execute(
                operation, copy.deepcopy(self.bundle["intent"]),
                self.bundle["evidence"])["status"],
            "COMMITTED",
        )

    def test_a_rejection_code_that_cannot_be_stored_is_still_recorded(self) -> None:
        """A definitive rejection is a settled fact; its wording must not unsettle it.

        The downstream's code is text from outside, and the module's own comment says
        nothing constrains it. Measured, two forms could not be written: a lone surrogate
        died at the binding as a raw UnicodeEncodeError and a code that is not a string
        died there as a raw ProgrammingError, both leaving the row mid-call over a
        rejection that had already happened and produced no effect.
        """
        operation = self.bundle["bridge_operation"]
        client = FakeOTCSClient(self.bundle["downstream_receipt"], reject_code="\ud800")
        result = self.bridge(client).execute(
            operation, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])
        self.assertEqual(result["status"], "DOWNSTREAM_REJECTED")
        record = self.bridge(client).outbox_record(
            operation["project_id"], operation["idempotency_key"])
        self.assertEqual(record["state"], "LOCAL_FAILED")
        # Kept, not invented: the characters that cannot be stored arrive as the escape
        # `backslashreplace` writes, and the rest of the code would be unchanged.
        self.assertEqual(record["rejection_code"], "\\ud800")

    def test_a_rejection_code_that_refuses_to_render_is_still_recorded(self) -> None:
        """The renderer of a settled fact must not be able to refuse to run.

        `_stored_reason` exists because a definitive rejection is, by the client contract,
        known to have produced no effect: refusing to record it would leave the row mid-call
        over a fact that is settled. It rendered a non-string code with `repr`, and `repr`
        runs the object's own code - so a code whose `__repr__` raises sent that exception
        out of the function, from inside the handler for the rejection, and left the row
        exactly where this function exists to stop it being left.

        The plant's `__str__` is ordinary on purpose: a value that failed every rendering
        would be refused by something earlier, and the case would be measuring that instead.
        """
        class RefusesToDescribeItself:
            def __str__(self) -> str:
                return "ordinary text"

            def __repr__(self) -> str:
                raise RuntimeError("this object will not describe itself")

        operation = self.bundle["bridge_operation"]
        client = FakeOTCSClient(
            self.bundle["downstream_receipt"], reject_code=RefusesToDescribeItself())
        result = self.bridge(client).execute(
            operation, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])
        self.assertEqual(result["status"], "DOWNSTREAM_REJECTED")
        record = self.bridge(client).outbox_record(
            operation["project_id"], operation["idempotency_key"])
        self.assertEqual(record["state"], "LOCAL_FAILED")
        # Not an invented reason: what is still known about a value that will not describe
        # itself is its type, and that is what the row carries.
        self.assertEqual(
            record["rejection_code"], "<unrenderable RefusesToDescribeItself>")

    def test_a_rejection_repr_subclass_is_stored_as_plain_text(self) -> None:
        """A successful repr is normalised before its result is sliced or stored."""
        class Unsliceable(str):
            def __getitem__(self, item):
                raise RuntimeError("REJECTION_REPR_SLICE_EXECUTED")

        class ReprSubclass:
            def __repr__(self):
                return Unsliceable("DOWNSTREAM_REPR_CODE")

        operation = self.bundle["bridge_operation"]
        client = FakeOTCSClient(self.bundle["downstream_receipt"], reject_code=ReprSubclass())
        result = self.bridge(client).execute(
            operation, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])
        record = self.bridge(client).outbox_record(
            operation["project_id"], operation["idempotency_key"])
        self.assertEqual(
            (result["status"], record["state"], record["rejection_code"],
             client.calls, client.effects),
            ("DOWNSTREAM_REJECTED", "LOCAL_FAILED", "DOWNSTREAM_REPR_CODE", 1, 0),
        )

    def test_an_unrenderable_rejection_does_not_ask_its_metaclass_for_a_name(self) -> None:
        """Failure to render a reason still settles the row without a metaclass call.

        The name is still recorded: it is read through `type`'s own descriptor, which the
        metaclass below cannot intercept, so the row carries the type's name and the
        metaclass's refusal never runs.
        """
        class Unnameable(type):
            def __getattribute__(cls, name):
                if name == "__name__":
                    raise RuntimeError("REJECTION_METACLASS_NAME_EXECUTED")
                return super().__getattribute__(name)

        class ReprAndNameRefuse(metaclass=Unnameable):
            def __str__(self):
                return "ordinary rendering"

            def __repr__(self):
                raise RuntimeError("REJECTION_REPR_REFUSED")

        operation = self.bundle["bridge_operation"]
        client = FakeOTCSClient(
            self.bundle["downstream_receipt"], reject_code=ReprAndNameRefuse())
        result = self.bridge(client).execute(
            operation, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])
        record = self.bridge(client).outbox_record(
            operation["project_id"], operation["idempotency_key"])
        self.assertEqual(
            (result["status"], record["state"], record["rejection_code"],
             client.calls, client.effects),
            ("DOWNSTREAM_REJECTED", "LOCAL_FAILED", "<unrenderable ReprAndNameRefuse>", 1, 0),
        )

    def test_an_unrenderable_rejection_whose_class_name_is_a_subclass_is_recorded(self) -> None:
        """A class's name may itself be a str subclass, and formatting it runs its code.

        Measured: `type(SubclassName("X"), (), {})` keeps the subclass as the class's
        name, and `"%s" % name` calls the subclass's `__str__`. So the name read through
        the base descriptor is made plain before it is formatted.
        """
        class RefusesToFormat(str):
            def __str__(self):
                raise RuntimeError("REJECTION_CLASS_NAME_FORMATTED")

        def refuse_repr(self):
            raise RuntimeError("REJECTION_REPR_REFUSED")

        oddly_named = type(RefusesToFormat("OddlyNamed"), (), {"__repr__": refuse_repr})
        operation = self.bundle["bridge_operation"]
        client = FakeOTCSClient(self.bundle["downstream_receipt"], reject_code=oddly_named())
        result = self.bridge(client).execute(
            operation, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])
        record = self.bridge(client).outbox_record(
            operation["project_id"], operation["idempotency_key"])
        self.assertEqual(
            (result["status"], record["state"], record["rejection_code"]),
            ("DOWNSTREAM_REJECTED", "LOCAL_FAILED", "<unrenderable OddlyNamed>"),
        )

    def test_a_rejection_code_that_is_not_a_string_is_rendered_not_replaced(self) -> None:
        """The control the case above needs, and it guards the promise, not the mechanism.

        A fix that answered every non-string code with its type name would pass the case
        above while throwing away the downstream's word - which is the one thing this
        function promises to keep. An object that CAN describe itself must still be
        recorded as it describes itself.
        """
        class DescribesItself:
            def __repr__(self) -> str:
                return "DOWNSTREAM_CODE_7"

        operation = self.bundle["bridge_operation"]
        client = FakeOTCSClient(
            self.bundle["downstream_receipt"], reject_code=DescribesItself())
        self.bridge(client).execute(
            operation, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])
        record = self.bridge(client).outbox_record(
            operation["project_id"], operation["idempotency_key"])
        self.assertEqual(record["rejection_code"], "DOWNSTREAM_CODE_7")

    def test_a_rejection_code_that_can_be_stored_is_kept_verbatim(self) -> None:
        """The control the case above needs: an ordinary code is not touched."""
        operation = self.bundle["bridge_operation"]
        client = FakeOTCSClient(
            self.bundle["downstream_receipt"], reject_code="DOWNSTREAM_POLICY")
        result = self.bridge(client).execute(
            operation, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])
        self.assertEqual(result["status"], "DOWNSTREAM_REJECTED")
        record = self.bridge(client).outbox_record(
            operation["project_id"], operation["idempotency_key"])
        self.assertEqual(
            (record["state"], record["rejection_code"], client.calls, client.effects),
            ("LOCAL_FAILED", "DOWNSTREAM_POLICY", 1, 0),
        )

    def test_a_rejection_code_that_refuses_to_be_encoded_is_still_recorded(self) -> None:
        """The same class as the case above, one layer down: `encode` is the object's code.

        `_storable_text` asks whether a string can be written into a TEXT column by
        encoding it, and `isinstance(value, str)` admits a SUBCLASS whose `encode` is
        whatever the subclass says. The clause there catches UnicodeEncodeError alone, so
        a subclass raising anything else sent that exception out of the rejection handler
        and left the row mid-call - exactly the outcome the repr guard was added to
        prevent, reached by the next method along.

        The plant is a str subclass and not a foreign object, because a foreign object is
        refused earlier and would measure that instead.
        """
        class RefusesToBeEncoded(str):
            def encode(self, *arguments: object, **keywords: object) -> bytes:
                raise RuntimeError("this code will not be encoded")

            def __getitem__(self, item: object) -> str:
                # The truncation is the object's code too, and an override returning
                # something sqlite cannot bind reaches the same raw driver error by a
                # different door. Both are in the plant so the fix is measured against
                # the class across both methods.
                raise RuntimeError("this code will not be sliced")

        operation = self.bundle["bridge_operation"]
        client = FakeOTCSClient(
            self.bundle["downstream_receipt"],
            reject_code=RefusesToBeEncoded("DOWNSTREAM_WILL_NOT_ENCODE"))
        result = self.bridge(client).execute(
            operation, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])
        self.assertEqual(result["status"], "DOWNSTREAM_REJECTED")
        record = self.bridge(client).outbox_record(
            operation["project_id"], operation["idempotency_key"])
        self.assertEqual(record["state"], "LOCAL_FAILED")
        # The characters are what the downstream said, so they are what is kept: asking
        # the base implementation answers the question without running the object's code.
        self.assertEqual(record["rejection_code"], "DOWNSTREAM_WILL_NOT_ENCODE")

    def test_a_receipt_string_is_read_as_its_characters_not_as_its_object(self) -> None:
        """A str subclass whose `__len__` raises, with ordinary characters, is admitted.

        `_text` asked `len` and truthiness of the object itself before anything normalised
        it, and a subclass whose `__len__` raised left the receipt admission AFTER the
        downstream effect. Two layers now make the answer about the characters - the
        mapping door copies the receipt to plain strings, and `_text` normalises again -
        and a break of either alone leaves this case green, measured; the case that
        reddens when `_text` alone stops normalising is the value-object case, which
        builds a receipt directly. Ordinary characters COMMIT. The assertion is
        on COMMITTED and not merely "no raw exception": the post-effect catch would also
        stop the exception, as RECONCILIATION_REQUIRED, and only a commit shows that the
        object's own code was never asked.
        """
        class RefusesToBeMeasured(str):
            def __len__(self) -> int:
                raise RuntimeError("this field will not be measured")

        receipt = copy.deepcopy(self.bundle["downstream_receipt"])
        receipt["signature_ref"] = RefusesToBeMeasured(
            self.bundle["downstream_receipt"]["signature_ref"])
        client = FakeOTCSClient(receipt)
        result = self.bridge(client).execute(
            self.bundle["bridge_operation"], copy.deepcopy(self.bundle["intent"]),
            self.bundle["evidence"])
        self.assertEqual(result["status"], "COMMITTED")

    def test_a_receipt_that_cannot_be_read_forces_reconciliation(self) -> None:
        """A receipt that cannot be read is an unusable receipt, not a row left mid-call.

        The admission caught only this module's errors, so a receipt mapping that raised
        on being read left the `try` and the row stayed CALLING over an effect that had
        happened. Two paths, one case each. A mapping whose own `keys` and `__getitem__`
        raise is read by the plain copy, which runs its code once and refuses it by name,
        so the row records OTCS_RECEIPT_FIELDS. And the clause that answers any other
        exception - kept for a fault in this module's own receipt code, which no copy
        sees - is driven by injecting exactly that fault, so it records the type's name.
        """
        from collections.abc import Mapping
        from contextlib import nullcontext
        from unittest import mock

        class Unreadable(Mapping):
            def __getitem__(self, key):
                raise RuntimeError("this receipt will not be read")

            def __iter__(self):
                raise RuntimeError("this receipt will not be read")

            def __len__(self) -> int:
                return 1

        class HandsBackAnUnreadableReceipt(FakeOTCSClient):
            def append_event(self, request):
                self.calls += 1
                self.effects += 1
                return Unreadable()

        def admits_nothing(value):
            raise RuntimeError("a fault in the module's own receipt code")

        operation = self.bundle["bridge_operation"]
        for label, client, fault, recorded in (
            ("a receipt mapping that will not be read",
             HandsBackAnUnreadableReceipt(self.bundle["downstream_receipt"]),
             None, "OTCS_RECEIPT_FIELDS"),
            ("a fault in the module's own receipt code",
             FakeOTCSClient(self.bundle["downstream_receipt"]),
             admits_nothing, "RuntimeError"),
        ):
            with self.subTest(path=label):
                self.setUp()
                with (mock.patch.object(OTCSReceiptRef, "from_mapping", fault)
                      if fault else nullcontext()):
                    with self.assertRaisesRegex(
                            OTCSReconciliationRequired,
                            rf"^OTCS_RECEIPT_UNUSABLE: {recorded}$"):
                        self.bridge(client).execute(
                            operation, copy.deepcopy(self.bundle["intent"]),
                            self.bundle["evidence"])
                self.assertEqual(client.effects, 1)
                record = self.bridge(client).outbox_record(
                    operation["project_id"], operation["idempotency_key"])
                self.assertEqual(record["state"], "RECONCILIATION_REQUIRED")
                self.assertEqual(record["last_error"], recorded)

    def test_a_receipt_that_says_it_matches_is_compared_by_its_characters(self) -> None:
        """A receipt for another project is refused even when its value says it matches.

        The value objects asked each helper and then kept what they had been HANDED, so
        the receipt-against-operation check ran the object's own `!=`. A str subclass
        that answers every comparison with "equal" carried a receipt naming another
        project past that check, after the downstream effect. The fields are now kept as
        the helpers' plain answers; the next case is the control that keeps the refusal
        about the characters and not about the type.
        """
        receipt = copy.deepcopy(self.bundle["downstream_receipt"])
        receipt["project_id"] = _AgreesWithEverything("another-project")
        client = FakeOTCSClient(receipt)
        operation = self.bundle["bridge_operation"]
        with self.assertRaisesRegex(
                OTCSReconciliationRequired,
                r"^OTCS_RECEIPT_UNUSABLE: OTCS_RECEIPT_MISMATCH$"):
            self.bridge(client).execute(
                operation, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])
        record = self.bridge(client).outbox_record(
            operation["project_id"], operation["idempotency_key"])
        self.assertEqual(record["state"], "RECONCILIATION_REQUIRED")

    def test_a_receipt_that_says_it_matches_and_does_is_committed(self) -> None:
        receipt = copy.deepcopy(self.bundle["downstream_receipt"])
        receipt["project_id"] = _AgreesWithEverything(receipt["project_id"])
        result = self.bridge(FakeOTCSClient(receipt)).execute(
            self.bundle["bridge_operation"], copy.deepcopy(self.bundle["intent"]),
            self.bundle["evidence"])
        self.assertEqual(result["status"], "COMMITTED")

    def test_a_value_object_keeps_the_answer_not_the_object_handed_in(self) -> None:
        """Each field is kept as the plain value its helper returned; a nested reference
        is admitted only as its exact class; the refusal names the field's own code.

        Rows marked `lie` were ADMITTED before this change, measured: the object's own
        `!=` or `<` answered the question the helper had already asked of its characters.
        The other rows pin shapes the same door now names instead of failing inside a
        comparison. The controls are the last block: an ordinary subclass is admitted and
        stored as the plain type, so the refusals are about values, not about subclassing.
        """
        from dataclasses import fields, replace

        class LiesAboutOrder(int):
            def __lt__(self, other):
                return False

        class NotAString:
            def __eq__(self, other):
                return True

            def __ne__(self, other):
                return False

        operation = OTCSAppendOperation.from_mapping(self.bundle["bridge_operation"])
        receipt = OTCSReceiptRef.from_mapping(self.bundle["downstream_receipt"])
        head, ref = operation.expected_head, operation.governing_object

        class SaysItIsTheSameReference(type(ref)):
            def __eq__(self, other):
                return True

            __hash__ = type(ref).__hash__

        another_governing_object = SaysItIsTheSameReference(
            ref.object_kind, ref.object_id, ref.hash_profile, "B" * 64)
        rows = [
            ("lie", "OTCS_HASH_PROFILE", lambda: replace(ref, hash_profile=NotAString())),
            ("lie", "OTCS_HASH_PROFILE",
             lambda: replace(ref, hash_profile=_AgreesWithEverything("another-profile"))),
            ("lie", "OTCS_HEAD_EVENT_REF_MISMATCH",
             lambda: replace(head, event_id=_AgreesWithEverything("another-event"))),
            ("lie", "OTCS_OPERATION_SEQUENCE",
             lambda: replace(operation, project_sequence=LiesAboutOrder(-7))),
            ("lie", "OTCS_BRIDGE_VERSION", lambda: replace(operation, bridge_version=NotAString())),
            ("lie", "OTCS_HASH_REF_FIELDS",
             lambda: replace(operation, governing_object=another_governing_object)),
            ("shape", "OTCS_HASH_REF_FIELDS",
             lambda: replace(operation, payload=operation.payload.to_mapping())),
            ("shape", "OTCS_HEAD_FIELDS",
             lambda: replace(operation, expected_head=head.to_mapping())),
            ("shape", "OTCS_HASH_REF_FIELDS",
             lambda: replace(head, history_digest=head.history_digest.to_mapping())),
            ("shape", "OTCS_HEAD_FIELDS",
             lambda: replace(receipt, previous_head=receipt.previous_head.to_mapping())),
            ("shape", "OTCS_LEGAL_EVIDENCE_FIELDS",
             lambda: replace(operation, legal_evidence=list(operation.legal_evidence))),
            ("shape", "OTCS_LEGAL_EVIDENCE_FIELDS",
             lambda: replace(operation, legal_evidence=operation.legal_evidence
                             + operation.legal_evidence[:1])),
        ]
        for kind, code, build in rows:
            with self.subTest(kind=kind, code=code):
                with self.assertRaises(OTCSBridgeError) as caught:
                    build()
                self.assertEqual(caught.exception.code, code)
                self.assertIs(type(caught.exception.detail), str)

        class Ordinary(str):
            pass

        class OrdinaryInt(int):
            pass

        admitted = [
            replace(operation, project_id=Ordinary(operation.project_id),
                    project_sequence=OrdinaryInt(operation.project_sequence)),
            # An identifier as well: a receipt arriving through `execute` is made plain by
            # the copy before its fields are asked, so only a receipt built here shows
            # whether the object keeps what it was handed.
            replace(receipt, signature_ref=Ordinary(receipt.signature_ref),
                    project_id=Ordinary(receipt.project_id),
                    project_sequence=OrdinaryInt(receipt.project_sequence)),
            replace(ref, object_id=Ordinary(ref.object_id)),
        ]
        plain = (str, int, tuple, type(ref), type(head))
        for value in admitted:
            for field in fields(value):
                with self.subTest(kept=type(value).__name__, field=field.name):
                    self.assertIn(type(getattr(value, field.name)), plain)

    def test_a_value_that_says_it_is_a_string_is_asked_its_real_type(self) -> None:
        """An object that answers `__class__` with `str` is not admitted as a string.

        `isinstance` consults `__class__`, so such an object passed every string door and
        the base normalisation behind it raised a bare TypeError - at a door, before any
        effect, and in the recording of a downstream rejection, after one, where it left
        the row CALLING. The control on the rejection path is a plain code, which settles
        the row; the hostile code must settle it the same way, recorded as rendered text.
        """
        operation = self.bundle["bridge_operation"]
        for field, value, code in (
            ("project_id", _ClaimsToBeAString(), "OTCS_OPERATION_PROJECT_ID"),
            ("project_sequence", _ClaimsToBeAnInteger(), "OTCS_OPERATION_SEQUENCE"),
        ):
            with self.subTest(door=field):
                hostile = copy.deepcopy(operation)
                hostile[field] = value
                client = FakeOTCSClient(self.bundle["downstream_receipt"])
                with self.assertRaisesRegex(OTCSBridgeError, rf"^{code}(:|$)"):
                    self.bridge(client).execute(
                        hostile, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])
                self.assertEqual(client.calls, 0)
        for label, reject_code in (
            ("control: a plain rejection code", "DOWNSTREAM_SAYS_NO"),
            ("a code that says it is a string", _ClaimsToBeAString()),
        ):
            with self.subTest(rejection=label):
                self.setUp()
                client = FakeOTCSClient(
                    self.bundle["downstream_receipt"], reject_code=reject_code)
                self.bridge(client).execute(
                    operation, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])
                record = self.bridge(client).outbox_record(
                    operation["project_id"], operation["idempotency_key"])
                self.assertEqual(record["state"], "LOCAL_FAILED")
                self.assertEqual(client.calls, 1)
                if label.startswith("control"):
                    self.assertEqual(record["rejection_code"], reject_code)
                else:
                    self.assertTrue(record["rejection_code"].startswith("<"),
                                    record["rejection_code"])

    def test_a_caller_string_that_says_it_matches_is_compared_by_its_characters(
        self,
    ) -> None:
        """What `execute` is handed is read as characters before any binding is checked.

        The intent and evidence checks compared the caller's own strings with the
        strings' own code: a scope field of other characters whose `!=` said equal, and a
        digest of other characters whose `upper` answered with the right one, each passed
        the binding and reached the downstream. Each row runs twice, with the wrong value
        as a plain string and as a string that lies, and both must be refused by the same
        code - so the refusal is about the characters, and the plain run shows the row
        reaches the check it names.
        """
        client = FakeOTCSClient(self.bundle["downstream_receipt"])
        self.bridge(client).execute(
            self.bundle["bridge_operation"], copy.deepcopy(self.bundle["intent"]),
            copy.deepcopy(self.bundle["evidence"]))
        self.assertEqual(client.calls, 1, "control: the untouched bundle reaches the downstream")

        def intent_scope(bundle, lie):
            wrong = "another-event-type"
            bundle["intent"]["scope"]["event_type"] = (
                _AgreesWithEverything(wrong) if lie else wrong)

        def intent_digest(bundle, lie):
            right = bundle["intent"]["payload_hash"].upper()
            bundle["intent"]["payload_hash"] = (
                _UpperAnswers("9" * 64, right) if lie else "9" * 64)

        def evidence_digest(bundle, lie):
            item = bundle["evidence"]["items"][0]
            right = item["sha256"].upper()
            item["sha256"] = _UpperAnswers("9" * 64, right) if lie else "9" * 64

        for mutate, code in (
            (intent_scope, "OTCS_INTENT_SCOPE"),
            (intent_digest, "OTCS_INTENT_BINDING"),
            (evidence_digest, "OTCS_EVIDENCE_BINDING"),
        ):
            for lie in (False, True):
                with self.subTest(row=mutate.__name__, lying=lie):
                    self.setUp()
                    bundle = copy.deepcopy(self.bundle)
                    mutate(bundle, lie)
                    client = FakeOTCSClient(self.bundle["downstream_receipt"])
                    with self.assertRaisesRegex(OTCSBridgeError, rf"^{code}(:|$)"):
                        self.bridge(client).execute(
                            bundle["bridge_operation"], bundle["intent"], bundle["evidence"])
                    self.assertEqual(client.calls, 0)
        # A key that is not a string: no document has one, and before the copy refused it
        # an integer key beside string ones escaped as a raw TypeError from `_closed`.
        with self.subTest(row="a key that is not text"):
            self.setUp()
            operation = copy.deepcopy(self.bundle["bridge_operation"])
            operation[7] = "a key no document has"
            client = FakeOTCSClient(self.bundle["downstream_receipt"])
            with self.assertRaisesRegex(OTCSBridgeError, r"^OTCS_OPERATION_FIELDS(:|$)"):
                self.bridge(client).execute(
                    operation, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])
            self.assertEqual(client.calls, 0)

    def test_what_is_validated_is_what_is_used(self) -> None:
        """The document the binding checks is the document the replay identity is taken of.

        The validators read a copy; the replay identity and the engine read what the
        caller handed over. For a dict subclass those are two readings of one object -
        `dict()` of it runs its own `keys` - and measured with an intent that stores one
        document and answers every read with another, the two sides saw different
        documents. `execute` now copies once and uses only the copy, so the stored
        identity is that of the document that was checked: a replay of that same
        document, as a plain dict, is the same request and calls nothing again.
        """
        honest = copy.deepcopy(self.bundle["intent"])
        shown = copy.deepcopy(honest)
        shown["scope"]["event_type"] = "another-event-type"
        client = FakeOTCSClient(self.bundle["downstream_receipt"])
        operation = self.bundle["bridge_operation"]
        self.bridge(client).execute(
            operation, _TwoFacedDict(honest, shown), copy.deepcopy(self.bundle["evidence"]))
        self.assertEqual(client.calls, 1)
        self.bridge(client).execute(
            operation, copy.deepcopy(honest), copy.deepcopy(self.bundle["evidence"]))
        self.assertEqual(client.calls, 1, "the replay of the checked document called again")

    def test_a_value_that_lies_about_its_type_is_answered_by_name_wherever_it_is_placed(
        self,
    ) -> None:
        """A caller's object whose `__class__` lies is answered by name at every place.

        The door leaves a value it does not recognise for the checks that refuse it by name,
        and some readers met it first and asked `isinstance`, which asks `__class__`.
        Measured by exactly this sweep: an object claiming `str` in a hash field of the
        binding, the intent or an evidence item left `execute` as a raw TypeError or
        AttributeError, and one claiming `list` left as a raw TypeError wherever it was
        iterated - by the hash-case normaliser, and at the evidence's `items` by the
        evidence check, which met it first there. The class is the question, so the sweep
        plants four liars - claiming str, int, mapping and list - at every leaf and object
        of the operation, the intent and the evidence, each on a fresh engine and outbox,
        and requires a named answer every time. It names no codes: which check answers is
        each field's own business, pinned elsewhere.

        The control is the unmodified documents, which commit, and the count of places
        driven, so a sweep that reached nothing cannot pass for a clean one.
        """
        liars = {
            "str": _ClaimsToBeAString,
            "int": _ClaimsToBeAnInteger,
            "mapping": _ClaimsToBeAMapping,
            "list": _ClaimsToBeAList,
        }
        base = {
            "operation": self.bundle["bridge_operation"],
            "intent": self.bundle["intent"],
            "evidence": self.bundle["evidence"],
        }

        def places(value, prefix=()):
            yield prefix
            if isinstance(value, dict):
                for key, child in value.items():
                    yield from places(child, prefix + (key,))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    yield from places(child, prefix + (index,))

        runs = iter(range(10 ** 6))

        def drive(documents):
            index = next(runs)
            engine = UniversalConnectionLedger(
                self.bundle["profile"],
                self.bundle["declaration"],
                signing_key=b"synthetic-reference-signing-key",
                clock=FixedClock(datetime(2026, 8, 1, 10, 0, tzinfo=timezone.utc)),
                state_path=self.temporary_root / f"liar-{index}-ledger.sqlite",
            )
            engine.activate(
                self.bundle["declaration"]["governance"]["approval_owner_id"],
                "evidence://synthetic/otcs/declaration-activation",
                actor_scope=ROLE_GOVERNANCE,
            )
            engine.issue_grant(copy.deepcopy(self.bundle["grant"]), actor_scope=ROLE_GOVERNANCE)
            client = FakeOTCSClient(self.bundle["downstream_receipt"])
            bridge = OTCSBridge(
                engine, client, self.temporary_root / f"liar-{index}-outbox.sqlite")
            return bridge.execute(
                documents["operation"], documents["intent"], documents["evidence"])

        control = drive(copy.deepcopy(base))
        self.assertEqual(control["status"], "COMMITTED")
        driven = 0
        refused = 0
        for door in base:
            for place in list(places(base[door]))[1:]:
                for name, liar in liars.items():
                    documents = copy.deepcopy(base)
                    target = documents[door]
                    for step in place[:-1]:
                        target = target[step]
                    target[place[-1]] = liar()
                    driven += 1
                    with self.subTest(door=door, place=list(place), liar=name):
                        try:
                            drive(documents)
                        except (OTCSBridgeError, ContractViolation):
                            refused += 1
                        else:
                            self.fail("a liar was ADMITTED here")
        # Every leaf and object of the three reference documents, four liars each - and the
        # answer counted, not the attempt. `driven` was incremented before the drive and
        # nothing else was asserted, so a liar that was admitted passed as quietly as one
        # refused: the number said how many were tried, and the case read as though it said
        # how many were answered. The `else` is what makes an admission a failure; the
        # equality below is what makes the count mean what its name says.
        #
        # Changing _plain_copy's unknown-value fallback from `return value` to
        # `return str(value)` reaches that `else`: a liar becomes an admitted string.
        # Removing only the engine's JSON-type check does not reach it, because the
        # bridge's own doors still refuse those objects. The two model breaks exercise
        # different boundaries; the latter is not evidence that this marker cannot bite.
        self.assertEqual(refused, driven)
        self.assertGreater(driven, 400)

    def test_a_value_that_lies_in_comparison_is_answered_by_name(self) -> None:
        """A value the door's copy does not recognise, answering every comparison with agreement.

        The copy leaves an object it does not recognise for the checks that refuse it by
        name, and the binding check is one of the readers that meets it first: it asks
        `actual != expected`, which runs that object's own comparison. The four liars of
        the sweep above claim a CLASS and are refused by exactly that inequality, so none
        of them says what happens when the comparison itself lies. Measured: such an object
        passes the binding and is answered one layer in, by the engine's own value-type
        check, with nothing committed and nothing sent downstream. This case pins WHERE the
        answer comes from - the binding inherits it - so that a change to that guard
        reddens here instead of opening a door silently. Three places: a compared field, a
        hash field, and a field inside the scope. The control is the unmodified documents.
        """

        class LiesInComparison:
            def __eq__(self, other):  # noqa: D105
                return True

            def __ne__(self, other):  # noqa: D105
                return False

            def __hash__(self):  # noqa: D105
                return 0

        client = FakeOTCSClient(self.bundle["downstream_receipt"])
        for place in (("action_id",), ("payload_hash",), ("scope", "project_id")):
            intent = copy.deepcopy(self.bundle["intent"])
            target = intent
            for step in place[:-1]:
                target = target[step]
            target[place[-1]] = LiesInComparison()
            with self.subTest(place="/".join(place)):
                with self.assertRaises(ContractViolation) as raised:
                    self.bridge(client).execute(
                        self.bundle["bridge_operation"], intent, self.bundle["evidence"])
                self.assertEqual(raised.exception.code, "JSON_VALUE_TYPE")
        self.assertEqual(
            self.bridge(client).execute(
                self.bundle["bridge_operation"],
                copy.deepcopy(self.bundle["intent"]),
                self.bundle["evidence"],
            )["status"],
            "COMMITTED",
        )

    def test_a_document_nested_past_the_limit_is_refused_at_the_door(self) -> None:
        """A caller's document nested past the engine's limit is refused at the door, by name.

        The door's copy stopped at the limit and left the rest as it was handed in, for the
        engine's depth guard to answer - but the replay identity's hash-case normaliser
        walks the whole document before the hash reaches that guard, with no bound.
        Measured: a plain list nested 3000 deep left `execute` as a raw RecursionError, and
        a str or dict subclass past the limit ran its own `upper` or `items` and left as
        what that raised. Each of the three doors refuses under its own code now, and
        nothing reaches the downstream. The depths are literals of the published limit, 64,
        so a change to it is a change this case notices rather than one it follows.

        The control is a list nested inside the bound: the door passes it, and whatever
        answers it next - the bridge's checks or the engine's, whose refusals pass through
        the bridge as they are - answers by name without the door's words.
        """
        class RaisingUpper(str):
            def upper(self):
                raise RuntimeError("the caller's upper ran")

        class RaisingItems(dict):
            def items(self):
                raise RuntimeError("the caller's items ran")

        def nest(leaf, depth):
            for _ in range(depth):
                leaf = [leaf]
            return leaf

        plants = (
            ("a plain list nested 3000 deep", lambda: nest(1, 3000)),
            ("a str subclass whose upper raises, 70 deep",
             lambda: nest({"payload_hash": RaisingUpper("a" * 64)}, 70)),
            ("a dict subclass whose items raises, 70 deep",
             lambda: nest(RaisingItems(x=1), 70)),
            # The boundary, counted as the wire counts it, the document itself included:
            # 64 lists below its top level make 65 containers, the innermost empty. The
            # door once counted values, as the engine does, and admitted this - while the
            # stored-row walk, which counts containers, refuses it when it reads a row back.
            ("65 containers, the innermost empty", lambda: nest([], 63)),
        )
        doors = (
            ("operation", "OTCS_OPERATION_FIELDS"),
            ("intent", "OTCS_INTENT_BINDING"),
            ("evidence", "OTCS_EVIDENCE_BINDING"),
        )

        def drive(door, value):
            documents = {
                "operation": copy.deepcopy(self.bundle["bridge_operation"]),
                "intent": copy.deepcopy(self.bundle["intent"]),
                "evidence": copy.deepcopy(self.bundle["evidence"]),
            }
            documents[door]["deep"] = value
            client = FakeOTCSClient(self.bundle["downstream_receipt"])
            with self.assertRaises((OTCSBridgeError, ContractViolation)) as raised:
                self.bridge(client).execute(
                    documents["operation"], documents["intent"], documents["evidence"])
            return raised.exception, client

        for label, plant in plants:
            for door, code in doors:
                with self.subTest(plant=label, door=door):
                    refusal, client = drive(door, plant())
                    self.assertIsInstance(refusal, OTCSBridgeError)
                    self.assertEqual(refusal.code, code)
                    self.assertIn("nested past 64", str(refusal))
                    self.assertEqual(client.calls, 0)
        # The controls, and what each of them can say. Through a door the plant is an
        # UNDECLARED field, so the document is refused whatever its depth: asserting the
        # absence of the door's own words there says the refusal was not this guard's, and
        # nothing more - an over-refusing guard with another detail would leave it green.
        for door, _code in doors:
            for label, inside in (("a list nested 40 deep", nest(1, 40)),
                                  ("64 containers, the innermost empty", nest([], 62))):
                with self.subTest(control=label, door=door):
                    refusal, client = drive(door, inside)
                    self.assertNotIn("nested past", str(refusal))
                    self.assertEqual(client.calls, 0)
        # So ADMISSION is asked where it is observable: of the door's own copy, which
        # returns the value it admits. The depths here are one container SHALLOWER than
        # the plants above, and deliberately: through a door the document itself is the
        # outermost container, and this call has no document around the value. At the
        # bound the copy returns what it was given; one container further it refuses with
        # the words the rows above require - the two sides of the boundary, one reader.
        for label, inside in (("a list nested 40 deep", nest(1, 40)),
                              ("64 containers, the innermost empty", nest([], 63))):
            with self.subTest(admitted=label):
                self.assertEqual(_plain_copy(inside, "OTCS_OPERATION_FIELDS"), inside)
        with self.subTest(admitted="65 containers, the innermost empty"):
            with self.assertRaises(OTCSBridgeError) as raised:
                _plain_copy(nest([], 64), "OTCS_OPERATION_FIELDS")
            self.assertIn("nested past 64", str(raised.exception))

    def test_a_stored_plain_column_of_the_wrong_type_is_refused_by_name(self) -> None:
        """A BLOB or an integer in a text column is refused, not handed back as the record.

        The decoder asked storability of strings and passed every non-string through, so
        five plain columns came back from `outbox_record` as `bytes` or `int`. Pinned here
        on `last_error`, the column a reader is least likely to type-check, with the two
        halves of the rule beside it: NULL where the schema allows it is an answer, and
        NULL where it does not is a refusal. And on a JSON column: once where the parse
        stood in for the question and `json.loads` takes bytes, and twice for the one JSON
        column declared NOT NULL - NULL, and the text `null`, which parses to the same None
        and is refused under its own detail. And twice on `state`, which
        the shape check skips because the state check answers it first: the row's own state
        name as a BLOB, the plant a reader would take for the honest value, and NULL, which
        a table without the module's NOT NULL admits.

        And the list of columns that may be NULL is held to the schema itself, read back
        from a table this module created: the list and the create statement are two homes
        for one fact, and this is the tie between them.
        """
        import sqlite3

        client = FakeOTCSClient(self.bundle["downstream_receipt"])
        operation = self.bundle["bridge_operation"]
        bridge = self.bridge(client)
        bridge.execute(operation, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])
        key = (operation["project_id"], operation["idempotency_key"])
        with closing(sqlite3.connect(self.outbox_path)) as connection:
            declared_nullable = {
                row[1] for row in connection.execute("PRAGMA table_info(otcs_bridge_outbox)")
                if not row[3]
            }
            base_row = dict(zip(
                [row[1] for row in connection.execute("PRAGMA table_info(otcs_bridge_outbox)")],
                connection.execute("SELECT * FROM otcs_bridge_outbox").fetchone()))
        self.assertEqual(declared_nullable, set(_OUTBOX_NULLABLE))

        columns = sorted(base_row)

        def plant(name, column, value):
            path = self.temporary_root / name
            row = dict(base_row, **{column: value})
            with closing(sqlite3.connect(path)) as connection:
                connection.execute(
                    "CREATE TABLE otcs_bridge_outbox (" + ", ".join(columns)
                    + ", PRIMARY KEY (project_id, idempotency_key))")
                connection.execute(
                    "INSERT INTO otcs_bridge_outbox (" + ", ".join(columns) + ") VALUES ("
                    + ", ".join("?" for _ in columns) + ")", [row[c] for c in columns])
                connection.commit()
            return OTCSBridge(self.engine, client, path)

        # The last row is a JSON column, which the parse used to answer: `json.loads`
        # accepts bytes, so the row's own document stored as a BLOB came back as the record.
        for label, column, value, code, detail in (
            ("a BLOB", "last_error", b"\xff\xfe", "OTCS_OUTBOX_ROW_TEXT", "last_error: not text"),
            ("an integer", "last_error", 7, "OTCS_OUTBOX_ROW_TEXT", "last_error: not text"),
            # A number the canonical form refuses is still a number in a text column. The
            # walk meant for parsed values used to answer it first, with the JSON code.
            ("infinity, stored as a REAL", "last_error", float("inf"),
             "OTCS_OUTBOX_ROW_TEXT", "last_error: not text"),
            ("NULL where the schema forbids it", "updated_at", None,
             "OTCS_OUTBOX_ROW_TEXT", "updated_at: null"),
            ("a BLOB of valid JSON", "request_json",
             base_row["request_json"].encode("utf-8"),
             "OTCS_OUTBOX_ROW_JSON", "request_json: not text"),
            # NULL in the one JSON column declared NOT NULL, and the four characters `null`,
            # which parse to the same None: both are refused, and the detail says which.
            ("NULL in request_json", "request_json", None,
             "OTCS_OUTBOX_ROW_JSON", "request_json: null"),
            ("the text null in request_json", "request_json", "null",
             "OTCS_OUTBOX_ROW_JSON", "request_json: JSON null"),
            ("a BLOB holding the row's own state", "state",
             base_row["state"].encode("utf-8"),
             "OTCS_OUTBOX_STATE", "state: not text"),
            ("NULL in state", "state", None, "OTCS_OUTBOX_STATE", "state: null"),
            # And valid JSON that is not a DOCUMENT. Every value this module writes into
            # those columns is an object, the parse admits any JSON value, and both of
            # these came back as the record's `request` - measured, `[]` and `7`.
            ("an array in request_json", "request_json", "[]",
             "OTCS_OUTBOX_ROW_JSON", "request_json: not an object"),
            ("a number in request_json", "request_json", "7",
             "OTCS_OUTBOX_ROW_JSON", "request_json: not an object"),
            ("an array in a nullable JSON column", "receipt_json", "[]",
             "OTCS_OUTBOX_ROW_JSON", "receipt_json: not an object"),
        ):
            with self.subTest(stored=label, column=column):
                with self.assertRaises(OTCSBridgeError) as raised:
                    plant(f"wrong-{column}-{label[:4]}.sqlite", column, value).outbox_record(*key)
                self.assertEqual(raised.exception.code, code)
                self.assertIn(detail, str(raised.exception))
        with self.subTest(stored="NULL where the schema allows it"):
            record = plant("null-last-error.sqlite", "last_error", None).outbox_record(*key)
            self.assertIsNone(record["last_error"])

    def test_a_stored_document_is_bounded_where_the_wire_bounds_it(self) -> None:
        """A stored JSON column is refused past the nesting limit exactly where the wire is.

        The walk over a parsed column applies the engine's limit, and it has twice counted
        differently from the wire's bracket scan: seeded at one, it refused a document of
        exactly 64 containers that the wire admits, so a row the engine accepted could not
        be read back; counting nodes, it admitted 65 containers whose innermost is empty,
        which the wire refuses. Both were measured by a probe and fixed, and nothing kept
        the measurement. This case is it: 63, 64 and 65 containers, the document itself
        counted, each with a scalar at the bottom and with an empty container there. The
        verdict is written as a literal of the published limit, 64, and the wire's scan and
        the walk are both held to it, so a change to either is a red here, not a new
        agreement.
        """
        import sqlite3

        from nc25_universal_adapter import WireError, _reject_deep_nesting

        client = FakeOTCSClient(self.bundle["downstream_receipt"])
        operation = self.bundle["bridge_operation"]
        self.bridge(client).execute(
            operation, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])
        key = (operation["project_id"], operation["idempotency_key"])
        with closing(sqlite3.connect(self.outbox_path)) as connection:
            columns = [row[1] for row in
                       connection.execute("PRAGMA table_info(otcs_bridge_outbox)")]
            base_row = dict(zip(
                columns, connection.execute("SELECT * FROM otcs_bridge_outbox").fetchone()))

        def read_back(name, text):
            path = self.temporary_root / name
            row = dict(base_row, request_json=text)
            with closing(sqlite3.connect(path)) as connection:
                connection.execute(
                    "CREATE TABLE otcs_bridge_outbox (" + ", ".join(columns)
                    + ", PRIMARY KEY (project_id, idempotency_key))")
                connection.execute(
                    "INSERT INTO otcs_bridge_outbox (" + ", ".join(columns) + ") VALUES ("
                    + ", ".join("?" for _ in columns) + ")", [row[c] for c in columns])
                connection.commit()
            return OTCSBridge(self.engine, client, path).outbox_record(*key)

        for containers in (63, 64, 65):
            for bottom, leaf in (("a scalar", "1"), ("an empty container", "")):
                # The object is the first container; the lists below it are the rest.
                lists = containers - 1
                text = '{"x": ' + "[" * lists + leaf + "]" * lists + "}"
                refused = containers > 64
                with self.subTest(containers=containers, bottom=bottom, side="wire"):
                    try:
                        _reject_deep_nesting(text)
                        wire_refused = False
                    except WireError:
                        wire_refused = True
                    self.assertEqual(wire_refused, refused)
                with self.subTest(containers=containers, bottom=bottom, side="walk"):
                    name = f"depth-{containers}-{'scalar' if leaf else 'empty'}.sqlite"
                    if refused:
                        with self.assertRaises(OTCSBridgeError) as raised:
                            read_back(name, text)
                        self.assertEqual(raised.exception.code, "OTCS_OUTBOX_ROW_JSON")
                        self.assertIn("request_json: nested past 64", str(raised.exception))
                    else:
                        record = read_back(name, text)
                        self.assertEqual(record["request"], json.loads(text))

    def test_the_outbox_reader_admits_its_identifiers_like_every_other_door(self) -> None:
        """Both public methods taking this pair refuse a malformed one by name.

        `recover` did and `outbox_record` did not, so which shape a caller had to satisfy
        depended on which method it called. The control matters as much as the refusal: a
        guard that refused everything would pass the first half of this case.
        """
        operation = self.bundle["bridge_operation"]
        client = FakeOTCSClient(self.bundle["downstream_receipt"])
        bridge = self.bridge(client)
        bridge.execute(
            operation, copy.deepcopy(self.bundle["intent"]), self.bundle["evidence"])

        for label, project_id, key, code in (
            ("an empty project id", "", operation["idempotency_key"],
             "OTCS_OPERATION_PROJECT_ID"),
            ("a project id that is not a string", 7, operation["idempotency_key"],
             "OTCS_OPERATION_PROJECT_ID"),
            ("an empty idempotency key", operation["project_id"], "",
             "OTCS_OPERATION_IDEMPOTENCY_KEY"),
        ):
            with self.subTest(outbox_record=label):
                with self.assertRaises(OTCSBridgeError) as raised:
                    bridge.outbox_record(project_id, key)
                self.assertEqual(raised.exception.code, code)

        # Control: the honest pair still returns the record it was asked for, and an
        # unknown but well-formed pair still answers None rather than refusing.
        self.assertEqual(
            bridge.outbox_record(
                operation["project_id"], operation["idempotency_key"])["state"],
            "LOCAL_COMMITTED",
        )
        self.assertIsNone(
            bridge.outbox_record(operation["project_id"], "no-such-key-31"))

    def test_public_lookup_uses_normalized_identifier_characters(self) -> None:
        """SQLite adaptation cannot replace the identifier accepted at the public door."""
        class RedirectedString(str):
            def __new__(cls, text, target):
                value = str.__new__(cls, text)
                value.target = target
                return value

            def __conform__(self, protocol):
                return self.target

        operation = self.bundle["bridge_operation"]
        client = FakeOTCSClient(self.bundle["downstream_receipt"])
        bridge = self.bridge(client)
        bridge.execute(operation, self.bundle["intent"], self.bundle["evidence"])
        honest = (operation["project_id"], operation["idempotency_key"])
        for method_name in ("recover", "outbox_record"):
            read = getattr(bridge, method_name)
            for position in (0, 1):
                for present in (False, True):
                    with self.subTest(method=method_name, identifier=position, present=present):
                        selectors = list(honest)
                        characters = honest[position] if present else "not-the-stored-identifier"
                        target = "not-the-stored-identifier" if present else honest[position]
                        selectors[position] = RedirectedString(characters, target)
                        if not present and method_name == "recover":
                            with self.assertRaisesRegex(OTCSBridgeError, r"^OTCS_OUTBOX_MISSING$"):
                                read(*selectors)
                        else:
                            answer = read(*selectors)
                            if present:
                                field = "status" if method_name == "recover" else "state"
                                self.assertEqual(answer[field],
                                                 "COMMITTED" if field == "status" else "LOCAL_COMMITTED")
                            else:
                                self.assertIsNone(answer)
        self.assertEqual(client.calls, 1)

    @staticmethod
    def _write_outbox_schema(path, column_collations=("BINARY", "BINARY"),
                             key_collations=("BINARY", "BINARY"), *,
                             reverse_key=False, without_rowid=False, extra_index=False):
        """An independent declared-column fixture with configurable key semantics."""
        import sqlite3

        keys = [f"project_id COLLATE {key_collations[0]}",
                f"idempotency_key COLLATE {key_collations[1]}"]
        if reverse_key:
            keys.reverse()
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
                "CREATE TABLE otcs_bridge_outbox ("
                f"project_id TEXT COLLATE {column_collations[0]} NOT NULL, "
                f"idempotency_key TEXT COLLATE {column_collations[1]} NOT NULL, "
                "operation_hash TEXT NOT NULL, permit_hash TEXT NOT NULL, "
                "request_json TEXT NOT NULL, state TEXT NOT NULL, receipt_json TEXT, "
                "execution_request_json TEXT, local_receipt_json TEXT, rejection_code TEXT, "
                "last_error TEXT, updated_at TEXT NOT NULL, PRIMARY KEY ("
                + ", ".join(keys) + "))" + (" WITHOUT ROWID" if without_rowid else ""))
            if extra_index:
                connection.execute("CREATE INDEX state_lookup ON otcs_bridge_outbox(state)")
            connection.commit()

    def test_outbox_refuses_primary_keys_that_alias_identifier_case(self) -> None:
        """Both key positions must retain exact, case-sensitive identifier uniqueness."""
        for position in (0, 1):
            for same_column_collation in (False, True):
                with self.subTest(position=position, column_matches_key=same_column_collation):
                    key_collations = ["BINARY", "BINARY"]
                    key_collations[position] = "NOCASE"
                    columns = key_collations if same_column_collation else ("BINARY", "BINARY")
                    path = self.temporary_root / f"aliased-key-{position}-{same_column_collation}.sqlite"
                    self._write_outbox_schema(path, columns, key_collations)
                    with self.assertRaisesRegex(
                            OTCSBridgeError, r"^OTCS_OUTBOX_COLUMNS: primary key collation is not BINARY$"):
                        SQLiteOTCSOutbox(path)

    def test_outbox_admits_equivalent_binary_key_schemas(self) -> None:
        """Key order, storage layout and unrelated indexes do not change key identity."""
        for reverse in (False, True):
            for without_rowid in (False, True):
                with self.subTest(reverse_key=reverse, without_rowid=without_rowid):
                    path = self.temporary_root / f"binary-key-{reverse}-{without_rowid}.sqlite"
                    self._write_outbox_schema(
                        path, key_collations=("binary", "BiNaRy"), reverse_key=reverse,
                        without_rowid=without_rowid, extra_index=True)
                    self.assertIsNone(SQLiteOTCSOutbox(path).get("project", "key"))

    def test_outbox_queries_keep_binary_keys_under_column_collation(self) -> None:
        """Every read and update uses the key's identity, not the column's collation."""
        from dataclasses import replace

        base = OTCSAppendOperation.from_mapping(self.bundle["bridge_operation"])
        for position in (0, 1):
            with self.subTest(identifier=position):
                columns = ["BINARY", "BINARY"]
                columns[position] = "NOCASE"
                path = self.temporary_root / f"column-collation-{position}.sqlite"
                self._write_outbox_schema(path, column_collations=columns)
                outbox = SQLiteOTCSOutbox(path)
                selectors = [base.project_id, base.idempotency_key]
                selectors[position] = selectors[position].swapcase()
                self.assertNotEqual(selectors[position],
                                    (base.project_id, base.idempotency_key)[position])
                other = (replace(base, project_id=selectors[0],
                                 expected_head=replace(base.expected_head, project_id=selectors[0]))
                         if position == 0 else replace(base, idempotency_key=selectors[1]))
                first = outbox.prepare(base, "A" * 64, "B" * 64, {"operation": base.to_mapping()})
                self.assertEqual(first["project_id"], base.project_id)
                self.assertIsNone(outbox.get(*selectors))
                second = outbox.prepare(other, "C" * 64, "D" * 64, {"operation": other.to_mapping()})
                self.assertEqual((second["project_id"], second["idempotency_key"]), tuple(selectors))
                outbox.transition(base.project_id, base.idempotency_key, {"PREPARED"}, "NOT_EXECUTED")
                self.assertEqual(outbox.get(*selectors)["state"], "PREPARED")
                outbox.transition(*selectors, {"PREPARED"}, "CALLING")
                self.assertEqual(outbox.get(base.project_id, base.idempotency_key)["state"], "NOT_EXECUTED")
                self.assertEqual(outbox.get(*selectors)["state"], "CALLING")
                # Ask BOTH keys after their states differ. A case-insensitive read can
                # otherwise select the expected state by index order and pass by chance.
                outbox.transition(base.project_id, base.idempotency_key,
                                  {"NOT_EXECUTED"}, "LOCAL_FAILED")
                self.assertEqual(outbox.get(base.project_id, base.idempotency_key)["state"], "LOCAL_FAILED")
                self.assertEqual(outbox.get(*selectors)["state"], "CALLING")

    def test_outbox_cannot_replay_under_another_engine_binding(self) -> None:
        client = FakeOTCSClient(self.bundle["downstream_receipt"])

        def crash_after_prepare(point: str) -> None:
            if point == "after_prepare":
                raise RuntimeError("SYNTHETIC_PREPARED_PAUSE")

        with self.assertRaisesRegex(RuntimeError, "^SYNTHETIC_PREPARED_PAUSE$"):
            self.bridge(client, fault_hook=crash_after_prepare).execute(
                self.bundle["bridge_operation"],
                self.bundle["intent"],
                self.bundle["evidence"],
            )

        profile = copy.deepcopy(self.bundle["profile"])
        declaration = copy.deepcopy(self.bundle["declaration"])
        grant = copy.deepcopy(self.bundle["grant"])
        intent = copy.deepcopy(self.bundle["intent"])
        profile["profile_version"] = "1.0.1"
        declaration["profile_binding"]["profile_version"] = profile[
            "profile_version"
        ]
        profile, declaration, _, _ = bind_fixture(
            profile,
            declaration,
            grant,
            intent,
        )
        other_engine = UniversalConnectionLedger(
            profile,
            declaration,
            signing_key=b"synthetic-other-signing-key",
            clock=self.clock,
            state_path=self.temporary_root / "other-ledger.sqlite",
        )
        other_bridge = OTCSBridge(
            other_engine,
            client,
            self.outbox_path,
        )

        with self.assertRaises(OTCSBridgeError) as caught:
            other_bridge.recover(
                self.bundle["bridge_operation"]["project_id"],
                self.bundle["bridge_operation"]["idempotency_key"],
            )
        self.assertEqual(
            caught.exception.code,
            "OTCS_OUTBOX_ENGINE_BINDING",
        )
        self.assertEqual(client.calls, 0)
        self.assertEqual(client.effects, 0)

    def _prepared_admission_row(self):
        client = FakeOTCSClient(self.bundle["downstream_receipt"])

        def pause(point):
            if point == "after_prepare":
                raise RuntimeError("SYNTHETIC_ADMISSION_PAUSE")

        bridge = self.bridge(client, fault_hook=pause)
        with self.assertRaisesRegex(RuntimeError, "^SYNTHETIC_ADMISSION_PAUSE$"):
            bridge.execute(self.bundle["bridge_operation"],
                           self.bundle["intent"], self.bundle["evidence"])
        operation = self.bundle["bridge_operation"]
        row = bridge.outbox_record(operation["project_id"], operation["idempotency_key"])
        self.assertEqual(row["state"], "PREPARED")
        self.assertEqual(client.calls, 0)
        return bridge, client, row

    @staticmethod
    def _rehash_admission_row(row):
        # Model a writer who knows the public hash recipe, but not the engine key.
        request = row["request"]
        admission = request["admission"]
        row["operation_hash"] = sha256_hex(_normalize_declared_hash_case({
            "identity_profile": "NC25_OTCS_BRIDGE_SUBMISSION_V1",
            "operation": OTCSAppendOperation.from_mapping(request["operation"]).to_mapping(),
            "intent": admission["intent"],
            "evidence_bundle": admission["evidence_bundle"],
        }))

    def _store_admission_row(self, row):
        operation = self.bundle["bridge_operation"]
        with closing(sqlite3.connect(self.outbox_path)) as connection, connection:
            connection.execute(
                "UPDATE otcs_bridge_outbox SET request_json=?, operation_hash=?, "
                "permit_hash=?, state=? WHERE project_id=? AND idempotency_key=?",
                (json.dumps(row["request"]), row["operation_hash"], row["permit_hash"],
                 row["state"], operation["project_id"], operation["idempotency_key"]),
            )

    def test_stored_operation_is_bound_to_its_original_admission(self) -> None:
        bridge, client, original = self._prepared_admission_row()
        key = (original["project_id"], original["idempotency_key"])
        changes = [
            ("target", [(('target_system_id',), 'other-registry')]),
            ("event id", [(('event_id',), 'other-event')]),
            ("event type", [(('event_type',), 'other_event')]),
            ("sequence", [(('project_sequence',), 9), (('expected_head', 'project_sequence'), 8)]),
            ("effective time", [(('effective_at',), '2026-08-01T10:00:01Z')]),
            ("registry mode", [(('registry_mode',), 'full_snapshot')]),
            ("governing reference", [(('governing_object', 'object_id'), 'other-record'),
                                      (('expected_head', 'governing_digest', 'object_id'), 'other-record')]),
            ("payload content", [(('payload', 'digest'), 'E' * 64)]),
            ("payload reference", [(('payload', 'object_id'), 'other-version')]),
            ("head event content", [(('expected_head', 'event_digest', 'digest'), 'E' * 64)]),
            ("head history", [(('expected_head', 'history_digest', 'digest'), 'E' * 64)]),
        ]
        changes.extend((kind, [(('legal_evidence', kind, 'digest'), 'E' * 64)])
                       for kind in self.bundle["bridge_operation"]["legal_evidence"])
        for label, edits in changes:
            with self.subTest(operation_family=label):
                row = copy.deepcopy(original)
                for path, value in edits:
                    target = row["request"]["operation"]
                    for part in path[:-1]:
                        target = target[part]
                    target[path[-1]] = value
                self._rehash_admission_row(row)
                self.assertNotEqual(row["operation_hash"], original["operation_hash"])
                self._store_admission_row(row)
                with self.assertRaises(OTCSBridgeError) as caught:
                    bridge.recover(*key)
                self.assertEqual(caught.exception.code, "OTCS_OUTBOX_ADMISSION")
                self.assertEqual(bridge.outbox_record(*key)["state"], "PREPARED")
                self.assertEqual(client.calls, 0)
        self._store_admission_row(original)
        self.assertEqual(bridge.recover(*key)["status"], "COMMITTED")
        self.assertEqual(client.effects, 1)

    def test_stored_admission_snapshot_and_permit_cannot_be_rebound(self) -> None:
        bridge, client, original = self._prepared_admission_row()
        key = (original["project_id"], original["idempotency_key"])
        for changed in ("intent", "evidence", "wire intent", "permit"):
            with self.subTest(changed=changed):
                row = copy.deepcopy(original)
                if changed == "intent":
                    row["request"]["admission"]["intent"]["requester_id"] = "other-workload"
                elif changed == "evidence":
                    row["request"]["admission"]["evidence_bundle"]["items"][0]["ref"] += "/other"
                elif changed == "wire intent":
                    row["request"]["nc25_permit"]["intent_id"] = "other-intent"
                else:
                    row["permit_hash"] = row["request"]["nc25_permit"]["permit_hash"] = "F" * 64
                self._rehash_admission_row(row)
                self._store_admission_row(row)
                with self.assertRaises(OTCSBridgeError) as caught:
                    bridge.recover(*key)
                self.assertEqual(caught.exception.code, "OTCS_OUTBOX_ADMISSION")
                self.assertEqual(bridge.outbox_record(*key)["state"], "PREPARED")
                self.assertEqual(client.calls, 0)

    def test_physical_outbox_selectors_are_bound_to_the_admitted_operation(self) -> None:
        bridge, client, original = self._prepared_admission_row()
        key = (original["project_id"], original["idempotency_key"])
        for column, replacement in (("project_id", "other-project"),
                                     ("idempotency_key", "other-key")):
            with self.subTest(selector=column):
                with closing(sqlite3.connect(self.outbox_path)) as connection, connection:
                    connection.execute(f"UPDATE otcs_bridge_outbox SET {column}=?", (replacement,))
                altered_key = (replacement, key[1]) if column == "project_id" else (key[0], replacement)
                with self.assertRaises(OTCSBridgeError) as caught:
                    bridge.recover(*altered_key)
                self.assertEqual(caught.exception.code, "OTCS_OUTBOX_ADMISSION")
                self.assertEqual(caught.exception.detail, "row selectors")
                self.assertEqual(client.calls, 0)
                with closing(sqlite3.connect(self.outbox_path)) as connection, connection:
                    connection.execute(f"UPDATE otcs_bridge_outbox SET {column}=?", (original[column],))
        # Changing BOTH the physical selector and the operation cannot manufacture
        # a new admitted project/key either, even with an honestly recomputed hash.
        for column, replacement in (("project_id", "other-project"),
                                     ("idempotency_key", "other-key")):
            with self.subTest(coherent_selector=column):
                row = copy.deepcopy(original)
                row["request"]["operation"][column] = replacement
                if column == "project_id":
                    row["request"]["operation"]["expected_head"]["project_id"] = replacement
                self._rehash_admission_row(row)
                self._store_admission_row(row)
                with closing(sqlite3.connect(self.outbox_path)) as connection, connection:
                    connection.execute(f"UPDATE otcs_bridge_outbox SET {column}=?", (replacement,))
                altered_key = (replacement, key[1]) if column == "project_id" else (key[0], replacement)
                with self.assertRaises(OTCSBridgeError) as caught:
                    bridge.recover(*altered_key)
                self.assertEqual(caught.exception.code, "OTCS_OUTBOX_ADMISSION")
                self.assertEqual(caught.exception.detail, "unknown submission")
                self.assertEqual(client.calls, 0)
                with closing(sqlite3.connect(self.outbox_path)) as connection, connection:
                    connection.execute(f"UPDATE otcs_bridge_outbox SET {column}=?", (original[column],))
                self._store_admission_row(original)
        self.assertEqual(bridge.recover(*key)["status"], "COMMITTED")

    def test_legacy_outbox_without_admission_is_refused_without_reauthorizing(self) -> None:
        bridge, client, original = self._prepared_admission_row()
        row = copy.deepcopy(original)
        del row["request"]["admission"]
        self._store_admission_row(row)
        key = (original["project_id"], original["idempotency_key"])
        with patch.object(self.engine, "evaluate_intent", side_effect=AssertionError("REAUTHORIZED")):
            for drive in (lambda: bridge.recover(*key),
                          lambda: bridge.execute(self.bundle["bridge_operation"],
                                                 self.bundle["intent"], self.bundle["evidence"])):
                with self.assertRaises(OTCSBridgeError) as caught:
                    drive()
                self.assertEqual(caught.exception.code, "OTCS_OUTBOX_ADMISSION")
        self.assertEqual(client.calls, 0)
        self.assertEqual(bridge.outbox_record(*key)["state"], "PREPARED")

    def test_caller_cannot_supply_the_reserved_operation_evidence(self) -> None:
        client = FakeOTCSClient(self.bundle["downstream_receipt"])
        evidence = copy.deepcopy(self.bundle["evidence"])
        evidence["items"].append({
            "evidence_type": "NC25_OTCS_BRIDGE_OPERATION",
            "ref": "urn:caller:operation", "sha256": "E" * 64, "status": "VALID",
        })
        with patch.object(self.engine, "evaluate_intent", side_effect=AssertionError("ADMITTED_CALLER_MARKER")):
            with self.assertRaises(OTCSBridgeError) as caught:
                self.bridge(client).execute(self.bundle["bridge_operation"], self.bundle["intent"], evidence)
        self.assertEqual(caught.exception.code, "OTCS_EVIDENCE_BINDING")
        self.assertEqual(client.calls, 0)

    def test_every_recovery_state_checks_admission_before_return_or_transition(self) -> None:
        bridge, client, original = self._prepared_admission_row()
        key = (original["project_id"], original["idempotency_key"])
        for state in ("PREPARED", "CALLING", "AMBIGUOUS", "DOWNSTREAM_COMMITTED",
                      "DOWNSTREAM_REJECTED", "LOCAL_COMMITTED", "LOCAL_FAILED",
                      "NOT_EXECUTED", "RECONCILIATION_REQUIRED"):
            with self.subTest(state=state):
                row = copy.deepcopy(original)
                row["state"] = state
                row["request"]["operation"]["payload"]["digest"] = "E" * 64
                self._rehash_admission_row(row)
                self._store_admission_row(row)
                with patch.object(bridge._outbox, "transition", side_effect=AssertionError("TRANSITION_BEFORE_ADMISSION")):
                    with self.assertRaises(OTCSBridgeError) as caught:
                        bridge.recover(*key)
                self.assertEqual(caught.exception.code, "OTCS_OUTBOX_ADMISSION")
                self.assertEqual(client.calls, 0)

    def test_transition_snapshot_is_rechecked_before_otcs_call(self) -> None:
        bridge, client, original = self._prepared_admission_row()
        key = (original["project_id"], original["idempotency_key"])
        real_transition = bridge._outbox.transition

        def replace_before_read(*args, **kwargs):
            row = copy.deepcopy(original)
            row["request"]["operation"]["payload"]["digest"] = "E" * 64
            self._rehash_admission_row(row)
            self._store_admission_row(row)
            return real_transition(*args, **kwargs)

        with patch.object(bridge._outbox, "transition", side_effect=replace_before_read):
            with self.assertRaises(OTCSBridgeError) as caught:
                bridge.recover(*key)
        self.assertEqual(caught.exception.code, "OTCS_OUTBOX_ADMISSION")
        self.assertEqual(client.calls, 0)
        self.assertEqual(client.effects, 0)
        self.assertEqual(bridge.outbox_record(*key)["state"], "CALLING")

    def test_admission_survives_resolver_restart_and_consumed_terminal_replay(self) -> None:
        seen = []

        def resolve(intent, evidence, now):
            seen.extend(item["evidence_type"] for item in evidence["items"])
            evidence["items"] = [item for item in evidence["items"]
                                 if item["evidence_type"] != "NC25_OTCS_BRIDGE_OPERATION"]
            return evidence

        self.engine._evidence_resolver = resolve
        bridge, client, prepared = self._prepared_admission_row()
        self.assertIn("NC25_OTCS_BRIDGE_OPERATION", seen)
        self.assertEqual(prepared["request"]["admission"], {
            "intent": self.bundle["intent"], "evidence_bundle": self.bundle["evidence"],
        })
        restarted = UniversalConnectionLedger(
            self.bundle["profile"], self.bundle["declaration"],
            signing_key=b"synthetic-reference-signing-key", clock=self.clock,
            state_path=self.temporary_root / "ledger.sqlite", evidence_resolver=resolve,
        )
        bridge = OTCSBridge(restarted, client, self.outbox_path)
        key = (prepared["project_id"], prepared["idempotency_key"])
        committed = bridge.recover(*key)
        self.assertEqual(committed["status"], "COMMITTED")
        self.assertEqual(set(client.requests[0]),
                         {"message_type", "bridge_version", "operation", "nc25_permit"})
        self.assertEqual(client.requests[0]["operation"], self.bundle["bridge_operation"])
        # A consumed permit is still an authenticated original admission after reload.
        terminal_engine = UniversalConnectionLedger(
            self.bundle["profile"], self.bundle["declaration"],
            signing_key=b"synthetic-reference-signing-key", clock=self.clock,
            state_path=self.temporary_root / "ledger.sqlite", evidence_resolver=resolve,
        )
        bridge = OTCSBridge(terminal_engine, client, self.outbox_path)
        self.assertEqual(bridge.recover(*key), committed)
        self.assertEqual(bridge.execute(self.bundle["bridge_operation"], self.bundle["intent"],
                                        self.bundle["evidence"]), committed)
        self.assertEqual(client.calls, 1)
        self.assertEqual(client.effects, 1)

    def _direct_engine_admission_row(self, label, *, operation=None, evidence=None):
        # An operator can call the engine directly; its authentic marker is not
        # proof that execute's cross-object checks ever ran.
        operation = copy.deepcopy(operation if operation is not None else self.bundle["bridge_operation"])
        evidence = copy.deepcopy(evidence if evidence is not None else self.bundle["evidence"])
        intent = copy.deepcopy(self.bundle["intent"])
        engine = UniversalConnectionLedger(
            self.bundle["profile"], self.bundle["declaration"],
            signing_key=b"synthetic-reference-signing-key", clock=self.clock,
            state_path=self.temporary_root / (label + "-ledger.sqlite"),
        )
        engine.activate(self.bundle["declaration"]["governance"]["approval_owner_id"],
                        "evidence://synthetic/direct-admission", actor_scope=ROLE_GOVERNANCE)
        engine.issue_grant(self.bundle["grant"], actor_scope=ROLE_GOVERNANCE)
        candidate = OTCSAppendOperation.from_mapping(operation)
        submitted = copy.deepcopy(evidence)
        submitted["items"].append({
            "evidence_type": "NC25_OTCS_BRIDGE_OPERATION",
            "ref": "urn:nc25:otcs:submitted-operation:v1",
            "sha256": sha256_hex(candidate.to_mapping()), "status": "VALID",
        })
        result = engine.evaluate_intent(intent, submitted, actor_scope=ROLE_OPERATOR)
        self.assertEqual(result["disposition"], "ALLOW")
        permit_hash = result["permit_hash"]
        row = {"request": {
            "message_type": "otcs_append_request", "bridge_version": OTCS_BRIDGE_VERSION,
            "operation": candidate.to_mapping(),
            "admission": {"intent": intent, "evidence_bundle": evidence},
            "nc25_permit": {
                "permit_hash": permit_hash, "profile_hash": engine.profile_hash,
                "declaration_hash": engine.declaration_hash,
                "intent_id": intent["intent_id"], "connector_id": intent["connector_id"],
                "binding": copy.deepcopy(intent["binding"]),
            },
        }}
        self._rehash_admission_row(row)
        client = FakeOTCSClient(self.bundle["downstream_receipt"])
        bridge = OTCSBridge(engine, client, self.temporary_root / (label + "-outbox.sqlite"))
        bridge._outbox.prepare(candidate, row["operation_hash"], permit_hash, row["request"])
        return bridge, client, (candidate.project_id, candidate.idempotency_key)

    def test_authenticated_recovery_rechecks_intent_operation_binding(self) -> None:
        operation = copy.deepcopy(self.bundle["bridge_operation"])
        operation["payload"]["digest"] = "E" * 64
        bridge, client, key = self._direct_engine_admission_row("intent-mismatch", operation=operation)
        with self.assertRaises(OTCSBridgeError) as caught:
            bridge.recover(*key)
        self.assertEqual(caught.exception.code, "OTCS_INTENT_BINDING")
        self.assertEqual(caught.exception.detail, "payload_hash")
        self.assertEqual(client.calls, 0)
        self.assertEqual(bridge.outbox_record(*key)["state"], "PREPARED")
        control, control_client, control_key = self._direct_engine_admission_row("intent-matching")
        self.assertEqual(control.recover(*control_key)["status"], "COMMITTED")
        self.assertEqual(control_client.effects, 1)

    def test_authenticated_recovery_rechecks_head_and_legal_evidence_binding(self) -> None:
        types = ["OTCS_EXPECTED_HEAD", *self.bundle["bridge_operation"]["legal_evidence"]]
        for index, evidence_type in enumerate(types):
            with self.subTest(evidence_type=evidence_type):
                evidence = copy.deepcopy(self.bundle["evidence"])
                item = next(item for item in evidence["items"] if item["evidence_type"] == evidence_type)
                item["sha256"] = "E" * 64
                bridge, client, key = self._direct_engine_admission_row(
                    "evidence-mismatch-" + str(index), evidence=evidence)
                with self.assertRaises(OTCSBridgeError) as caught:
                    bridge.recover(*key)
                self.assertEqual(caught.exception.code, "OTCS_EVIDENCE_BINDING")
                self.assertEqual(caught.exception.detail, evidence_type)
                self.assertEqual(client.calls, 0)
                self.assertEqual(bridge.outbox_record(*key)["state"], "PREPARED")
        control, client, key = self._direct_engine_admission_row("evidence-matching")
        self.assertEqual(control.recover(*key)["status"], "COMMITTED")
        self.assertEqual(client.effects, 1)

    def test_lowercase_stored_permit_hash_recovers_and_replays(self) -> None:
        bridge, client, row = self._prepared_admission_row()
        self.assertNotEqual(row["permit_hash"], row["permit_hash"].lower())
        row["permit_hash"] = row["permit_hash"].lower()
        row["request"]["nc25_permit"]["permit_hash"] = row["permit_hash"]
        self._store_admission_row(row)
        key = (row["project_id"], row["idempotency_key"])
        try:
            recovered = bridge.recover(*key)
        except OTCSBridgeError as exc:
            self.fail("case-equivalent permit was refused: " + exc.code)
        self.assertEqual(recovered["status"], "COMMITTED")
        self.assertEqual(bridge.recover(*key), recovered)
        self.assertEqual(client.calls, 1)
        self.assertEqual(client.effects, 1)

    def test_same_key_rejects_a_changed_full_submission(self) -> None:
        client = FakeOTCSClient(self.bundle["downstream_receipt"])
        bridge = self.bridge(client)
        bridge.execute(
            self.bundle["bridge_operation"],
            self.bundle["intent"],
            self.bundle["evidence"],
        )
        changed_evidence = copy.deepcopy(self.bundle["evidence"])
        changed_evidence["items"][0]["ref"] += "/changed"

        with self.assertRaises(OTCSBridgeError) as caught:
            bridge.execute(
                self.bundle["bridge_operation"],
                self.bundle["intent"],
                changed_evidence,
            )
        self.assertEqual(caught.exception.code, "OTCS_IDEMPOTENCY_CONFLICT")
        self.assertEqual(client.calls, 1)
        self.assertEqual(client.effects, 1)

    def test_stale_head_records_failure_without_resource_debit(self) -> None:
        client = FakeOTCSClient(
            self.bundle["downstream_receipt"],
            reject_code="OTCS_STALE_HEAD",
        )
        before = self.engine.structural_remaining
        bridge = self.bridge(client)
        result = bridge.execute(
            self.bundle["bridge_operation"],
            self.bundle["intent"],
            self.bundle["evidence"],
        )

        self.assertEqual(result["status"], "DOWNSTREAM_REJECTED")
        self.assertEqual(result["rejection_code"], "OTCS_STALE_HEAD")
        self.assertEqual(result["ledger_receipt"]["outcome"], "FAILED")
        self.assertEqual(client.calls, 1)
        self.assertEqual(client.effects, 0)
        self.assertEqual(self.engine.structural_remaining, before)
        self.assertEqual(list(self.engine.committed_resources), [])
        stored = bridge.outbox_record(
            self.bundle["bridge_operation"]["project_id"],
            self.bundle["bridge_operation"]["idempotency_key"],
        )
        self.assertEqual(stored["state"], "LOCAL_FAILED")

    def test_late_local_finalization_requires_reconciliation(self) -> None:
        client = FakeOTCSClient(self.bundle["downstream_receipt"])

        def expire_after_downstream_persisted(point: str) -> None:
            if point == "after_downstream_persisted":
                self.clock.advance(seconds=301)
                raise RuntimeError("SYNTHETIC_LOCAL_PAUSE")

        with self.assertRaisesRegex(RuntimeError, "^SYNTHETIC_LOCAL_PAUSE$"):
            self.bridge(
                client,
                fault_hook=expire_after_downstream_persisted,
            ).execute(
                self.bundle["bridge_operation"],
                self.bundle["intent"],
                self.bundle["evidence"],
            )

        bridge = self.bridge(client)
        with self.assertRaises(OTCSReconciliationRequired) as caught:
            bridge.recover(
                self.bundle["bridge_operation"]["project_id"],
                self.bundle["bridge_operation"]["idempotency_key"],
            )
        self.assertEqual(
            caught.exception.code,
            "OTCS_LOCAL_FINALIZATION_REFUSED",
        )
        self.assertEqual(client.calls, 1)
        self.assertEqual(client.effects, 1)
        stored = bridge.outbox_record(
            self.bundle["bridge_operation"]["project_id"],
            self.bundle["bridge_operation"]["idempotency_key"],
        )
        self.assertEqual(stored["state"], "RECONCILIATION_REQUIRED")

    def test_otcs_admissibility_field_is_rejected_as_receipt_shape(self) -> None:
        client = FakeOTCSClient(
            self.bundle["downstream_receipt"],
            add_allowed_field=True,
        )
        bridge = self.bridge(client)
        with self.assertRaises(OTCSReconciliationRequired) as caught:
            bridge.execute(
                self.bundle["bridge_operation"],
                self.bundle["intent"],
                self.bundle["evidence"],
            )
        self.assertEqual(caught.exception.code, "OTCS_RECEIPT_UNUSABLE")
        self.assertEqual(client.effects, 1)
        self.assertFalse(
            any(
                event["event_type"] == "EXECUTION_RECORDED"
                for event in self.engine.ledger.events_copy()
            )
        )
        stored = bridge.outbox_record(
            self.bundle["bridge_operation"]["project_id"],
            self.bundle["bridge_operation"]["idempotency_key"],
        )
        self.assertEqual(stored["state"], "RECONCILIATION_REQUIRED")

    def _break_the_seal(self) -> None:
        """Make the engine unable to vouch for itself, the ordinary way.

        `_assert_integrity` recomputes the profile digest and compares it to the
        sealed `profile_hash`, so one extra key is a real PROFILE_SEAL_FAILURE on
        the normal path.  `profile_hash` itself is untouched, which is what keeps
        the outbox's engine-binding check passing and puts the fault where these
        two tests need it: inside the engine call, not before it.
        """
        self.engine.profile = {**self.engine.profile, "__seal_broken__": "x"}

    def _mend_the_seal(self) -> None:
        self.engine.profile = {
            key: value
            for key, value in self.engine.profile.items()
            if key != "__seal_broken__"
        }

    def test_local_integrity_fault_leaves_the_row_retryable(self) -> None:
        client = FakeOTCSClient(self.bundle["downstream_receipt"])

        def pause_after_downstream_persisted(point: str) -> None:
            if point == "after_downstream_persisted":
                raise RuntimeError("SYNTHETIC_LOCAL_PAUSE")

        with self.assertRaisesRegex(RuntimeError, "^SYNTHETIC_LOCAL_PAUSE$"):
            self.bridge(
                client,
                fault_hook=pause_after_downstream_persisted,
            ).execute(
                self.bundle["bridge_operation"],
                self.bundle["intent"],
                self.bundle["evidence"],
            )
        project_id = self.bundle["bridge_operation"]["project_id"]
        idempotency_key = self.bundle["bridge_operation"]["idempotency_key"]
        self.assertEqual(
            self.bridge(client).outbox_record(project_id, idempotency_key)["state"],
            "DOWNSTREAM_COMMITTED",
        )

        self._break_the_seal()
        with self.assertRaises(IntegrityViolation) as caught:
            self.bridge(client).recover(project_id, idempotency_key)
        self.assertEqual(caught.exception.code, "PROFILE_SEAL_FAILURE")
        self.assertEqual(
            self.bridge(client).outbox_record(project_id, idempotency_key)["state"],
            "DOWNSTREAM_COMMITTED",
        )

        self._mend_the_seal()
        result = self.bridge(client).recover(project_id, idempotency_key)
        self.assertEqual(result["status"], "COMMITTED")
        self.assertEqual(
            self.bridge(client).outbox_record(project_id, idempotency_key)["state"],
            "LOCAL_COMMITTED",
        )
        self.assertEqual(client.calls, 1)
        self.assertEqual(client.effects, 1)

    def test_prepared_integrity_fault_stays_retryable(self) -> None:
        client = FakeOTCSClient(self.bundle["downstream_receipt"])

        def pause_after_prepare(point: str) -> None:
            if point == "after_prepare":
                raise RuntimeError("SYNTHETIC_PREPARED_PAUSE")

        with self.assertRaisesRegex(RuntimeError, "^SYNTHETIC_PREPARED_PAUSE$"):
            self.bridge(client, fault_hook=pause_after_prepare).execute(
                self.bundle["bridge_operation"],
                self.bundle["intent"],
                self.bundle["evidence"],
            )
        project_id = self.bundle["bridge_operation"]["project_id"]
        idempotency_key = self.bundle["bridge_operation"]["idempotency_key"]
        self.assertEqual(client.calls, 0)

        self._break_the_seal()
        with self.assertRaises(IntegrityViolation) as caught:
            self.bridge(client).recover(project_id, idempotency_key)
        self.assertEqual(caught.exception.code, "PROFILE_SEAL_FAILURE")
        stored = self.bridge(client).outbox_record(project_id, idempotency_key)
        self.assertEqual(stored["state"], "PREPARED")
        self.assertIsNone(stored["rejection_code"])
        self.assertEqual(client.calls, 0)

        self._mend_the_seal()
        result = self.bridge(client).recover(project_id, idempotency_key)
        self.assertEqual(result["status"], "COMMITTED")
        self.assertEqual(client.calls, 1)
        self.assertEqual(client.effects, 1)


    def test_receipt_identity_mismatch_forces_reconciliation(self) -> None:
        """A receipt that identifies another request is refused, never sealed.

        The three identity fields below are guarded by the receipt comparison
        alone: a corrupted event reference is already refused by the event-ref
        check, so it would not exercise this claim.  The downstream effect has
        already happened by the time the receipt arrives, so the only safe move
        is reconciliation - accepting it would seal a foreign receipt digest
        into the local execution event and record a commit nobody requested.
        """
        for field, foreign_value in (
            ("project_id", "another-project"),
            ("project_sequence", 4242),
            ("idempotency_key", "another-key-001"),
        ):
            with self.subTest(field=field):
                foreign = copy.deepcopy(self.bundle["downstream_receipt"])
                foreign[field] = foreign_value
                client = FakeOTCSClient(foreign)
                outbox = self.temporary_root / f"otcs-outbox-{field}.sqlite"
                bridge = OTCSBridge(self.engine, client, outbox)

                with self.assertRaises(OTCSReconciliationRequired) as caught:
                    bridge.execute(
                        self.bundle["bridge_operation"],
                        self.bundle["intent"],
                        self.bundle["evidence"],
                    )

                self.assertEqual(caught.exception.code, "OTCS_RECEIPT_UNUSABLE")
                self.assertEqual(client.calls, 1)
                self.assertEqual(client.effects, 1)
                stored = bridge.outbox_record(
                    self.bundle["bridge_operation"]["project_id"],
                    self.bundle["bridge_operation"]["idempotency_key"],
                )
                self.assertEqual(stored["state"], "RECONCILIATION_REQUIRED")
                self.assertIsNone(stored.get("local_receipt"))

    def test_declared_shape_refuses_each_corruption_with_its_own_code(self) -> None:
        """One corruption per row, and the exact code the bridge owes it.

        The engine already carries this shape at
        test_universal_connection.py:1117-1142: a table of (label, corruption,
        code), one subTest per row, a FRESH deep copy built inside the loop
        because a corruption is never undone, and an anchored "^CODE(:|$)"
        pattern.  "^CODE$" would be wrong here - the bridge renders
        "<code>: <detail>" whenever a detail is present - and an unanchored
        CODE would be wrong too: OTCS_RECEIPT_ID is a prefix of
        OTCS_RECEIPT_IDEMPOTENCY_KEY, and only the "(:|$)" tail keeps the
        shorter pattern from accepting the longer code.

        The drivers are the two shape constructors, not execute(): every code
        below is raised before any engine or client is consulted, so routing a
        row through a live execution would cost a permit and a downstream call
        for no additional coverage.

        The rows are NOT read off statement order.  A nested reference is built
        to completion before the containing __post_init__ runs, so corrupting
        an inner reference OVERTAKES every check of the outer object.  What
        decides is the VALUE, not the act: a legal-evidence key ADDED with a
        well-formed reference still reaches OTCS_LEGAL_EVIDENCE_FIELDS, while
        one added with a malformed value is intercepted earlier by OTCSHashRef
        and certifies OTCS_HASH_REF_FIELDS instead.  The row removes a key
        because a removed key leaves no value to intercept at all.
        The head sequence has minimum 0, so only a negative value reaches
        OTCS_HEAD_SEQUENCE - zero falls through to the successor check.  Each
        row was run against the live bridge and its ACTUAL code compared with
        the expected one before it was admitted to this table.
        """
        # Control: an untouched fixture must build under both drivers. Without
        # it, a fixture that no longer parses at all would turn every row below
        # green for the wrong reason.
        OTCSAppendOperation.from_mapping(
            copy.deepcopy(self.bundle["bridge_operation"])
        )
        OTCSReceiptRef.from_mapping(
            copy.deepcopy(self.bundle["downstream_receipt"])
        )

        # JSON arrays and objects are valid JSON values but cannot name a
        # registry mode. They must reach the named refusal, not set hashing.
        for mode in ("reference_only", "full_snapshot"):
            with self.subTest(registry_mode_control=mode):
                value = copy.deepcopy(self.bundle["bridge_operation"])
                value["registry_mode"] = mode
                self.assertEqual(
                    OTCSAppendOperation.from_mapping(value).registry_mode, mode
                )
        for mode in (None, True, 7, 1.5, [], {}, ["reference_only"], "partial"):
            with self.subTest(registry_mode_invalid=mode):
                value = copy.deepcopy(self.bundle["bridge_operation"])
                value["registry_mode"] = mode
                with self.assertRaisesRegex(
                    OTCSBridgeError, r"^OTCS_REGISTRY_MODE(:|$)"
                ):
                    OTCSAppendOperation.from_mapping(value)

        operation_rows = (
            # OTCSHashRef, reached through the first reference the operation builds
            ("hash: fields", lambda o: o["governing_object"].pop("digest"),
             "OTCS_HASH_REF_FIELDS"),
            ("hash: object_kind",
             lambda o: o["governing_object"].__setitem__("object_kind", ""),
             "OTCS_HASH_OBJECT_KIND"),
            ("hash: object_id",
             lambda o: o["governing_object"].__setitem__("object_id", ""),
             "OTCS_HASH_OBJECT_ID"),
            ("hash: profile",
             lambda o: o["governing_object"].__setitem__("hash_profile", "SHA256"),
             "OTCS_HASH_PROFILE"),
            ("hash: digest",
             lambda o: o["governing_object"].__setitem__("digest", "zz"),
             "OTCS_HASH_DIGEST"),
            # OTCSHeadRef
            ("head: fields", lambda o: o["expected_head"].pop("event_id"),
             "OTCS_HEAD_FIELDS"),
            ("head: project_id",
             lambda o: o["expected_head"].__setitem__("project_id", ""),
             "OTCS_HEAD_PROJECT_ID"),
            ("head: object_kind",
             lambda o: o["expected_head"].__setitem__("governing_object_kind", ""),
             "OTCS_HEAD_OBJECT_KIND"),
            ("head: sequence",
             lambda o: o["expected_head"].__setitem__("project_sequence", -1),
             "OTCS_HEAD_SEQUENCE"),
            ("head: event_id",
             lambda o: o["expected_head"].__setitem__("event_id", ""),
             "OTCS_HEAD_EVENT_ID"),
            ("head: governing kind mismatch",
             lambda o: o["expected_head"].__setitem__(
                 "governing_object_kind", "project_recordx"),
             "OTCS_HEAD_GOVERNING_KIND_MISMATCH"),
            ("head: event ref mismatch",
             lambda o: o["expected_head"]["event_digest"].__setitem__(
                 "object_id", "otcs-event-9999"),
             "OTCS_HEAD_EVENT_REF_MISMATCH"),
            ("head: history kind",
             lambda o: o["expected_head"]["history_digest"].__setitem__(
                 "object_kind", "project_historyx"),
             "OTCS_HEAD_HISTORY_KIND"),
            # OTCSAppendOperation itself
            ("op: fields", lambda o: o.pop("registry_mode"),
             "OTCS_OPERATION_FIELDS"),
            ("op: bridge_version",
             lambda o: o.__setitem__("bridge_version", "9.9.9"),
             "OTCS_BRIDGE_VERSION"),
            ("op: project_id", lambda o: o.__setitem__("project_id", ""),
             "OTCS_OPERATION_PROJECT_ID"),
            ("op: event_id", lambda o: o.__setitem__("event_id", ""),
             "OTCS_OPERATION_EVENT_ID"),
            ("op: event_type", lambda o: o.__setitem__("event_type", ""),
             "OTCS_OPERATION_EVENT_TYPE"),
            ("op: sequence", lambda o: o.__setitem__("project_sequence", 0),
             "OTCS_OPERATION_SEQUENCE"),
            ("op: idempotency_key",
             lambda o: o.__setitem__("idempotency_key", ""),
             "OTCS_OPERATION_IDEMPOTENCY_KEY"),
            ("op: effective_at",
             lambda o: o.__setitem__("effective_at", "not-a-time"),
             "OTCS_OPERATION_EFFECTIVE_AT"),
            ("op: target", lambda o: o.__setitem__("target_system_id", ""),
             "OTCS_OPERATION_TARGET"),
            ("op: registry_mode",
             lambda o: o.__setitem__("registry_mode", "partial"),
             "OTCS_REGISTRY_MODE"),
            ("op: head project mismatch",
             lambda o: o["expected_head"].__setitem__(
                 "project_id", "otcs-project-9999"),
             "OTCS_HEAD_PROJECT_MISMATCH"),
            ("op: sequence not successor",
             lambda o: o.__setitem__("project_sequence", 9),
             "OTCS_SEQUENCE_NOT_SUCCESSOR"),
            ("op: event id not successor",
             lambda o: o.__setitem__("event_id", "otcs-event-0003"),
             "OTCS_EVENT_ID_NOT_SUCCESSOR"),
            ("op: governing object mismatch",
             lambda o: o["governing_object"].__setitem__(
                 "object_id", "otcs-project-0004-record-x"),
             "OTCS_GOVERNING_OBJECT_MISMATCH"),
            ("op: legal evidence key removed",
             lambda o: o["legal_evidence"].pop("OTCS_CONSENT_RECORD"),
             "OTCS_LEGAL_EVIDENCE_FIELDS"),
            ("op: legal evidence not a mapping",
             lambda o: o.__setitem__("legal_evidence", []),
             "OTCS_LEGAL_EVIDENCE_FIELDS"),
        )

        receipt_rows = (
            ("rcpt: fields", lambda r: r.pop("key_id"), "OTCS_RECEIPT_FIELDS"),
            ("rcpt: receipt_id", lambda r: r.__setitem__("receipt_id", ""),
             "OTCS_RECEIPT_ID"),
            ("rcpt: project_id", lambda r: r.__setitem__("project_id", ""),
             "OTCS_RECEIPT_PROJECT_ID"),
            ("rcpt: event_id", lambda r: r.__setitem__("event_id", ""),
             "OTCS_RECEIPT_EVENT_ID"),
            ("rcpt: idempotency_key",
             lambda r: r.__setitem__("idempotency_key", ""),
             "OTCS_RECEIPT_IDEMPOTENCY_KEY"),
            ("rcpt: issuer", lambda r: r.__setitem__("issuer_id", ""),
             "OTCS_RECEIPT_ISSUER"),
            ("rcpt: epoch", lambda r: r.__setitem__("operator_epoch", ""),
             "OTCS_RECEIPT_EPOCH"),
            ("rcpt: key_id", lambda r: r.__setitem__("key_id", ""),
             "OTCS_RECEIPT_KEY_ID"),
            ("rcpt: sequence", lambda r: r.__setitem__("project_sequence", 0),
             "OTCS_RECEIPT_SEQUENCE"),
            ("rcpt: effective_at",
             lambda r: r.__setitem__("effective_at", "not-a-time"),
             "OTCS_RECEIPT_EFFECTIVE_AT"),
            ("rcpt: signature_ref",
             lambda r: r.__setitem__("signature_ref", ""),
             "OTCS_RECEIPT_SIGNATURE_REF"),
            ("rcpt: proof_ref",
             lambda r: r.__setitem__("inclusion_proof_ref", ""),
             "OTCS_RECEIPT_PROOF_REF"),
            ("rcpt: event ref mismatch",
             lambda r: r["event_digest"].__setitem__(
                 "object_id", "otcs-event-9999"),
             "OTCS_RECEIPT_EVENT_REF_MISMATCH"),
            ("rcpt: digest ref mismatch",
             lambda r: r["receipt_digest"].__setitem__(
                 "object_kind", "append_receiptx"),
             "OTCS_RECEIPT_DIGEST_REF_MISMATCH"),
            ("rcpt: log root kind",
             lambda r: r["log_root"].__setitem__(
                 "object_kind", "transparency_log_rootx"),
             "OTCS_RECEIPT_LOG_ROOT_KIND"),
        )

        for label, corrupt, code in operation_rows:
            with self.subTest(row=label):
                value = copy.deepcopy(self.bundle["bridge_operation"])
                corrupt(value)
                with self.assertRaisesRegex(OTCSBridgeError, rf"^{code}(:|$)"):
                    OTCSAppendOperation.from_mapping(value)

        for label, corrupt, code in receipt_rows:
            with self.subTest(row=label):
                value = copy.deepcopy(self.bundle["downstream_receipt"])
                corrupt(value)
                with self.assertRaisesRegex(OTCSBridgeError, rf"^{code}(:|$)"):
                    OTCSReceiptRef.from_mapping(value)


    def test_intent_and_evidence_bindings_refuse_with_their_own_codes(self) -> None:
        """Four codes that no shape constructor can reach.

        The drivers here are the two private STATIC validators, and that is a
        measured minimum rather than a preference: no dataclass in the bridge
        carries an intent or an evidence bundle, so `from_mapping` cannot
        arrive at either guard, while `execute` would demand an engine, a
        client and an outbox for no additional coverage.  Both validators are
        `@staticmethod`, so neither needs a constructed bridge.

        Two traps decide these rows, and both were measured rather than
        reasoned.  First, three separate loops upper-case any value whose field
        name ends in `_hash` before comparing, so a corruption that changes
        only the CASE is swallowed and the row would go green having proved
        nothing; every row below changes the value itself.  Second, the intent
        binding loop runs to completion before the scope loop begins, so a row
        meant for the scope must leave all six binding fields untouched.
        """
        # Control: the untouched fixture must pass BOTH validators. Without it
        # a fixture that no longer binds at all would turn every row green for
        # the wrong reason.
        operation = OTCSAppendOperation.from_mapping(
            copy.deepcopy(self.bundle["bridge_operation"])
        )
        OTCSBridge._validate_intent_binding(
            operation, copy.deepcopy(self.bundle["intent"])
        )
        OTCSBridge._validate_evidence_binding(
            operation, copy.deepcopy(self.bundle["evidence"])
        )

        def corrupt_intent(mutate):
            intent = copy.deepcopy(self.bundle["intent"])
            mutate(intent)
            return ("intent", intent)

        def corrupt_evidence(mutate):
            evidence = copy.deepcopy(self.bundle["evidence"])
            mutate(evidence)
            return ("evidence", evidence)

        rows = (
            # ── intent binding: six compared fields, first difference wins ──
            ("action id diverges",
             corrupt_intent(lambda i: i.update(action_id="NO_EFFECT_FALLBACK")),
             "OTCS_INTENT_BINDING"),
            ("idempotency key removed - absent reads as a difference",
             corrupt_intent(lambda i: i.pop("idempotency_key")),
             "OTCS_INTENT_BINDING"),
            ("target system diverges",
             corrupt_intent(lambda i: i.update(target_system_id="local-fallback")),
             "OTCS_INTENT_BINDING"),
            ("history summary hash diverges by VALUE, not by case",
             corrupt_intent(lambda i: i.update(history_summary_hash="9" * 64)),
             "OTCS_INTENT_BINDING"),
            ("intent is not an object at all",
             ("intent", []),
             "OTCS_INTENT_BINDING"),
            # ── intent scope: four compared fields, binding left intact ──
            ("scope project diverges",
             corrupt_intent(
                 lambda i: i["scope"].update(project_id="otcs-project-9999")
             ),
             "OTCS_INTENT_SCOPE"),
            ("scope registry mode diverges",
             corrupt_intent(
                 lambda i: i["scope"].update(registry_mode="full_snapshot")
             ),
             "OTCS_INTENT_SCOPE"),
            ("scope governing kind removed",
             corrupt_intent(lambda i: i["scope"].pop("governing_object_kind")),
             "OTCS_INTENT_SCOPE"),
            ("scope is missing entirely",
             corrupt_intent(lambda i: i.pop("scope")),
             "OTCS_INTENT_SCOPE"),
            # ── evidence binding ──
            ("a required evidence digest diverges",
             corrupt_evidence(
                 lambda e: e["items"][2].update(sha256="9" * 64)
             ),
             "OTCS_EVIDENCE_BINDING"),
            ("a required evidence type is absent",
             corrupt_evidence(lambda e: e["items"].pop(4)),
             "OTCS_EVIDENCE_BINDING"),
            ("the item list is a tuple, and membership is strict",
             corrupt_evidence(
                 lambda e: e.update(items=tuple(e["items"]))
             ),
             "OTCS_EVIDENCE_BINDING"),
            # ── evidence duplication: caught in the FIRST pass ──
            ("the same evidence type appears twice",
             corrupt_evidence(
                 lambda e: e["items"].append(copy.deepcopy(e["items"][2]))
             ),
             "OTCS_EVIDENCE_DUPLICATE"),
        )

        for label, (kind, value), code in rows:
            with self.subTest(row=label, code=code):
                fresh = OTCSAppendOperation.from_mapping(
                    copy.deepcopy(self.bundle["bridge_operation"])
                )
                with self.assertRaisesRegex(OTCSBridgeError, rf"^{code}(:|$)"):
                    if kind == "intent":
                        OTCSBridge._validate_intent_binding(fresh, value)
                    else:
                        OTCSBridge._validate_evidence_binding(fresh, value)


    def test_outbox_guards_refuse_with_their_own_codes(self) -> None:
        """Eleven codes that live on the outbox row rather than on a shape.

        Shape constructors do not reach these stored-row guards. The drivers
        call the owning methods directly. Their shared prepared fixture carries
        a genuine engine admission, so the admission check cannot obscure the
        particular later refusal each case is meant to reach.

        Every pair below was RUN before it was admitted, and two of them had to
        be corrected by that run rather than by reading.  A row whose only
        stated defect was a short permit hash reached the closed field-set
        check first, because the request it carried was missing `operation`;
        and a row meant to prove a terminal state without an execution request
        was overtaken by the engine-binding check, because its profile and
        declaration hashes were placeholders rather than the engine's own.
        Both now carry a complete request, so the stated defect is the only
        one.

        The empty connector id is reachable only from inside: on every public
        route an earlier guard answers first.  It is witnessed here because a
        guard that can fire deserves a witness.

        A state outside the nine is not limited to private routes. A deployment
        can supply an existing database without a CHECK constraint, and the
        public read then raises the code with no earlier guard in the way.
        The row below still uses the private driver, which is the cheapest way
        to reach the guard, but the code has left the internal-only set and the
        public route is witnessed separately.
        """
        _, _, admitted_row = self._prepared_admission_row()
        permit_hash = admitted_row["permit_hash"]
        operation = OTCSAppendOperation.from_mapping(
            copy.deepcopy(self.bundle["bridge_operation"])
        )

        def permit_row(**over):
            nc25 = {
                "intent_id": self.bundle["intent"]["intent_id"],
                "connector_id": self.bundle["intent"]["connector_id"],
                "binding": copy.deepcopy(self.bundle["intent"]["binding"]),
            }
            nc25.update(over)
            return {"permit_hash": permit_hash, "request": {"nc25_permit": nc25}}

        def full_request():
            return copy.deepcopy(admitted_row["request"])

        def outbox(name):
            return SQLiteOTCSOutbox(self.temporary_root / name)

        def bridge_for(name):
            return self.bridge(FakeOTCSClient(self.bundle["downstream_receipt"]))

        # Control: an untouched permit row must NOT be called dead. Without it
        # every refusal row below would pass for a predicate that refuses
        # everything, which names nothing.
        self.assertIsNone(
            bridge_for("control")._permit_not_live_reason(permit_row(), operation)
        )

        def prepared_then_wrong_expectation():
            book = outbox("otcs-outbox-conflict.sqlite")
            book.prepare(
                operation, "A" * 64, "B" * 64,
                {"message_type": "otcs_append_request"},
            )
            book.transition(
                operation.project_id, operation.idempotency_key,
                {"CALLING"}, "AMBIGUOUS",
            )

        def terminal_without_execution_request():
            row = {
                "project_id": operation.project_id,
                "idempotency_key": operation.idempotency_key,
                "operation_hash": admitted_row["operation_hash"],
                "permit_hash": permit_hash,
                "state": "DOWNSTREAM_COMMITTED",
                "request": full_request(),
                "receipt": copy.deepcopy(self.bundle["downstream_receipt"]),
                "execution_request": None,
                "local_receipt": None,
            }
            bridge_for("advance")._advance(row, recovery=False)

        rows = (
            ("a row carries no request at all",
             lambda: OTCSBridge._operation_from_row({}),
             "OTCS_OUTBOX_REQUEST"),
            ("the request field set is not the closed one",
             lambda: bridge_for("fields")._validate_row_engine_binding(
                 {"permit_hash": "0" * 64,
                  "request": dict(full_request(), stray_field=1)}),
             "OTCS_OUTBOX_REQUEST"),
            ("the row's permit hash is not a SHA-256",
             lambda: bridge_for("hash")._validate_row_engine_binding(
                 {"permit_hash": "0" * 63, "request": full_request()}),
             "OTCS_OUTBOX_PERMIT_HASH"),
            ("the row's permit binding is not an object",
             lambda: bridge_for("permit")._permit_not_live_reason(
                 permit_row(binding="not-a-mapping"), operation),
             "OTCS_OUTBOX_PERMIT"),
            ("the row names a different intent than the live permit",
             lambda: bridge_for("binding")._permit_not_live_reason(
                 permit_row(intent_id="synthetic-otcs-intent-999"), operation),
             "OTCS_OUTBOX_PERMIT_BINDING"),
            ("the connector id is empty",
             lambda: OTCSBridge._execution_request(
                 {"permit_hash": "A" * 64,
                  "request": {"nc25_permit": {"connector_id": "", "binding": {}}}},
                 None, outcome="COMMITTED", downstream_receipt_hash=None,
                 committed_at="2026-08-01T10:00:00Z"),
             "OTCS_OUTBOX_CONNECTOR_ID"),
            ("a stored row carries a state outside the nine",
             lambda: SQLiteOTCSOutbox._decoded(
                 {"state": "SHIPPED", "request_json": None, "receipt_json": None,
                  "execution_request_json": None, "local_receipt_json": None}),
             "OTCS_OUTBOX_STATE"),
            ("a transition asks for a state outside the nine",
             lambda: outbox("otcs-outbox-t1.sqlite").transition(
                 operation.project_id, "any-key", {"PREPARED"}, "LOCAL_DONE"),
             "OTCS_OUTBOX_TRANSITION"),
            ("a transition EXPECTS a state outside the nine",
             lambda: outbox("otcs-outbox-t2.sqlite").transition(
                 operation.project_id, "any-key", {"PREPARED", "NOPE"}, "CALLING"),
             "OTCS_OUTBOX_TRANSITION"),
            ("the row a transition names was never written",
             lambda: outbox("otcs-outbox-t3.sqlite").transition(
                 operation.project_id, "synthetic-otcs-idempotency-999",
                 {"PREPARED"}, "CALLING"),
             "OTCS_OUTBOX_MISSING"),
            ("the row is in PREPARED and the caller demanded CALLING",
             prepared_then_wrong_expectation,
             "OTCS_OUTBOX_CONFLICT"),
            ("a terminal row carries no execution request",
             terminal_without_execution_request,
             "OTCS_OUTBOX_EXECUTION_REQUEST"),
            ("a non-terminal state is asked to produce a result",
             lambda: OTCSBridge._result({"state": "PREPARED"}),
             "OTCS_OUTBOX_RESULT_STATE"),
        )

        for label, drive, code in rows:
            with self.subTest(row=label, code=code):
                with self.assertRaisesRegex(OTCSBridgeError, rf"^{code}(:|$)"):
                    drive()


    def test_no_stored_row_value_leaves_the_bridge_vocabulary(self) -> None:
        """A stored outbox value answers with a bridge refusal, never raw.

        The outbox is plain SQLite without a MAC, and the bridge accepts a
        database it did not create (the reason OTCS_OUTBOX_STATE left the
        internal-only list). A JSON column that did not parse - invalid text,
        an integer literal past the parser's digit limit, undecodable bytes -
        raised JSONDecodeError or ValueError out of the row decoder, past the
        bridge vocabulary. That member is pinned to OTCS_OUTBOX_ROW_JSON for
        each of the four JSON columns.

        The sweep asks the class question of non-key columns of the row in a
        table carrying the module's column names without its CHECK constraint
        or column types. Each stored form is kept as written: every public read
        and resume must end in a bridge or engine refusal, or in an answer.
        The two key columns have separate lookup controls after the sweep.

        Among the swept columns, `state` is asked on the terminal base alone.
        This is a further limit, separate from the key-column controls. A hostile
        value there replaces the base's state, so the row stops being the base
        it was drawn from and the same question would be asked five times for
        one answer. The cost is that the column which selects the recovery path
        is never hostile on a row that reaches recovery.

        It asks it of rows in five states. Three are taken from a real run
        paused at one of the bridge's own fault points, with the permit still
        live; the fourth, CALLING, is such a paused row moved on by the
        transition the bridge itself performs, because the bridge has no fault
        point inside the call; the fifth, LOCAL_COMMITTED, is the run carried to
        its end, whose permit the commit has consumed. That fifth row is the early return: a
        terminal state answers from the resume before any recovery step, so a
        sweep over it alone certified the read and nothing of recovery or
        replay, and the four paused rows are what cover those. Every case runs on its own copy of the engine
        state, so a case that finalises a permit cannot starve the cases after
        it. Not covered: DOWNSTREAM_REJECTED, which the bridge has no fault
        point to pause in.
        """
        import sqlite3
        from contextlib import closing

        from nc25_universal_ledger import ContractViolation

        operation = self.bundle["bridge_operation"]
        key = (operation["project_id"], operation["idempotency_key"])

        def state_copy(source, target):
            # The engine store runs in WAL mode; the backup API copies what the
            # write-ahead log holds, a file copy would not.
            with closing(sqlite3.connect(source)) as src, closing(sqlite3.connect(target)) as dst:
                src.backup(dst)

        def engine_on(state_file):
            return UniversalConnectionLedger(
                self.bundle["profile"],
                self.bundle["declaration"],
                signing_key=b"synthetic-reference-signing-key",
                clock=self.clock,
                state_path=state_file,
            )

        clean_state = self.temporary_root / "ledger-clean.sqlite"
        state_copy(self.temporary_root / "ledger.sqlite", clean_state)

        def paused_run(name, pause_at):
            state_file = self.temporary_root / f"base-{name}-ledger.sqlite"
            state_copy(clean_state, state_file)
            outbox = self.temporary_root / f"base-{name}-outbox.sqlite"

            def pause(point):
                if point == pause_at:
                    raise RuntimeError("SYNTHETIC_PAUSE")

            bridge = OTCSBridge(
                engine_on(state_file), FakeOTCSClient(self.bundle["downstream_receipt"]),
                outbox, _fault_hook=pause,
            )
            try:
                bridge.execute(operation, self.bundle["intent"], self.bundle["evidence"])
            except RuntimeError as exc:
                self.assertEqual(str(exc), "SYNTHETIC_PAUSE")
            return bridge, state_file, outbox

        bases = {}
        for name, pause_at in (
            ("LOCAL_COMMITTED", None),
            ("PREPARED", "after_prepare"),
            ("CALLING", "after_prepare"),
            ("AMBIGUOUS", "after_downstream_response"),
            ("DOWNSTREAM_COMMITTED", "after_downstream_persisted"),
        ):
            bridge, state_file, outbox = paused_run(name, pause_at)
            if name == "CALLING":
                # No fault point sits between the CALLING transition and the
                # append, so the row is moved there the way the bridge moves it.
                bridge._outbox.transition(*key, {"PREPARED"}, "CALLING")
            with closing(sqlite3.connect(outbox)) as connection:
                connection.row_factory = sqlite3.Row
                row = dict(connection.execute("SELECT * FROM otcs_bridge_outbox").fetchone())
            self.assertEqual(row["state"], name)
            bases[name] = (row, state_file)
        columns = list(bases["LOCAL_COMMITTED"][0])
        self.assertIn("request_json", columns)

        digit_limit = sys.get_int_max_str_digits() or 4300
        # A marker, not a value: the insert binds it as ordinary text and a CAST then
        # replaces that column with bytes no decoder can read. Binding those bytes
        # directly would make a BLOB, which is a different form and already swept.
        INVALID_UTF8_TEXT = "\x01invalid-utf8-marker"
        stored_forms = {
            "text that is not JSON": "{",
            "integer literal past the digit limit": "9" * (digit_limit + 1),
            # A literal depth, not one read from sys.getrecursionlimit(): the
            # form must stay past any recursion limit a run could set.
            "array nested past the recursion limit": "[" * 100_000 + "]" * 100_000,
            # The form above dies at `json.loads` and never reaches the walk. This one
            # PARSES: 600 levels is inside the parser's own limit and outside what a deep
            # copy of the decoded record survives - measured, 400 parses and copies, 600
            # parses and the copy raises. Before the walk carried the engine's nesting
            # limit, a value in this band left a public read as a bare RecursionError
            # under no code at all, and no planted form landed here to say so.
            "array nested inside the parser's limit but past a deep copy":
                "[" * 600 + "]" * 600,
            "non-ASCII text": "é",
            "undecodable bytes": b"\xff\xfe\xfd",
            "integer": 7,
            "null": None,
            "empty text": "",
            # Not the same form as the bytes above: a bytes parameter binds as a BLOB,
            # which the decoder sees as a non-string. This one is written through a CAST
            # so the column is TEXT holding bytes that are not UTF-8 - the form that used
            # to fail inside the driver at the fetch, before any bridge code named it.
            "text that is not UTF-8": INVALID_UTF8_TEXT,
            # Innocent bytes, guilty value: this text is pure ASCII and parses, and what
            # it parses INTO is a lone surrogate that cannot be written back. A check on
            # the stored bytes alone passes it, which is what the first version of that
            # check did; the write two calls later was where it died.
            "JSON carrying a surrogate escape": '{"note": "\\ud800"}',
        }

        # One engine per base, its state file reset from the base before every
        # case: the engine reads its persisted state on each call, so the reset
        # isolates the cases without constructing an engine for each.
        case_engines = {}
        for base_state in bases:
            case_ledger = self.temporary_root / f"case-{base_state}-ledger.sqlite"
            state_copy(bases[base_state][1], case_ledger)
            case_engines[base_state] = (engine_on(case_ledger), case_ledger)

        def foreign_outbox(name, base_state, column, value, *, reset_engine=True):
            path = self.temporary_root / name
            base_row, base_ledger = bases[base_state]
            row = dict(base_row, **{column: value})
            engine, case_ledger = case_engines[base_state]
            if reset_engine:
                state_copy(base_ledger, case_ledger)
            with closing(sqlite3.connect(path)) as connection:
                connection.execute(
                    "CREATE TABLE otcs_bridge_outbox ("
                    + ", ".join(columns)
                    + ", PRIMARY KEY (project_id, idempotency_key))"
                )
                connection.execute(
                    "INSERT INTO otcs_bridge_outbox ("
                    + ", ".join(columns)
                    + ") VALUES ("
                    + ", ".join("?" for _ in columns)
                    + ")",
                    [row[name] for name in columns],
                )
                if value == INVALID_UTF8_TEXT:
                    connection.execute(
                        f"UPDATE otcs_bridge_outbox SET {column} = CAST(? AS TEXT)",
                        (b"\xff\xfe\xfd",),
                    )
                connection.commit()
            return OTCSBridge(
                engine, FakeOTCSClient(self.bundle["downstream_receipt"]), path,
            )

        # Control: each unmodified base row resumes to a commit on fresh engine
        # state, before and after the sweep. For the non-terminal bases this
        # reaches the end of recovery. The controls reset their own state; they
        # do not prove that the sweep's separate per-case reset held.
        def resumes_from_every_base(when):
            # What this control says: an unmodified base row still resumes to a commit, before
            # and after the sweep, on a fresh engine state. What it does NOT say: that each case
            # left the engine as it found it. Measured: with the reset dropped, the after-sweep
            # run does not commit - every case carries its recovery to the end and the commit
            # consumes the permit, which is the fixture's design. A tooth for the reset would
            # have to assert the in-vocabulary refusal a consumed permit gives, not a commit.
            for base_state in bases:
                with self.subTest(control=f"unmodified base row resumes {when}", base=base_state):
                    bridge = foreign_outbox(f"control-{when}-{base_state}.sqlite", base_state, "state", base_state)
                    self.assertEqual(bridge.recover(*key)["status"], "COMMITTED")

        resumes_from_every_base("before the sweep")

        # The table itself, pinned: an outbox table this module did not create
        # may lack a column the bridge reads. Each is dropped in turn, and the
        # read refuses by the table's columns before any statement names it.
        for missing in columns:
            with self.subTest(member="outbox table without a column", column=missing):
                kept = [name for name in columns if name != missing]
                keys = [name for name in ("project_id", "idempotency_key") if name in kept]
                path = self.temporary_root / f"without-{missing}.sqlite"
                base_row = bases["LOCAL_COMMITTED"][0]
                with closing(sqlite3.connect(path)) as connection:
                    connection.execute(
                        "CREATE TABLE otcs_bridge_outbox (" + ", ".join(kept)
                        + (", PRIMARY KEY (" + ", ".join(keys) + ")" if keys else "") + ")"
                    )
                    connection.execute(
                        "INSERT INTO otcs_bridge_outbox (" + ", ".join(kept) + ") VALUES ("
                        + ", ".join("?" for _ in kept) + ")",
                        [base_row[name] for name in kept],
                    )
                    connection.commit()
                # The store refuses where it is opened: construction is what raises, and the
                # read below is never reached. Both are inside the assertion so the case still
                # says that no public path sees the foreign table.
                with self.assertRaisesRegex(OTCSBridgeError, r"^OTCS_OUTBOX_COLUMNS(:|$)"):
                    OTCSBridge(
                        case_engines["LOCAL_COMMITTED"][0],
                        FakeOTCSClient(self.bundle["downstream_receipt"]), path,
                    ).outbox_record(*key)

        with self.subTest(member="outbox table with a column the module does not declare"):
            # The other direction of the same class. `declared - present` alone left this open:
            # the table has everything the bridge names, so nothing was missing, and `SELECT *`
            # carried the undeclared value into the decoded record.
            keys = ["project_id", "idempotency_key"]
            path = self.temporary_root / "with-undeclared-column.sqlite"
            base_row = bases["LOCAL_COMMITTED"][0]
            widened = list(columns) + ["undeclared_column"]
            with closing(sqlite3.connect(path)) as connection:
                connection.execute(
                    "CREATE TABLE otcs_bridge_outbox (" + ", ".join(widened)
                    + ", PRIMARY KEY (" + ", ".join(keys) + "))"
                )
                connection.execute(
                    "INSERT INTO otcs_bridge_outbox (" + ", ".join(widened) + ") VALUES ("
                    + ", ".join("?" for _ in widened) + ")",
                    [base_row[name] for name in columns] + ["carried"],
                )
                connection.commit()
            with self.assertRaisesRegex(OTCSBridgeError, r"^OTCS_OUTBOX_COLUMNS(:|$)"):
                OTCSBridge(
                    case_engines["LOCAL_COMMITTED"][0],
                    FakeOTCSClient(self.bundle["downstream_receipt"]), path,
                ).outbox_record(*key)

        with self.subTest(member="outbox table carrying our columns and no primary key"):
            # The third direction, and the one the names alone cannot ask. A create does
            # nothing when a table of that name is already there and retrofits no
            # constraint, so this table passed: two rows sharing the project and the
            # idempotency key lived in it and `get` answered with whichever the driver
            # reached first - measured, against our own table, which refuses the second
            # row itself. Idempotency is what that key carries.
            path = self.temporary_root / "without-primary-key.sqlite"
            base_row = bases["LOCAL_COMMITTED"][0]
            with closing(sqlite3.connect(path)) as connection:
                connection.execute(
                    "CREATE TABLE otcs_bridge_outbox (" + ", ".join(columns) + ")")
                for state in ("CALLING", base_row["state"]):
                    connection.execute(
                        "INSERT INTO otcs_bridge_outbox (" + ", ".join(columns) + ") VALUES ("
                        + ", ".join("?" for _ in columns) + ")",
                        [state if name == "state" else base_row[name] for name in columns],
                    )
                connection.commit()
            with self.assertRaisesRegex(
                    OTCSBridgeError, r"^OTCS_OUTBOX_COLUMNS: primary key absent$"):
                OTCSBridge(
                    case_engines["LOCAL_COMMITTED"][0],
                    FakeOTCSClient(self.bundle["downstream_receipt"]), path,
                ).outbox_record(*key)

        for column in ("request_json", "receipt_json", "execution_request_json", "local_receipt_json"):
            with self.subTest(member="stored JSON column that does not parse", column=column):
                bridge = foreign_outbox(f"pinned-{column}.sqlite", "LOCAL_COMMITTED", column, "{")
                with self.assertRaisesRegex(OTCSBridgeError, r"^OTCS_OUTBOX_ROW_JSON(:|$)"):
                    bridge.outbox_record(*key)

        # Pinned by name, and it is what witnesses this code: the sweep below catches every
        # bridge refusal and goes on, so a code only swept is a code the failure-surface
        # ratchet counts as declared and unwitnessed. A JSON column would carry the same
        # code, not a neighbour's - the round trip is the FIRST loop in `_decoded`, ahead
        # of the parse - and `rejection_code` is chosen only because a plain text column
        # shows the refusal without a second mechanism standing behind it.
        with self.subTest(member="stored text column that cannot be decoded"):
            bridge = foreign_outbox(
                "pinned-undecodable-text.sqlite", "LOCAL_COMMITTED",
                "rejection_code", INVALID_UTF8_TEXT,
            )
            with self.assertRaisesRegex(OTCSBridgeError, r"^OTCS_OUTBOX_ROW_TEXT(:|$)"):
                bridge.outbox_record(*key)

        escapes: list[str] = []
        cases = 0
        for base_state in bases:
            for column in columns:
                # The state column itself is swept once, on the terminal base:
                # any value there replaces the base's state.
                if column == "state" and base_state != "LOCAL_COMMITTED":
                    continue
                # The two LOOKUP KEY columns are not swept here, and the reason is not
                # taste: a hostile value in one of them moves the row away from the key
                # every call below asks for, so the reader finds nothing and the sweep
                # records "nothing escaped" from a row it never reached. Measured - a row
                # whose `project_id` was changed answers None on the honest key, while the
                # untouched row answers with a record. What happens to such a row instead
                # is a question of its own, and the case under this loop asks it.
                if column in ("project_id", "idempotency_key"):
                    continue
                for label, value in stored_forms.items():
                    # The read does not depend on the state, so it is swept on
                    # the terminal base only; it writes nothing to the engine.
                    surfaces = ("outbox_record", "recover", "execute") if base_state == "LOCAL_COMMITTED" else ("recover", "execute")
                    for surface in surfaces:
                        bridge = foreign_outbox(
                            f"sweep-{cases}.sqlite", base_state, column, value,
                            reset_engine=surface != "outbox_record",
                        )
                        cases += 1
                        try:
                            if surface == "outbox_record":
                                # An ANSWER is judged too, by the shape the schema declares.
                                # This loop counted only exceptions that left the vocabulary,
                                # so a BLOB or an integer handed back as `last_error` - or as
                                # `operation_hash` - counted as an answer and passed. Measured:
                                # five plain columns did exactly that before the decoder
                                # asked their type.
                                answer = bridge.outbox_record(*key)
                                if answer is not None:
                                    for name, got in answer.items():
                                        if name in ("request", "receipt", "execution_request",
                                                    "local_receipt", "state"):
                                            continue
                                        if got is None and name in _OUTBOX_NULLABLE:
                                            continue
                                        if not isinstance(got, str):
                                            escapes.append(
                                                f"{base_state} {surface} {column} <- {label}: "
                                                f"answered {name} as {type(got).__name__}")
                                    if answer.get("request") is None:
                                        escapes.append(
                                            f"{base_state} {surface} {column} <- {label}: "
                                            f"answered with no request")
                            elif surface == "recover":
                                bridge.recover(*key)
                            else:
                                bridge.execute(operation, self.bundle["intent"], self.bundle["evidence"])
                        except (OTCSBridgeError, ContractViolation):
                            continue
                        except Exception as exc:  # noqa: BLE001 - the class under test
                            escapes.append(f"{base_state} {surface} {column} <- {label}: {type(exc).__name__}")

        # The question the two key columns are left out of the sweep for. A stored row
        # whose key is not this key's is NOT this key's row: the reader answers with
        # nothing, which is the whole of what can be said about it, and nothing leaves the
        # vocabulary because nothing is read. The control beside it is the same reader on
        # the untouched row, so "answers nothing" cannot pass for "the reader is broken".
        for column in ("project_id", "idempotency_key"):
            with self.subTest(member="a stored row whose key is hostile", column=column):
                bridge = foreign_outbox(
                    f"hostile-key-{column}.sqlite", "LOCAL_COMMITTED", column, b"\xff\xfe")
                self.assertIsNone(bridge.outbox_record(*key))
        with self.subTest(member="the control for those two"):
            bridge = foreign_outbox(
                "hostile-key-control.sqlite", "LOCAL_COMMITTED", "last_error", None)
            self.assertIsNotNone(bridge.outbox_record(*key))

        resumes_from_every_base("after the sweep")
        self.assertGreaterEqual(len(columns), 12, "the sweep saw fewer columns than the table has")
        self.assertEqual(escapes, [], f"{len(escapes)} of {cases} stored values left the vocabulary")

    def test_construction_and_recovery_refuse_with_their_own_codes(self) -> None:
        """Six codes on the two ends of a run: building the bridge, and
        finding a row that cannot go forward.

        The constructor is the only driver for two of them - one grep hit each,
        both inside `__init__`, factored into no helper - so the row IS the
        call.  The canonicalizer is module-private and is driven directly: no
        public entry point carries a value that JSON cannot represent, and that
        is a fact about the CONTRACT rather than about the guard, recorded as
        such in the vocabulary.

        `OTCS_RECEIPT_MISMATCH` deserves its own sentence.  Through the public
        path it can never be witnessed: the only `except OTCSBridgeError` in
        the module wraps the receipt validation and re-raises everything it
        catches as `OTCS_RECEIPT_UNUSABLE`.  An already-shipped case asserts
        that wrapper and is named correctly; what it certifies is the wrapper's
        code, not this one.  The row below therefore calls `_validate_receipt`
        directly, which is also the reason it can pass `None` for `self`: the
        body touches no instance state.
        """
        # Control: the untouched receipt must validate against the untouched
        # operation. Without it a fixture that no longer matches at all would
        # turn the mismatch rows green for the wrong reason.
        OTCSBridge._validate_receipt(
            None,
            OTCSAppendOperation.from_mapping(
                copy.deepcopy(self.bundle["bridge_operation"])
            ),
            OTCSReceiptRef.from_mapping(
                copy.deepcopy(self.bundle["downstream_receipt"])
            ),
        )

        def volatile_engine():
            engine = UniversalConnectionLedger(
                self.bundle["profile"],
                self.bundle["declaration"],
                signing_key=b"synthetic-reference-signing-key",
                clock=self.clock,
            )
            return OTCSBridge(
                engine,
                FakeOTCSClient(self.bundle["downstream_receipt"]),
                self.temporary_root / "otcs-outbox-volatile.sqlite",
            )

        def receipt_with(field, value):
            raw = copy.deepcopy(self.bundle["downstream_receipt"])
            raw[field] = value
            return OTCSBridge._validate_receipt(
                None,
                OTCSAppendOperation.from_mapping(
                    copy.deepcopy(self.bundle["bridge_operation"])
                ),
                OTCSReceiptRef.from_mapping(raw),
            )

        _, _, admitted_row = self._prepared_admission_row()
        permit_hash = admitted_row["permit_hash"]
        operation = OTCSAppendOperation.from_mapping(
            copy.deepcopy(self.bundle["bridge_operation"])
        )

        def stuck_row(state, **over):
            row = {
                "project_id": operation.project_id,
                "idempotency_key": operation.idempotency_key,
                "operation_hash": admitted_row["operation_hash"],
                "permit_hash": permit_hash,
                "state": state,
                "request": copy.deepcopy(admitted_row["request"]),
                "receipt": None,
                "execution_request": None,
                "local_receipt": None,
            }
            row.update(over)
            return row

        def advance(state, **over):
            bridge = self.bridge(FakeOTCSClient(self.bundle["downstream_receipt"]))
            bridge._advance(stuck_row(state, **over), recovery=False)

        def recover_advance(state, **over):
            # recovery=True is the whole point of the row below: it is the only
            # way to reach the CALLING liveness check, which execute() never
            # sees because CALLING without recovery refuses earlier.
            bridge = self.bridge(FakeOTCSClient(self.bundle["downstream_receipt"]))
            bridge._advance(stuck_row(state, **over), recovery=True)

        rows = (
            ("the ledger was built without durable state",
             volatile_engine,
             "OTCS_DURABLE_ENGINE_REQUIRED"),
            ("the client has no append_event at all",
             lambda: self.bridge(object()),
             "OTCS_CLIENT_INVALID"),
            ("the client's append_event is not callable",
             lambda: self.bridge(type("Blunt", (), {"append_event": 7})()),
             "OTCS_CLIENT_INVALID"),
            ("a value JSON cannot represent",
             lambda: _canonical_text({"v": float("nan")}),
             "OTCS_BRIDGE_JSON"),
            ("a value JSON cannot serialise at all",
             lambda: _canonical_text({"v": object()}),
             "OTCS_BRIDGE_JSON"),
            ("the receipt names another project",
             lambda: receipt_with("project_id", "another-project"),
             "OTCS_RECEIPT_MISMATCH"),
            ("the receipt names another sequence",
             lambda: receipt_with("project_sequence", 4242),
             "OTCS_RECEIPT_MISMATCH"),
            ("the row already asked for reconciliation",
             lambda: advance("RECONCILIATION_REQUIRED",
                             last_error="OTCS_RECEIPT_MISMATCH"),
             "OTCS_RECONCILIATION_REQUIRED"),
            ("the row is mid-flight and this is not a recovery",
             lambda: advance("CALLING"),
             "OTCS_RECOVERY_REQUIRED"),
        )

        for label, drive, code in rows:
            with self.subTest(row=label, code=code):
                with self.assertRaisesRegex(OTCSBridgeError, rf"^{code}(:|$)"):
                    drive()


if __name__ == "__main__":
    unittest.main(verbosity=2)
