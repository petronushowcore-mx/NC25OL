"""Live-engine observer export and independent-reader causal checks."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python"))

from nc25_universal_ledger import (  # noqa: E402
    ContractViolation,
    Ed25519DetachedSigner,
    FixedClock,
    IntegrityViolation,
    ROLE_ARCHITECT,
    UniversalConnectionLedger,
    bind_fixture,
    build_observer_export,
    canonical_json,
    load_json,
)
from nc25ol_reader import ReaderError, main, verify_export  # noqa: E402


class ReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        profile = load_json(ROOT / "profiles" / "banking" / "bank-profile.json")
        declaration = load_json(ROOT / "examples" / "synthetic-connection-declaration.json")
        grant = load_json(ROOT / "examples" / "synthetic-authority-grant.json")
        intent = load_json(ROOT / "examples" / "synthetic-intent-allow.json")
        evidence = load_json(ROOT / "examples" / "synthetic-evidence-bundle.json")
        cls.raw_profile = profile
        cls.raw_declaration = declaration
        cls.raw_grant = grant
        cls.raw_intent = intent
        cls.profile, cls.declaration, bound_grant, bound_intent = bind_fixture(
            profile, declaration, grant, intent
        )
        cls.evidence = evidence
        cls.signer = Ed25519DetachedSigner.generate("observer-export-test")
        cls.engine = UniversalConnectionLedger(
            cls.profile,
            cls.declaration,
            signing_key=b"synthetic-reference-signing-key",
            clock=FixedClock(datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)),
        )
        cls.engine.activate(
            cls.declaration["governance"]["approval_owner_id"],
            "evidence://synthetic/declaration-activation",
            actor_scope="nc25.governance",
        )
        cls.engine.issue_grant(bound_grant, actor_scope="nc25.governance")
        result = cls.engine.evaluate_intent(
            bound_intent, evidence, actor_scope="nc25.operator"
        )
        request = {
            "message_type": "execution_request",
            "permit_hash": result["permit_hash"],
            "connector_id": bound_intent["connector_id"],
            "binding": bound_intent["binding"],
            "state_anchor_hash": bound_intent["state_anchor_hash"],
            "outcome": "COMMITTED",
            "downstream_receipt_hash": "9" * 64,
            "committed_at": "2026-08-01T10:00:00Z",
        }
        cls.engine.commit_execution(
            request, actor_scope="nc25.executor",
            route_permit_hash=result["permit_hash"],
        )
        denied_intent = copy.deepcopy(bound_intent)
        denied_intent["intent_id"] = "synthetic-intent-reader-denied"
        denied_intent["idempotency_key"] = "synthetic-idempotency-reader-denied"
        denied_intent["payload_hash"] = hashlib.sha256(b"reader-denied").hexdigest()
        denied_intent["hard_block_flags"][profile["controls"]["hard_block_flag_ids"][0]] = True
        denied_evidence = copy.deepcopy(evidence)
        denied_evidence["intent_id"] = denied_intent["intent_id"]
        refusal = cls.engine.evaluate_intent(
            denied_intent, denied_evidence, actor_scope="nc25.operator"
        )
        if refusal["message_code"] != "EXECUTION_DENIED":
            raise AssertionError("live engine did not produce the refusal fixture")
        cls.bundle = build_observer_export(
            cls.engine, cls.signer, actor_scope=ROLE_ARCHITECT
        )
        cls.pin = cls.bundle["public_key"]["fingerprint_sha256"]

    def assert_refused(self, bundle: dict, expected: str) -> None:
        with self.assertRaises(ReaderError) as caught:
            verify_export(bundle, expected_fingerprint=self.pin)
        self.assertEqual(caught.exception.code, expected)

    def test_live_engine_export_is_readable_without_engine_in_reader(self) -> None:
        result = verify_export(self.bundle, expected_fingerprint=self.pin)
        self.assertTrue(result["verified"])
        self.assertTrue(result["signature_valid"])
        self.assertEqual(result["authorized"], 1)
        self.assertEqual(result["executed"], 1)
        self.assertEqual(result["refused_by_code"], {"EXECUTION_DENIED": 1})
        self.assertEqual(
            [event["record"]["message_code"] for event in self.bundle["events"]],
            ["EXECUTION_AUTHORIZED", "EXECUTION_COMMITTED", "EXECUTION_DENIED"],
        )
        for event in self.bundle["events"]:
            self.assertEqual(
                set(event["record"]),
                {"channel", "message_code", "event_time", "subject_ref"},
            )
            self.assertNotIn("payload", event["record"])

    def test_format_and_genesis_match_frozen_public_literals(self) -> None:
        self.assertEqual(self.bundle["format"], "nc25ol-observer-export/v1")
        self.assertEqual(self.bundle["events"][0]["previous_hash"], "0" * 64)

    def test_unpinned_signature_is_not_authenticated(self) -> None:
        result = verify_export(self.bundle)
        self.assertTrue(result["signature_valid"])
        self.assertFalse(result["verified"])

    def assert_projection_mismatch(self, altered: list[dict]) -> None:
        with patch.object(self.engine, "observer_projection", return_value=altered):
            with self.assertRaisesRegex(
                IntegrityViolation, "^OBSERVER_EXPORT_PROJECTION_MISMATCH"
            ):
                build_observer_export(
                    self.engine, self.signer, actor_scope=ROLE_ARCHITECT
                )

    def test_equal_length_projection_reorder_refused(self) -> None:
        original = self.engine.observer_projection(actor_scope=ROLE_ARCHITECT)
        reordered = copy.deepcopy(original)
        reordered[0], reordered[2] = reordered[2], reordered[0]
        self.assert_projection_mismatch(reordered)

    def test_equal_length_projection_substitution_refused(self) -> None:
        original = self.engine.observer_projection(actor_scope=ROLE_ARCHITECT)
        substituted = copy.deepcopy(original)
        substituted[1]["subject_ref"] = "substituted-public-subject"
        self.assert_projection_mismatch(substituted)

    def test_tampered_public_record_rejected_at_its_hash(self) -> None:
        broken = copy.deepcopy(self.bundle)
        broken["events"][0]["record"]["subject_ref"] = "changed-public-subject"
        self.assert_refused(broken, "EVENT_HASH_MISMATCH")

    def test_removed_event_rejected_at_count(self) -> None:
        broken = copy.deepcopy(self.bundle)
        broken["events"].pop()
        self.assert_refused(broken, "EVENT_COUNT_MISMATCH")

    def test_reordered_events_rejected_at_order(self) -> None:
        broken = copy.deepcopy(self.bundle)
        broken["events"][0], broken["events"][1] = (
            broken["events"][1], broken["events"][0]
        )
        self.assert_refused(broken, "EVENT_ORDER_INVALID")

    def test_foreign_valid_key_rejected_by_external_pin(self) -> None:
        foreign = Ed25519DetachedSigner.generate("another-export-key")
        broken = build_observer_export(
            self.engine, foreign, actor_scope=ROLE_ARCHITECT
        )
        self.assert_refused(broken, "KEY_UNEXPECTED")

    def test_cli_json_input_boundary_is_a_stable_refusal(self) -> None:
        reader = Path(os.environ.get(
            "NC25_READER_MUTANT", str(ROOT / "sdk" / "python" / "nc25ol_reader.py")
        ))
        cases = (
            ("valid_export_control", json.dumps(self.bundle), 0, None),
            ("malformed_json", "{", 2, "JSON_INVALID"),
            ("duplicate_key", '{"x":1,"x":2}', 2, "JSON_DUPLICATE_KEY"),
            ("nonfinite_constant", "NaN", 2, "JSON_CONSTANT_INVALID"),
            ("large_integer", '{"n":' + "9" * 5000 + "}", 2, "JSON_INVALID"),
            ("deep_array", "[" * 2048 + "0" + "]" * 2048, 2, None),
        )
        with tempfile.TemporaryDirectory(prefix="reader-json-input-") as folder:
            for name, text, expected_status, expected_code in cases:
                with self.subTest(case=name):
                    path = Path(folder) / (name + ".json")
                    path.write_text(text, encoding="utf-8")
                    result = subprocess.run(
                        [sys.executable, "-B", str(reader), str(path),
                         "--expect-fingerprint", self.pin],
                        cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                        errors="replace", timeout=30, check=False,
                    )
                    self.assertEqual(result.returncode, expected_status, result.stderr)
                    self.assertEqual(result.stderr, "")
                    payload = json.loads(result.stdout)
                    self.assertEqual(payload["verified"], expected_status == 0)
                    if expected_status == 0:
                        self.assertTrue(payload["signature_valid"])
                    elif expected_code is not None:
                        self.assertEqual(payload["code"], expected_code)
                    else:
                        self.assertIn(
                            payload["code"], {"JSON_INVALID", "EXPORT_FIELDS_INVALID"}
                        )

    def test_cli_requires_external_fingerprint_pin(self) -> None:
        with patch.object(sys, "argv", ["nc25ol_reader", "export.json"]):
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    main()
        self.assertEqual(caught.exception.code, 2)

    def test_signature_of_different_head_rejected(self) -> None:
        broken = copy.deepcopy(self.bundle)
        other_head = {
            "event_count": broken["head"]["event_count"],
            "head_hash": hashlib.sha256(b"different head").hexdigest().upper(),
        }
        broken["signature"] = dict(self.signer.sign(canonical_json({
            "format": broken["format"],
            "head": other_head,
            "public_key": broken["public_key"],
        })))
        self.assert_refused(broken, "HEAD_SIGNATURE_INVALID")

    def test_narrow_observer_profile_refuses_export(self) -> None:
        narrow = copy.deepcopy(self.raw_profile)
        narrow["roles"]["observer_projection_fields"] = ["channel", "event_time"]
        narrow, declaration, _, _ = bind_fixture(
            narrow, self.raw_declaration, self.raw_grant, self.raw_intent
        )
        engine = UniversalConnectionLedger(
            narrow, declaration, signing_key=b"synthetic-reference-signing-key"
        )
        with self.assertRaisesRegex(ContractViolation, "^OBSERVER_EXPORT_FIELDS"):
            build_observer_export(engine, self.signer, actor_scope=ROLE_ARCHITECT)



    def test_export_limits_match_published_literals(self) -> None:
        import nc25ol_reader as reader
        self.assertEqual((reader.MAX_EVENTS, reader.MAX_EXPORT_BYTES), (100000, 33554432))

    def assert_export_succeeds(self) -> dict:
        try:
            return build_observer_export(self.engine, self.signer, actor_scope=ROLE_ARCHITECT)
        except ContractViolation as exc:
            self.fail(f"in-bound export refused as {exc.code}")

    def test_exporter_event_limit_is_inclusive(self) -> None:
        self.assertEqual(self.bundle["head"]["event_count"], 3)
        with patch("nc25ol_reader.MAX_EVENTS", 3):
            self.assertEqual(self.assert_export_succeeds()["head"]["event_count"], 3)
        with patch("nc25ol_reader.MAX_EVENTS", 2):
            with self.assertRaisesRegex(ContractViolation, "^OBSERVER_EXPORT_EVENT_LIMIT(:|$)"):
                build_observer_export(self.engine, self.signer, actor_scope=ROLE_ARCHITECT)

    def test_exporter_canonical_byte_limit_is_inclusive(self) -> None:
        bound = len(canonical_json(self.bundle))
        with patch("nc25ol_reader.MAX_EXPORT_BYTES", bound):
            self.assertEqual(len(canonical_json(self.assert_export_succeeds())), bound)
        with patch("nc25ol_reader.MAX_EXPORT_BYTES", bound - 1):
            with self.assertRaisesRegex(ContractViolation, "^OBSERVER_EXPORT_BYTE_LIMIT(:|$)"):
                build_observer_export(self.engine, self.signer, actor_scope=ROLE_ARCHITECT)

if __name__ == "__main__":
    unittest.main()
