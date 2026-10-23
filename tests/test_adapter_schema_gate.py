"""The HTTP adapter checks each POST body against its packaged JSON Schema."""

from __future__ import annotations

import importlib.util
import copy
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python"))
sys.path.insert(0, str(ROOT / "tests"))

import nc25_universal_adapter as wire  # noqa: E402
from test_contract_conformance import (  # noqa: E402
    _activate_body,
    _adapter_fixture,
    _exec_request,
    _http_call,
)

if os.environ.get("NC25_ADAPTER_MUTANT"):
    spec = importlib.util.spec_from_file_location(
        "adapter_schema_mutant", os.environ["NC25_ADAPTER_MUTANT"]
    )
    assert spec is not None and spec.loader is not None
    wire = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wire)
    wire.SCHEMA_DIR = ROOT / "core" / "schemas"


CASES = (
    ("activate", "/v1/declarations:activate", "nc25.governance",
     {"profile": {}, "declaration": {}, "activated_by": "actor", "approval_evidence_ref": "ref"},
     "$.profile.", "activate"),
    ("grant", "/v1/authority-grants", "nc25.governance",
     {"message_type": "authority_grant"}, "$.grant_id", "issue_grant"),
    ("revoke", "/v1/authority-revocations", "nc25.governance",
     {"message_type": "authority_revocation"}, "$.grant_id", "revoke_grant"),
    ("operator", "/v1/operator/intents:evaluate", "nc25.operator",
     {"intent": {"message_type": "intent"},
      "evidence_bundle": {"message_type": "evidence_bundle"}},
     "$.intent.", "evaluate_intent"),
    ("consume", "/v1/executor/permits/" + "a" * 64 + ":consume", "nc25.executor",
     {"message_type": "execution_request"}, "$.permit_hash", "commit_execution"),
)


class AdapterSchemaGateTests(unittest.TestCase):
    def test_schema_refusals_precede_engine_without_mutation(self) -> None:
        app, grant, intent, evidence = _adapter_fixture()
        app = wire.UniversalConnectionHttpAdapter(app._engine)

        def refused(route, path, body, scope, method, field, validator, idem=None):
            with self.subTest(route=route):
                before = app._engine._snapshot_state()
                with patch.object(app._engine, method,
                                  side_effect=AssertionError("mutating method reached")) as mutate, \
                     patch.object(app._engine, "_assert_integrity",
                                  side_effect=AssertionError("domain validator reached")) as validate:
                    status, response = _http_call(app, "POST", path, body, scope=scope, idem=idem)
                self.assertEqual((status, response["code"], response["message"]),
                                 (400, "BODY_SCHEMA", f"{field}: {validator}"))
                mutate.assert_not_called()
                validate.assert_not_called()
                self.assertEqual(app._engine._snapshot_state(), before)

        body = _activate_body(app)
        del body["approval_evidence_ref"]
        refused("activate", "/v1/declarations:activate", body, "nc25.governance", "activate",
                "$.approval_evidence_ref", "required")
        self.assertEqual(_http_call(app, "POST", "/v1/declarations:activate",
                                    _activate_body(app), scope="nc25.governance")[0], 201)

        bad_grant = copy.deepcopy(grant)
        bad_grant["message_type"] = "wrong"
        refused("grant", "/v1/authority-grants", bad_grant, "nc25.governance", "issue_grant",
                "$.message_type", "const")
        self.assertEqual(_http_call(app, "POST", "/v1/authority-grants", grant,
                                    scope="nc25.governance")[0], 201)

        revocation = {
            "message_type": "wrong", "grant_id": grant["grant_id"],
            "declaration_hash": app._engine.declaration_hash,
            "revoked_at": "2026-08-01T10:00:00Z", "revoked_by": grant["issued_by"],
            "reason_code": "SYNTHETIC_REVOCATION",
            "evidence_ref": "evidence://synthetic/revocation/wire",
        }
        refused("revoke", "/v1/authority-revocations", revocation, "nc25.governance",
                "revoke_grant", "$.message_type", "const")

        bad_intent = copy.deepcopy(intent)
        bad_intent["message_type"] = "wrong"
        refused("operator", "/v1/operator/intents:evaluate",
                {"intent": bad_intent, "evidence_bundle": evidence}, "nc25.operator",
                "evaluate_intent", "$.intent.message_type", "const",
                idem=intent["idempotency_key"])
        status, decision = _http_call(app, "POST", "/v1/operator/intents:evaluate",
                                      {"intent": intent, "evidence_bundle": evidence},
                                      scope="nc25.operator", idem=intent["idempotency_key"])
        self.assertEqual((status, decision["disposition"]), (200, "ALLOW"))
        bad_execution = _exec_request(intent, decision["permit_hash"])
        bad_execution["message_type"] = "wrong"
        refused("consume", f"/v1/executor/permits/{decision['permit_hash']}:consume",
                bad_execution, "nc25.executor", "commit_execution", "$.message_type", "const")

    def test_schema_precedes_domain_refusal_for_mixed_errors(self) -> None:
        app, grant, _intent, _evidence = _adapter_fixture()
        app = wire.UniversalConnectionHttpAdapter(app._engine)
        bad_grant = copy.deepcopy(grant)
        bad_grant["message_type"] = "wrong"
        status, reply = _http_call(app, "POST", "/v1/authority-grants", bad_grant,
                                   scope="nc25.governance")
        self.assertEqual((status, reply["code"], reply["message"]),
                         (400, "BODY_SCHEMA", "$.message_type: const"))
        # A schema-valid body still receives the engine's state refusal.
        status, reply = _http_call(app, "POST", "/v1/authority-grants", grant,
                                   scope="nc25.governance")
        self.assertEqual((status, reply["code"]), (400, "DECLARATION_NOT_ACTIVE"))
        bad_activation = _activate_body(app)
        bad_activation["profile"]["profile_id"] = "tampered-profile"
        status, reply = _http_call(app, "POST", "/v1/declarations:activate", bad_activation,
                                   scope="nc25.governance")
        self.assertEqual((status, reply["code"]), (409, "ACTIVATE_PROFILE_MISMATCH"))
        del bad_activation["activated_by"]
        status, reply = _http_call(app, "POST", "/v1/declarations:activate", bad_activation,
                                   scope="nc25.governance")
        self.assertEqual((status, reply["code"], reply["message"]),
                         (400, "BODY_SCHEMA", "$.activated_by: required"))
        self.assertEqual(_http_call(app, "POST", "/v1/declarations:activate",
                                    _activate_body(app), scope="nc25.governance")[0], 201)
        active_activation = _activate_body(app)
        del active_activation["approval_evidence_ref"]
        status, reply = _http_call(app, "POST", "/v1/declarations:activate", active_activation,
                                   scope="nc25.governance")
        self.assertEqual((status, reply["code"], reply["message"]),
                         (400, "BODY_SCHEMA", "$.approval_evidence_ref: required"))
        mixed = copy.deepcopy(grant)
        del mixed["grant_id"]
        mixed["unexpected_field"] = True
        status, reply = _http_call(app, "POST", "/v1/authority-grants", mixed,
                                   scope="nc25.governance")
        self.assertEqual((status, reply["code"], reply["message"]),
                         (400, "BODY_SCHEMA", "$.grant_id: required"))
        long_ref = copy.deepcopy(grant)
        long_ref["approval_evidence_ref"] = "x" * 501
        before = app._engine._snapshot_state()
        status, reply = _http_call(app, "POST", "/v1/authority-grants", long_ref,
                                   scope="nc25.governance")
        self.assertEqual((status, reply["code"], reply["message"]),
                         (400, "BODY_SCHEMA", "$.approval_evidence_ref: maxLength"))
        self.assertEqual(app._engine._snapshot_state(), before)
        bad_time = copy.deepcopy(grant)
        bad_time["valid_from"] = "not-a-time"
        status, reply = _http_call(app, "POST", "/v1/authority-grants", bad_time,
                                   scope="nc25.governance")
        self.assertEqual((status, reply["code"], reply["message"]),
                         (400, "BODY_SCHEMA", "$.valid_from: format"))

    def test_missing_validator_refuses_all_post_routes(self) -> None:
        with patch.dict(sys.modules, {"jsonschema": None}):
            for name, path, scope, body, _field, method in CASES:
                with self.subTest(route=name):
                    engine = Mock()
                    app = wire.UniversalConnectionHttpAdapter(engine)
                    status, response = _http_call(
                        app, "POST", path, body, scope=scope, idem="synthetic-key"
                    )
                    self.assertEqual(
                        (status, response.get("code") if isinstance(response, dict) else None),
                        (503, "SCHEMA_VALIDATION_UNAVAILABLE"),
                    )
                    getattr(engine, method).assert_not_called()

    def test_missing_date_time_checker_refuses_all_post_routes(self) -> None:
        from jsonschema import FormatChecker

        with patch.dict(FormatChecker.checkers, {}, clear=True):
            for name, path, scope, body, _field, method in CASES:
                with self.subTest(route=name):
                    engine = Mock()
                    app = wire.UniversalConnectionHttpAdapter(engine)
                    status, response = _http_call(
                        app, "POST", path, body, scope=scope, idem="synthetic-key"
                    )
                    self.assertEqual((status, response["code"]),
                                     (503, "SCHEMA_VALIDATION_UNAVAILABLE"))
                    getattr(engine, method).assert_not_called()

    def test_valid_post_bodies_pass_to_engine(self) -> None:
        app, grant, intent, evidence = _adapter_fixture()
        app = wire.UniversalConnectionHttpAdapter(app._engine)
        status, _ = _http_call(
            app, "POST", "/v1/declarations:activate", _activate_body(app),
            scope="nc25.governance",
        )
        self.assertEqual(status, 201)
        status, _ = _http_call(
            app, "POST", "/v1/authority-grants", grant, scope="nc25.governance"
        )
        self.assertEqual(status, 201)
        status, decision = _http_call(
            app, "POST", "/v1/operator/intents:evaluate",
            {"intent": intent, "evidence_bundle": evidence},
            scope="nc25.operator", idem=intent["idempotency_key"],
        )
        self.assertEqual((status, decision.get("disposition")), (200, "ALLOW"))
        permit_hash = decision["permit_hash"]
        status, _ = _http_call(
            app, "POST", f"/v1/executor/permits/{permit_hash}:consume",
            _exec_request(intent, permit_hash), scope="nc25.executor",
        )
        self.assertEqual(status, 200)
        status, _ = _http_call(
            app, "POST", "/v1/authority-revocations",
            {
                "message_type": "authority_revocation",
                "grant_id": grant["grant_id"],
                "declaration_hash": app._engine.declaration_hash,
                "revoked_at": "2026-08-01T10:00:00Z",
                "revoked_by": grant["issued_by"],
                "reason_code": "SYNTHETIC_REVOCATION",
                "evidence_ref": "evidence://synthetic/revocation/wire",
            }, scope="nc25.governance",
        )
        self.assertEqual(status, 204)


if __name__ == "__main__":
    unittest.main()
