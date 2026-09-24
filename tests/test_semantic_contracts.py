from __future__ import annotations

import copy
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python"))

from nc25_universal_ledger import (  # noqa: E402
    CORE_ANCHOR,
    ContractViolation,
    FixedClock,
    IntegrityViolation,
    UniversalConnectionLedger,
    bind_fixture,
    load_json,
    validate_declaration,
    validate_profile,
)


class SemanticContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = load_json(
            ROOT / "profiles" / "banking" / "bank-profile.json"
        )
        self.declaration = load_json(
            ROOT / "examples" / "synthetic-connection-declaration.json"
        )
        self.grant = load_json(
            ROOT / "examples" / "synthetic-authority-grant.json"
        )
        self.intent = load_json(
            ROOT / "examples" / "synthetic-intent-allow.json"
        )
        self.evidence = load_json(
            ROOT / "examples" / "synthetic-evidence-bundle.json"
        )

    def test_duplicate_action_is_rejected(self) -> None:
        changed = copy.deepcopy(self.profile)
        changed["action_alphabet"].append(
            copy.deepcopy(changed["action_alphabet"][0])
        )
        with self.assertRaisesRegex(ContractViolation, "^DUPLICATE_ACTION_ID(:|$)"):
            validate_profile(changed)

    def test_unknown_effect_mapping_is_rejected(self) -> None:
        changed = copy.deepcopy(self.profile)
        changed["action_alphabet"][0]["effect_class_id"] = "UNKNOWN_EFFECT"
        with self.assertRaisesRegex(ContractViolation, "^UNKNOWN_EFFECT_CLASS(:|$)"):
            validate_profile(changed)

    def test_fallback_must_be_zero_effect(self) -> None:
        changed = copy.deepcopy(self.profile)
        for effect in changed["effect_classes"]:
            if effect["effect_class_id"] == "NO_EFFECT":
                effect["mutates_external_state"] = True
        with self.assertRaisesRegex(
            ContractViolation,
            "^SAFE_FALLBACK_NOT_ZERO_EFFECT(:|$)",
        ):
            validate_profile(changed)

    def test_witness_hash_is_verified(self) -> None:
        changed = copy.deepcopy(self.profile)
        changed["mapping_witness"]["method"] += " Tampered."
        with self.assertRaisesRegex(IntegrityViolation, "^WITNESS_HASH_MISMATCH(:|$)"):
            validate_profile(changed)

    def test_witness_must_cover_every_action(self) -> None:
        changed = copy.deepcopy(self.profile)
        changed["mapping_witness"]["covered_action_ids"].pop()
        with self.assertRaisesRegex(
            ContractViolation,
            "^WITNESS_ACTION_COVERAGE(:|$)",
        ):
            validate_profile(changed)

    def test_failure_posture_cannot_allow(self) -> None:
        changed = copy.deepcopy(self.profile)
        changed["failure_posture"]["ambiguity"] = "ALLOW"
        with self.assertRaisesRegex(
            ContractViolation,
            "^FIXED_FAILURE_POSTURE(:|$)",
        ):
            validate_profile(changed)

    def test_registry_must_remain_hash_only(self) -> None:
        changed = copy.deepcopy(self.profile)
        changed["registry_policy"]["mode"] = "FULL_EVIDENCE"
        with self.assertRaisesRegex(
            ContractViolation,
            "^REGISTRY_NOT_HASH_ONLY(:|$)",
        ):
            validate_profile(changed)

    def test_declaration_cannot_expand_profile_actions(self) -> None:
        changed = copy.deepcopy(self.declaration)
        changed["instance_scope"]["action_ids"].append("UNDECLARED_ACTION")
        with self.assertRaisesRegex(ContractViolation, "^SCOPE_UNKNOWN_ACTION(:|$)"):
            validate_declaration(changed, self.profile)

    def test_target_cannot_be_off_limits(self) -> None:
        changed = copy.deepcopy(self.declaration)
        changed["interfaces"]["off_limits_system_ids"].append(
            "bank-sandbox-ledger"
        )
        with self.assertRaisesRegex(
            ContractViolation,
            "^TARGET_OFF_LIMITS_OVERLAP(:|$)",
        ):
            validate_declaration(changed, self.profile)

    def test_resource_limits_cover_selected_actions(self) -> None:
        changed = copy.deepcopy(self.declaration)
        changed["resource_limits"] = [
            item
            for item in changed["resource_limits"]
            if item["resource_id"] != "money_minor_units"
        ]
        with self.assertRaisesRegex(
            ContractViolation,
            "^RESOURCE_LIMIT_COVERAGE(:|$)",
        ):
            validate_declaration(changed, self.profile)

    def test_profile_hash_binding_is_verified(self) -> None:
        changed = copy.deepcopy(self.declaration)
        changed["profile_binding"]["profile_hash"] = "0" * 64
        with self.assertRaisesRegex(IntegrityViolation, "^PROFILE_HASH_MISMATCH(:|$)"):
            validate_declaration(changed, self.profile)

    def test_interface_roles_cannot_collapse(self) -> None:
        changed = copy.deepcopy(self.declaration)
        changed["interfaces"]["executor_service_id"] = changed["interfaces"][
            "operator_service_id"
        ]
        with self.assertRaisesRegex(
            ContractViolation,
            "^INTERFACE_ROLE_OVERLAP(:|$)",
        ):
            validate_declaration(changed, self.profile)

    def test_operator_cannot_submit_gate_data(self) -> None:
        profile, declaration, grant, intent = bind_fixture(
            self.profile,
            self.declaration,
            self.grant,
            self.intent,
        )
        engine = UniversalConnectionLedger(
            profile,
            declaration,
            signing_key=b"synthetic-reference-signing-key",
            clock=FixedClock(
                datetime(2026, 8, 1, 10, 0, tzinfo=timezone.utc)
            ),
        )
        engine.activate(
            "synthetic-approval-owner",
            "evidence://synthetic/declaration-activation",
            actor_scope="nc25.governance",
        )
        engine.issue_grant(grant, actor_scope="nc25.governance")
        intent["scope"]["gate_margin"] = "0.01"
        with self.assertRaisesRegex(
            ContractViolation,
            "^OPERATOR_GATE_DATA_FORBIDDEN(:|$)",
        ):
            engine.evaluate_intent(intent, self.evidence, actor_scope="nc25.operator")

    def test_core_anchor_mirrors_are_synchronized(self) -> None:
        manifest = load_json(ROOT / "SOURCE-MANIFEST.json")
        manifest_core = next(
            item
            for item in manifest["inputs"]
            if item["role"] == "immutable_nc25_core"
        )
        expected = dict(CORE_ANCHOR)
        self.assertEqual(
            {key: manifest_core[key] for key in expected},
            expected,
        )

        for schema_name in (
            "profile.schema.json",
            "connection-declaration.schema.json",
        ):
            schema = load_json(ROOT / "core" / "schemas" / schema_name)
            properties = schema["$defs"]["core_anchor"]["properties"]
            self.assertEqual(
                {key: properties[key]["const"] for key in expected},
                expected,
            )

        registry = load_json(
            ROOT / "core" / "schemas" / "registry-record.schema.json"
        )
        registry_properties = registry["properties"]["core_anchor"]["properties"]
        registry_expected = {
            key: expected[key] for key in ("core_version", "doi", "sha256")
        }
        self.assertEqual(
            {key: registry_properties[key]["const"] for key in registry_expected},
            registry_expected,
        )

        crosswalk = load_json(ROOT / "core" / "nc25-core-crosswalk.json")
        self.assertEqual(crosswalk["source_file"], expected["file_name"])
        self.assertEqual(crosswalk["source_sha256"], expected["sha256"])

    def test_control_maps_must_be_complete(self) -> None:
        profile, declaration, grant, intent = bind_fixture(
            self.profile,
            self.declaration,
            self.grant,
            self.intent,
        )
        engine = UniversalConnectionLedger(
            profile,
            declaration,
            signing_key=b"synthetic-reference-signing-key",
            clock=FixedClock(
                datetime(2026, 8, 1, 10, 0, tzinfo=timezone.utc)
            ),
        )
        engine.activate(
            "synthetic-approval-owner",
            "evidence://synthetic/declaration-activation",
            actor_scope="nc25.governance",
        )
        engine.issue_grant(grant, actor_scope="nc25.governance")
        intent["prerequisite_results"].pop("KYC_VERIFIED")
        with self.assertRaisesRegex(
            ContractViolation,
            "^PREREQUISITE_RESULTS(:|$)",
        ):
            engine.evaluate_intent(intent, self.evidence, actor_scope="nc25.operator")


if __name__ == "__main__":
    unittest.main(verbosity=2)
