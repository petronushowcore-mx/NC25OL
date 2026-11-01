"""Behavioral controls for the fixed declaration-field inventory."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "declaration_field_census", ROOT / "tools" / "declaration_field_census.py"
)
assert SPEC is not None and SPEC.loader is not None
census = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(census)


class DeclarationFieldCensusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.declaration = json.loads(
            (ROOT / census.DECLARATION_SCHEMA).read_text(encoding="utf-8")
        )
        cls.registry = json.loads(
            (ROOT / census.REGISTRY_SCHEMA).read_text(encoding="utf-8")
        )
        cls.engine = (ROOT / census.ENGINE).read_text(encoding="utf-8")

    def check(self, declaration=None, registry=None, engine=None) -> list[str]:
        return census.audit(
            ROOT,
            declaration_schema=declaration or self.declaration,
            registry_schema=registry or self.registry,
            engine_source=engine or self.engine,
        )

    def test_current_inventory_and_document(self) -> None:
        self.assertEqual([], self.check())
        self.assertEqual(31, len(census.schema_leaves(self.declaration)))
        self.assertEqual(16, len(census.schema_leaves(self.registry)))
        self.assertEqual(17, len(census.REMOVED_DECLARATION))
        self.assertEqual(
            census.render_document(ROOT),
            (ROOT / "DECLARATION-FIELDS.md").read_text(encoding="utf-8"),
        )

    def test_new_declaration_field_is_first_refusal(self) -> None:
        broken = copy.deepcopy(self.declaration)
        connector = broken["properties"]["connector"]
        connector["properties"]["injected_gate"] = {"type": "boolean"}
        connector["required"].append("injected_gate")
        self.assertEqual(
            ["UNCLASSIFIED_DECLARATION_FIELD:connector.injected_gate"],
            self.check(declaration=broken),
        )

    def test_new_registry_field_is_first_refusal(self) -> None:
        broken = copy.deepcopy(self.registry)
        broken["properties"]["injected_gate"] = {"type": "boolean"}
        broken["required"].append("injected_gate")
        self.assertEqual(
            ["UNCLASSIFIED_REGISTRY_FIELD:injected_gate"],
            self.check(registry=broken),
        )

    def test_removed_engine_consumer_is_named(self) -> None:
        anchor = 'scope["action_ids"]'
        self.assertIn(anchor, self.engine)
        broken = self.engine.replace(anchor, 'scope["deleted_action_ids"]', 1)
        self.assertEqual(
            "MISSING_ENGINE_CONSUMER:instance_scope.action_ids",
            self.check(engine=broken)[0],
        )

    def test_comment_cannot_replace_engine_consumer(self) -> None:
        anchor = 'scope["action_ids"]'
        broken = self.engine.replace(anchor, 'scope["deleted_action_ids"]', 1)
        broken = broken.replace(
            "\nclass SystemClock:",
            '\n# scope["action_ids"]\nclass SystemClock:',
            1,
        )
        self.assertEqual(
            "MISSING_ENGINE_CONSUMER:instance_scope.action_ids",
            self.check(engine=broken)[0],
        )

    def test_registry_status_cannot_admit_unreachable_state(self) -> None:
        broken = copy.deepcopy(self.registry)
        broken["properties"]["status"]["enum"].append("SUSPENDED")
        self.assertEqual(
            "REGISTRY_STATUS_OUTSIDE_ENGINE_STATES",
            self.check(registry=broken)[0],
        )

    def test_status_comment_cannot_mask_wider_executable_check(self) -> None:
        marker = 'record["status"] not in {\n                "DRAFT", "ACTIVE",\n'
        self.assertIn(marker, self.engine)
        broken = self.engine.replace(
            marker,
            'record["status"] not in {\n                "DRAFT", "ACTIVE", "SUSPENDED",\n',
            1,
        )
        broken = (
            '# record["status"] not in {"DRAFT", "ACTIVE"}\n' + broken
        )
        self.assertEqual("REGISTRY_ENGINE_STATUS_MISMATCH", self.check(engine=broken)[0])

    def test_string_literal_cannot_replace_engine_consumer(self) -> None:
        # A source anchor proves that a field reaches code, so a string that
        # merely quotes the anchor must not satisfy it: a refusal detail, a
        # docstring and the literal part of an f-string each quote it here
        # after the real consumer is gone.
        anchor = 'scope["action_ids"]'
        broken = self.engine.replace(anchor, 'scope["deleted_action_ids"]', 1)
        for name, prose in (
            ("detail", "_NOTE = ContractViolation(\"X\", 'scope[\"action_ids\"] invalid')"),
            ("docstring", 'def _note():\n    """scope["action_ids"]"""'),
            ("f-string", "_NOTE = f'{len(broken_input)} scope[\"action_ids\"]'"),
        ):
            with self.subTest(name=name):
                planted = broken.replace("\nclass SystemClock:", "\n" + prose + "\n\n\nclass SystemClock:", 1)
                self.assertEqual(
                    ["MISSING_ENGINE_CONSUMER:instance_scope.action_ids"],
                    self.check(engine=planted)[:1],
                    f"STRING_SATISFIED_ANCHOR {name}",
                )

    def test_restore_status_check_cannot_admit_unreachable_state(self) -> None:
        # The census reads the restore path's status test where it runs, in
        # _restore_checked_state: widening it must be named, as widening the
        # registry projection's test is.
        marker = 'state["status"] not in {"DRAFT", "ACTIVE"}'
        self.assertIn(marker, self.engine)
        broken = self.engine.replace(marker, 'state["status"] not in {"DRAFT", "ACTIVE", "SUSPENDED"}', 1)
        self.assertEqual(["REGISTRY_ENGINE_STATUS_MISMATCH"], self.check(engine=broken)[:1], "RESTORE_WIDENING_UNNAMED")

    def test_unused_definition_does_not_claim_a_declaration_field(self) -> None:
        control = copy.deepcopy(self.declaration)
        control["$defs"]["unused_definition"] = {"type": "boolean"}
        self.assertEqual([], self.check(declaration=control))

    def test_banking_crosswalk_claims_no_removed_declaration_field(self) -> None:
        # The crosswalk is the banking profile's mapping witness. A section may
        # route only to declaration fields the schema still has, and a section
        # routed to declaration.interfaces or to a field under it may not claim
        # a service whose interface field was removed. A claim is matched by the
        # name the removed id carries; a bare role word such as governance is
        # not matched.
        crosswalk = json.loads(
            (ROOT / "profiles" / "banking" / "questionnaire-crosswalk.json")
            .read_text(encoding="utf-8")
        )
        leaves = [leaf.replace("[]", "") for leaf in census.schema_leaves(self.declaration)]
        services = [
            name.removeprefix("interfaces.").removesuffix("_id").replace("_", " ")
            for name in census.REMOVED_DECLARATION
            if name.startswith("interfaces.")
        ]
        self.assertEqual(5, len(services), f"removed interface services: {services}")
        interface_sections = 0
        for section in crosswalk["sections"]:
            label = section["questionnaire_section"]
            for path in section["universal_paths"]:
                field = path.removeprefix("declaration.")
                if field != path:
                    self.assertTrue(
                        any(leaf == field or leaf.startswith(field + ".") for leaf in leaves),
                        f"{label}: {path} is not a current declaration field",
                    )
            if any(
                p == "declaration.interfaces" or p.startswith("declaration.interfaces.")
                for p in section["universal_paths"]
            ):
                interface_sections += 1
                effect = section["connection_effect"].lower()
                claimed = [service for service in services if service in effect]
                self.assertEqual([], claimed, f"{label}: claims a removed interface service")
        self.assertTrue(
            interface_sections,
            "no section routes to declaration.interfaces or a field under it",
        )


if __name__ == "__main__":
    unittest.main()
