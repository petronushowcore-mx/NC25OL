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

    def test_unused_definition_does_not_claim_a_declaration_field(self) -> None:
        control = copy.deepcopy(self.declaration)
        control["$defs"]["unused_definition"] = {"type": "boolean"}
        self.assertEqual([], self.check(declaration=control))


if __name__ == "__main__":
    unittest.main()
