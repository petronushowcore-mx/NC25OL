"""Account for every fixed connection-declaration and registry field.

Run from the package root with ``python -B tools/declaration_field_census.py``.
The inventory is deliberately explicit: adding a schema property requires a
decision and an engine consumer before it can pass this check.
"""

from __future__ import annotations

import argparse
import ast
import io
import json
import tokenize
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DECLARATION_SCHEMA = "core/schemas/connection-declaration.schema.json"
REGISTRY_SCHEMA = "core/schemas/registry-record.schema.json"
ENGINE = "sdk/python/nc25_universal_ledger.py"

# G: a runtime refusal or budget; B: validated binding, identity, or projection.
# The anchor is an expression in validate_declaration, unless the note says
# otherwise. A required-key literal or a hash of the whole object is not a
# consumer for this inventory.
DECLARATION = {
    "schema_version": ("B", 'declaration["schema_version"] != "1.0.0"', "fixed wire version"),
    "declaration_id": ("B", '_require_identifier(declaration["declaration_id"]', "validated declaration identity"),
    "declaration_version": ("B", '_require_version(declaration["declaration_version"]', "version syntax and binding; no revision budget"),
    "created_at": ("B", 'parse_utc(declaration["created_at"])', "ordering only; not a trusted clock"),
    "effective_from": ("G", 'parse_utc(declaration["effective_from"])', "effective window"),
    "expires_at": ("G", 'parse_utc(declaration["expires_at"])', "expiry window"),
    "core_anchor.file_name": ("B", '_validate_core_anchor(declaration["core_anchor"])', "whole anchor equals fixed core tuple"),
    "core_anchor.core_version": ("B", '_validate_core_anchor(declaration["core_anchor"])', "whole anchor equals fixed core tuple"),
    "core_anchor.doi": ("B", '_validate_core_anchor(declaration["core_anchor"])', "whole anchor equals fixed core tuple"),
    "core_anchor.sha256": ("B", '_validate_core_anchor(declaration["core_anchor"])', "whole anchor equals fixed core tuple"),
    "profile_binding.profile_id": ("B", 'binding["profile_id"] != profile["profile_id"]', "profile identity binding"),
    "profile_binding.profile_version": ("B", 'binding["profile_version"] != profile["profile_version"]', "profile version binding"),
    "profile_binding.profile_hash": ("B", '_require_sha256(binding["profile_hash"]', "profile byte digest binding"),
    "connector.connector_id": ("G", '_require_identifier(connector["connector_id"]', "connector identity and routing"),
    "instance_scope.action_ids": ("G", 'scope["action_ids"]', "allowlisted actions"),
    "instance_scope.effect_class_ids": ("G", 'scope["effect_class_ids"]', "allowlisted effect classes"),
    "instance_scope.target_system_ids": ("G", 'scope["target_system_ids"]', "allowlisted targets"),
    "instance_scope.action_target_bindings": ("G", 'scope["action_target_bindings"]', "action-to-target restriction"),
    "instance_scope.scope_constraints": ("G", 'scope["scope_constraints"]', "named scope dimensions"),
    "structural_budget.capacity": ("G", 'structural["capacity"]', "finite structural capacity"),
    "resource_limits[].resource_id": ("G", 'limit["resource_id"]', "catalogue resource identity"),
    "resource_limits[].max_per_intent": ("G", 'limit["max_per_intent"]', "per-intent limit"),
    "resource_limits[].max_committed_per_window": ("G", 'limit["max_committed_per_window"]', "window commitment limit"),
    "resource_limits[].window_seconds": ("G", 'limit["window_seconds"]', "window length"),
    "governance.approval_owner_id": ("G", 'self.declaration["governance"]["approval_owner_id"]', "grant approval actor"),
    "governance.authority_issuer_id": ("G", 'self.declaration["governance"]["authority_issuer_id"]', "grant issuer actor"),
    "governance.revision_authority_ids": ("G", 'governance["revision_authority_ids"]', "grant revokers; no revision permission"),
    "governance.no_live_gate_override": ("B", 'governance["no_live_gate_override"] is not True', "constant true; no external governance proof"),
    "interfaces.off_limits_system_ids": ("G", 'interfaces["off_limits_system_ids"]', "target overlap refusal"),
    "mapping_witness_binding.witness_id": ("B", 'witness_binding["witness_id"] != profile["mapping_witness"]["witness_id"]', "mapping witness identity binding"),
    "mapping_witness_binding.witness_hash": ("B", 'witness_binding["witness_hash"]', "mapping witness digest binding"),
}

# Removed from the candidate declaration schema and its three supplied
# declarations. Their previous validation was syntax-only; there was no
# corresponding live issuer, environment, selector, service, provenance,
# predecessor-chain, or evidence-content check in the engine.
REMOVED_DECLARATION = (
    "predecessor_declaration_hash",
    "connector.workload_identity_issuer",
    "connector.environment_ids",
    "structural_budget.selector_id",
    "structural_budget.unit",
    "structural_budget.provenance",
    "governance.profile_owner_id",
    "governance.declaration_owner_id",
    "governance.change_process_ref",
    "interfaces.governance_service_id",
    "interfaces.operator_service_id",
    "interfaces.executor_service_id",
    "interfaces.architect_store_id",
    "interfaces.observer_projection_id",
    "evidence_refs[].evidence_type",
    "evidence_refs[].ref",
    "evidence_refs[].sha256",
)

RETIRED_FORMAT_REFUSALS = (
    "DECLARATION_EVIDENCE",
    "ENVIRONMENT_IDS",
    "INTERFACE_ID",
    "INTERFACE_ROLE_OVERLAP",
    "PREDECESSOR_HASH",
    "SELECTOR_ID",
    "STRUCTURAL_PROVENANCE",
    "STRUCTURAL_UNIT",
    "WORKLOAD_IDENTITY_ISSUER",
)

REGISTRY = (
    "schema_version", "connector_id", "profile_id", "profile_version",
    "profile_hash", "declaration_id", "declaration_version",
    "declaration_hash", "core_anchor.core_version", "core_anchor.doi",
    "core_anchor.sha256", "status", "activated_at", "revoked",
    "ledger_head_hash", "latest_receipt_root",
)


def _resolve(schema: dict, node: dict) -> dict:
    while "$ref" in node:
        ref = node["$ref"]
        if not ref.startswith("#/$defs/"):
            raise ValueError(f"unsupported schema reference: {ref}")
        node = schema["$defs"][ref.removeprefix("#/$defs/")]
    return node


def schema_leaves(schema: dict) -> tuple[str, ...]:
    """Return fixed leaves; variable-key maps count as one declared field."""
    leaves: list[str] = []

    def walk(node: dict, path: str) -> None:
        node = _resolve(schema, node)
        props = node.get("properties")
        if isinstance(props, dict):
            for key, child in props.items():
                walk(child, f"{path}.{key}" if path else key)
            return
        if node.get("type") == "array":
            item = _resolve(schema, node.get("items", {}))
            if isinstance(item.get("properties"), dict):
                walk(item, path + "[]")
                return
        leaves.append(path)

    walk(schema, "")
    return tuple(leaves)


def _source_without_comments(source: str) -> str:
    """Keep offsets and lines while removing only Python comment tokens."""
    lines = source.splitlines(keepends=True)
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT:
            row, start = token.start
            _, end = token.end
            line = lines[row - 1]
            lines[row - 1] = line[:start] + " " * (end - start) + line[end:]
    return "".join(lines)


def _status_states(source: str, method_name: str, record_name: str) -> tuple[str, ...]:
    """Read the executable status membership test of one named method."""
    tree = ast.parse(source)
    methods = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == method_name
    ]
    if len(methods) != 1:
        return ()
    found = []
    for node in ast.walk(methods[0]):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1:
            continue
        if not isinstance(node.ops[0], ast.NotIn) or len(node.comparators) != 1:
            continue
        left, right = node.left, node.comparators[0]
        if not (isinstance(left, ast.Subscript)
                and isinstance(left.value, ast.Name)
                and left.value.id == record_name
                and isinstance(left.slice, ast.Constant)
                and left.slice.value == "status"
                and isinstance(right, ast.Set)):
            continue
        values = tuple(
            item.value for item in right.elts
            if isinstance(item, ast.Constant) and isinstance(item.value, str)
        )
        if len(values) != len(right.elts):
            return ()
        found.append(values)
    return found[0] if len(found) == 1 else ()


def line_of(source: str, anchor: str, start: int = 0) -> int | None:
    pos = source.find(anchor, start)
    return None if pos < 0 else source.count("\n", 0, pos) + 1


def audit(root: Path = ROOT, *, declaration_schema: dict | None = None,
          registry_schema: dict | None = None,
          engine_source: str | None = None) -> list[str]:
    """Return ordered errors. Unknown schema fields always win first-red."""
    if declaration_schema is None:
        declaration_schema = json.loads((root / DECLARATION_SCHEMA).read_text(encoding="utf-8"))
    if registry_schema is None:
        registry_schema = json.loads((root / REGISTRY_SCHEMA).read_text(encoding="utf-8"))
    if engine_source is None:
        engine_source = (root / ENGINE).read_text(encoding="utf-8")
    engine_code = _source_without_comments(engine_source)
    declaration_leaves = schema_leaves(declaration_schema)
    registry_leaves = schema_leaves(registry_schema)
    for name in declaration_leaves:
        if name not in DECLARATION:
            return [f"UNCLASSIFIED_DECLARATION_FIELD:{name}"]
    for name in registry_leaves:
        if name not in REGISTRY:
            return [f"UNCLASSIFIED_REGISTRY_FIELD:{name}"]
    errors: list[str] = []
    for name in DECLARATION:
        if name not in declaration_leaves:
            errors.append(f"MISSING_DECLARATION_FIELD:{name}")
    for name in REGISTRY:
        if name not in registry_leaves:
            errors.append(f"MISSING_REGISTRY_FIELD:{name}")
    if tuple(registry_schema["properties"]["status"].get("enum", ())) != ("DRAFT", "ACTIVE"):
        errors.append("REGISTRY_STATUS_OUTSIDE_ENGINE_STATES")
    start = engine_code.find("def validate_declaration(")
    end = engine_code.find("\nclass SystemClock:", start)
    if start < 0 or end < 0:
        errors.append("DECLARATION_VALIDATOR_NOT_FOUND")
        declaration_block = ""
    else:
        declaration_block = engine_code[start:end]
    for name, (_, anchor, _) in DECLARATION.items():
        block = engine_code if anchor.startswith("self.declaration[") else declaration_block
        if anchor not in block:
            errors.append(f"MISSING_ENGINE_CONSUMER:{name}")
    if ("_validate_core_anchor(declaration[\"core_anchor\"])" in declaration_block
            and "dict(anchor) != CORE_ANCHOR" not in engine_code):
        errors.append("CORE_ANCHOR_BINDING_MISSING")
    registry_start = engine_code.find("    def registry_record(")
    registry_end = engine_code.find("    def ledger_head(", registry_start)
    registry_block = engine_code[registry_start:registry_end] if registry_start >= 0 and registry_end > registry_start else ""
    if "self._assert_registry_projection(record)" not in registry_block:
        errors.append("REGISTRY_PROJECTION_CHECK_MISSING")
    for name in REGISTRY:
        leaf = name.rsplit(".", 1)[-1]
        if f'"{leaf}":' not in registry_block:
            errors.append(f"MISSING_REGISTRY_PROJECTION:{name}")
    if (_status_states(engine_code, "_assert_registry_projection", "record") != ("DRAFT", "ACTIVE")
            or _status_states(engine_code, "_restore_state", "state") != ("DRAFT", "ACTIVE")):
        errors.append("REGISTRY_ENGINE_STATUS_MISMATCH")
    return errors


def render_document(root: Path = ROOT) -> str:
    engine = (root / ENGINE).read_text(encoding="utf-8")
    lines = [
        "# Declaration fields",
        "",
        "The schema's fixed declaration fields are classified below. G means a runtime",
        "refusal or budget; B means validated identity, integrity or projection binding.",
        "A required-key name or whole-object hash alone does not count as a consumer.",
        "Variable-key maps count at their declared parent field.",
        "",
        "| Declaration field | Decision | Engine reference | Limit |",
        "|---|---|---|---|",
    ]
    for name, (kind, anchor, limit) in DECLARATION.items():
        number = line_of(engine, anchor)
        reference = f"`{ENGINE}:{number}`" if number is not None else "MISSING"
        lines.append(f"| `{name}` | retain {kind} | {reference} | {limit} |")
    lines.extend([
        "", "The following 17 former declaration leaves are removed from the candidate",
        "schema and supplied declarations. Their former checks established format only,",
        "not the external property suggested by their names:", "",
    ])
    lines.extend(f"- `{name}`" for name in REMOVED_DECLARATION)
    lines.extend([
        "", "The candidate intentionally retires the following nine format-only",
        "engine refusal codes together with those fields. These retirements are recorded",
        "separately from runtime wire observations and the remaining engine witness debt:", "",
    ])
    lines.extend(f"- `{code}`" for code in RETIRED_FORMAT_REFUSALS)
    lines.extend([
        "", "The baseline also preserves a historical wire-observation gap for",
        "`EXECUTION_BINDING_MISMATCH`. This code still has an engine assertion; that",
        "does not establish that it crossed the adapter's translation path. The engine",
        "guards `OBSERVER_EXPORT_ENGINE` and `OBSERVER_EXPORT_SIGNER` remain present but",
        "unwitnessed by the recorded suites. They are retained as witness debt, not",
        "retired codes or a claim of complete coverage.",
        "", "Schema-invalid POST bodies are refused as `BODY_SCHEMA` with the field path",
        "before domain validation. The recorded runtime therefore no longer constructs",
        "45 former wire refusals from those invalid bodies. This ingress policy change",
        "does not retire the published engine vocabulary or replace its domain guards.",
        "The baseline retains the earlier loss record and its original explanation",
        "alongside this separately stated wire-observation change.",
        "", "The registry retains 16 fixed fields. Its `status` domain is `DRAFT` and",
        "`ACTIVE`, the only states created and restored by the engine. `revoked` reports",
        "whether any grant was revoked; it is not a connector-level `REVOKED` state.",
        "", "| Registry field | Decision | Engine reference |",
        "|---|---|---|",
    ])
    for name in REGISTRY:
        leaf = name.rsplit(".", 1)[-1]
        number = line_of(engine, f'"{leaf}":', engine.find("    def registry_record("))
        reference = f"`{ENGINE}:{number}`" if number is not None else "MISSING"
        lines.append(f"| `{name}` | retain projection | {reference} |")
    lines.extend([
        "", "The inventory check rejects a new unclassified schema leaf before checking",
        "source anchors. A source anchor proves that a field reaches a named code path;",
        "behavioral suites must separately establish refusal and binding semantics.",
        "It does not attest external issuer identity, a trusted clock, service existence,",
        "evidence dereference, or authorization to revise a declaration.", "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--write-document", action="store_true")
    args = parser.parse_args()
    errors = audit(args.root)
    if errors:
        for error in errors:
            print(error)
        return 1
    if args.write_document:
        (args.root / "DECLARATION-FIELDS.md").write_text(
            render_document(args.root), encoding="utf-8", newline="\n"
        )
    print("DECLARATION_FIELDS_OK: 31 declaration fields; 16 registry fields")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
