# Declaration fields

The schema's fixed declaration fields are classified below. G means a runtime
refusal or budget; B means validated identity, integrity or projection binding.
A required-key name or whole-object hash alone does not count as a consumer.
Variable-key maps count at their declared parent field.

| Declaration field | Decision | Engine reference | Limit |
|---|---|---|---|
| `schema_version` | retain B | `sdk/python/nc25_universal_ledger.py:1057` | fixed wire version |
| `declaration_id` | retain B | `sdk/python/nc25_universal_ledger.py:1059` | validated declaration identity |
| `declaration_version` | retain B | `sdk/python/nc25_universal_ledger.py:1060` | version syntax and binding; no revision budget |
| `created_at` | retain B | `sdk/python/nc25_universal_ledger.py:1061` | ordering only; not a trusted clock |
| `effective_from` | retain G | `sdk/python/nc25_universal_ledger.py:1062` | effective window |
| `expires_at` | retain G | `sdk/python/nc25_universal_ledger.py:1063` | expiry window |
| `core_anchor.file_name` | retain B | `sdk/python/nc25_universal_ledger.py:1066` | whole anchor equals fixed core tuple |
| `core_anchor.core_version` | retain B | `sdk/python/nc25_universal_ledger.py:1066` | whole anchor equals fixed core tuple |
| `core_anchor.doi` | retain B | `sdk/python/nc25_universal_ledger.py:1066` | whole anchor equals fixed core tuple |
| `core_anchor.sha256` | retain B | `sdk/python/nc25_universal_ledger.py:1066` | whole anchor equals fixed core tuple |
| `profile_binding.profile_id` | retain B | `sdk/python/nc25_universal_ledger.py:1076` | profile identity binding |
| `profile_binding.profile_version` | retain B | `sdk/python/nc25_universal_ledger.py:1078` | profile version binding |
| `profile_binding.profile_hash` | retain B | `sdk/python/nc25_universal_ledger.py:1080` | profile byte digest binding |
| `connector.connector_id` | retain G | `sdk/python/nc25_universal_ledger.py:1089` | connector identity and routing |
| `instance_scope.action_ids` | retain G | `sdk/python/nc25_universal_ledger.py:1107` | allowlisted actions |
| `instance_scope.effect_class_ids` | retain G | `sdk/python/nc25_universal_ledger.py:1108` | allowlisted effect classes |
| `instance_scope.target_system_ids` | retain G | `sdk/python/nc25_universal_ledger.py:1109` | allowlisted targets |
| `instance_scope.action_target_bindings` | retain G | `sdk/python/nc25_universal_ledger.py:1113` | action-to-target restriction |
| `instance_scope.scope_constraints` | retain G | `sdk/python/nc25_universal_ledger.py:1129` | named scope dimensions |
| `structural_budget.capacity` | retain G | `sdk/python/nc25_universal_ledger.py:1152` | finite structural capacity |
| `resource_limits[].resource_id` | retain G | `sdk/python/nc25_universal_ledger.py:1169` | catalogue resource identity |
| `resource_limits[].max_per_intent` | retain G | `sdk/python/nc25_universal_ledger.py:1173` | per-intent limit |
| `resource_limits[].max_committed_per_window` | retain G | `sdk/python/nc25_universal_ledger.py:1177` | window commitment limit |
| `resource_limits[].window_seconds` | retain G | `sdk/python/nc25_universal_ledger.py:1181` | window length |
| `governance.approval_owner_id` | retain G | `sdk/python/nc25_universal_ledger.py:2668` | declaration activation actor; also a permitted grant revoker |
| `governance.authority_issuer_id` | retain G | `sdk/python/nc25_universal_ledger.py:2728` | grant issuer actor |
| `governance.revision_authority_ids` | retain G | `sdk/python/nc25_universal_ledger.py:1214` | grant revokers; no revision permission |
| `governance.no_live_gate_override` | retain B | `sdk/python/nc25_universal_ledger.py:1215` | constant true; no external governance proof |
| `interfaces.off_limits_system_ids` | retain G | `sdk/python/nc25_universal_ledger.py:1228` | target overlap refusal |
| `mapping_witness_binding.witness_id` | retain B | `sdk/python/nc25_universal_ledger.py:1245` | mapping witness identity binding |
| `mapping_witness_binding.witness_hash` | retain B | `sdk/python/nc25_universal_ledger.py:1248` | mapping witness digest binding |

The following 17 former declaration leaves are removed from the candidate
schema and supplied declarations. Their former checks established format only,
not the external property suggested by their names:

- `predecessor_declaration_hash`
- `connector.workload_identity_issuer`
- `connector.environment_ids`
- `structural_budget.selector_id`
- `structural_budget.unit`
- `structural_budget.provenance`
- `governance.profile_owner_id`
- `governance.declaration_owner_id`
- `governance.change_process_ref`
- `interfaces.governance_service_id`
- `interfaces.operator_service_id`
- `interfaces.executor_service_id`
- `interfaces.architect_store_id`
- `interfaces.observer_projection_id`
- `evidence_refs[].evidence_type`
- `evidence_refs[].ref`
- `evidence_refs[].sha256`

The candidate intentionally retires the following nine format-only
engine refusal codes together with those fields. These retirements are recorded
separately from runtime wire observations and the remaining engine witness debt:

- `DECLARATION_EVIDENCE`
- `ENVIRONMENT_IDS`
- `INTERFACE_ID`
- `INTERFACE_ROLE_OVERLAP`
- `PREDECESSOR_HASH`
- `SELECTOR_ID`
- `STRUCTURAL_PROVENANCE`
- `STRUCTURAL_UNIT`
- `WORKLOAD_IDENTITY_ISSUER`

The baseline also preserves a historical wire-observation gap for
`EXECUTION_BINDING_MISMATCH`. This code still has an engine assertion; that
does not establish that it crossed the adapter's translation path. The engine
guards `OBSERVER_EXPORT_ENGINE` and `OBSERVER_EXPORT_SIGNER` remain present but
unwitnessed by the recorded suites. They are retained as witness debt, not
retired codes or a claim of complete coverage.

Schema-invalid POST bodies are refused as `BODY_SCHEMA` with the field path
before domain validation. The recorded runtime therefore no longer constructs
45 former wire refusals from those invalid bodies. This ingress policy change
does not retire the published engine vocabulary or replace its domain guards.
The baseline retains the earlier loss record and its original explanation
alongside this separately stated wire-observation change.

The registry retains 16 fixed fields. Its `status` domain is `DRAFT` and
`ACTIVE`, the only states created and restored by the engine. `revoked` reports
whether any grant was revoked; it is not a connector-level `REVOKED` state.

| Registry field | Decision | Engine reference |
|---|---|---|
| `schema_version` | retain projection | `sdk/python/nc25_universal_ledger.py:4101` |
| `connector_id` | retain projection | `sdk/python/nc25_universal_ledger.py:4102` |
| `profile_id` | retain projection | `sdk/python/nc25_universal_ledger.py:4103` |
| `profile_version` | retain projection | `sdk/python/nc25_universal_ledger.py:4104` |
| `profile_hash` | retain projection | `sdk/python/nc25_universal_ledger.py:4105` |
| `declaration_id` | retain projection | `sdk/python/nc25_universal_ledger.py:4106` |
| `declaration_version` | retain projection | `sdk/python/nc25_universal_ledger.py:4107` |
| `declaration_hash` | retain projection | `sdk/python/nc25_universal_ledger.py:4108` |
| `core_anchor.core_version` | retain projection | `sdk/python/nc25_universal_ledger.py:4110` |
| `core_anchor.doi` | retain projection | `sdk/python/nc25_universal_ledger.py:4111` |
| `core_anchor.sha256` | retain projection | `sdk/python/nc25_universal_ledger.py:4112` |
| `status` | retain projection | `sdk/python/nc25_universal_ledger.py:4114` |
| `activated_at` | retain projection | `sdk/python/nc25_universal_ledger.py:4115` |
| `revoked` | retain projection | `sdk/python/nc25_universal_ledger.py:4116` |
| `ledger_head_hash` | retain projection | `sdk/python/nc25_universal_ledger.py:4117` |
| `latest_receipt_root` | retain projection | `sdk/python/nc25_universal_ledger.py:4118` |

The inventory check rejects a new unclassified schema leaf before checking
source anchors. A source anchor proves that a field reaches a named code path;
behavioral suites must separately establish refusal and binding semantics.
It does not attest external issuer identity, a trusted clock, service existence,
evidence dereference, or authorization to revise a declaration.
