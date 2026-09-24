from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "tools"))
import failure_surface  # noqa: E402
sys.path.pop(0)


EXPECTED_PROFILE_HASH = (
    "D0467762926BF45A856431BF8038044852681456D1FBBAEEEBC80A4EC1674C6F"
)
EXPECTED_DECLARATION_HASH = (
    "54E6C072FA6D20F2F4E32030E26F124C339BEE10F9307B6FA2D35EDF33DFC78E"
)
STANDALONE_PACKAGE_CHECK_IDS = frozenset(
    {
        "required_files", "no_build_artefacts", "gitignore_python_caches",
        "dependency_lock", "package_manifest_shape",
        "package_manifest_coverage", "package_manifest_hashes",
        "collectible_script_suites", "documented_acceptance_route",
        "acceptance_runner_bytecode_guard", "synthetic_fixture_clock_documented",
        "profile_semantics",
        "declaration_semantics", "second_profile_witness_hash",
        "second_profile_hash", "second_runtime_binding",
        "otcs_profile_witness_hash", "otcs_profile_hash",
        "otcs_runtime_binding", "otcs_bridge_boundary",
        "witness_evidence_present", "witness_evidence_sha256", "profile_hash",
        "declaration_hash", "runtime_profile_binding",
        "runtime_declaration_binding", "manifest_path_containment",
        "path_containment_self_test", "crosswalk_core_binding",
        "crosswalk_entry_count", "crosswalk_unique_ids", "crosswalk_line_ranges",
        "schema_file_count", "schema_dialect", "schema_identity",
        "runtime_execution_permit_bound", "domain_neutral_core", "openapi_version",
        "openapi_routes", "openapi_role_scopes",
        # Counts declarations without pairing them with individual routes;
        # this is not a per-route mTLS proof.
        "openapi_mtls_declaration_floor",
        "runtime_allow", "operator_projection_exact", "runtime_commit_debits",
        "ledger_chain", "registry_projection_exact", "registry_rejects_nested_forbidden_data",
        "logical_quote_punctuation", "docx_document_part", "docx_title",
        "docx_projection_source_bound", "docx_acceptance_counts_current",
        "docx_header_version_matches_title", "package_version_consistency",
        "citation_metadata_contract",
        "acceptance_report_gate_rows_current",
        "failure_surface_static_ratchet", "package_counter_literals_current",
        "acceptance_report_ratchet_figures_current",
        "openapi_error_codes_match_closed_world",
        "acceptance_report_bound_to_bytes",
    }
)
EXTERNAL_SOURCE_CHECK_IDS = frozenset(
    {"external_source_root", "core_present", "core_sha256", "core_bytes", "core_lines"}
)
ALL_PACKAGE_CHECK_IDS = STANDALONE_PACKAGE_CHECK_IDS | EXTERNAL_SOURCE_CHECK_IDS


class Checks:
    """Every declared check reports exactly one verdict, whatever else fails.

    `require` used to raise on the first failure, which meant one failing check
    took every later check with it: a single stray `.pyc` from an ordinary test
    run silenced the rest and reddened under a name unrelated to the work in
    hand. Moving that one scan to the end fixed that one plant and left the
    class open, because any other unlisted file did the same thing.

    The property this class now holds is the one that can be held: not "no check
    silences another" - a check whose precondition an earlier failure destroyed
    has nothing true to say - but "no check is ever missing from the record".
    A check that cannot run reports BLOCKED and names what blocked it, so the
    verdict set is invariant and reading it tells an operator exactly which
    checks failed rather than only which one failed first.
    """

    def __init__(self) -> None:
        self.verdicts: dict[str, str] = {}

    def _record(self, label: str, kind: str, reason: str = "") -> None:
        if label not in ALL_PACKAGE_CHECK_IDS:
            raise AssertionError(f"UNDECLARED_PACKAGE_CHECK: {label}")
        if label in self.verdicts:
            raise AssertionError(f"DUPLICATE_PACKAGE_CHECK: {label}")
        self.verdicts[label] = kind
        print(f"{kind} {label}: {reason}" if reason else f"{kind} {label}")

    @property
    def passed_ids(self) -> set[str]:
        return {label for label, kind in self.verdicts.items() if kind == "PASS"}

    def require(self, condition: bool, label: str) -> None:
        self._record(label, "PASS" if condition else "FAIL")

    def passed(self, label: str) -> None:
        self._record(label, "PASS")

    def blocked(self, label: str, reason: str) -> None:
        self._record(label, "BLOCKED", reason)

    def finish(self, external_sources_checked: bool) -> None:
        expected = STANDALONE_PACKAGE_CHECK_IDS
        if external_sources_checked:
            expected = expected | EXTERNAL_SOURCE_CHECK_IDS
        missing = expected - set(self.verdicts)
        extra = set(self.verdicts) - expected
        failed = sorted(
            label
            for label, kind in self.verdicts.items()
            if kind != "PASS" and label in expected
        )
        if missing or extra:
            # A declared id with no verdict is itself a failure. Without this
            # clause the invariant would be hoped for rather than held: a check
            # that vanished would simply not be counted.
            raise AssertionError(
                f"PACKAGE_CHECK_MANIFEST missing={sorted(missing)} extra={sorted(extra)}"
            )
        if failed:
            raise AssertionError(f"PACKAGE_CHECKS_FAILED {failed}")
        print(f"PACKAGE_CHECKS={len(self.passed_ids)}/{len(expected)} PASS")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def core_deposit_availability_claims(text: str) -> list[str]:
    """Flag affirmative retrieval wording in the package's core instructions.

    This is a lexical tripwire, not a general natural-language proof: it covers
    retrieval/availability verbs with DOI/deposit source phrases, including
    the parenthetical DOI instruction form. Extend the fixtures when adding
    new instruction forms. Clause-local negation must not excuse another claim.
    """
    normalized = " ".join(text.replace("`", "").replace("\u2019", "'").split())
    clauses = re.split(r"[.!?;]\s+|\b(?:but|however)\b", normalized, flags=re.I)
    action = re.compile(
        r"\b(?:obtain(?:s|ed|ing)?|retriev(?:e|es|ed|ing)|download(?:s|ed|ing)?|"
        r"fetch(?:es|ed|ing)?|available|suppl(?:y|ies|ied|ying))\b", re.I
    )
    source = re.compile(
        r"\b(?:from|via|by|at|under|through|using)\s+"
        r"(?:(?:the|this|that|its|our|public|OSF)\s+)*(?:DOI|deposit)\b"
        r"|\(\s*DOI\b", re.I
    )
    negation = re.compile(
        r"\b(?:not|never|cannot|can't|isn't|aren't|wasn't|weren't|don't|doesn't)\s+"
        r"(?:(?:be|been|being|currently|publicly|directly|readily|now|ever|yet|to)\s+)*$",
        re.I,
    )
    claims = []
    for clause in clauses:
        actions = list(action.finditer(clause))
        for index, match in enumerate(actions):
            end = actions[index + 1].start() if index + 1 < len(actions) else len(clause)
            tail = clause[match.end():end]
            if source.search(tail) and not negation.search(clause[:match.start()]):
                claims.append(clause.strip())
                break
    return claims


def safe_source_path(base: Path, relative_path: str) -> Path:
    if not isinstance(relative_path, str) or not relative_path.strip():
        raise AssertionError("manifest_path_containment")
    relative = Path(relative_path)
    if relative.is_absolute():
        raise AssertionError("manifest_path_containment")
    base_resolved = base.resolve()
    candidate = (base_resolved / relative).resolve()
    try:
        candidate.relative_to(base_resolved)
    except ValueError as exc:
        raise AssertionError("manifest_path_containment") from exc
    return candidate


def resolve_source_root() -> tuple[Path | None, str]:
    """Decide whether the external-source checks are in play, before running.

    Resolved once, from the environment and the tree, and used both to run the
    checks and to decide which ids a crashed run must still account for.
    Inferring the mode from which checks happened to speak - the earlier form -
    silently narrowed the declared set whenever a crash landed before the
    external checks, which is the one case the verdict invariant exists for.
    """
    configured_root = os.environ.get("NC25_SOURCES_ROOT")
    if configured_root:
        return Path(configured_root), "strict"
    auto_root = ROOT.parent.parent
    try:
        inputs = json.loads(
            (ROOT / "SOURCE-MANIFEST.json").read_text(encoding="utf-8")
        )["inputs"]
    except (OSError, ValueError, KeyError, TypeError):
        return None, "standalone"
    if external_source_tree_available(auto_root, inputs):
        return auto_root, "auto"
    return None, "standalone"


def external_source_tree_available(base: Path, inputs: list[dict]) -> bool:
    try:
        for item in inputs:
            item_path = safe_source_path(base, item["relative_path"])
            if not item_path.is_file():
                return False
    except (AssertionError, KeyError):
        return False
    return True


def execution_request(engine: UniversalConnectionLedger, result: dict, intent: dict) -> dict:
    return {
        "message_type": "execution_request",
        "permit_hash": result["permit_hash"],
        "connector_id": intent["connector_id"],
        "binding": intent["binding"],
        "state_anchor_hash": intent["state_anchor_hash"],
        "outcome": "COMMITTED",
        "downstream_receipt_hash": "9" * 64,
        "committed_at": "2026-08-01T10:00:00Z",
    }


def load_spec_counts():
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        import spec_counts
    finally:
        sys.path.pop(0)
    return spec_counts


def projection_visible_sections(projection_text: str) -> dict[str, list[str]]:
    """Parse the projection's Visible text part into member -> paragraphs.

    The projection is byte-bound to the shipped DOCX by the regression suite,
    so reading it here reads the shipped document without re-parsing the zip.
    """
    marker = "\n## Visible text\n"
    index = projection_text.find(marker)
    if index == -1:
        # An empty result fails every projection-based check loudly; a raise
        # here would surface an id outside the declared check manifest.
        return {}
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in projection_text[index + len(marker):].splitlines():
        header = re.fullmatch(r"### `([^`]+)`", line)
        if header:
            current = sections.setdefault(header.group(1), [])
            continue
        item = re.fullmatch(r"\d+\. (.*)", line)
        if item and current is not None:
            current.append(item.group(1))
    return sections


# These comparisons share one AST counter (tools/spec_counts.py) with the
# DOCX builder, so they detect a stale shipped document, not a counting
# mistake: both sides of every comparison run the same counting code.
def docx_acceptance_count_mismatches(document_paragraphs: list[str]) -> list[str]:
    counts = load_spec_counts()
    clauses = {
        "contract_conformance": (
            r"(\d+) checks covering shipped artefacts, active format and length"
            r" bounds, live outputs, wire references, route table, per-route"
            r" security, and engine operations",
            counts.literal_collection_size(
                ROOT / "tests" / "test_contract_conformance.py",
                "EXPECTED_CONFORMANCE_IDS",
            ),
        ),
        "contract_regressions": (
            r"(\d+) focused tests derived from the executable suite",
            counts.test_method_count(
                ROOT / "tests" / "test_contract_regressions.py",
                "ContractRegressions",
            ),
        ),
        # Counted apart from the regressions for the same reason the report
        # names them apart: the bridge has its own acceptance step now, so a
        # summed figure would certify a suite shape that no longer exists.
        "otcs_bridge": (
            # The whole generated sentence, because the match is a fullmatch:
            # a truncated pattern cannot match the paragraph at all, so from
            # the commit that introduced this clause - the same commit that
            # introduced the sentence, already in its long form - it reported
            # `matches=0` and never once compared the count it exists to
            # compare: it was born unable to match. Its red read as a stale
            # document, which is the most expensive way for a check to fail -
            # it named a real defect elsewhere and hid its own behind it.
            r"(\d+) tests over the permit-gated append seam, including every"
            r" declared refusal code of its own vocabulary",
            counts.test_method_count(
                ROOT / "tests" / "test_otcs_bridge.py",
                "OTCSBridgeRegressions",
            ),
        ),
        "functional_behaviour": (
            r"(\d+) positive and negative state-machine tests, each run"
            r" against all three shipped profiles",
            counts.test_method_count(
                ROOT / "tests" / "test_universal_connection.py",
                "ConnectionSuite",
            ),
        ),
        "safety_mutations": (
            r"(\d+) named safety facts",
            counts.literal_collection_size(
                ROOT / "tests" / "test_safety_mutations.py",
                "EXPECTED_MUTATION_IDS",
            ),
        ),
        "semantic_contracts": (
            r"(\d+) profile, declaration, role, and input tests",
            counts.test_method_count(
                ROOT / "tests" / "test_semantic_contracts.py",
                "SemanticContractTests",
            ),
        ),
    }
    mismatches: list[str] = []
    for clause_id, (pattern, expected_count) in sorted(clauses.items()):
        matches = [
            match
            for paragraph in document_paragraphs
            if (match := re.fullmatch(pattern, paragraph)) is not None
        ]
        if len(matches) != 1:
            mismatches.append(f"{clause_id}: phrase matches={len(matches)}")
        elif int(matches[0].group(1)) != expected_count:
            mismatches.append(
                f"{clause_id}: docx={matches[0].group(1)} actual={expected_count}"
            )
    return mismatches


def docx_title_version(sections: dict[str, list[str]]) -> str | None:
    """Version value of the first title-table Version cell, or None.

    document.xml carries a second Version row (the NC2.5 core anchor), so the
    extraction is anchored to the FIRST Version paragraph and requires the
    three-component package shape immediately after it.
    """
    paragraphs = sections.get("word/document.xml", [])
    for index, paragraph in enumerate(paragraphs):
        if paragraph == "Version":
            if index + 1 < len(paragraphs) and re.fullmatch(
                r"\d+\.\d+\.\d+", paragraphs[index + 1]
            ):
                return paragraphs[index + 1]
            return None
    return None


def docx_header_version_mismatches(sections: dict[str, list[str]]) -> list[str]:
    problems: list[str] = []
    header_versions = [
        match.group(1)
        for name in sorted(sections)
        if re.fullmatch(r"word/header\d+\.xml", name)
        for paragraph in sections[name]
        for match in re.finditer(r"\bv(\d+\.\d+)\b", paragraph)
    ]
    if len(header_versions) != 1:
        problems.append(f"header version matches={len(header_versions)}")
    title_version = docx_title_version(sections)
    if title_version is None:
        problems.append("title version missing after first Version cell")
    if not problems:
        major_minor = ".".join(title_version.split(".")[:2])
        if header_versions[0] != major_minor:
            problems.append(
                f"header v{header_versions[0]} != title {title_version}"
            )
    return problems


def citation_metadata_mismatches() -> list[str]:
    """Check the package's citation name and material-specific SPDX licences.

    This is a package metadata contract, not a complete CFF schema validator.
    CFF 1.2.0 represents several licences as a list of SPDX identifiers.
    """
    import yaml

    try:
        citation = yaml.safe_load((ROOT / "CITATION.cff").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        return [f"citation unreadable: {type(exc).__name__}"]
    if not isinstance(citation, dict):
        return ["citation must be a mapping"]
    problems = []
    if citation.get("title") != "NC25OL - Navigational Cybernetics 2.5 Open Ledger":
        problems.append("citation title differs from the package name")
    licences = citation.get("license")
    if not (isinstance(licences, list) and len(licences) == 2
            and all(isinstance(value, str) for value in licences)
            and set(licences) == {"MIT", "CC-BY-4.0"}):
        problems.append("citation licences must list MIT and CC-BY-4.0 separately")
    return problems


def package_version_mismatches(sections: dict[str, list[str]]) -> list[str]:
    manifest = json.loads(
        (ROOT / "SOURCE-MANIFEST.json").read_text(encoding="utf-8")
    )
    package_version = manifest.get("package_version")
    if not isinstance(package_version, str) or not re.fullmatch(
        r"\d+\.\d+\.\d+", package_version
    ):
        return [f"SOURCE-MANIFEST package_version invalid: {package_version!r}"]
    problems: list[str] = []
    openapi_text = (
        ROOT / "protocol" / "universal-connection.openapi.yaml"
    ).read_text(encoding="utf-8")
    openapi_versions = re.findall(r"(?m)^  version: (\S+)$", openapi_text)
    if len(openapi_versions) != 1:
        problems.append(f"openapi info.version matches={len(openapi_versions)}")
    elif openapi_versions[0] != package_version:
        problems.append(
            f"openapi {openapi_versions[0]} != package {package_version}"
        )
    title_version = docx_title_version(sections)
    if title_version is None:
        problems.append("docx title version missing")
    elif title_version != package_version:
        problems.append(f"docx title {title_version} != package {package_version}")
    major_minor = ".".join(package_version.split(".")[:2])
    docx_names = sorted(path.name for path in ROOT.glob("*.docx"))
    if len(docx_names) != 1:
        problems.append(f"docx files found={len(docx_names)}")
    elif not docx_names[0].endswith(f"v{major_minor}.docx"):
        problems.append(f"docx filename does not carry v{major_minor}")
    # The report carries the FULL version, not major.minor. The second digit is
    # unused by convention, so major.minor is constant across every patch - and
    # a report compared on it satisfies the check unchanged after a patch bump,
    # which is exactly how a report generated for an earlier byte-set passed
    # here. The patch digit is the only one that moves, and it is the one that
    # identifies the bound set of file hashes, so it is the one compared.
    report_versions = re.findall(
        r"(?m)^Version: `(\d+\.\d+\.\d+)`$",
        (ROOT / "ACCEPTANCE-REPORT.md").read_text(encoding="utf-8"),
    )
    if len(report_versions) != 1:
        problems.append(f"report version matches={len(report_versions)}")
    elif report_versions[0] != package_version:
        problems.append(
            f"report version {report_versions[0]} != package {package_version}"
        )
    # The README title is the adopter's entry point; it drifted once
    # (v0.1 survived the 0.1 -> 0.2 bump), so it is ratcheted here too.
    readme_text = (ROOT / "README.md").read_text(encoding="utf-8")
    readme_titles = re.findall(
        r"(?m)^# NC25OL - Navigational Cybernetics 2\.5 Open Ledger v(\d+\.\d+)$",
        readme_text,
    )
    if len(readme_titles) != 1:
        problems.append(f"readme title matches={len(readme_titles)}")
    elif readme_titles[0] != major_minor:
        problems.append(
            f"readme title {readme_titles[0]} != package {major_minor}"
        )
    # Two more sites carry the version and nothing read them, so nothing held
    # them: citation metadata and the changelog heading. The ratchet exists
    # against exactly this drift, and these were outside it.
    citation_versions = re.findall(
        r'(?m)^version: "(\d+\.\d+\.\d+)"$',
        (ROOT / "CITATION.cff").read_text(encoding="utf-8"),
    )
    if len(citation_versions) != 1:
        problems.append(f"citation version matches={len(citation_versions)}")
    elif citation_versions[0] != package_version:
        problems.append(
            f"citation version {citation_versions[0]} != package {package_version}"
        )
    changelog_versions = re.findall(
        r"(?m)^## (\d+\.\d+\.\d+)$",
        (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"),
    )
    if not changelog_versions:
        problems.append("changelog carries no version heading")
    elif changelog_versions[0] != package_version:
        problems.append(
            f"changelog newest {changelog_versions[0]} != package {package_version}"
        )
    # Every prose mention of the spec document must carry the current
    # major.minor, or a rename strands stale references in shipped text.
    for name in ("README.md", "LICENSE"):
        text = (ROOT / name).read_text(encoding="utf-8")
        stale = [
            match
            for match in re.findall(r"Specification v(\d+\.\d+)\.docx", text)
            if match != major_minor
        ]
        if stale:
            problems.append(f"{name} stale spec mentions: {stale}")
    return problems


def acceptance_report_row_mismatches() -> list[str]:
    counts = load_spec_counts()
    report = (ROOT / "ACCEPTANCE-REPORT.md").read_text(encoding="utf-8")
    expected_rows = {
        "Functional behavior across all three reference profiles": 3
        * counts.test_method_count(
            ROOT / "tests" / "test_universal_connection.py", "ConnectionSuite"
        ),
        "Semantic contracts": counts.test_method_count(
            ROOT / "tests" / "test_semantic_contracts.py", "SemanticContractTests"
        ),
        "Named safety mutations": counts.literal_collection_size(
            ROOT / "tests" / "test_safety_mutations.py", "EXPECTED_MUTATION_IDS"
        ),
        "JSON Schema and OpenAPI conformance": counts.literal_collection_size(
            ROOT / "tests" / "test_contract_conformance.py",
            "EXPECTED_CONFORMANCE_IDS",
        ),
        # The bridge has its own acceptance step and its own gate row, so the
        # two suites are counted apart. Summing them here would refuse a
        # correctly split report. The clause above derives the whole row set
        # from the report builder and refuses a difference in either direction.
        "Contract regression cases": counts.test_method_count(
            ROOT / "tests" / "test_contract_regressions.py", "ContractRegressions"
        ),
        "OTCS bridge behaviour and refusal vocabulary": counts.test_method_count(
            ROOT / "tests" / "test_otcs_bridge.py", "OTCSBridgeRegressions"
        ),
        "Failure-surface ratchet": 1,
    }
    problems: list[str] = []
    # The row labels belong to the report builder. Until this clause the
    # verifier kept a second transcription of them and nothing held the two
    # together, so a row could vanish from the checker without any red: that
    # is precisely how the bridge row shipped unchecked for a day, and the
    # omission was found by reading rather than by a failing test. Derive the
    # builder's set and refuse a difference in either direction - a label
    # asserted here but no longer emitted is as much a defect as one emitted
    # and no longer asserted.
    #
    # What this does NOT close, said plainly because a reader will otherwise
    # assume it does: it compares MEMBERSHIP, not the association between a
    # step and its label. Exchange two labels inside the builder's mapping and
    # the value set is unchanged, so this passes while the next report writes
    # each step's result under the other step's name. Anchoring that would
    # mean transcribing the pairs somewhere - the very copy this clause exists
    # to remove - so the association is watched by reading, not by a check.
    package_integrity_label = "Package integrity checks"
    ordered_labels = counts.literal_mapping_values(
        ROOT / "tools" / "build_acceptance_report.py", "GATE_ROWS"
    )
    declared_labels = set(ordered_labels)
    asserted_labels = set(expected_rows) | {package_integrity_label}
    if asserted_labels != declared_labels:
        problems.append(
            "gate-row labels:"
            f" asserted_only={sorted(asserted_labels - declared_labels)}"
            f" declared_only={sorted(declared_labels - asserted_labels)}"
        )

    table = counts.acceptance_gate_rows(report)
    if table is None or [label for label, _ in table] != ordered_labels:
        problems.append("gate-row table population or order differs from declared rows")

    def report_row(label: str) -> tuple[int, int] | None:
        rows = [value for name, value in (table or []) if name == label]
        if len(rows) != 1:
            problems.append(f"{label}: rows={len(rows)}")
            return None
        value = re.fullmatch(r"`([0-9]+)/([0-9]+) PASS`", rows[0])
        if value is None:
            problems.append(f"{label}: result is not a PASS count")
            return None
        return int(value[1]), int(value[2])

    for label, expected in sorted(expected_rows.items()):
        row = report_row(label)
        if row is not None and (row[0] != row[1] or row[0] != expected):
            problems.append(f"{label}: report={row[0]}/{row[1]} actual={expected}")
    # The package-integrity count depends on whether the external immutable
    # core was available to the recording run, so both totals are admissible -
    # EXCEPT when the report says which run it was. A generated report always
    # declares `source mode `strict``, because the generator refuses to build
    # from anything else, and its own prose then states that the table records
    # the release configuration. Accepting the standalone total against that
    # sentence let the table contradict the paragraph three lines below it
    # while every byte-binding stayed green.
    allowed_totals = {
        len(STANDALONE_PACKAGE_CHECK_IDS),
        len(ALL_PACKAGE_CHECK_IDS),
    }
    if re.search(r"source mode `strict`", report):
        allowed_totals = {len(ALL_PACKAGE_CHECK_IDS)}
    row = report_row(package_integrity_label)
    if row is not None and (row[0] != row[1] or row[0] not in allowed_totals):
        problems.append(
            f"{package_integrity_label}: report={row[0]}/{row[1]}"
            f" allowed={sorted(allowed_totals)}"
        )
    return problems


def acceptance_report_ratchet_figures_mismatches() -> list[str]:
    baseline = json.loads(
        (ROOT / "tests" / "failure-surface-baseline.json").read_text(
            encoding="utf-8"
        )
    )
    runtime = baseline.get("runtime")
    if not isinstance(runtime, dict):
        return ["failure-surface baseline has no runtime block"]
    expected = (
        len(baseline["engine_refusal_codes"]),
        len(baseline["wire_error_codes"]),
        baseline["emission_points_all"],
        baseline["emission_points_static"],
        len(baseline["dynamic_emission_points"]),
        len(runtime["constructed_engine_codes"]),
        len(runtime["witnessed_codes"]),
        len(runtime["unwitnessed_codes"]),
        len(runtime["foreign_translated_codes"]),
        # The bridge is a third closed world and the sentence must say so, or
        # the report keeps describing a two-world ratchet that no longer runs.
        #
        # A baseline written before the third world existed has no such key,
        # and reading it with [] would raise KeyError - a crash where the
        # answer should be a named refusal. The check REPORTS the absence
        # instead, because "the recorded baseline predates this figure" and
        # "the figure disagrees" are different facts and a reader must be able
        # to tell them apart.
        len(baseline.get("bridge_refusal_codes", ())),
    )
    if "bridge_refusal_codes" not in baseline:
        return [
            "tests/failure-surface-baseline.json: no bridge_refusal_codes -"
            " the recorded baseline predates the third closed world;"
            " regenerate it before reading the report's figures"
        ]
    report = " ".join(
        (ROOT / "ACCEPTANCE-REPORT.md").read_text(encoding="utf-8").split()
    )
    # Every match, not the first. `report_row` a few lines up already refuses
    # a label that appears other than exactly once, and these two sentences
    # were the pair that did not: a correct sentence left standing earlier in
    # the file satisfies a search while the section a reader actually reaches
    # carries different numbers. A decoy is cheap; the refusal costs one line.
    matches = list(re.finditer(
        # `code[s]?` on every slot the writer agrees with `plural()`, which is
        # five of them. Until this line the reader spelled a fixed `codes` in
        # those five and accepted either form in one - and the one it accepted
        # happened to be the only figure currently equal to one. Any other
        # figure falling to one would have made the writer emit the singular
        # and this reader answer "sentence missing": a false red on a truthful
        # report. The bridge slot was the last exemption and is one no longer:
        # an exemption maintained in two files is a rule with a hole in it, so
        # every slot now reads the same way and the writer agrees all seven
        # nouns with their counts.
        r"(\d+) engine refusal code[s]? and (\d+) wire error code[s]? in the"
        r" closed world; raise and helper-emission points all=(\d+),"
        r" static=(\d+), dynamic=(\d+); (\d+) engine refusal code[s]?"
        r" constructed and (\d+) witnessed during the recorded run;"
        r" (\d+) code[s]? unwitnessed; (\d+) code[s]? re-emitted by the"
        r" translation site belonging to neither vocabulary;"
        r" and (\d+) OTCS bridge refusal code[s]? in a closed world of their own",
        report,
    ))
    if len(matches) != 1:
        return [
            "ACCEPTANCE-REPORT.md: failure-surface figures sentences="
            f"{len(matches)}, expected exactly one"
        ]
    match = matches[0]
    observed = tuple(int(group) for group in match.groups())
    if observed != expected:
        return [
            f"ACCEPTANCE-REPORT.md: figures observed={observed} expected={expected}"
        ]
    return []


def acceptance_report_binding_mismatches() -> list[str]:
    """The report names the bytes it was generated for; hold it to them.

    The digest rule lives in run_acceptance.bound_bytes and is imported, not
    restated: the writer and the reader of this fact share one definition.
    """
    from run_acceptance import bound_bytes

    manifest = json.loads(
        (ROOT / "PACKAGE-MANIFEST.json").read_text(encoding="utf-8")
    )
    expected_digest, expected_document = bound_bytes(manifest)
    report = " ".join(
        (ROOT / "ACCEPTANCE-REPORT.md").read_text(encoding="utf-8").split()
    )
    # Exactly one, for the reason the figures check states: a valid sentence
    # left standing earlier satisfies a search while the section the reader
    # reaches carries other digests.
    matches = list(re.finditer(
        r"every entry except this report, digest to `([A-F0-9]{64})`.*?"
        r"the geometry below describes has SHA-256 `([A-F0-9]{64})`",
        report,
    ))
    if len(matches) != 1:
        return [
            "ACCEPTANCE-REPORT.md: bound-bytes sentences="
            f"{len(matches)}, expected exactly one"
        ]
    match = matches[0]
    problems: list[str] = []
    if match.group(1) != expected_digest:
        problems.append(
            "ACCEPTANCE-REPORT.md: manifest digest "
            f"{match.group(1)[:12]}... != shipped {expected_digest[:12]}..."
        )
    if match.group(2) != expected_document:
        problems.append(
            "ACCEPTANCE-REPORT.md: bound document "
            f"{match.group(2)[:12]}... != shipped {expected_document[:12]}..."
        )
    return problems


def package_counter_literal_mismatches() -> list[str]:
    standalone = len(STANDALONE_PACKAGE_CHECK_IDS)
    strict = len(ALL_PACKAGE_CHECK_IDS)
    expected = {
        "README.md": [(standalone, standalone), (strict, strict)],
        "ACCEPTANCE-REPORT.md": [(standalone, standalone)],
        "tools/build_acceptance_report.py": [],
    }
    problems: list[str] = []
    for relative, expected_pairs in expected.items():
        source = (ROOT / relative).read_text(encoding="utf-8")
        observed = [
            (int(left), int(right))
            for left, right in re.findall(r"PACKAGE_CHECKS=(\d+)/(\d+)", source)
        ]
        if observed != expected_pairs:
            problems.append(
                f"{relative}: observed={observed} expected={expected_pairs}"
            )
    return problems


def _run_checks(
    checks: "Checks", source_root: Path | None, source_mode: str
) -> None:
    required_files = [
        ".gitignore",
        "README.md",
        "LICENSE",
        "SOURCE-MANIFEST.json",
        "PACKAGE-MANIFEST.json",
        "requirements-lock.txt",
        "UNIVERSAL-CONNECTION-RUNBOOK.md",
        "ACCEPTANCE-REPORT.md",
        load_spec_counts().spec_docx_name(ROOT),
        "core/nc25-core-crosswalk.json",
        "core/schemas/profile.schema.json",
        "core/schemas/connection-declaration.schema.json",
        "core/schemas/runtime-contracts.schema.json",
        "core/schemas/registry-record.schema.json",
        "protocol/universal-connection.openapi.yaml",
        "sdk/python/nc25_universal_ledger.py",
        "sdk/python/nc25_universal_adapter.py",
        "sdk/python/nc25_otcs_bridge.py",
        "profiles/PROFILE-AUTHORING-CHECKLIST.md",
        "profiles/banking/bank-profile.json",
        "profiles/banking/questionnaire-crosswalk.json",
        "profiles/document-release/reference-connection.json",
        "profiles/otcs/reference-connection.json",
        "examples/synthetic-connection-declaration.json",
        "examples/synthetic-authority-grant.json",
        "examples/synthetic-intent-allow.json",
        "examples/synthetic-evidence-bundle.json",
        "tests/test_universal_connection.py",
        "tests/test_semantic_contracts.py",
        "tests/test_safety_mutations.py",
        "tests/test_contract_conformance.py",
        "tests/run_acceptance.py",
        "tests/check_failure_surface.py",
        "tests/failure-surface-baseline.json",
        "tests/test_contract_regressions.py",
        "tests/test_otcs_bridge.py",
        "tests/verify_package.py",
        "tools/build_acceptance_report.py",
        "tools/build_review_bundle.py",
        "tools/build_docx_audit_projection.py",
        "tools/build_error_code_enum.py",
        "tools/failure_surface.py",
        "tools/build_universal_specification.py",
        "tools/build_package_manifest.py",
        "tools/spec_counts.py",
        "DOCX-AUDIT-PROJECTION.md",
    ]
    missing = [path for path in required_files if not (ROOT / path).is_file()]
    # The list is a transcription of which modules must ship, and a
    # transcription only ever closes the names already on it: another generator
    # could be added, never listed, and deleted again with this check silent.
    # So the shipped module tree is read and held to the list. Derived, not
    # transcribed - a new module under these two directories is either named
    # here or it is a finding, and no third state is reachable.
    shipped_modules = sorted(
        item.relative_to(ROOT).as_posix()
        for directory in ("tools", "tests")
        for item in (ROOT / directory).rglob("*.py")
        if "__pycache__" not in item.parts
    )
    unlisted = [path for path in shipped_modules if path not in required_files]
    checks.require(not missing and not unlisted, "required_files")

    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    checks.require(
        {"__pycache__/", "*.py[cod]", ".pytest_cache/"} <= set(gitignore),
        "gitignore_python_caches",
    )
    dependency_lock = (ROOT / "requirements-lock.txt").read_text(
        encoding="utf-8"
    ).splitlines()
    expected_lock_versions = {
        "attrs": "26.1.0",
        "cffi": "2.1.1",
        "cryptography": "50.0.1",
        "jsonschema": "4.26.0",
        "jsonschema-specifications": "2025.9.1",
        "lxml": "6.1.2",
        "pycparser": "3.0",
        "python-docx": "1.2.0",
        "pyyaml": "6.0.3",
        "referencing": "0.37.0",
        "rpds-py": "2026.6.3",
        "typing-extensions": "4.16.0",
    }
    lock_versions: dict[str, str] = {}
    lock_hash_counts: dict[str, int] = {}
    active_name: str | None = None
    lock_shape_ok = True
    for raw_line in dependency_lock:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not raw_line[:1].isspace():
            active_name = None
            if not line.endswith(chr(92)) or line.count("==") != 1:
                lock_shape_ok = False
                continue
            requirement = line[:-1].strip()
            name, version = requirement.split("==", 1)
            normalized = name.lower().replace("_", "-")
            if not normalized or not version or normalized in lock_versions:
                lock_shape_ok = False
                continue
            lock_versions[normalized] = version
            lock_hash_counts[normalized] = 0
            active_name = normalized
            continue
        hash_value = line.rstrip(chr(92)).strip()
        prefix = "--hash=sha256:"
        if active_name is None or not hash_value.startswith(prefix):
            lock_shape_ok = False
            continue
        digest = hash_value[len(prefix) :]
        if len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            lock_shape_ok = False
            continue
        lock_hash_counts[active_name] += 1
    checks.require(
        lock_shape_ok
        and lock_versions == expected_lock_versions
        and all(lock_hash_counts.get(name, 0) > 0 for name in lock_versions),
        "dependency_lock",
    )
    package_manifest = json.loads(
        (ROOT / "PACKAGE-MANIFEST.json").read_text(encoding="utf-8")
    )
    package_entries = package_manifest.get("files", [])
    package_entry_paths = [entry.get("path") for entry in package_entries]
    checks.require(
        set(package_manifest)
        == {"manifest_version", "hash_algorithm", "self_exclusion", "files"}
        and package_manifest["manifest_version"] == "1.0.0"
        and package_manifest["hash_algorithm"] == "SHA-256"
        and all(
            set(entry) == {"path", "byte_length", "sha256"}
            and isinstance(entry["path"], str)
            and isinstance(entry["byte_length"], int)
            and re.fullmatch(r"[A-F0-9]{64}", entry["sha256"])
            for entry in package_entries
        )
        and len(package_entry_paths) == len(set(package_entry_paths)),
        "package_manifest_shape",
    )
    # Mirrors tools/build_package_manifest.py exactly, and the asymmetry is the
    # point: build output is excluded at any depth because that is where it
    # appears, while the repository directory is excluded only at the root
    # because that is the only place it belongs. Matching `.git` at any depth
    # left a hole with no reporter at all - `git status` treats a nested
    # repository directory as a foreign boundary, so a file under one was
    # invisible here, invisible in the manifest, and invisible to git.
    excluded_parts = {"__pycache__", ".pytest_cache"}
    repository_directory = ".git"
    excluded_suffixes = {".pyc", ".pyo", ".bak", ".tmp", ".orig", ".rej"}
    actual_package_files = {
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if path.is_file()
        and path.relative_to(ROOT).as_posix() != "PACKAGE-MANIFEST.json"
        and path.relative_to(ROOT).parts[:1] != (repository_directory,)
        and not (set(path.relative_to(ROOT).parts) & excluded_parts)
        and path.suffix.lower() not in excluded_suffixes
    }
    checks.require(
        set(package_entry_paths) == actual_package_files
        and load_spec_counts().spec_docx_name(ROOT) in package_entry_paths,
        "package_manifest_coverage",
    )
    package_hash_failures = []
    for entry in package_entries:
        package_path = safe_source_path(ROOT, entry["path"])
        if (
            not package_path.is_file()
            or package_path.stat().st_size != entry["byte_length"]
            or file_sha256(package_path).upper() != entry["sha256"]
        ):
            package_hash_failures.append(entry["path"])
    checks.require(not package_hash_failures, "package_manifest_hashes")
    safety_source = (ROOT / "tests" / "test_safety_mutations.py").read_text(encoding="utf-8")
    conformance_source = (ROOT / "tests" / "test_contract_conformance.py").read_text(encoding="utf-8")
    checks.require(
        "def test_safety_mutation_suite()" in safety_source
        and "def test_contract_conformance_suite()" in conformance_source,
        "collectible_script_suites",
    )
    runbook = (ROOT / "UNIVERSAL-CONNECTION-RUNBOOK.md").read_text(encoding="utf-8")
    # Check reader-facing text, not source-code fixtures containing bad examples.
    availability_claims = [
        f"{relative}: {claim}"
        for relative in sorted(package_entry_paths)
        if relative.endswith(".md") or relative == "LICENSE"
        for claim in core_deposit_availability_claims(
            safe_source_path(ROOT, relative).read_text(encoding="utf-8")
        )
    ]
    for claim in availability_claims:
        print(f"CORE_DEPOSIT_AVAILABILITY {claim}")
    checks.require(
        "python -B tests/run_acceptance.py" in runbook
        and re.search(r"(?m)^python tests/", runbook) is None
        and not availability_claims,
        "documented_acceptance_route",
    )
    runner_source = (ROOT / "tests" / "run_acceptance.py").read_text(encoding="utf-8")
    checks.require(
        'command = [sys.executable, "-B", str(ROOT / relative_path)]' in runner_source
        and 'environment["PYTHONDONTWRITEBYTECODE"] = "1"' in runner_source,
        "acceptance_runner_bytecode_guard",
    )
    checks.require(
        "FixedClock(datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc))"
        in (ROOT / "README.md").read_text(encoding="utf-8"),
        "synthetic_fixture_clock_documented",
    )

    sys.path.insert(0, str(ROOT / "sdk" / "python"))
    from nc25_universal_ledger import (  # noqa: E402
        ContractViolation,
        FixedClock,
        IntegrityViolation,
        UniversalConnectionLedger,
        bind_fixture,
        load_json,
        sha256_hex,
        validate_declaration,
        validate_profile,
    )
    from nc25_otcs_bridge import (  # noqa: E402
        OTCSAppendOperation,
        OTCSBridgeError,
        OTCSReceiptRef,
        OTCS_HEAD_EVIDENCE_TYPE,
        OTCS_LEGAL_EVIDENCE_TYPES,
    )
    # keep import path temporary to avoid side effects in subsequent imports.
    sys.path.pop(0)

    manifest = load_json(ROOT / "SOURCE-MANIFEST.json")
    profile = load_json(ROOT / "profiles" / "banking" / "bank-profile.json")
    declaration = load_json(
        ROOT / "examples" / "synthetic-connection-declaration.json"
    )
    grant = load_json(ROOT / "examples" / "synthetic-authority-grant.json")
    intent = load_json(ROOT / "examples" / "synthetic-intent-allow.json")
    evidence = load_json(ROOT / "examples" / "synthetic-evidence-bundle.json")
    crosswalk = load_json(ROOT / "core" / "nc25-core-crosswalk.json")

    try:
        validate_profile(profile)
    except (ContractViolation, IntegrityViolation) as exc:
        raise AssertionError("profile_semantics") from exc
    checks.passed("profile_semantics")
    try:
        validate_declaration(declaration, profile)
    except (ContractViolation, IntegrityViolation) as exc:
        raise AssertionError("declaration_semantics") from exc
    checks.passed("declaration_semantics")
    second = load_json(
        ROOT / "profiles" / "document-release" / "reference-connection.json"
    )
    second_witness = dict(second["profile"]["mapping_witness"])
    declared_witness = second_witness.pop("witness_hash")
    checks.require(
        sha256_hex(second_witness) == declared_witness,
        "second_profile_witness_hash",
    )
    second_profile_hash = sha256_hex(second["profile"])
    second_declaration_hash = sha256_hex(second["declaration"])
    checks.require(
        second["declaration"]["profile_binding"]["profile_hash"]
        == second_profile_hash,
        "second_profile_hash",
    )
    checks.require(
        all(
            second[key]["binding"]["profile_hash"] == second_profile_hash
            and second[key]["binding"]["declaration_hash"] == second_declaration_hash
            for key in ("grant", "intent")
        ),
        "second_runtime_binding",
    )

    otcs = load_json(
        ROOT / "profiles" / "otcs" / "reference-connection.json"
    )
    otcs_witness = dict(otcs["profile"]["mapping_witness"])
    otcs_declared_witness = otcs_witness.pop("witness_hash")
    checks.require(
        sha256_hex(otcs_witness) == otcs_declared_witness,
        "otcs_profile_witness_hash",
    )
    otcs_profile_hash = sha256_hex(otcs["profile"])
    otcs_declaration_hash = sha256_hex(otcs["declaration"])
    checks.require(
        otcs["declaration"]["profile_binding"]["profile_hash"]
        == otcs_profile_hash,
        "otcs_profile_hash",
    )
    checks.require(
        all(
            otcs[key]["binding"]["profile_hash"] == otcs_profile_hash
            and otcs[key]["binding"]["declaration_hash"]
            == otcs_declaration_hash
            for key in ("grant", "intent")
        ),
        "otcs_runtime_binding",
    )
    try:
        validate_profile(otcs["profile"])
        validate_declaration(otcs["declaration"], otcs["profile"])
        otcs_operation = OTCSAppendOperation.from_mapping(
            otcs["bridge_operation"]
        )
        otcs_receipt = OTCSReceiptRef.from_mapping(
            otcs["downstream_receipt"]
        )
    except (ContractViolation, IntegrityViolation, OTCSBridgeError):
        otcs_boundary_ok = False
    else:
        otcs_evidence = {
            item["evidence_type"]: item["sha256"].upper()
            for item in otcs["evidence"]["items"]
        }
        otcs_legal = otcs_operation.legal_evidence_mapping()
        otcs_boundary_ok = (
            otcs_operation.payload.digest == otcs["intent"]["payload_hash"].upper()
            and otcs_operation.expected_head.history_digest.digest
            == otcs["intent"]["history_summary_hash"].upper()
            and otcs_operation.expected_head.event_digest.digest
            == otcs["intent"]["state_anchor_hash"].upper()
            and set(otcs_legal) == set(OTCS_LEGAL_EVIDENCE_TYPES)
            and all(
                otcs_legal[evidence_type].digest
                == otcs_evidence[evidence_type]
                for evidence_type in OTCS_LEGAL_EVIDENCE_TYPES
            )
            and otcs_evidence[OTCS_HEAD_EVIDENCE_TYPE]
            == otcs_operation.expected_head.event_digest.digest
            and otcs["intent"]["authority_grant_id"]
            == otcs["grant"]["grant_id"]
            and "authority_grant_id" not in otcs["bridge_operation"]["legal_evidence"]
            and otcs_receipt.previous_head == otcs_operation.expected_head
            and "allowed" not in otcs["downstream_receipt"]
        )
    checks.require(otcs_boundary_ok, "otcs_bridge_boundary")

    witness_ref = profile["mapping_witness"]["evidence_refs"][0]
    witness_ref_path = safe_source_path(ROOT, witness_ref["ref"])
    checks.require(witness_ref_path.is_file(), "witness_evidence_present")
    checks.require(
        file_sha256(witness_ref_path) == witness_ref["sha256"],
        "witness_evidence_sha256",
    )
    checks.require(sha256_hex(profile) == EXPECTED_PROFILE_HASH, "profile_hash")
    checks.require(
        sha256_hex(declaration) == EXPECTED_DECLARATION_HASH,
        "declaration_hash",
    )
    checks.require(
        grant["binding"]["profile_hash"] == EXPECTED_PROFILE_HASH
        and intent["binding"]["profile_hash"] == EXPECTED_PROFILE_HASH,
        "runtime_profile_binding",
    )
    checks.require(
        grant["binding"]["declaration_hash"] == EXPECTED_DECLARATION_HASH
        and intent["binding"]["declaration_hash"] == EXPECTED_DECLARATION_HASH,
        "runtime_declaration_binding",
    )

    input_by_role = {item["role"]: item for item in manifest["inputs"]}
    core_manifest = input_by_role["immutable_nc25_core"]

    for item in manifest["inputs"]:
        safe_source_path(ROOT, item["relative_path"])
    checks.passed("manifest_path_containment")

    try:
        safe_source_path(ROOT, "../outside-package")
    except AssertionError:
        checks.passed("path_containment_self_test")
    else:
        raise AssertionError("path_containment_self_test")

    print(f"SOURCE_MODE={source_mode}")
    if source_root is not None:
        checks.require(source_root.is_dir(), "external_source_root")
        core_path = safe_source_path(
            source_root,
            core_manifest["relative_path"],
        )
        checks.require(core_path.is_file(), "core_present")
        checks.require(
            file_sha256(core_path) == core_manifest["sha256"],
            "core_sha256",
        )
        checks.require(
            core_path.stat().st_size == core_manifest["byte_length"],
            "core_bytes",
        )
        core_lines = core_path.read_text(encoding="utf-8").splitlines()
        checks.require(len(core_lines) == core_manifest["line_count"], "core_lines")
        core_line_count = len(core_lines)

        # Guarded by the verdicts themselves, not by having reached this line.
        # `require` records and returns - that is the property the class above
        # exists to hold - so until this guard the line printed PASS after the
        # very failures it claimed to summarise: a core present with the wrong
        # bytes recorded FAIL core_sha256, FAIL core_bytes, FAIL core_lines,
        # and then announced that the external-source checks passed. The
        # acceptance runner reads this line as the evidence that the run was
        # the release configuration, so the lie did not stay local.
        external_verdict = (
            "PASS"
            if EXTERNAL_SOURCE_CHECK_IDS <= checks.passed_ids
            else "FAIL"
        )
        print(f"EXTERNAL_SOURCE_CHECKS={external_verdict}")
    else:
        core_line_count = core_manifest["line_count"]
        print("EXTERNAL_SOURCE_CHECKS=NOT_RUN")

    checks.require(
        crosswalk["source_sha256"] == core_manifest["sha256"],
        "crosswalk_core_binding",
    )
    entries = crosswalk["entries"]
    checks.require(len(entries) == 16, "crosswalk_entry_count")
    checks.require(
        len({entry["id"] for entry in entries}) == len(entries),
        "crosswalk_unique_ids",
    )
    range_numbers = [
        int(number)
        for entry in entries
        for number in re.findall(r"\d+", entry["source_lines"])
    ]
    checks.require(
        min(range_numbers) >= 1 and max(range_numbers) <= core_line_count,
        "crosswalk_line_ranges",
    )

    schema_paths = sorted((ROOT / "core" / "schemas").glob("*.json"))
    checks.require(len(schema_paths) == 4, "schema_file_count")
    schemas = [json.loads(path.read_text(encoding="utf-8")) for path in schema_paths]
    checks.require(
        all(schema.get("$schema", "").endswith("2020-12/schema") for schema in schemas),
        "schema_dialect",
    )
    checks.require(
        all(schema.get("$id") and schema.get("title") for schema in schemas),
        "schema_identity",
    )
    runtime_schema = next(
        schema
        for schema in schemas
        if schema["$id"].endswith("/runtime-contracts.schema.json")
    )
    checks.require(
        "execution_permit" in runtime_schema["$defs"]
        and any(
            item.get("$ref") == "#/$defs/execution_permit"
            for item in runtime_schema["oneOf"]
        ),
        "runtime_execution_permit_bound",
    )

    neutral_roots = [ROOT / "core", ROOT / "protocol", ROOT / "sdk" / "python"]
    neutral_files = [
        path
        for neutral_root in neutral_roots
        for path in neutral_root.rglob("*")
        if path.is_file()
        and path.suffix.lower() in {".json", ".py", ".yaml", ".yml"}
        and "__pycache__" not in path.parts
    ]
    bank_vocabulary = re.compile(r"\b(?:bank|banking)\b|BANK_", re.IGNORECASE)
    checks.require(
        not any(bank_vocabulary.search(path.read_text(encoding="utf-8")) for path in neutral_files),
        "domain_neutral_core",
    )

    openapi = (ROOT / "protocol" / "universal-connection.openapi.yaml").read_text(
        encoding="utf-8"
    )
    required_paths = [
        "/v1/declarations:activate:",
        "/v1/authority-grants:",
        "/v1/authority-revocations:",
        "/v1/operator/intents:evaluate:",
        "/v1/executor/permits/{permit_hash}:consume:",
        "/v1/architect/permits/{permit_hash}:",
        "/v1/architect/decisions/{request_hash}:",
        "/v1/architect/ledger/head:",
        "/v1/registry/connectors/{connector_id}:",
    ]
    checks.require("openapi: 3.1.0" in openapi, "openapi_version")
    checks.require(all(path in openapi for path in required_paths), "openapi_routes")
    checks.require(
        all(
            scope in openapi
            for scope in [
                "nc25.governance",
                "nc25.operator",
                "nc25.executor",
                "nc25.architect",
            ]
        ),
        "openapi_role_scopes",
    )
    # A FLOOR, not a per-route proof, and the name overstated it: this counts
    # occurrences and pairs them with nothing, so nine declarations under one
    # operation satisfy it for nine operations. The per-route property is held
    # by `openapi_route_security` in the conformance suite, which parses the
    # document and names each path - and which is skipped entirely when the
    # YAML library is absent, leaving this floor as the only thing said about
    # mutual TLS. That is the limit, stated where the weaker check lives.
    checks.require(
        openapi.count("mutualTLS: []") >= len(required_paths),
        "openapi_mtls_declaration_floor",
    )
    # The contract's Error.code enum is the vocabulary a caller can actually
    # receive, and it is held to the LIVE static scan rather than to the
    # recorded baseline: a code added to the engine or the adapter without a
    # baseline regeneration would otherwise stay invisible here. The codes the
    # translation site re-emits from an integrity halt belong to neither
    # vocabulary and are observable only at run time, so that part is read
    # from the baseline's recorded run. Reddens in either direction.
    enum_block = re.search(
        r"(?ms)^        code:\n.*?^          enum:\n((?:^            - \S+\n)+)",
        openapi,
    )
    declared_codes = (
        set(re.findall(r"(?m)^            - (\S+)$", enum_block.group(1)))
        if enum_block
        else set()
    )
    static_surface, _ = failure_surface.static_snapshot()
    recorded_baseline = json.loads(
        (ROOT / "tests" / "failure-surface-baseline.json").read_text(encoding="utf-8")
    )
    live_codes = (
        set(static_surface["engine_refusal_codes"])
        | set(static_surface["wire_error_codes"])
        | set(recorded_baseline["runtime"]["foreign_translated_codes"])
    )
    checks.require(
        bool(enum_block) and declared_codes == live_codes,
        "openapi_error_codes_match_closed_world",
    )

    bound = bind_fixture(profile, declaration, grant, intent)
    bound_profile, bound_declaration, bound_grant, bound_intent = bound
    engine = UniversalConnectionLedger(
        bound_profile,
        bound_declaration,
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
    engine.issue_grant(bound_grant, actor_scope="nc25.governance")
    result = engine.evaluate_intent(bound_intent, evidence, actor_scope="nc25.operator")
    checks.require(result["disposition"] == "ALLOW", "runtime_allow")
    checks.require(
        set(result)
        == {
            "message_type",
            "intent_id",
            "request_hash",
            "disposition",
            "channel",
            "message_code",
            "permit_hash",
            "expires_at",
        },
        "operator_projection_exact",
    )
    receipt = engine.commit_execution(
        execution_request(engine, result, bound_intent),
        actor_scope="nc25.executor",
        route_permit_hash=result["permit_hash"],
    )
    checks.require(
        receipt["structural_debit"] == 100
        and receipt["resource_debits"]["money_minor_units"] == 12500,
        "runtime_commit_debits",
    )
    checks.require(engine.ledger.verify(), "ledger_chain")

    registry = engine.registry_record(engine.declaration["connector"]["connector_id"], actor_scope="nc25.architect")
    expected_registry_keys = {
        "schema_version",
        "connector_id",
        "profile_id",
        "profile_version",
        "profile_hash",
        "declaration_id",
        "declaration_version",
        "declaration_hash",
        "core_anchor",
        "status",
        "activated_at",
        "revoked",
        "ledger_head_hash",
        "latest_receipt_root",
    }
    checks.require(set(registry) == expected_registry_keys, "registry_projection_exact")
    engine.activated_at = {
        "raw_intent": {"payload": "must-not-leave-local-ledger"}
    }
    try:
        engine.registry_record(engine.declaration["connector"]["connector_id"], actor_scope="nc25.architect")
    except IntegrityViolation as exc:
        checks.require(
            exc.code == "REGISTRY_DATA_EXPANSION",
            "registry_rejects_nested_forbidden_data",
        )
    else:
        raise AssertionError("registry_rejects_nested_forbidden_data")

    markdown = "\n".join(
        path.read_text(encoding="utf-8")
        for path in ROOT.rglob("*.md")
        if path.is_file() and path.name != "DOCX-AUDIT-PROJECTION.md"
    )
    checks.require(
        re.search(r'\."|,"', markdown) is None,
        "logical_quote_punctuation",
    )

    docx_path = ROOT / load_spec_counts().spec_docx_name(ROOT)
    with zipfile.ZipFile(docx_path) as archive:
        names = set(archive.namelist())
        checks.require("word/document.xml" in names, "docx_document_part")
        document_xml = archive.read("word/document.xml").decode("utf-8")
    checks.require(
        "NC25OL" in document_xml
        and "Navigational Cybernetics 2.5 Open Ledger" in document_xml,
        "docx_title",
    )

    projection_text = (ROOT / "DOCX-AUDIT-PROJECTION.md").read_text(
        encoding="utf-8"
    )
    declared_projection_sources = re.findall(
        r"(?m)^- Source SHA-256: `([A-F0-9]{64})`$",
        projection_text,
    )
    checks.require(
        len(declared_projection_sources) == 1
        and declared_projection_sources[0] == file_sha256(docx_path),
        "docx_projection_source_bound",
    )
    projection_sections = projection_visible_sections(projection_text)
    checks.require(
        not docx_acceptance_count_mismatches(
            projection_sections.get("word/document.xml", [])
        ),
        "docx_acceptance_counts_current",
    )
    checks.require(
        not docx_header_version_mismatches(projection_sections),
        "docx_header_version_matches_title",
    )
    checks.require(
        not citation_metadata_mismatches(), "citation_metadata_contract",
    )
    checks.require(
        not package_version_mismatches(projection_sections),
        "package_version_consistency",
    )
    checks.require(
        not acceptance_report_row_mismatches(),
        "acceptance_report_gate_rows_current",
    )
    _, failure_surface_problems = failure_surface.check_baseline(
        include_runtime=False
    )
    checks.require(
        not failure_surface_problems,
        "failure_surface_static_ratchet",
    )
    checks.require(
        not acceptance_report_binding_mismatches(),
        "acceptance_report_bound_to_bytes",
    )
    checks.require(
        not package_counter_literal_mismatches(),
        "package_counter_literals_current",
    )
    checks.require(
        not acceptance_report_ratchet_figures_mismatches(),
        "acceptance_report_ratchet_figures_current",
    )

    # Deliberately LAST, and the reason is the failure mode rather than the
    # rule. Running a suite without -B leaves compiled copies beside the source;
    # they must never travel with the package, because undeclared build output
    # sits outside the exact PACKAGE-MANIFEST coverage set. This scan once stood
    # first, and `require` then raised on the first failure, so one stray .pyc
    # from the ordinary way of iterating on a test switched off every other
    # check in this file and reported it under an unrelated name. `require` no
    # longer raises - it records a verdict per check and `finish` reports them
    # all - so that particular silencing cannot recur. The scan stays last for
    # the reason that survives: nothing here depends on the tree being clean,
    # so its failure is the one that costs no other check's coverage.
    #
    # A nested repository directory is scanned too. The manifest excludes a
    # repository directory ONLY at the root, so files under one at depth are
    # DECLARED like any other file - which is the point: matching the name at
    # any depth once made them invisible to the manifest, to the coverage
    # check and to `git status` alike, and a file could ship outside the
    # hash-bound set with nothing saying so. This scan reaches them because
    # git will not: a nested repository is a foreign boundary to it.
    artefact_directories = {"__pycache__", ".pytest_cache"}
    artefacts = [
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if path.is_file()
        and path.relative_to(ROOT).parts[:1] != (".git",)
        and (
            path.suffix.lower() in {".pyc", ".pyo", ".bak", ".tmp", ".orig", ".rej"}
            or set(path.relative_to(ROOT).parts) & artefact_directories
            or ".git" in path.relative_to(ROOT).parts
        )
    ]
    checks.require(not artefacts, "no_build_artefacts")


def main() -> None:
    checks = Checks()
    # ONE resolution, passed to both consumers. The docstring on
    # `resolve_source_root` has said "resolved once … and used both to run the
    # checks and to decide which ids a crashed run must still account for"
    # while the function was in fact called twice, independently: here for the
    # declared-id set and again inside `_run_checks` for the run itself. One
    # rule evaluated twice is not one resolution, and between the two calls the
    # environment or the tree can move - which would make a crashed run account
    # for a different set of ids than the run had been performing.
    source_root, source_mode = resolve_source_root()
    external = source_root is not None
    try:
        _run_checks(checks, source_root, source_mode)
    except BaseException as exc:  # noqa: BLE001 - see the comment below
        # A check crashed instead of returning a verdict, which usually means an
        # earlier failure destroyed a precondition it needed. Recording every
        # failure rather than raising on the first one makes failures VISIBLE;
        # it cannot make a destroyed precondition true again. So the checks that
        # never got to speak are recorded as BLOCKED naming the crash: the
        # verdict set stays invariant, and the cause arrives attributed instead
        # of as a bare traceback with no indication of how far the run got.
        reason = f"{type(exc).__name__}: {exc}".replace("\n", " ")[:200]
        declared = STANDALONE_PACKAGE_CHECK_IDS | (
            EXTERNAL_SOURCE_CHECK_IDS if external else frozenset()
        )
        for label in sorted(declared - set(checks.verdicts)):
            checks.blocked(label, reason)
    checks.finish(external)


if __name__ == "__main__":
    main()
