"""Shared stdlib-only AST readers for the specification builder and checks.

The DOCX builder and the package verifier derive the acceptance numbers
through this single module, so the shipped document and the checker cannot
drift apart by carrying two counting implementations. Because both sides of
a comparison use the same counter, a check built on it detects staleness of
a shipped artefact, not counting correctness.

The same argument reaches past numbers, so the module also reads a collection
one side owns and the other would otherwise transcribe - the gate-row labels
being the case that made it necessary. A reader here, whatever it returns, is
a reader: it exists so that a fact has one home and the second side asks for
it instead of keeping a copy.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path


def spec_docx_name(root: Path) -> str:
    """Spec DOCX filename derived from the manifest's major.minor version.

    Single source for every tool and check that names the shipped document,
    so a version bump renames it in exactly one place. The package verifier
    still cross-checks the on-disk filename against the manifest, OpenAPI,
    DOCX title, and report versions independently, so a wrong manifest value
    cannot silently pass as a consistent rename.
    """
    manifest = json.loads(
        (root / "SOURCE-MANIFEST.json").read_text(encoding="utf-8")
    )
    major_minor = ".".join(manifest["package_version"].split(".")[:2])
    return (
        "NC25OL Specification "
        f"v{major_minor}.docx"
    )


def acceptance_gate_rows(report: str) -> list[tuple[str, str]] | None:
    """Read the complete two-column gate table, or refuse its structure.

    Cell whitespace and optional outer pipes do not change table membership.
    Read every nonblank body line, even when its result is not a PASS token.
    Every structural line permits at most three leading columns; tabs advance
    to four-column stops. Greater indentation can end or suppress the table.
    This is the report's fixed table format, not a general Markdown parser.
    """
    def cells(line: str) -> list[str]:
        line = line.strip()
        if line.startswith("|"):
            line = line[1:]
        if line.endswith("|"):
            line = line[:-1]
        return [cell.strip() for cell in line.split("|")]

    def table_indentation(line: str) -> bool:
        return re.match(r"^ {0,3}\S", line.expandtabs(4)) is not None

    lines = report.splitlines()
    headers = []
    fence: tuple[str, int] | None = None
    for index, line in enumerate(lines):
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if marker:
            token = marker.group(1)
            if fence is None:
                fence = (token[0], len(token))
            elif (token[0] == fence[0] and len(token) >= fence[1]
                  and not line[marker.end():].strip()):
                fence = None
            continue
        if fence is None and cells(line) == ["Gate", "Recorded result"]:
            if not table_indentation(line):
                return None
            headers.append(index)
    if len(headers) != 1:
        return None
    start = headers[0] + 1
    if start >= len(lines):
        return None
    if not table_indentation(lines[start]):
        return None
    separator = cells(lines[start])
    if len(separator) != 2 or any(
        re.fullmatch(r":?-{3,}:?", cell) is None for cell in separator
    ):
        return None
    rows = []
    for line in lines[start + 1:]:
        if not line.strip():
            break
        if not table_indentation(line):
            return None
        row = cells(line)
        if len(row) != 2:
            return None
        rows.append((row[0], row[1]))
    return rows


def sole_assignment(tree: ast.AST, name: str, *, where: str = "") -> ast.expr | None:
    """The value assigned to `name` at module level, and there must be one.

    Returning the FIRST match is the failure this guards. Python binds the
    LAST top-level assignment, so a reader that stops at the first validates a
    statement the running program never uses: a correct definition placed above
    a poisoned one satisfies every check derived from this module while the
    program runs on the poisoned one. Refusing more than one costs nothing —
    a module with two top-level definitions of the same name has a defect
    whatever the reader does.

    Takes a parsed tree rather than a path because the other caller already
    holds one. It is published rather than private because it had a second
    home: the failure-surface tool carried the same reader, found and fixed the
    same way on the same day, and a reader whose whole purpose is to refuse a
    duplicated declaration is a poor thing to declare twice.

    Returns None when the name is absent; the caller decides whether that is
    an error, because for a shipped declaration it is and for an optional one
    it is not.
    """
    found = []
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                found.append(node.value)
    if len(found) > 1:
        raise RuntimeError(
            f"Symbol assigned {len(found)} times at module level:"
            f" {name}{' in ' + where if where else ''}"
        )
    return found[0] if found else None


def _sole_assignment(path: Path, symbol: str) -> ast.expr:
    """The path-taking form, for callers that have not parsed the file."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    value = sole_assignment(tree, symbol, where=path.name)
    if value is None:
        raise RuntimeError(f"Acceptance symbol not found: {symbol} in {path.name}")
    return value


def literal_collection_size(path: Path, symbol: str) -> int:
    value_node = _sole_assignment(path, symbol)
    if (
        isinstance(value_node, ast.Call)
        and isinstance(value_node.func, ast.Name)
        and value_node.func.id in {"set", "frozenset"}
        and len(value_node.args) == 1
    ):
        value_node = value_node.args[0]
    # A duplicate literal would collapse in the runtime collection while a
    # plain len() over a list/tuple argument counts it twice; deduplicate so
    # the derived number matches runtime.
    return len(set(ast.literal_eval(value_node)))


def literal_mapping_values(path: Path, symbol: str) -> list[str]:
    """String values of the literal mapping assigned to `symbol`.

    The counters above stop a shipped artefact from drifting away from the
    suite it describes. This does the same for a LIST one side owns and the
    other only transcribed: it lets a checker read the writer's collection
    instead of keeping a second copy beside it.

    The gate-row labels needed it. The report builder owned them and the
    package verifier asserted its own transcription, and nothing held the two
    together - so a row could be dropped from the checker with no test to say
    so. That is exactly how the OTCS bridge row shipped unchecked: it was
    added to the builder's rows and never to the verifier's, and the omission
    was found by reading, not by a red.
    """
    mapping = ast.literal_eval(_sole_assignment(path, symbol))
    if not isinstance(mapping, dict):
        raise RuntimeError(f"Not a literal mapping: {symbol}")
    return [value for value in mapping.values() if isinstance(value, str)]


def test_method_count(path: Path, class_name: str) -> int:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    # Every definition of the name, not the first: a class defined twice at
    # module level runs as the LAST definition, and a reader that stops at the
    # first would count the methods of a class the suite never instantiates.
    # Same shape as `_sole_assignment`, and refused for the same reason.
    classes = [node for node in tree.body
               if isinstance(node, ast.ClassDef) and node.name == class_name]
    if len(classes) != 1:
        raise RuntimeError(
            f"Test class defined {len(classes)} times at module level:"
            f" {class_name} in {path.name}"
        )
    names = [
        item.name
        for item in classes[0].body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.name.startswith("test_")
    ]
    if len(names) != len(set(names)):
        # A shadowed duplicate runs once but would be counted twice.
        raise RuntimeError(f"Duplicate test method in {class_name}")
    return len(names)
