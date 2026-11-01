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
from collections.abc import Iterator
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


def _own_code(body: list[ast.stmt]) -> Iterator[tuple[ast.AST, ast.stmt]]:
    """(node, statement) for every node in one scope's own code.

    A scope's own code is its statements, the blocks nested in them — if, for,
    while, try, with and match open no scope — and the parts of a nested def,
    class or lambda that run where the definition stands: decorators, defaults,
    annotations, bases and keywords. A nested body is a scope of its own and is
    not entered. Neither is a comprehension's target, which binds inside the
    comprehension; the rest of a comprehension is, because an assignment
    expression there binds in the enclosing scope. Nor is a name annotated
    without a value, which binds nothing; an attribute or subscript annotated
    that way is still evaluated, so it is walked.
    """
    pending = [(node, node) for node in body]
    while pending:
        node, statement = pending.pop()
        if isinstance(node, ast.stmt):
            statement = node
        yield node, statement
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            children = [child for child in ast.iter_child_nodes(node) if child not in node.body]
        elif isinstance(node, ast.Lambda):
            children = [node.args]
        elif isinstance(node, ast.comprehension):
            children = [node.iter, *node.ifs]
        elif isinstance(node, ast.AnnAssign) and node.value is None:
            children = [node.annotation]
            if not isinstance(node.target, ast.Name):
                children.append(node.target)
        else:
            children = ast.iter_child_nodes(node)
        pending.extend((child, statement) for child in children)


def _binds(node: ast.AST, name: str) -> bool:
    """Whether the node binds `name` in the scope whose own code holds it."""
    if isinstance(node, ast.Name):
        # Every assignment target — plain, augmented, annotated with a value or
        # unpacked — a for or with target, an assignment expression, a `type`
        # alias, and `del`.
        return node.id == name and not isinstance(node.ctx, ast.Load)
    if isinstance(node, ast.alias):
        # `import a.b` binds `a`; a star import may bind any name.
        return node.name == "*" or (node.asname or node.name.partition(".")[0]) == name
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name == name
    if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
        return node.name == name
    if isinstance(node, ast.MatchMapping):
        return node.rest == name
    return False


def _module_bindings(tree: ast.AST, name: str) -> list[tuple[ast.AST, ast.stmt, ast.AST | None]]:
    """Every binding of `name` in the module namespace, in source order.

    Each comes with the def or class it sits in, or None for module code. A
    binding inside a def or class counts only where that def or class declares
    the name global: it rebinds the module's name when that code runs.
    """
    sites = [(node, statement, None) for node, statement in _own_code(tree.body)
             if _binds(node, name)]
    for scope in ast.walk(tree):
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            own = list(_own_code(scope.body))
            if any(isinstance(node, ast.Global) and name in node.names for node, _ in own):
                sites += [(node, statement, scope) for node, statement in own
                          if _binds(node, name)]
    return sorted(sites, key=lambda site: site[0].lineno)


def _named(sites: list[tuple[ast.AST, ast.stmt, ast.AST | None]]) -> str:
    return ", ".join(
        f"{type(statement).__name__} line {node.lineno}"
        + ("" if scope is None else f" in {scope.name}, which declares it global")
        for node, statement, scope in sites
    )


def sole_assignment(tree: ast.AST, name: str, *, where: str = "") -> ast.expr | None:
    """The value assigned to `name` at module level, and there must be one.

    Returning the FIRST match is the failure this guards. Python binds the
    LAST top-level assignment, so a reader that stops at the first validates a
    statement the running program never uses: a correct definition placed above
    a poisoned one satisfies every check derived from this module while the
    program runs on the poisoned one. Refusing more than one costs nothing —
    a module with two top-level definitions of the same name has a defect
    whatever the reader does.

    The poisoned definition need not be a second top-level assignment, so
    every binding of the name in the module namespace is counted: an augmented
    assignment, an assignment inside an if, for, while, try, with or match
    block, an unpacking target, a for, with, except or case target, an
    assignment expression, an import, a def or class of the name, `del`, a
    star import, which may bind any name, and a binding inside a def or class
    that declares the name global. The name annotated without a value binds
    nothing and is not counted. The reader does not follow control flow, so it
    asks for one unconditional statement: two bindings in exclusive branches
    are refused like any two, and a single binding is read only when it
    assigns the name itself, plainly or with an annotation, at the top level
    of the module; any other single binding is refused rather than read as
    absent. Named limit: a name written dynamically — through globals(), exec
    or setattr on the module — and an in-place change to the bound value are
    not bindings, and this reader does not see them.

    Takes a parsed tree rather than a path because the other caller already
    holds one. It is published rather than private because the failure-surface
    tool needs the same reader, and a reader whose whole purpose is to refuse a
    duplicated declaration is a poor thing to declare twice.

    Returns None when the name is absent; the caller decides whether that is
    an error, because for a shipped declaration it is and for an optional one
    it is not.
    """
    sites = _module_bindings(tree, name)
    place = f"{name}{' in ' + where if where else ''}"
    if len(sites) > 1:
        raise RuntimeError(
            f"Symbol bound {len(sites)} times in the module namespace: {place} ({_named(sites)})"
        )
    if not sites:
        return None
    node, statement, _ = sites[0]
    top_level = any(statement is item for item in tree.body)
    if top_level and isinstance(statement, ast.Assign) and any(
        target is node for target in statement.targets
    ):
        return statement.value
    if top_level and isinstance(statement, ast.AnnAssign) and statement.target is node:
        return statement.value
    raise RuntimeError(
        "Symbol bound once, but not by an assignment of the name at the top level:"
        f" {place} ({_named(sites)})"
    )


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

    The gate-row labels need it. The report builder owns them, and a package
    verifier keeping its own transcription would hold nothing to them: a row
    added to the builder's rows and never to the verifier's would go unchecked,
    with no test to say so.
    """
    mapping = ast.literal_eval(_sole_assignment(path, symbol))
    if not isinstance(mapping, dict):
        raise RuntimeError(f"Not a literal mapping: {symbol}")
    return [value for value in mapping.values() if isinstance(value, str)]


def test_method_count(path: Path, class_name: str) -> int:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    # Every binding of the name, not the first class: a class defined twice,
    # or rebound by any binding `sole_assignment` counts, runs as the LAST
    # binding, and a reader that stops at the first class would count the
    # methods of a class the suite never instantiates. So the name must be
    # bound once, by a class statement at the top level of the module.
    sites = _module_bindings(tree, class_name)
    if len(sites) != 1 or not isinstance(sites[0][0], ast.ClassDef) or not any(
        sites[0][0] is item for item in tree.body
    ):
        raise RuntimeError(
            f"Test class not bound once by a top-level class statement:"
            f" {class_name} in {path.name} ({_named(sites)})"
        )
    names = [
        item.name
        for item in sites[0][0].body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.name.startswith("test_")
    ]
    if len(names) != len(set(names)):
        # A shadowed duplicate runs once but would be counted twice.
        raise RuntimeError(f"Duplicate test method in {class_name}")
    return len(names)
