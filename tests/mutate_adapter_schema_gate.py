"""Break POST schema ingress; optionally also test an earlier adapter source."""

from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "sdk" / "python" / "nc25_universal_adapter.py"
CALLS = (
    ("activate", "_activate"),
    ("grant", "_issue_grant"),
    ("revoke", "_revoke_grant"),
    ("operator", "_evaluate_intent"),
    ("consume", "_consume_permit"),
)
PATH_TEST = "AdapterSchemaGateTests.test_schema_refusals_precede_engine_without_mutation"
MISSING_TEST = "AdapterSchemaGateTests.test_missing_validator_refuses_all_post_routes"
VALID_TEST = "AdapterSchemaGateTests.test_valid_post_bodies_pass_to_engine"
FORMAT_TEST = "AdapterSchemaGateTests.test_missing_date_time_checker_refuses_all_post_routes"


def check_mutant(tree, destination, test, routes):
    destination.write_text(ast.unparse(ast.fix_missing_locations(tree)) + "\n", encoding="utf-8")
    env = os.environ.copy()
    env["NC25_ADAPTER_MUTANT"] = str(destination)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, "-B", str(ROOT / "tests" / "test_adapter_schema_gate.py"), test],
        cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8",
        errors="replace", check=False,
    )
    headers = re.findall(r"^FAIL: ([^\n]+)$", result.stderr, re.MULTILINE)
    actual_routes = re.findall(r"^FAIL: .*\(route='([^']+)'\)$", result.stderr, re.MULTILINE)
    errors = re.findall(r"^ERROR: ", result.stderr, re.MULTILINE)
    test_name = test.rsplit(".", 1)[1]
    expected_count = 1 if routes is None else len(routes)
    if (result.returncode == 0 or errors or len(headers) != expected_count
            or any(not header.startswith(test_name + " ") for header in headers)
            or (routes is not None and actual_routes != routes)):
        raise SystemExit(
            f"MUTATION_NOT_FIRST_RED {test}: returncode={result.returncode} "
            f"failures={headers!r} errors={len(errors)} stderr_tail={result.stderr[-1200:]!r}"
        )
    return headers[0]


def main() -> None:
    if len(sys.argv) > 2:
        raise SystemExit("usage: mutate_adapter_schema_gate.py [previous_adapter.py]")
    previous_adapter = Path(sys.argv[1]) if len(sys.argv) == 2 else None
    source = SOURCE.read_text(encoding="utf-8")
    baseline_env = os.environ.copy()
    baseline_env.pop("NC25_ADAPTER_MUTANT", None)
    baseline = subprocess.run(
        [sys.executable, "-B", str(ROOT / "tests" / "test_adapter_schema_gate.py")],
        cwd=ROOT, env=baseline_env, capture_output=True, text=True, encoding="utf-8",
        errors="replace", check=False,
    )
    sys.stdout.write(baseline.stdout + baseline.stderr)
    if baseline.returncode != 0 or not re.search(r"Ran 5 tests in ", baseline.stderr):
        raise SystemExit("ADAPTER_SCHEMA_BASELINE_FAILED")
    completed = 0
    with tempfile.TemporaryDirectory(prefix="adapter-schema-mutations-") as folder:
        mutant = Path(folder) / "nc25_universal_adapter.py"
        if previous_adapter is not None:
            tree = ast.parse(previous_adapter.read_text(encoding="utf-8"))
            first = check_mutant(tree, mutant, PATH_TEST, [route for route, _ in CALLS])
            print(f"MUTATION previous_adapter first={first}")
            completed += 1
        for route, method in CALLS:
            tree = ast.parse(source)
            owner = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                         and node.name == "UniversalConnectionHttpAdapter")
            handler = next(node for node in owner.body if isinstance(node, ast.FunctionDef)
                           and node.name == method)
            targets = [index for index, node in enumerate(handler.body)
                       if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                       and isinstance(node.value.func, ast.Name)
                       and node.value.func.id == "_validate_request_schema"]
            if len(targets) != 1:
                raise SystemExit(f"MUTATION_ANCHOR_INVALID {route}: {len(targets)}")
            handler.body[targets[0]] = ast.copy_location(ast.Pass(), handler.body[targets[0]])
            first = check_mutant(tree, mutant, MISSING_TEST, [route])
            path_first = check_mutant(tree, mutant, PATH_TEST, [route])
            print(f"MUTATION {route} first={first}; path_first={path_first}")
            completed += 1

        tree = ast.parse(source)
        format_call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                           and isinstance(node.func, ast.Name) and node.func.id == "FormatChecker")
        format_call.keywords = []
        first = check_mutant(tree, mutant, FORMAT_TEST, [route for route, _ in CALLS])
        print(f"MUTATION missing_date_time_guard first={first}")
        completed += 1

        tree = ast.parse(source)
        validator = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                         and node.name == "_validate_request_schema")
        schema_raise = next(node for node in ast.walk(validator) if isinstance(node, ast.Raise)
                            and isinstance(node.exc, ast.Call) and len(node.exc.args) >= 3
                            and isinstance(node.exc.args[1], ast.Constant)
                            and node.exc.args[1].value == "BODY_SCHEMA")
        schema_raise.exc.args[2] = ast.Constant(value="schema invalid")
        first = check_mutant(tree, mutant, PATH_TEST, [route for route, _ in CALLS])
        print(f"MUTATION missing_field_path first={first}")
        completed += 1

        tree = ast.parse(source)
        validator = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                         and node.name == "_validate_request_schema")
        final_branch = next(index for index, node in enumerate(validator.body)
                            if isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                            and isinstance(node.test.left, ast.Name) and node.test.left.id == "error")
        validator.body.insert(final_branch, ast.parse(
            'if error is None: raise WireError(400, "BODY_SCHEMA", "$: forced refusal")'
        ).body[0])
        first = check_mutant(tree, mutant, VALID_TEST, None)
        print(f"MUTATION rejects_valid_request first={first}")
        completed += 1
    expected = len(CALLS) + 3 + int(previous_adapter is not None)
    if completed != expected:
        raise SystemExit("MUTATION_INVENTORY_INCOMPLETE")
    print(f"ADAPTER_SCHEMA_MUTATIONS={completed}/{expected} PASS")


if __name__ == "__main__":
    main()
