"""Optional admission-time observation control. No execution authority is created here."""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import tempfile
import threading
from typing import Any, Callable

from collections.abc import Mapping

from nc25_universal_ledger import CONTROL_BOOLEAN_FIELDS, CONTROL_FIELDS, sha256_hex

MAX_INPUT_BYTES = 1_048_576
MAX_OUTPUT_BYTES = 2_097_152
VERDICTS = frozenset({
    "target_true_in_declared_fibre", "target_false_in_declared_fibre",
    "insufficient_basis", "outside_declared_domain",
})


class ObservationError(RuntimeError):
    """Local module failure; Ledger translates resolver failures at its boundary."""


def observation_query(intent: dict) -> dict[str, str]:
    """Bind opaque projection keys to this complete intent and declaration binding."""
    return {"skeleton": sha256_hex(intent["binding"]), "observation": sha256_hex(intent)}


def _digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _run_process(command: list[str], timeout: float) -> bytes:
    """Bound each pipe in memory, kill the direct child on overflow or timeout.

    The executable is trusted startup configuration, never a request-supplied
    program. This is a resource bound for that child, not a process sandbox.
    """
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as error:
        raise ObservationError("OBSERVATION_BINARY") from error
    output = [bytearray(), bytearray()]
    failures: list[str] = []

    def stop():
        try:
            process.kill()
        except OSError:
            pass

    def read_pipe(stream, slot):
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                if len(output[slot]) + len(chunk) > MAX_OUTPUT_BYTES:
                    failures.append("OBSERVATION_OUTPUT_LIMIT")
                    stop()
                    break
                output[slot].extend(chunk)
        except OSError:
            failures.append("OBSERVATION_OUTPUT")
            stop()

    readers = [threading.Thread(target=read_pipe, args=(stream, slot), daemon=True)
               for slot, stream in enumerate((process.stdout, process.stderr))]
    for reader in readers:
        reader.start()
    try:
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise ObservationError("OBSERVATION_TIMEOUT") from error
    finally:
        if process.poll() is None:
            stop()
        process.wait(timeout=5)
        for reader in readers:
            reader.join(timeout=1)
        # The trusted engine spawns no children retaining its pipe handles.
        if any(reader.is_alive() for reader in readers):
            raise ObservationError("OBSERVATION_OUTPUT")
        process.stdout.close()
        process.stderr.close()
    if failures:
        raise ObservationError(failures[0])
    if process.returncode != 0 or output[1]:
        raise ObservationError("OBSERVATION_PROCESS_FAILED")
    return bytes(output[0])


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ObservationError("OBSERVATION_OUTPUT")
        result[key] = value
    return result


def _constant(value):
    raise ObservationError("OBSERVATION_OUTPUT")


def _decode_output(raw: bytes, request: dict) -> dict:
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                            parse_constant=_constant)
        fields = {"schema", "target", "scope", "query", "verdict", "matching_world_ids"}
        if not isinstance(result, dict) or result.get("verdict") not in VERDICTS:
            raise ObservationError("OBSERVATION_OUTPUT")
        mixed = result["verdict"] == "insufficient_basis"
        if set(result) != fields | ({"witness"} if mixed else set()):
            raise ObservationError("OBSERVATION_OUTPUT")
        if (type(result["schema"]) is not int or result["schema"] != 1
                or result["scope"] != "supplied_compatible_worlds"):
            raise ObservationError("OBSERVATION_OUTPUT")
        if result["target"] != request["target"]:
            raise ObservationError("OBSERVATION_TARGET")
        if result["query"] != request["query"]:
            raise ObservationError("OBSERVATION_BINDING")
        ids = result["matching_world_ids"]
        # Check returned evidence against the supplied cases and declared query.
        matching = [world for world in request["worlds"]
                    if {"skeleton": world["skeleton"], "observation": world["observation"]}
                    == request["query"]]
        if not isinstance(ids, list) or ids != [world["id"] for world in matching]:
            raise ObservationError("OBSERVATION_OUTPUT")
        if (result["verdict"] == "outside_declared_domain") != (not ids):
            raise ObservationError("OBSERVATION_OUTPUT")
        if result["verdict"] in {"target_true_in_declared_fibre", "target_false_in_declared_fibre"}:
            expected = result["verdict"] == "target_true_in_declared_fibre"
            if any(world["target_holds"] is not expected for world in matching):
                raise ObservationError("OBSERVATION_OUTPUT")
        if mixed:
            witness = result["witness"]
            if not isinstance(witness, dict) or set(witness) != {"true_world_id", "false_world_id"}:
                raise ObservationError("OBSERVATION_OUTPUT")
            by_id = {world["id"]: world["target_holds"] for world in matching}
            if (by_id.get(witness["true_world_id"]) is not True
                    or by_id.get(witness["false_world_id"]) is not False):
                raise ObservationError("OBSERVATION_OUTPUT")
        return result
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError) as error:
        raise ObservationError("OBSERVATION_OUTPUT") from error


@dataclass(frozen=True)
class ObservationControls:
    """Immutable startup settings. Callbacks and their data remain trusted inputs.

    Only a new admission invokes this resolver. Existing permits and replayed
    decisions retain Ledger's normal lifetime; this does not add revocation.
    """
    executable: Path
    prerequisite_id: str
    target: str
    request_provider: Callable
    base_resolver: Callable | None = None
    timeout_seconds: float = 5.0
    scratch_dir: Path | None = None
    _binary_digest: str = field(init=False, repr=False)

    def __post_init__(self):
        if (not callable(self.request_provider)
                or (self.base_resolver is not None and not callable(self.base_resolver))
                or not isinstance(self.prerequisite_id, str) or not self.prerequisite_id.strip()
                or not isinstance(self.target, str) or not self.target.strip()
                or type(self.timeout_seconds) not in (int, float)
                or not math.isfinite(self.timeout_seconds) or not 0 < self.timeout_seconds <= 60):
            raise ObservationError("OBSERVATION_CONFIG")
        try:
            executable = Path(self.executable).resolve(strict=True)
            if not executable.is_file() or not os.access(executable, os.X_OK):
                raise ObservationError("OBSERVATION_BINARY")
            object.__setattr__(self, "executable", executable)
            object.__setattr__(self, "_binary_digest", _digest(executable))
            if self.scratch_dir is not None:
                scratch = Path(self.scratch_dir).resolve(strict=True)
                if not scratch.is_dir():
                    raise ObservationError("OBSERVATION_CONFIG")
                object.__setattr__(self, "scratch_dir", scratch)
        except (OSError, TypeError) as error:
            raise ObservationError("OBSERVATION_CONFIG") from error
        # Probe the real configured executable before accepting any work.
        request = {"schema": 1, "target": self.target, "worlds": [],
                   "query": {"skeleton": "startup", "observation": "startup"}}
        self._evaluate(request)

    def _evaluate(self, request: dict) -> dict:
        try:
            raw = json.dumps(request, ensure_ascii=False, allow_nan=False,
                             separators=(",", ":")).encode("utf-8")
        except (ValueError, TypeError, UnicodeError, RecursionError) as error:
            raise ObservationError("OBSERVATION_INPUT") from error
        if len(raw) > MAX_INPUT_BYTES:
            raise ObservationError("OBSERVATION_INPUT_LIMIT")
        try:
            if _digest(self.executable) != self._binary_digest:
                raise ObservationError("OBSERVATION_BINARY_CHANGED")
            with tempfile.TemporaryDirectory(prefix="nc25-observation-", dir=self.scratch_dir) as directory:
                path = Path(directory) / "request.json"
                path.write_bytes(raw)
                output = _run_process([str(self.executable), str(path)], self.timeout_seconds)
            if _digest(self.executable) != self._binary_digest:
                raise ObservationError("OBSERVATION_BINARY_CHANGED")
        except OSError as error:
            raise ObservationError("OBSERVATION_BINARY") from error
        return _decode_output(output, request)

    def __call__(self, intent: dict, now) -> dict:
        snapshot = copy.deepcopy(intent)
        query = observation_query(snapshot)
        baseline = (self.base_resolver(copy.deepcopy(snapshot), now)
                    if self.base_resolver is not None
                    else {name: copy.deepcopy(snapshot[name]) for name in CONTROL_FIELDS})
        # Materialize the core Mapping contract before copying read-only views.
        if isinstance(baseline, Mapping):
            baseline = dict(baseline)
            for name in CONTROL_BOOLEAN_FIELDS:
                if isinstance(baseline.get(name), Mapping):
                    baseline[name] = dict(baseline[name])
        controls = copy.deepcopy(baseline)
        # Ledger validates the complete result; reject a missing selected control here.
        if (not isinstance(controls, dict) or set(controls) != set(CONTROL_FIELDS)
                or not isinstance(controls["prerequisite_results"], dict)
                or type(controls["prerequisite_results"].get(self.prerequisite_id)) is not bool
                or not isinstance(controls["ambiguity_flags"], list)):
            raise ObservationError("OBSERVATION_CONTROLS")
        request = copy.deepcopy(self.request_provider(copy.deepcopy(snapshot), now))
        if not isinstance(request, dict) or request.get("query") != query:
            raise ObservationError("OBSERVATION_BINDING")
        if request.get("target") != self.target:
            raise ObservationError("OBSERVATION_TARGET")
        report = self._evaluate(request)
        definite = report["verdict"] == "target_true_in_declared_fibre"
        controls["prerequisite_results"][self.prerequisite_id] = (
            controls["prerequisite_results"][self.prerequisite_id] and definite)
        if report["verdict"] in {"insufficient_basis", "outside_declared_domain"}:
            if "OBSERVATION_UNDETERMINED" not in controls["ambiguity_flags"]:
                controls["ambiguity_flags"].append("OBSERVATION_UNDETERMINED")
        return controls


def configure_observation_controls(*, enabled: bool, executable: Path | None = None,
                                   prerequisite_id: str | None = None, target: str | None = None,
                                   request_provider: Callable | None = None,
                                   base_resolver: Callable | None = None,
                                   timeout_seconds: float = 5.0,
                                   scratch_dir: Path | None = None) -> Any:
    """Select the optional module before constructing UniversalConnectionLedger.

    Disabled returns the original resolver unchanged, without loading Lean or
    touching an executable. Enabled failures never fall back to that resolver.
    """
    if type(enabled) is not bool:
        raise ObservationError("OBSERVATION_CONFIG")
    if not enabled:
        return base_resolver
    return ObservationControls(executable, prerequisite_id, target, request_provider,
                               base_resolver, timeout_seconds, scratch_dir)
