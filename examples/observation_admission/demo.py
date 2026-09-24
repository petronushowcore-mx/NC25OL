"""Native observation classification composed with a synthetic Ledger admission."""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile

ROOT = Path(os.environ.get("NC25_LEDGER_ROOT", Path(__file__).resolve().parents[2])).resolve()
sys.path.insert(0, str(ROOT / "sdk" / "python"))
from nc25_universal_ledger import (
    CONTROL_FIELDS, FixedClock, UniversalConnectionLedger, bind_fixture, sha256_hex,
)
from nc25_observation import configure_observation_controls, observation_query

TARGET = "declared_content_condition"


def request_for(intent, values=(True,)):
    """Construct declared cases for this exact intent; values are synthetic premises."""
    query = observation_query(intent)
    return {"schema": 1, "target": TARGET, "query": query,
            "worlds": [{"id": f"case-{index}", **query, "target_holds": value}
                       for index, value in enumerate(values)]}


def controls_from(intent):
    return {name: copy.deepcopy(intent[name]) for name in CONTROL_FIELDS}


class Fixture:
    """Explicit fixed-time authority fixture; no external system is modified."""
    def __init__(self, directory):
        self.directory = Path(directory)
        raw = json.loads((ROOT / "profiles/document-release/reference-connection.json").read_text(encoding="utf-8"))
        self.profile, self.declaration, self.grant, self.intent = bind_fixture(
            *(raw[name] for name in ("profile", "declaration", "grant", "intent")))
        self.evidence = copy.deepcopy(raw["evidence"])
        self.clock = FixedClock(datetime(2026, 8, 1, 10, tzinfo=timezone.utc))
        self.key = secrets.token_bytes(32)

    def open(self, resolver=None, *, durable=False, activate=True):
        engine = UniversalConnectionLedger(
            self.profile, self.declaration, self.key, clock=self.clock,
            control_resolver=resolver,
            state_path=self.directory / "ledger.sqlite" if durable else None)
        if activate:
            engine.activate(self.declaration["governance"]["approval_owner_id"],
                            "evidence://synthetic/observation-example", actor_scope="nc25.governance")
            engine.issue_grant(self.grant, actor_scope="nc25.governance")
        return engine

    def evaluate(self, engine, *, fresh=None):
        intent, evidence = copy.deepcopy(self.intent), copy.deepcopy(self.evidence)
        if fresh is not None:
            intent["idempotency_key"] = fresh
            intent["intent_id"] = fresh
            evidence["intent_id"] = fresh
        return engine.evaluate_intent(intent, evidence, actor_scope="nc25.operator")

    def execution(self, permit_hash):
        return {"message_type": "execution_request", "permit_hash": permit_hash,
                "connector_id": self.intent["connector_id"], "binding": self.intent["binding"],
                "state_anchor_hash": self.intent["state_anchor_hash"], "outcome": "COMMITTED",
                "downstream_receipt_hash": sha256_hex({"synthetic_receipt": True}),
                "committed_at": "2026-08-01T10:00:00Z"}


def run(executable, directory, *, enabled=True, values=(True,)):
    fixture = Fixture(directory)
    resolver = configure_observation_controls(
        enabled=enabled, executable=executable, prerequisite_id="CONTENT_APPROVED",
        target=TARGET, request_provider=lambda intent, now: request_for(intent, values),
        scratch_dir=directory)
    engine = fixture.open(resolver)
    result = fixture.evaluate(engine)
    answer = {"module_enabled": enabled, "supplied_target_values": list(values),
              "disposition": result["disposition"], "permit_issued": bool(engine.permits),
              "observation_scope": "supplied_compatible_worlds" if enabled else None,
              "synthetic_fixture": True}
    if result["disposition"] == "ALLOW":
        request = fixture.execution(result["permit_hash"])
        receipt = engine.commit_execution(request, actor_scope="nc25.executor",
                                          route_permit_hash=request["permit_hash"])
        answer["recorded_outcome"] = receipt["outcome"]
        answer["synthetic_execution"] = True
    return answer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, default=os.environ.get("NC25_OBSERVATION_ENGINE"))
    parser.add_argument("--disabled", action="store_true")
    parser.add_argument("--case", choices=("true", "false", "mixed", "outside"), default="true")
    parser.add_argument("--scratch", type=Path)
    args = parser.parse_args()
    if not args.disabled and args.engine is None:
        parser.error("provide --engine or NC25_OBSERVATION_ENGINE")
    values = {"true": (True,), "false": (False,), "mixed": (True, False), "outside": ()}[args.case]
    with tempfile.TemporaryDirectory(prefix="nc25-observation-demo-", dir=args.scratch) as directory:
        print(json.dumps(run(args.engine, Path(directory), enabled=not args.disabled, values=values), indent=2))


if __name__ == "__main__":
    main()