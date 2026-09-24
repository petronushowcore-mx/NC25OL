"""Native executable and Ledger composition checks; no live authority is exercised."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from demo import Fixture, TARGET, controls_from, request_for
import nc25_observation as observation
from nc25_universal_ledger import ContractViolation, sha256_hex


class Cases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("NC25_OBSERVATION_ENGINE")
        if not configured:
            raise RuntimeError("NC25_OBSERVATION_ENGINE is required; native checks cannot be skipped")
        cls.executable = Path(configured).resolve(strict=True)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="nc25-observation-test-")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.fixture = Fixture(self.path)

    def resolver(self, values=(True,), **kwargs):
        config = {"enabled": True, "executable": self.executable,
                  "prerequisite_id": "CONTENT_APPROVED", "target": TARGET,
                  "request_provider": lambda intent, now: request_for(intent, values),
                  "scratch_dir": self.path}
        config.update(kwargs)
        return observation.configure_observation_controls(**config)

    def assert_closed(self, resolver):
        engine = self.fixture.open(resolver)
        with self.assertRaisesRegex(ContractViolation, "CONTROL_RESOLUTION_FAILED"):
            self.fixture.evaluate(engine)
        self.assertEqual(engine.permits, {}, "NO_PERMIT_AFTER_RESOLVER_FAILURE")
        self.assertEqual(engine.idempotency, {}, "FAILURE_DOES_NOT_BURN_RETRY_KEY")
        return engine

    def report(self, request):
        return {"schema": 1, "target": request["target"], "scope": "supplied_compatible_worlds",
                "query": request["query"], "verdict": "target_true_in_declared_fibre",
                "matching_world_ids": [world["id"] for world in request["worlds"]]}

    def test_a_disabled_does_not_touch_engine_or_callbacks(self):
        def baseline(intent, now):
            return controls_from(intent)
        resolver = observation.configure_observation_controls(
            enabled=False, executable=self.path / "missing", base_resolver=baseline,
            request_provider=lambda *args: self.fail("DISABLED_PROVIDER_CALLED"))
        self.assertIs(resolver, baseline, "DISABLED_PRESERVES_RESOLVER_IDENTITY")
        self.assertIsNone(observation.configure_observation_controls(enabled=False))
        result = self.fixture.evaluate(self.fixture.open(resolver))
        self.assertEqual(result["disposition"], "ALLOW", "DISABLED_ORDINARY_ADMISSION")

    def test_b_native_true_commits_once(self):
        engine = self.fixture.open(self.resolver())
        result = self.fixture.evaluate(engine)
        self.assertEqual(result["disposition"], "ALLOW", "DEFINITE_TRUE_CAN_PASS")
        before = engine.structural_remaining
        request = self.fixture.execution(result["permit_hash"])
        receipt = engine.commit_execution(request, actor_scope="nc25.executor",
                                          route_permit_hash=request["permit_hash"])
        self.assertEqual(receipt["outcome"], "COMMITTED", "REAL_LEDGER_COMMIT")
        self.assertLess(engine.structural_remaining, before, "COMMIT_DEBITS_BUDGET")
        after = engine.structural_remaining
        self.assertEqual(engine.commit_execution(request, actor_scope="nc25.executor",
                         route_permit_hash=request["permit_hash"]), receipt, "EXACT_EXECUTION_REPLAY")
        self.assertEqual(engine.structural_remaining, after, "NO_SECOND_DEBIT")

    def test_c_false_cannot_issue_permit(self):
        engine = self.fixture.open(self.resolver((False,)))
        result = self.fixture.evaluate(engine)
        self.assertEqual(result["disposition"], "REFUSAL", "FALSE_REFUSES")
        self.assertEqual(engine.permits, {}, "FALSE_HAS_NO_PERMIT")

    def test_d_mixed_requires_review(self):
        resolver = self.resolver((True, False))
        controls = resolver(self.fixture.intent, self.fixture.clock.now())
        self.assertIn("OBSERVATION_UNDETERMINED", controls["ambiguity_flags"], "MIXED_IS_UNDETERMINED")
        engine = self.fixture.open(resolver)
        self.assertEqual(self.fixture.evaluate(engine)["disposition"], "MANUAL_REVIEW", "MIXED_REVIEW")
        self.assertEqual(engine.permits, {}, "MIXED_HAS_NO_PERMIT")

    def test_e_outside_requires_review(self):
        engine = self.fixture.open(self.resolver(()))
        self.assertEqual(self.fixture.evaluate(engine)["disposition"], "MANUAL_REVIEW", "OUTSIDE_REVIEW")
        self.assertEqual(engine.permits, {}, "OUTSIDE_HAS_NO_PERMIT")

    def test_f_true_cannot_erase_false_baseline(self):
        def baseline(intent, now):
            result = controls_from(intent)
            result["prerequisite_results"]["CONTENT_APPROVED"] = False
            return result
        engine = self.fixture.open(self.resolver(base_resolver=baseline))
        self.assertEqual(self.fixture.evaluate(engine)["disposition"], "REFUSAL", "BASELINE_FALSE_PRESERVED")
        self.assertEqual(engine.permits, {}, "BASELINE_REFUSAL_HAS_NO_PERMIT")

    def test_g_other_controls_preserved(self):
        for field, key, value, disposition in (
            ("prerequisite_results", "DESTINATION_AUTHORIZED", False, "REFUSAL"),
            ("hard_block_flags", "RETENTION_HOLD", True, "REFUSAL"),
            ("manual_review_flags", "CLASSIFICATION_UNCERTAIN", True, "MANUAL_REVIEW"),
            ("ambiguity_flags", None, "OTHER_UNCERTAINTY", "MANUAL_REVIEW"),
        ):
            with self.subTest(field=field):
                def baseline(intent, now):
                    result = controls_from(intent)
                    if key is None:
                        result[field].append(value)
                    else:
                        result[field][key] = value
                    return result
                resolver = self.resolver(base_resolver=baseline)
                actual = resolver(self.fixture.intent, self.fixture.clock.now())
                self.assertEqual(actual, baseline(self.fixture.intent, None), "OTHER_CONTROLS_UNCHANGED")
                engine = self.fixture.open(resolver)
                self.assertEqual(self.fixture.evaluate(engine)["disposition"], disposition)
                self.assertEqual(engine.permits, {}, "OTHER_CONTROLS_HAVE_NO_PERMIT")

    def test_h_callbacks_cannot_rebind_original_intent(self):
        original = copy.deepcopy(self.fixture.intent)
        seen = []
        def baseline(intent, now):
            controls = controls_from(intent)
            intent["payload_hash"] = "A" * 64
            return controls
        def provider(intent, now):
            seen.append(copy.deepcopy(intent))
            request = request_for(intent)
            intent["payload_hash"] = "B" * 64
            return request
        resolver = self.resolver(base_resolver=baseline, request_provider=provider)
        resolver(self.fixture.intent, self.fixture.clock.now())
        self.assertEqual(seen, [original], "PROVIDER_SEES_ORIGINAL_INTENT")
        self.assertEqual(self.fixture.intent, original, "CALLBACKS_DO_NOT_MUTATE_CALLER")
        def rebinding_provider(intent, now):
            intent["payload_hash"] = "C" * 64
            return request_for(intent)
        self.assert_closed(self.resolver(request_provider=rebinding_provider))

    def test_i_query_binds_full_intent_and_binding(self):
        intent = self.fixture.intent
        expected = {"skeleton": sha256_hex(intent["binding"]), "observation": sha256_hex(intent)}
        self.assertEqual(observation.observation_query(intent), expected, "EXACT_INTENT_QUERY")
        for part in ("skeleton", "observation"):
            with self.subTest(part=part):
                def provider(intent, now):
                    request = request_for(intent)
                    request["query"][part] = "0" * 64
                    return request
                self.assert_closed(self.resolver(request_provider=provider))

    def test_j_target_mismatch_refuses(self):
        def provider(intent, now):
            request = request_for(intent)
            request["target"] = "other_target"
            return request
        self.assert_closed(self.resolver(request_provider=provider))

    def test_k_output_schema_and_binding_refuse(self):
        resolver = self.resolver()
        request = request_for(self.fixture.intent)
        good = self.report(request)
        altered = []
        for field, value in (("schema", True), ("schema", 2), ("scope", "all_worlds"),
                             ("target", "another_target"), ("query", {"skeleton": "other", "observation": "other"}),
                             ("matching_world_ids", ["not_a_case"]), ("verdict", "ALLOW")):
            candidate = copy.deepcopy(good)
            candidate[field] = value
            altered.append(candidate)
        extra = copy.deepcopy(good)
        extra["extra"] = True
        altered.append(extra)
        for candidate in altered:
            with self.subTest(candidate=candidate):
                with mock.patch.object(observation, "_run_process", return_value=json.dumps(candidate).encode()):
                    self.assert_closed(resolver)

    def test_l_duplicate_and_invalid_json_refuse(self):
        resolver = self.resolver()
        request = request_for(self.fixture.intent)
        valid = json.dumps(self.report(request))
        for raw in (b"", b"not JSON", b"\xff", b'{"schema":1,"schema":1}',
                    valid.replace('"schema": 1', '"schema": 1, "schema": 1').encode(),
                    valid.replace('"schema": 1', '"schema": NaN').encode()):
            with self.subTest(raw=raw[:40]):
                with mock.patch.object(observation, "_run_process", return_value=raw):
                    self.assert_closed(resolver)

    def test_m_malformed_input_refuses(self):
        for field, value in (("schema", True), ("worlds", "not_cases"), ("unexpected", True)):
            with self.subTest(field=field):
                def provider(intent, now):
                    request = request_for(intent)
                    request[field] = value
                    return request
                self.assert_closed(self.resolver(request_provider=provider))

    def test_n_provider_and_process_errors_are_closed(self):
        def broken_provider(intent, now):
            raise RuntimeError("provider unavailable")
        self.assert_closed(self.resolver(request_provider=broken_provider))
        resolver = self.resolver()
        with mock.patch.object(observation, "_run_process", side_effect=observation.ObservationError("OBSERVATION_TIMEOUT")):
            self.assert_closed(resolver)

    def test_o_native_missing_or_changed_refuses(self):
        with self.assertRaises(observation.ObservationError, msg="MISSING_FAILS_STARTUP"):
            self.resolver(executable=self.path / "absent-engine")
        copied = self.path / self.executable.name
        shutil.copy2(self.executable, copied)
        resolver = self.resolver(executable=copied)
        with copied.open("ab") as stream:
            stream.write(b"changed")
        self.assert_closed(resolver)
        copied.unlink()
        self.assert_closed(resolver)

    def test_p_process_timeout_and_output_are_bounded(self):
        with self.assertRaisesRegex(observation.ObservationError, "OBSERVATION_TIMEOUT"):
            observation._run_process([sys.executable, "-c", "import time; time.sleep(2)"], 0.05)
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream):
                command = f"import sys; sys.{stream}.buffer.write(b'x' * 2097153)"
                with self.assertRaisesRegex(observation.ObservationError, "OBSERVATION_OUTPUT_LIMIT"):
                    observation._run_process([sys.executable, "-c", command], 5)
        self.assertEqual(observation._run_process([sys.executable, "-c", "print('bounded')"], 5),
                         b"bounded\r\n" if os.name == "nt" else b"bounded\n", "SMALL_OUTPUT_SURVIVES")
        with self.assertRaisesRegex(observation.ObservationError, "OBSERVATION_PROCESS_FAILED"):
            observation._run_process([sys.executable, "-c", "raise SystemExit(2)"], 5)

    def test_q_no_authority_or_executor_bypass(self):
        calls = []
        def provider(intent, now):
            calls.append(True)
            return request_for(intent)
        engine = self.fixture.open(self.resolver(request_provider=provider))
        self.fixture.intent["requester_id"] = "unapproved-requester"
        self.assertEqual(self.fixture.evaluate(engine)["disposition"], "REFUSAL", "AUTHORITY_STILL_REQUIRED")
        self.assertEqual(calls, [], "NO_OBSERVATION_BEFORE_AUTHORITY")
        self.assertEqual(engine.permits, {})
        self.fixture.intent["requester_id"] = self.fixture.grant["subject_id"]
        result = self.fixture.evaluate(engine, fresh="authorized-request")
        self.assertEqual(result["disposition"], "ALLOW")
        request = self.fixture.execution(result["permit_hash"])
        with self.assertRaises(ContractViolation, msg="EXECUTOR_SCOPE_STILL_REQUIRED"):
            engine.commit_execution(request, actor_scope="nc25.operator", route_permit_hash=request["permit_hash"])
        self.assertFalse(engine.permits[result["permit_hash"]].consumed)

    def test_r_replay_and_restart_preserve_issued_permit(self):
        engine = self.fixture.open(durable=True)
        first = self.fixture.evaluate(engine)
        self.assertEqual(first["disposition"], "ALLOW")
        calls = []
        def provider(intent, now):
            calls.append(intent["intent_id"])
            return request_for(intent, (True, False))
        restarted = self.fixture.open(self.resolver(request_provider=provider), durable=True, activate=False)
        self.assertEqual(self.fixture.evaluate(restarted), first, "REPLAY_IS_NOT_NEW_ADMISSION")
        self.assertEqual(calls, [], "REPLAY_DOES_NOT_RERUN_OBSERVATION")
        request = self.fixture.execution(first["permit_hash"])
        receipt = restarted.commit_execution(request, actor_scope="nc25.executor", route_permit_hash=request["permit_hash"])
        self.assertEqual(receipt["outcome"], "COMMITTED", "EXISTING_PERMIT_RETAINS_LIFETIME")
        self.assertEqual(calls, [], "COMMIT_IS_NOT_NEW_ADMISSION")
        self.assertEqual(self.fixture.evaluate(restarted, fresh="new-observation")["disposition"], "MANUAL_REVIEW")
        self.assertEqual(calls, ["new-observation"], "NEW_KEY_OBTAINS_NEW_OBSERVATION")

    def test_s_missing_selected_control_refuses(self):
        self.assert_closed(self.resolver(prerequisite_id="UNKNOWN_CONTROL"))

    def test_t_ambiguity_is_preserved_without_duplicate(self):
        def baseline(intent, now):
            result = controls_from(intent)
            result["ambiguity_flags"] = ["OTHER_UNCERTAINTY", "OBSERVATION_UNDETERMINED"]
            return result
        resolver = self.resolver((True, False), base_resolver=baseline)
        self.assertEqual(resolver(self.fixture.intent, self.fixture.clock.now())["ambiguity_flags"],
                         ["OTHER_UNCERTAINTY", "OBSERVATION_UNDETERMINED"])

    def test_u_mixed_witness_envelope_checked(self):
        request = request_for(self.fixture.intent, (True, False))
        good = self.report(request)
        good.update(verdict="insufficient_basis", witness={"true_world_id": "case-0", "false_world_id": "case-1"})
        self.assertEqual(observation._decode_output(json.dumps(good).encode(), request), good)
        bad = copy.deepcopy(good)
        bad["witness"]["false_world_id"] = "case-0"
        with self.assertRaises(observation.ObservationError, msg="OPPOSING_WITNESS_REQUIRED"):
            observation._decode_output(json.dumps(bad).encode(), request)
        good["verdict"] = "outside_declared_domain"
        del good["witness"]
        with self.assertRaises(observation.ObservationError, msg="OUTSIDE_REQUIRES_EMPTY_FIBRE"):
            observation._decode_output(json.dumps(good).encode(), request)

    def test_v_mapping_baselines_preserve_core_contract(self):
        from collections import UserDict
        from types import MappingProxyType
        fields = ("prerequisite_results", "hard_block_flags", "manual_review_flags")
        for wrapper in (dict, UserDict, MappingProxyType):
            for field in (None, *fields):
                if wrapper is dict and field is not None:
                    continue
                def baseline(intent, now):
                    result = controls_from(intent)
                    if field is None:
                        return wrapper(result)
                    result[field] = wrapper(result[field])
                    return result
                for enabled in (False, True):
                    with self.subTest(wrapper=wrapper.__name__, field=field, enabled=enabled):
                        resolver = self.resolver(base_resolver=baseline) if enabled else baseline
                        engine = self.fixture.open(resolver)
                        try:
                            result = self.fixture.evaluate(engine)
                        except ContractViolation as error:
                            self.fail(f"MAPPING_BASELINE_COMPATIBLE: {error}")
                        self.assertEqual(result["disposition"], "ALLOW", "MAPPING_BASELINE_COMPATIBLE")

    def test_w_invalid_mapping_controls_remain_closed(self):
        fields = ("prerequisite_results", "hard_block_flags", "manual_review_flags")
        invalid = [("outer", None), ("ambiguity_flags", ()), ("extra", True)]
        invalid += [(field, "pairs") for field in fields]
        invalid += [(field, "integer") for field in fields]
        for field, value in invalid:
            def baseline(intent, now):
                result = controls_from(intent)
                if field == "outer":
                    return list(result.items())
                if value == "pairs":
                    result[field] = list(result[field].items())
                elif value == "integer":
                    result[field][next(iter(result[field]))] = 1
                else:
                    result[field] = value
                return result
            for enabled in (False, True):
                with self.subTest(field=field, value=value, enabled=enabled):
                    resolver = self.resolver(base_resolver=baseline) if enabled else baseline
                    engine = self.fixture.open(resolver)
                    with self.assertRaisesRegex(ContractViolation, "CONTROL_RESOLUTION_(FAILED|INVALID)"):
                        self.fixture.evaluate(engine)
                    self.assertEqual(engine.permits, {}, "INVALID_MAPPING_HAS_NO_PERMIT")
                    self.assertEqual(engine.idempotency, {}, "INVALID_MAPPING_KEEPS_RETRY_KEY")


    def test_x_definite_verdict_matches_supplied_premises(self):
        for expected, verdict in (
            (True, "target_true_in_declared_fibre"),
            (False, "target_false_in_declared_fibre"),
        ):
            for values in ((expected,), (expected, expected)):
                with self.subTest(expected=expected, values=values, valid=True):
                    request = request_for(self.fixture.intent, values)
                    good = self.report(request)
                    good["verdict"] = verdict
                    # Opposing cases outside this query must not invalidate it.
                    unrelated = dict(request["worlds"][0], id="other-case",
                                     observation="another-observation", target_holds=not expected)
                    request["worlds"].append(unrelated)
                    self.assertEqual(observation._decode_output(json.dumps(good).encode(), request),
                                     good, "DEFINITE_USES_ONLY_MATCHING_CASES")
            for values in ((not expected,), (expected, not expected), (not expected, expected)):
                with self.subTest(expected=expected, values=values, valid=False):
                    request = request_for(self.fixture.intent, values)
                    bad = self.report(request)
                    bad["verdict"] = verdict
                    resolver = self.resolver(values)
                    with mock.patch.object(observation, "_run_process",
                                           return_value=json.dumps(bad).encode()):
                        self.assert_closed(resolver)


if __name__ == "__main__":
    unittest.main()