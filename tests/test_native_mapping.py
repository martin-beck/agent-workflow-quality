# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Native-gate mapping contract, hostile input and evidence normalization tests."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from awq import native_mapping
from awq.cli import main
from awq.project import ProjectError
from awq.registry import canonical_bytes
from scripts.validate_contracts import validate

ROOT = Path(__file__).resolve().parents[1]


def document() -> dict[str, Any]:
    return dict(json.loads((ROOT / "fixtures/conforming/native-gate-mapping.json").read_bytes()))


def document_v2() -> dict[str, Any]:
    return dict(json.loads((ROOT / "fixtures/conforming/native-gate-mapping-v2.json").read_bytes()))


class NativeMappingTests(unittest.TestCase):
    def test_v2_correlates_sequential_observations_without_equating_producers(self) -> None:
        value = document_v2()
        validate(value, "native-gate-mapping.schema.json")
        for observation in value["observations"]:
            validate(observation["identity"], "evidence-identity.schema.json")
        result = native_mapping.evaluate(value)
        self.assertEqual("pass", result["status"])
        self.assertEqual(2, result["schema_version"])
        self.assertEqual([], result["mappings"][0]["correlation_mismatches"])
        self.assertEqual("native", result["mappings"][0]["platform_class"])
        self.assertEqual("SET-PYTHON-20260910", result["mappings"][0]["observation_set_id"])
        rendered = json.dumps(result, sort_keys=True)
        for excluded in ("correlation_sha256", "producer_sha256", "tool_sha256", "run_id"):
            self.assertNotIn(excluded, rendered)

    def test_v2_wrong_set_scope_source_and_tree_fail_closed(self) -> None:
        cases: list[tuple[list[str | int], Any, str]] = [
            (
                ["observations", 0, "identity", "correlation_sha256"],
                "0" * 64,
                "awq-correlation",
            ),
            (
                ["mappings", 0, "correlation", "input_sha256"],
                "0" * 64,
                "awq-correlation",
            ),
            (
                ["mappings", 0, "correlation", "source_tree"],
                "0" * 40,
                "awq-correlation",
            ),
            (
                ["observations", 0, "source"],
                "awq-requirement",
                "missing-or-wrong-evidence",
            ),
        ]
        for path, replacement, expected in cases:
            with self.subTest(path=path):
                value = document_v2()
                target: Any = value
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = replacement
                if expected == "missing-or-wrong-evidence":
                    with self.assertRaisesRegex(ProjectError, expected):
                        native_mapping.evaluate(value)
                else:
                    result = native_mapping.evaluate(value)
                    self.assertEqual("fail", result["status"])
                    self.assertIn(expected, result["mappings"][0]["correlation_mismatches"])

    def test_v2_freshness_future_and_platform_promotion_are_explicit(self) -> None:
        cases: list[tuple[list[str | int], Any, str]] = [
            (["observations", 0, "identity", "collected_at"], "2026-09-10T20:00:00Z", "awq-stale"),
            (
                ["observations", 1, "identity", "collected_at"],
                "2026-09-10T20:21:00Z",
                "native-collected-in-future",
            ),
            (
                ["observations", 1, "identity", "platform_class"],
                "hosted-portability",
                "native-platform-class-promotion",
            ),
            (
                ["observations", 1, "identity", "tool_sha256"],
                "0" * 64,
                "native-tool-pin",
            ),
        ]
        for path, replacement, expected in cases:
            with self.subTest(expected=expected):
                value = document_v2()
                target: Any = value
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = replacement
                result = native_mapping.evaluate(value)
                self.assertEqual("fail", result["status"])
                self.assertIn(expected, result["mappings"][0]["correlation_mismatches"])

    def test_v2_dirty_tree_unknown_fields_and_malformed_identity_are_rejected(self) -> None:
        candidates = []
        value = document_v2()
        value["mappings"][0]["correlation"]["tree_state"] = "dirty"
        candidates.append(value)
        value = document_v2()
        value["observations"][0]["identity"]["host"] = "PRIVATE-MACHINE"
        candidates.append(value)
        value = document_v2()
        value["observations"][0]["identity"]["attempt"] = True
        candidates.append(value)
        value = document_v2()
        value["evaluated_at"] = "2026-09-10T22:20:00+02:00"
        candidates.append(value)
        for candidate in candidates:
            with self.assertRaises(ProjectError) as caught:
                native_mapping.evaluate(candidate)
            self.assertNotIn("PRIVATE-MACHINE", str(caught.exception))

    def test_v2_observation_set_identifiers_are_unique(self) -> None:
        value = document_v2()
        second = copy.deepcopy(value["mappings"][0])
        second["id"] = "NATIVE-PYTHON-SECOND"
        value["mappings"].append(second)
        with self.assertRaisesRegex(ProjectError, "observation-set-duplicate"):
            native_mapping.evaluate(value)

    def test_v1_remains_legacy_digest_only_evidence(self) -> None:
        result = native_mapping.evaluate(document())
        self.assertEqual(1, result["schema_version"])
        self.assertNotIn("correlation_mismatches", result["mappings"][0])
        value = document()
        value["evaluated_at"] = "2026-09-10T20:20:00Z"
        with self.assertRaises(ProjectError):
            native_mapping.evaluate(value)

    def test_schema_examples_coverage_and_determinism(self) -> None:
        value = document()
        validate(value, "native-gate-mapping.schema.json")
        first = native_mapping.evaluate(value)
        self.assertEqual(first, native_mapping.evaluate(json.loads(canonical_bytes(value))))
        self.assertEqual("pass", first["status"])
        self.assertEqual({"mapped": 5, "equivalent": 5, "unresolved": 0}, first["coverage"])
        self.assertTrue(all(item["native_gate"] == "retain" for item in first["mappings"]))
        self.assertEqual({"adapter"}, {item["awq_result"]["kind"] for item in first["mappings"]})
        rendered = json.dumps(first, sort_keys=True)
        self.assertNotIn("native_command", rendered)
        self.assertNotIn("evidence_sha256", rendered)

    def test_requirement_and_adapter_sources_remain_distinct(self) -> None:
        value = document()
        mapping = value["mappings"][0]
        mapping["awq_result"] = {"identifier": mapping["requirement"], "kind": "requirement"}
        value["observations"][0]["source"] = "awq-requirement"
        result = native_mapping.evaluate(value)
        self.assertEqual("requirement", result["mappings"][0]["awq_result"]["kind"])
        self.assertEqual("retain", result["native_gate"])

    def test_mismatch_and_inconclusive_are_truthful_failures(self) -> None:
        for status in ("fail", "error", "skip"):
            with self.subTest(status=status):
                value = document()
                value["observations"][0]["status"] = status
                result = native_mapping.evaluate(value)
                self.assertEqual("fail", result["status"])
                self.assertEqual(1, result["coverage"]["unresolved"])
                self.assertFalse(result["mappings"][0]["equivalent"])

    def test_missing_duplicate_and_wrong_source_evidence_fail_closed(self) -> None:
        candidates = []
        missing = document()
        missing["observations"].pop(0)
        candidates.append(missing)
        duplicate = document()
        duplicate["observations"].insert(1, copy.deepcopy(duplicate["observations"][0]))
        candidates.append(duplicate)
        wrong = document()
        wrong["observations"][0]["source"] = "awq-requirement"
        candidates.append(wrong)
        for candidate in candidates:
            with self.assertRaises(ProjectError):
                native_mapping.evaluate(candidate)
        for name in ("missing-evidence.json", "contradictory-evidence.json"):
            value = json.loads(
                (ROOT / "fixtures/nonconforming/native-gate-mapping" / name).read_bytes()
            )
            validate(value, "native-gate-mapping.schema.json")
            with self.assertRaises(ProjectError):
                native_mapping.evaluate(value)

    def test_unknown_references_classification_and_claim_fail_closed(self) -> None:
        mutations: list[tuple[list[str | int], Any]] = [
            (["schema_version"], 2),
            (["mappings", 0, "requirement"], "AWQ-UNKNOWN-999"),
            (["mappings", 0, "requirement"], []),
            (["mappings", 0, "awq_result", "identifier"], "ADAPTER-UNKNOWN"),
            (["mappings", 0, "awq_result", "identifier"], []),
            (["mappings", 0, "tier"], "release"),
            (["mappings", 0, "evidence_class"], "proof"),
            (["mappings", 0, "input_scope"], "../private"),
            (["mappings", 0, "deadline_seconds"], 0),
            (["mappings", 0, "claim"], "certified"),
            (["observations", 0, "status"], "success"),
            (["observations", 0, "evidence_sha256"], "not-a-digest"),
            (["observations", 0, "mapping"], []),
            (["mappings", 0, "tool_pin", "name"], 1),
        ]
        for path, replacement in mutations:
            with self.subTest(path=path):
                value = document()
                target: Any = value
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = replacement
                with self.assertRaises(ProjectError):
                    native_mapping.evaluate(value)

    def test_unsafe_commands_and_private_values_are_rejected_without_echo(self) -> None:
        for replacement in (
            ["/usr/bin/python3", "-m", "unittest"],
            ["python3", "../private/test.py"],
            ["python3", "https://example.invalid/tool"],
            ["python3", "$TOKEN"],
            ["python3", "--" + "token" + "=PRIVATE_MARKER"],
        ):
            value = document()
            value["mappings"][3]["native_command"] = replacement
            with self.assertRaises(ProjectError) as caught:
                native_mapping.evaluate(value)
            self.assertNotIn("PRIVATE_MARKER", str(caught.exception))
        value = document()
        value["mappings"][0]["limitation"] = "leak /" + "home" + "/private-user/source"
        with self.assertRaises(ProjectError) as caught:
            native_mapping.evaluate(value)
        self.assertNotIn("private-user", str(caught.exception))

    def test_order_unknown_fields_boolean_integer_and_tool_binding_fail_closed(self) -> None:
        candidates = []
        value = document()
        value["mappings"].reverse()
        candidates.append(value)
        value = document()
        value["mappings"][0]["prompt"] = "PRIVATE_MARKER"
        candidates.append(value)
        value = document()
        value["mappings"][0]["deadline_seconds"] = True
        candidates.append(value)
        value = document()
        value["mappings"][0]["native_command"][0] = "python3"
        candidates.append(value)
        for candidate in candidates:
            with self.assertRaises(ProjectError) as caught:
                native_mapping.evaluate(candidate)
            self.assertNotIn("PRIVATE_MARKER", str(caught.exception))

    def test_cli_confined_canonical_and_duplicate_json(self) -> None:
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = main(
                [
                    "--root",
                    str(ROOT),
                    "native-map-evaluate",
                    "fixtures/conforming/native-gate-mapping.json",
                    "--format",
                    "json",
                ]
            )
        self.assertEqual(0, code)
        self.assertEqual("pass", json.loads(stream.getvalue())["status"])
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = main(
                [
                    "--root",
                    str(ROOT),
                    "native-map-evaluate",
                    "fixtures/conforming/native-gate-mapping-v2.json",
                    "--format",
                    "json",
                ]
            )
        v2_result = json.loads(stream.getvalue())
        self.assertEqual(0, code)
        self.assertEqual(2, v2_result["schema_version"])
        self.assertEqual([], v2_result["mappings"][0]["correlation_mismatches"])
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")
            relative = path.relative_to(ROOT).as_posix()
            with self.assertRaises(ProjectError):
                native_mapping.evaluate_file(ROOT, relative)
        for relative in ("../outside.json", "/absolute.json", "not-json.txt"):
            with self.assertRaises(ProjectError):
                native_mapping.evaluate_file(ROOT, relative)


if __name__ == "__main__":
    unittest.main()
