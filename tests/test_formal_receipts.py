# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Formal receipt v2 identity, sensitivity, correspondence and proof-limit tests."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

import jsonschema

from awq import formal_receipts
from awq.cli import main
from awq.project import ProjectError
from awq.registry import canonical_bytes
from scripts.validate_contracts import validate

ROOT = Path(__file__).resolve().parents[1]


def receipt() -> dict[str, Any]:
    return dict(json.loads((ROOT / "templates/formal-execution-receipt.json").read_bytes()))


def expectation() -> dict[str, Any]:
    return dict(json.loads((ROOT / "templates/formal-execution-expectation.json").read_bytes()))


def bind_trace(value: dict[str, Any]) -> dict[str, Any]:
    value["correspondence"]["trace_sha256"] = hashlib.sha256(
        canonical_bytes(value["correspondence"]["trace"])
    ).hexdigest()
    return value


class FormalExecutionReceiptTests(unittest.TestCase):
    def test_exact_receipt_schema_runtime_and_content_minimized_cli(self) -> None:
        value = receipt()
        validate(value, "formal-execution-receipt.schema.json")
        validate(expectation(), "formal-execution-expectation.schema.json")
        result = formal_receipts.evaluate(value, expectation())
        self.assertEqual(result, formal_receipts.evaluate(copy.deepcopy(value), expectation()))
        self.assertEqual("pass", result["status"])
        self.assertEqual("exhausted", result["outcome"])
        self.assertEqual("bounded-trace-correspondence", result["correspondence"]["classification"])
        self.assertEqual("retain", result["native_gate"])
        self.assertEqual(list(formal_receipts.NON_CLAIMS), result["non_claims"])
        self.assertNotIn("trace", result["correspondence"])
        self.assertNotIn("observation_sha256", json.dumps(result))

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(
                [
                    "--root",
                    str(ROOT),
                    "formal-receipt-evaluate",
                    "templates/formal-execution-receipt.json",
                    "templates/formal-execution-expectation.json",
                    "--format",
                    "json",
                ]
            )
        self.assertEqual(0, code)
        self.assertEqual(result, json.loads(output.getvalue()))
        self.assertNotIn(str(ROOT), output.getvalue())

    def test_wrong_identities_bounds_outcomes_and_proof_inflation_fail_closed(self) -> None:
        changes: list[tuple[list[str], Any]] = [
            (["source", "commit"], "0" * 39),
            (["source", "tree"], "private/path"),
            (["model", "source_sha256"], "A" * 64),
            (["model", "config_sha256"], False),
            (["tool", "executable_sha256"], "0" * 63),
            (["run", "argv_sha256"], "g" * 64),
            (["run", "attempt"], True),
            (["bounds", "max_steps"], 0),
            (["bounds", "max_steps"], 1_000_001),
            (["result", "status"], "fail"),
            (["result", "counterexample_sha256"], "8" * 64),
            (["sensitivity", "model_sha256"], "c" * 64),
            (["sensitivity", "expected_outcome"], "verified"),
            (["sensitivity", "observed_outcome"], "exhausted"),
            (["non_claims"], ["unbounded-proof"]),
            (["limitations"], list(reversed(formal_receipts.LIMITATIONS))),
        ]
        for path, replacement in changes:
            value = receipt()
            target: Any = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(ProjectError):
                formal_receipts.evaluate(value, expectation())

        with self.assertRaises(ProjectError):
            formal_receipts.evaluate_file(
                ROOT,
                "fixtures/nonconforming/formal-receipt/proof-inflation.json",
                "templates/formal-execution-expectation.json",
            )

    def test_trusted_expectation_rejects_valid_identity_substitutions(self) -> None:
        changes: list[tuple[list[str], Any]] = [
            (["source", "commit"], "9" * 40),
            (["source", "tree"], "8" * 40),
            (["model", "source_sha256"], "9" * 64),
            (["model", "config_sha256"], "8" * 64),
            (["tool", "executable_sha256"], "7" * 64),
            (["tool", "version"], "1.8.1"),
            (["run", "id"], "RUN-OTHER"),
            (["run", "attempt"], 2),
            (["run", "argv_sha256"], "6" * 64),
            (["bounds", "max_steps"], 17),
            (["result", "outcome"], "verified"),
        ]
        for path, replacement in changes:
            value = receipt()
            target: Any = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = replacement
            if path[0] == "result":
                value["result"]["status"] = "pass"
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(ProjectError, "trusted-identity-mismatch"),
            ):
                formal_receipts.evaluate(value, expectation())

    def test_sensitivity_execution_mutation_and_result_bindings_fail_closed(self) -> None:
        for field, replacement in (
            ("tool_sha256", "0" * 64),
            ("run_sha256", "0" * 64),
            ("bounds_sha256", "0" * 64),
            ("mutation_sha256", "0" * 63),
            ("result_sha256", "0" * 63),
            ("mutation_id", "MUTATION-" + "A" * 101),
        ):
            value = receipt()
            value["sensitivity"][field] = replacement
            with self.subTest(field=field), self.assertRaises(ProjectError):
                formal_receipts.evaluate(value, expectation())

        for version in ("latest2", "2026-main1", "1.0-SNAPSHOT2"):
            value = receipt()
            value["tool"]["version"] = version
            with (
                self.subTest(schema_version=version),
                self.assertRaises(jsonschema.ValidationError),
            ):
                validate(value, "formal-execution-receipt.schema.json")

    def test_trusted_expectation_binds_complete_sensitivity(self) -> None:
        for field, replacement in (
            ("model_sha256", "7" * 64),
            ("config_sha256", "6" * 64),
            ("mutation_id", "MUTATION-OTHER"),
            ("mutation_sha256", "5" * 64),
            ("result_sha256", "4" * 64),
            ("counterexample_sha256", "3" * 64),
        ):
            value = receipt()
            value["sensitivity"][field] = replacement
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ProjectError, "trusted-identity-mismatch"),
            ):
                formal_receipts.evaluate(value, expectation())

    def test_floating_versions_identifier_bounds_and_collection_edges_fail(self) -> None:
        for field, replacement in (
            (["tool", "version"], "latest"),
            (["tool", "version"], "latest2"),
            (["tool", "version"], "2026-main1"),
            (["tool", "version"], "1.0-SNAPSHOT2"),
            (["model", "id"], "MODEL-" + "A" * 101),
            (["tool", "adapter_id"], "ADAPTER-" + "A" * 101),
            (["model", "operations"], []),
            (["model", "states"], ["z", "a"]),
            (["bounds"], {}),
            (["bounds"], {"z": 1, "a": 1}),
            (["correspondence", "classification"], "proof"),
            (["correspondence", "trace"], []),
        ):
            value = receipt()
            target: Any = value
            for key in field[:-1]:
                target = target[key]
            target[field[-1]] = replacement
            with self.subTest(field=field), self.assertRaises(ProjectError):
                formal_receipts.evaluate(value, expectation())

    def test_counterexample_and_incomplete_outcome_semantics(self) -> None:
        counterexample = receipt()
        counterexample["result"].update(
            status="fail", outcome="counterexample", counterexample_sha256="8" * 64
        )
        expected = expectation()
        expected["expected_outcome"] = "counterexample"
        self.assertEqual("fail", formal_receipts.evaluate(counterexample, expected)["status"])
        incomplete = receipt()
        incomplete["result"].update(status="fail", outcome="incomplete")
        expected = expectation()
        expected["expected_outcome"] = "incomplete"
        self.assertEqual("incomplete", formal_receipts.evaluate(incomplete, expected)["outcome"])
        for outcome, digest in (
            ("counterexample", None),
            ("incomplete", "8" * 64),
            ("verified", "8" * 64),
        ):
            value = receipt()
            value["result"].update(
                status="pass" if outcome == "verified" else "fail",
                outcome=outcome,
                counterexample_sha256=digest,
            )
            with self.subTest(outcome=outcome), self.assertRaises(ProjectError):
                formal_receipts.evaluate(value, expectation())

    def test_incomplete_duplicate_and_reordered_mappings_fail(self) -> None:
        for field in ("operation_map", "state_map"):
            for mode in ("missing", "duplicate-target", "reordered", "unknown"):
                value = receipt()
                model_field = "operations" if field == "operation_map" else "states"
                value["model"][model_field] = ["begin", "finish"]
                prefix = "OP" if field == "operation_map" else "STATE"
                value["correspondence"][field] = [
                    {"implementation": f"{prefix}-0000", "model": "begin"},
                    {"implementation": f"{prefix}-0001", "model": "finish"},
                ]
                if mode == "missing":
                    value["correspondence"][field].pop()
                elif mode == "duplicate-target":
                    value["correspondence"][field][1]["implementation"] = f"{prefix}-0000"
                elif mode == "reordered":
                    value["correspondence"][field].reverse()
                else:
                    value["correspondence"][field][1]["model"] = "unknown"
                with self.subTest(field=field, mode=mode), self.assertRaises(ProjectError):
                    formal_receipts.evaluate(value, expectation())

    def test_trace_order_mapping_and_digest_are_bound(self) -> None:
        cases = []
        value = receipt()
        value["correspondence"]["trace"][0]["sequence"] = 1
        cases.append(value)
        value = receipt()
        value["correspondence"]["trace"][0]["implementation_operation"] = "OP-9999"
        cases.append(bind_trace(value))
        value = receipt()
        value["correspondence"]["trace"][0]["implementation_state"] = "STATE-9999"
        cases.append(bind_trace(value))
        value = receipt()
        value["correspondence"]["trace"][0]["observation_sha256"] = "8" * 64
        cases.append(value)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ProjectError):
                formal_receipts.evaluate(value, expectation())

    def test_schema_and_runtime_reject_closed_leaf_shapes(self) -> None:
        cases = []
        for path, replacement in (
            (["schema_version"], 1),
            (["kind"], "proof"),
            (["receipt_id"], "private@example.invalid"),
            (["model", "language"], "dynamic"),
            (["bounds", "max_steps"], 1.5),
        ):
            value = receipt()
            target: Any = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = replacement
            cases.append(value)
        unknown = receipt()
        unknown["private_output"] = "PRIVATE-OUTPUT"
        cases.append(unknown)
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(jsonschema.ValidationError):
                    validate(value, "formal-execution-receipt.schema.json")
                with self.assertRaises(ProjectError) as caught:
                    formal_receipts.evaluate(value, expectation())
                self.assertNotIn("PRIVATE-OUTPUT", str(caught.exception))

    def test_canonical_bounded_confined_file_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "receipt.json"
            path.write_bytes(canonical_bytes(receipt()))
            expected_path = root / "expected.json"
            expected_path.write_bytes(canonical_bytes(expectation()))
            self.assertEqual(
                "pass",
                formal_receipts.evaluate_file(root, "receipt.json", "expected.json")["status"],
            )
            for relative in (
                "../receipt.json",
                "/private/receipt.json",
                "x/../receipt.json",
                "x\\receipt.json",
                "receipt.txt",
                "missing.json",
            ):
                with self.subTest(relative=relative), self.assertRaises(ProjectError):
                    formal_receipts.evaluate_file(root, relative, "expected.json")
            link = root / "link.json"
            link.symlink_to(path)
            with self.assertRaises(ProjectError):
                formal_receipts.evaluate_file(root, "link.json", "expected.json")
            for raw in (
                canonical_bytes(receipt()).rstrip(),
                b'{"kind":"formal-execution-receipt","kind":"proof"}\n',
                b'{"value":NaN}\n',
                b"x" * (formal_receipts.MAX_BYTES + 1),
            ):
                path.write_bytes(raw)
                with self.assertRaises(ProjectError):
                    formal_receipts.evaluate_file(root, "receipt.json", "expected.json")


if __name__ == "__main__":
    unittest.main()
