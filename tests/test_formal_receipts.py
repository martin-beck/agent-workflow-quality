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


def bind_trace(value: dict[str, Any]) -> dict[str, Any]:
    value["correspondence"]["trace_sha256"] = hashlib.sha256(
        canonical_bytes(value["correspondence"]["trace"])
    ).hexdigest()
    return value


class FormalExecutionReceiptTests(unittest.TestCase):
    def test_exact_receipt_schema_runtime_and_content_minimized_cli(self) -> None:
        value = receipt()
        validate(value, "formal-execution-receipt.schema.json")
        result = formal_receipts.evaluate(value)
        self.assertEqual(result, formal_receipts.evaluate(copy.deepcopy(value)))
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
                formal_receipts.evaluate(value)

        with self.assertRaises(ProjectError):
            formal_receipts.evaluate_file(
                ROOT, "fixtures/nonconforming/formal-receipt/proof-inflation.json"
            )

    def test_counterexample_and_incomplete_outcome_semantics(self) -> None:
        counterexample = receipt()
        counterexample["result"].update(
            status="fail", outcome="counterexample", counterexample_sha256="8" * 64
        )
        self.assertEqual("fail", formal_receipts.evaluate(counterexample)["status"])
        incomplete = receipt()
        incomplete["result"].update(status="fail", outcome="incomplete")
        self.assertEqual("incomplete", formal_receipts.evaluate(incomplete)["outcome"])
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
                formal_receipts.evaluate(value)

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
                    formal_receipts.evaluate(value)

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
                formal_receipts.evaluate(value)

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
                    formal_receipts.evaluate(value)
                self.assertNotIn("PRIVATE-OUTPUT", str(caught.exception))

    def test_canonical_bounded_confined_file_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "receipt.json"
            path.write_bytes(canonical_bytes(receipt()))
            self.assertEqual("pass", formal_receipts.evaluate_file(root, "receipt.json")["status"])
            for relative in (
                "../receipt.json",
                "/private/receipt.json",
                "x/../receipt.json",
                "x\\receipt.json",
                "receipt.txt",
                "missing.json",
            ):
                with self.subTest(relative=relative), self.assertRaises(ProjectError):
                    formal_receipts.evaluate_file(root, relative)
            link = root / "link.json"
            link.symlink_to(path)
            with self.assertRaises(ProjectError):
                formal_receipts.evaluate_file(root, "link.json")
            for raw in (
                canonical_bytes(receipt()).rstrip(),
                b'{"kind":"formal-execution-receipt","kind":"proof"}\n',
                b'{"value":NaN}\n',
                b"x" * (formal_receipts.MAX_BYTES + 1),
            ):
                path.write_bytes(raw)
                with self.assertRaises(ProjectError):
                    formal_receipts.evaluate_file(root, "receipt.json")


if __name__ == "__main__":
    unittest.main()
