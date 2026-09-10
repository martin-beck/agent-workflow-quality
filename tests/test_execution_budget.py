# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Execution budget, lifecycle, cleanup and isolation-observation tests."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from awq import execution_budget
from awq.cli import main
from awq.project import ProjectError
from awq.registry import canonical_bytes
from scripts.validate_contracts import validate

ROOT = Path(__file__).resolve().parents[1]


def receipt() -> dict[str, Any]:
    return dict(json.loads((ROOT / "fixtures/conforming/execution-receipt.json").read_bytes()))


class ExecutionBudgetTests(unittest.TestCase):
    def test_complete_receipt_is_deterministic_and_content_minimized(self) -> None:
        value = receipt()
        validate(value, "execution-receipt.schema.json")
        result = execution_budget.evaluate(value)
        self.assertEqual("pass", result["status"])
        self.assertEqual(result, execution_budget.evaluate(json.loads(canonical_bytes(value))))
        self.assertEqual(
            {"enforced": 3, "observed": 4, "estimated": 1, "unavailable": 1},
            result["classifications"],
        )
        self.assertEqual("exhausted", result["model"]["outcome"])
        rendered = json.dumps(result, sort_keys=True)
        for excluded in ("argv_sha256", "measurement", "tool", "/home/", "environment values"):
            self.assertNotIn(excluded, rendered)

    def test_dimensions_are_complete_typed_and_bounded(self) -> None:
        candidates = []
        value = receipt()
        value["dimensions"].pop()
        candidates.append(value)
        value = receipt()
        value["dimensions"][0]["unit"] = "bytes"
        candidates.append(value)
        value = receipt()
        value["dimensions"][1]["used"] = 1_000_001
        candidates.append(value)
        value = receipt()
        value["dimensions"][7]["measurement"] = {
            "name": "meter",
            "version": "1.0.0",
            "sha256": "a" * 64,
        }
        candidates.append(value)
        value = receipt()
        value["dimensions"][0]["classification"] = "claimed"
        candidates.append(value)
        for candidate in candidates:
            with self.assertRaises(ProjectError):
                execution_budget.evaluate(candidate)

    def test_reservation_conservation_and_effect_order_fail_closed(self) -> None:
        cases: list[tuple[str, Any]] = [
            ("settled", 2),
            ("state", "reserved"),
            ("effect_step", 0),
            ("settlement_step", 0),
        ]
        for field, replacement in cases:
            with self.subTest(field=field):
                value = receipt()
                value["reservations"][0][field] = replacement
                with self.assertRaises(ProjectError):
                    execution_budget.evaluate(value)
        value = receipt()
        value["reservations"].append(copy.deepcopy(value["reservations"][0]))
        with self.assertRaisesRegex(ProjectError, "duplicate"):
            execution_budget.evaluate(value)

        value = receipt()
        value["reservations"][0]["amount"] = 2
        value["reservations"][0]["settled"] = 2
        with self.assertRaisesRegex(ProjectError, "settlement-unaccounted"):
            execution_budget.evaluate(value)

        value = receipt()
        item = value["reservations"][0]
        item.update(
            {
                "amount": 100,
                "effect": "none",
                "effect_step": None,
                "state": "reserved",
                "settled": 0,
                "settlement_step": None,
            }
        )
        with self.assertRaisesRegex(ProjectError, "reservation-capacity"):
            execution_budget.evaluate(value)

    def test_refund_stale_and_active_reservations_preserve_balance(self) -> None:
        value = receipt()
        item = value["reservations"][0]
        item.update(
            {
                "effect": "none",
                "effect_step": None,
                "state": "refunded",
                "settled": 0,
                "refunded": 1,
                "settlement_step": 3,
            }
        )
        self.assertEqual("pass", execution_budget.evaluate(value)["status"])
        item["state"] = "stale"
        item["expires_step"] = 4
        self.assertEqual("pass", execution_budget.evaluate(value)["status"])
        item["state"] = "reserved"
        item["refunded"] = 0
        item["settlement_step"] = None
        with self.assertRaisesRegex(ProjectError, "stale-reservation"):
            execution_budget.evaluate(value)

    def test_cleanup_failures_are_explicit_without_retaining_command(self) -> None:
        value = receipt()
        termination = value["process"]["termination"]
        termination.update(
            {
                "deadline_reached": True,
                "term_sent": False,
                "kill_sent": False,
                "descendants": "surviving",
                "orphan_outcome": "surviving",
            }
        )
        value["process"]["process_scope"] = "none"
        result = execution_budget.evaluate(value)
        self.assertEqual("fail", result["status"])
        self.assertEqual(
            [
                "descendants-survived",
                "orphan-survived",
                "process-boundary-missing",
                "term-missing",
            ],
            result["findings"],
        )
        self.assertNotIn("argv_sha256", json.dumps(result))

    def test_sandbox_is_observation_not_portable_isolation(self) -> None:
        value = receipt()
        value["sandbox"][0]["classification"] = "enforced"
        with self.assertRaisesRegex(ProjectError, "unsupported-isolation-claim"):
            execution_budget.evaluate(value)
        value = receipt()
        value["sandbox"][0]["outcome"] = "blocked"
        with self.assertRaisesRegex(ProjectError, "sandbox-unavailable"):
            execution_budget.evaluate(value)
        value = receipt()
        value["sandbox"][1]["tool"]["name"] = "/home/private"
        with self.assertRaises(ProjectError) as caught:
            execution_budget.evaluate(value)
        self.assertNotIn("private", str(caught.exception).casefold())

    def test_bounded_model_exhausts_small_lifecycle(self) -> None:
        result = execution_budget.bounded_model()
        self.assertEqual("exhausted", result["outcome"])
        self.assertEqual([], result["violated_invariants"])
        self.assertGreater(result["rejected_transitions"], 0)
        self.assertEqual(8, result["termination_states"])
        self.assertGreater(result["termination_rejected"], 0)
        self.assertIn("no implementation refinement", result["limitation"])

    def test_cli_confines_paths_and_rejects_noncanonical_json(self) -> None:
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = main(
                [
                    "--root",
                    str(ROOT),
                    "execution-receipt-evaluate",
                    "fixtures/conforming/execution-receipt.json",
                    "--format",
                    "json",
                ]
            )
        self.assertEqual(0, code)
        self.assertEqual("pass", json.loads(stream.getvalue())["status"])
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")
            relative = path.relative_to(ROOT).as_posix()
            with self.assertRaises(ProjectError):
                execution_budget.evaluate_file(ROOT, relative)
        for candidate_path in ("../private.json", "/home/private.json", "bad.txt"):
            with self.assertRaises(ProjectError):
                execution_budget.evaluate_file(ROOT, candidate_path)


if __name__ == "__main__":
    unittest.main()
