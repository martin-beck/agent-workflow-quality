# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Execution budget, lifecycle, cleanup and isolation-observation tests."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import platform
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

import jsonschema

from awq import adapters, execution_budget
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

        value["source"]["kind"] = "unbound"
        with self.assertRaisesRegex(ProjectError, "source-kind"):
            execution_budget.evaluate(value)
        with self.assertRaises(jsonschema.ValidationError):
            validate(value, "execution-receipt.schema.json")

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
        value["dimensions"][7]["limit"] = 1
        candidates.append(value)
        value = receipt()
        value["dimensions"][0]["classification"] = "claimed"
        candidates.append(value)
        for candidate in candidates:
            with self.assertRaises(ProjectError):
                execution_budget.evaluate(candidate)

        for candidate in [candidates[index] for index in (1, 3, 4)]:
            with self.assertRaises(jsonschema.ValidationError):
                validate(candidate, "execution-receipt.schema.json")

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

        for receipt_id, reservation_id in (
            ("RES-WRONG", "RES-ACTION-001"),
            ("RECEIPT-EXAMPLE-001", "RECEIPT-WRONG"),
        ):
            value = receipt()
            value["receipt_id"] = receipt_id
            value["reservations"][0]["id"] = reservation_id
            with self.assertRaises(ProjectError):
                execution_budget.evaluate(value)

        for effect_step, settlement_step, expected in (
            (1, 0, "settlement"),
            (11, 12, "reserve-before-effect"),
            (6, 6, "reserve-before-effect"),
        ):
            value = receipt()
            value["reservations"][0]["effect_step"] = effect_step
            value["reservations"][0]["settlement_step"] = settlement_step
            with self.assertRaisesRegex(ProjectError, expected):
                execution_budget.evaluate(value)

        value = receipt()
        value["reservations"][0]["created_step"] = 6
        value["reservations"][0]["expires_step"] = 10
        value["reservations"][0]["effect_step"] = 7
        value["reservations"][0]["settlement_step"] = 8
        with self.assertRaisesRegex(ProjectError, "reservation-window"):
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
        item["settlement_step"] = 5
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

        value = receipt()
        value["process"]["termination"]["descendants"] = "unknown"
        value["process"]["termination"]["orphan_outcome"] = "unknown"
        result = execution_budget.evaluate(value)
        self.assertEqual("fail", result["status"])
        self.assertEqual(["descendants-unknown", "orphan-unknown"], result["findings"])

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

        value = receipt()
        network = next(item for item in value["sandbox"] if item["boundary"] == "network")
        network["outcome"] = "allowed"
        result = execution_budget.evaluate(value)
        self.assertEqual(
            {"classification": "observed", "outcome": "allowed"},
            result["sandbox"]["network"],
        )
        self.assertEqual("pass", result["status"])

    def test_bounded_model_exhausts_small_lifecycle(self) -> None:
        result = execution_budget.bounded_model()
        self.assertEqual("exhausted", result["outcome"])
        self.assertEqual([], result["violated_invariants"])
        self.assertGreater(result["rejected_transitions"], 0)
        self.assertGreater(result["chronology_rejected"], 0)
        self.assertEqual(160, result["termination_states"])
        self.assertGreater(result["termination_rejected"], 0)
        self.assertGreater(result["termination_findings"], 0)
        self.assertIn("no implementation refinement", result["limitation"])

    def test_adapter_lifecycle_maps_to_bound_receipt(self) -> None:
        tool = Path(sys.executable).name
        contract: dict[str, Any] = {
            "id": "ADAPTER-SYNTHETIC-PYTHON",
            "tool": tool,
            "version": platform.python_version(),
            "version_argv": [tool, "--version"],
            "version_output": f"Python {platform.python_version()}",
            "argv": [tool, "-c", "raise SystemExit(0)"],
            "timeout_seconds": 2,
            "tier": "pr",
            "evidence": "contract-test",
            "limitation": "Synthetic lifecycle mapping only.",
            "remediation": "Repair the synthetic lifecycle fixture.",
            "formats": [".py"],
            "config_paths": ["pyproject.toml"],
        }
        with mock.patch("awq.adapters.shutil.which", return_value=sys.executable):
            adapter_result = adapters.run_adapter(ROOT, contract)
        self.assertEqual("pass", adapter_result["status"])
        value = receipt()
        value["source"]["sha256"] = hashlib.sha256(canonical_bytes(adapter_result)).hexdigest()
        value["process"]["argv_sha256"] = hashlib.sha256(
            canonical_bytes(contract["argv"])
        ).hexdigest()
        value["process"]["deadline_seconds"] = contract["timeout_seconds"]
        wall = next(item for item in value["dimensions"] if item["id"] == "wall")
        wall["used"] = adapter_result["duration_ms"]
        wall["measurement"]["name"] = contract["tool"]
        wall["measurement"]["version"] = contract["version"]
        result = execution_budget.evaluate_adapter_lifecycle(value, contract, adapter_result)
        self.assertEqual("pass", result["status"])
        self.assertEqual("awq-adapter-result-v1", result["source"]["kind"])
        value["source"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ProjectError, "adapter-result-binding"):
            execution_budget.evaluate_adapter_lifecycle(value, contract, adapter_result)
        value["source"]["sha256"] = hashlib.sha256(canonical_bytes(adapter_result)).hexdigest()
        wall["used"] += 1
        with self.assertRaisesRegex(ProjectError, "adapter-wall-binding"):
            execution_budget.evaluate_adapter_lifecycle(value, contract, adapter_result)
        wall["used"] -= 1
        value["process"]["deadline_seconds"] += 1
        with self.assertRaisesRegex(ProjectError, "adapter-process-binding"):
            execution_budget.evaluate_adapter_lifecycle(value, contract, adapter_result)
        value["process"]["deadline_seconds"] -= 1
        mismatched_result = {**adapter_result, "id": "ADAPTER-OTHER"}
        with self.assertRaisesRegex(ProjectError, "adapter-result"):
            execution_budget.evaluate_adapter_lifecycle(value, contract, mismatched_result)

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
