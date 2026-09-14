# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

import copy
import json
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from awq import experiment
from awq.project import ProjectError

ROOT = Path(__file__).resolve().parents[1]


def receipt() -> dict[str, Any]:
    raw_digest = "d" * 64
    return {
        "schema_version": 1,
        "kind": "experiment-receipt",
        "experiment_id": "EXP-SMALL",
        "source": {"revision": "a" * 40, "tree_sha256": "b" * 64},
        "workload_sha256": "c" * 64,
        "config_sha256": "e" * 64,
        "predeclaration": {
            "registered_at": "2026-09-01T00:00:00Z",
            "design_sha256": "f" * 64,
            "population": "Deterministic public synthetic cases.",
            "planned_samples": 35,
            "repeats": 7,
            "warmup_samples": 3,
            "precision_target_ppm": 50_000,
            "confidence": {"method": "exact", "level_ppm": 950_000},
            "stopping_rule": {
                "kind": "fixed-samples",
                "max_samples": 35,
                "max_duration_seconds": 300,
            },
            "resource_budget": {
                "cpu_seconds": 120,
                "wall_seconds": 300,
                "memory_bytes": 268_435_456,
            },
        },
        "conditions": {
            "load_model": "closed",
            "concurrency": 1,
            "cache_state": "cold",
            "network_state": "offline",
            "retries": 0,
            "timeout_seconds": 10,
        },
        "observations": {
            "source_revisions": ["a" * 40],
            "attempted": 35,
            "completed": 32,
            "failed": 1,
            "timed_out": 1,
            "cancelled": 1,
            "missing": 0,
            "contaminated": 0,
            "highest_tested_capacity": 1,
            "claimed_capacity": 1,
            "raw_result_sha256": raw_digest,
            "observed_at": "2026-09-01T01:00:00Z",
        },
        "bias_treatment": {
            "coordinated_omission": "not-applicable",
            "survivorship_bias": "included-failures",
            "capacity_basis": "highest-tested",
            "contamination_disposition": "none",
            "contamination_rationale": "",
        },
        "uncertainty": {
            "method": "exact",
            "level_ppm": 950_000,
            "estimate": 1000,
            "lower": 950,
            "upper": 1050,
            "precision_achieved_ppm": 50_000,
            "status": "met",
        },
        "raw_artifacts": [{"id": "aggregate-1", "sha256": raw_digest, "bytes": 4096}],
        "methodology_review": "Reviewed deterministic sampling and all disclosed outcomes.",
        "environmental_validity": "unverified",
    }


class ExperimentReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = json.loads((ROOT / "schemas/experiment-receipt.schema.json").read_bytes())
        Draft202012Validator.check_schema(self.schema)

    def assert_rejected(self, value: dict[str, Any]) -> None:
        with self.assertRaises(ProjectError):
            experiment.validate_receipt(value)

    def test_deterministic_small_and_consumer_receipts(self) -> None:
        small = receipt()
        Draft202012Validator(self.schema).validate(small)
        first = experiment.evaluate(small)
        self.assertEqual(first, experiment.evaluate(copy.deepcopy(small)))
        self.assertEqual("none", first["baseline_action"])
        self.assertEqual("consumer-owned", first["regression_decision"])
        self.assertNotIn("raw_artifacts", first)

        study = copy.deepcopy(small)
        study["experiment_id"] = "EXP-CONSUMER-STUDY"
        study["predeclaration"]["planned_samples"] = 100
        study["predeclaration"]["stopping_rule"] = {
            "kind": "precision-or-budget",
            "max_samples": 100,
            "max_duration_seconds": 3600,
        }
        study["conditions"].update(
            load_model="open",
            concurrency=32,
            cache_state="warm",
            network_state="controlled",
            retries=2,
        )
        study["observations"].update(
            attempted=80,
            completed=75,
            failed=2,
            timed_out=1,
            cancelled=1,
            missing=1,
            contaminated=2,
            highest_tested_capacity=32,
            claimed_capacity=32,
        )
        study["bias_treatment"].update(
            coordinated_omission="measured",
            contamination_disposition="excluded-with-rationale",
            contamination_rationale=(
                "Two samples overlapped a separately recorded maintenance window."
            ),
        )
        study["environmental_validity"] = "reviewed"
        Draft202012Validator(self.schema).validate(study)
        self.assertEqual("pass", experiment.evaluate(study)["status"])

    def test_hostile_methodology_claims_fail_closed(self) -> None:
        mutations: tuple[Callable[[dict[str, Any]], None], ...] = (
            lambda x: x["predeclaration"].update(planned_samples=34),
            lambda x: x["observations"].update(failed=0),
            lambda x: x["uncertainty"].update(lower=1100),
            lambda x: x["observations"].update(contaminated=1),
            lambda x: x["observations"]["source_revisions"].append("9" * 40),
            lambda x: x["predeclaration"]["stopping_rule"].update(max_duration_seconds=0),
            lambda x: x["observations"].update(claimed_capacity=2),
            lambda x: x["bias_treatment"].update(capacity_basis="inferred"),
            lambda x: x["observations"].update(raw_result_sha256="9" * 64),
            lambda x: x.update(extra=True),
        )
        for mutate in mutations:
            item = receipt()
            mutate(item)
            self.assert_rejected(item)

    def test_adaptive_stopping_requires_precision_or_budget_exhaustion(self) -> None:
        item = receipt()
        item["predeclaration"]["stopping_rule"]["kind"] = "precision-or-budget"
        item["uncertainty"].update(precision_achieved_ppm=60_000, status="not-met")
        item["observations"].update(attempted=34, completed=31, failed=1, timed_out=1, cancelled=1)
        self.assert_rejected(item)

    def test_schema_and_runtime_reject_boolean_counts(self) -> None:
        item = receipt()
        item["conditions"]["retries"] = False
        self.assertFalse(Draft202012Validator(self.schema).is_valid(item))
        self.assert_rejected(item)
