# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Evidence coverage aggregation contract tests."""

import json
import unittest
from pathlib import Path

from awq import coverage
from awq.project import ProjectError
from scripts.validate_contracts import validate

ROOT = Path(__file__).resolve().parents[1]


class CoverageTests(unittest.TestCase):
    def test_coverage_is_deterministic_and_content_minimized(self) -> None:
        value = json.loads((ROOT / "fixtures/conforming/evidence-coverage.json").read_text())
        validate(value, "evidence-coverage.schema.json")
        first = coverage.evaluate(ROOT, "fixtures/conforming/evidence-coverage.json")
        second = coverage.evaluate(ROOT, "fixtures/conforming/evidence-coverage.json")
        self.assertEqual(first, second)
        self.assertEqual(first["records"], 3)
        self.assertEqual([item["task_id"] for item in first["tasks"]], ["AR-1001", "AR-1002"])
        self.assertEqual(first["roles"][0]["role"], "diagnostic")
        self.assertNotIn("evidence_class", json.dumps(first))

    def test_coverage_rejects_unlocked_roles_and_duplicate_identity(self) -> None:
        for kind in ("requirement", "role", "duplicate"):
            value = json.loads((ROOT / "fixtures/conforming/evidence-coverage.json").read_text())
            if kind == "requirement":
                value["records"][0]["requirement"] = "AWQ-NOT-LOCKED"
            elif kind == "role":
                value["records"][0]["role"] = "owner"
            else:
                value["records"].append(dict(value["records"][0]))
            path = ROOT / "fixtures/conforming/evidence-coverage-hostile.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            try:
                with self.assertRaises(ProjectError):
                    coverage.evaluate(ROOT, path.relative_to(ROOT).as_posix())
            finally:
                path.unlink()

    def test_coverage_rejects_malformed_records_and_documents(self) -> None:
        fixture = ROOT / "fixtures/conforming/evidence-coverage.json"
        original = json.loads(fixture.read_text())
        for kind in ("missing", "empty", "status", "evidence"):
            value = json.loads(json.dumps(original))
            if kind == "missing":
                value["records"][0].pop("status")
            elif kind == "empty":
                value["records"][0]["task_id"] = ""
            elif kind == "status":
                value["records"][0]["status"] = "bogus"
            else:
                value["records"][0]["evidence_class"] = "bogus"
            path = ROOT / "fixtures/conforming/evidence-coverage-hostile.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            try:
                with self.assertRaises(ProjectError):
                    coverage.evaluate(ROOT, path.relative_to(ROOT).as_posix())
            finally:
                path.unlink()
        for value in ({"schema_version": 2, "records": []}, {"schema_version": 1, "records": {}}):
            path = ROOT / "fixtures/conforming/evidence-coverage-hostile.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            try:
                with self.assertRaises(ProjectError):
                    coverage.evaluate(ROOT, path.relative_to(ROOT).as_posix())
            finally:
                path.unlink()
