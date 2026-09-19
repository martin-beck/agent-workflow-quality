# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT
"""Positive and hostile tests for the cross-project oracle trace."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

import jsonschema

from awq import oracle_workflow_integration as subject
from awq.project import ProjectError
from tests.support import Repository


class OracleWorkflowIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repository()
        self.value = json.loads(
            (
                Path(__file__).parents[1]
                / "quality/oracle-workflow-integration/ar-0061-example.json"
            ).read_bytes()
        )

    def tearDown(self) -> None:
        self.repo.close()

    def test_positive_schema_runtime_and_deterministic_evaluation(self) -> None:
        schema = json.loads(
            (
                Path(__file__).parents[1] / "schemas/oracle-workflow-integration.schema.json"
            ).read_bytes()
        )
        jsonschema.Draft202012Validator(schema).validate(self.value)
        self.assertEqual(self.value, subject.validate(copy.deepcopy(self.value)))
        target = self.repo.root / "quality/oracle-workflow-integration/trace.json"
        target.parent.mkdir(parents=True)
        target.write_bytes(
            (json.dumps(self.value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
        self.assertEqual(
            subject.evaluate_file(self.repo.root, "quality/oracle-workflow-integration/trace.json"),
            subject.evaluate_file(self.repo.root, "quality/oracle-workflow-integration/trace.json"),
        )

    def test_skipped_stale_quality_only_and_private_traces_fail_closed(self) -> None:
        cases = []
        skipped = copy.deepcopy(self.value)
        skipped["stages"] = skipped["stages"][:2] + skipped["stages"][3:]
        cases.append(skipped)
        stale = copy.deepcopy(self.value)
        stale["stages"][4]["task_revision"] = 2
        cases.append(stale)
        quality_only = copy.deepcopy(self.value)
        quality_only["awg_decision"]["disposition"] = "clarify"
        cases.append(quality_only)
        private = copy.deepcopy(self.value)
        private["privacy_projection"]["public_safe"] = False
        cases.append(private)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ProjectError):
                subject.validate(value)

    def test_unknown_fields_and_empty_declaration_fail_closed(self) -> None:
        unknown = copy.deepcopy(self.value)
        unknown["extra"] = True
        with self.assertRaises(ProjectError):
            subject.validate(unknown)
        self.assertEqual(
            "missing-oracle-workflow-integration", subject.check(self.repo.root, [])[0]["code"]
        )
