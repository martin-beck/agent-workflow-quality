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

    def test_each_identity_and_ownership_boundary_is_hostile(self) -> None:
        cases = []
        for field, replacement in (
            ("trace_id", "bad"),
            ("schema_version", 2),
            ("task", None),
            ("task", {"id": "AR-X", "revision": 1}),
            ("task", {"id": "AR-0061", "revision": True}),
            ("stages", None),
            ("stages", self.value["stages"][:7]),
        ):
            value = copy.deepcopy(self.value)
            value[field] = replacement
            cases.append(value)
        for index, field, replacement in (
            (0, "owner", "awg"),
            (1, "name", "discussion"),
            (2, "status", "pending"),
            (3, "evidence_class", "quality"),
            (4, "event_ref", "bad"),
            (5, "task_revision", 1),
            (6, "evidence_ref", "../private"),
        ):
            value = copy.deepcopy(self.value)
            value["stages"][index][field] = replacement
            cases.append(value)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ProjectError):
                subject.validate(value)

    def test_decision_quality_privacy_and_limitations_boundaries_are_hostile(self) -> None:
        cases = []
        for field, replacement in (
            ("awg_decision", None),
            (
                "awg_decision",
                {"disposition": "accepted", "packet_ref": "../x", "decision_sha256": "1" * 64},
            ),
            (
                "awg_decision",
                {"disposition": "accepted", "packet_ref": "trace/p", "decision_sha256": "bad"},
            ),
            ("awq_quality", None),
            (
                "awq_quality",
                {"status": "failed", "evidence_ref": "trace/q", "requirement_sha256": "2" * 64},
            ),
            (
                "awq_quality",
                {"status": "passed", "evidence_ref": "../q", "requirement_sha256": "2" * 64},
            ),
            (
                "awq_quality",
                {"status": "passed", "evidence_ref": "trace/q", "requirement_sha256": "bad"},
            ),
            ("privacy_projection", None),
            (
                "privacy_projection",
                {"public_safe": True, "projection_sha256": "3" * 64, "redacted_fields": [""]},
            ),
            (
                "privacy_projection",
                {"public_safe": True, "projection_sha256": "bad", "redacted_fields": ["x"]},
            ),
            ("limitations", []),
        ):
            value = copy.deepcopy(self.value)
            value[field] = replacement
            cases.append(value)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ProjectError):
                subject.validate(value)

    def test_file_and_check_failures_are_content_minimized(self) -> None:
        target = self.repo.root / "quality/oracle-workflow-integration"
        target.mkdir(parents=True)
        malformed = target / "malformed.json"
        malformed.write_text("{", encoding="utf-8")
        with self.assertRaises(ProjectError):
            subject.evaluate_file(
                self.repo.root, "quality/oracle-workflow-integration/malformed.json"
            )
        noncanonical = target / "noncanonical.json"
        noncanonical.write_text(json.dumps(self.value, indent=2), encoding="utf-8")
        with self.assertRaisesRegex(ProjectError, "canonical"):
            subject.evaluate_file(
                self.repo.root, "quality/oracle-workflow-integration/noncanonical.json"
            )
        findings = subject.check(self.repo.root, [malformed, noncanonical])
        self.assertEqual(2, len(findings))
