# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Positive and hostile tests for discussion reconciliation evidence."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from typing import Any

import jsonschema

from awq import discussion_reconciliation
from awq.project import ProjectError
from tests.support import Repository


class DiscussionReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repository()
        self.value = json.loads(
            (
                Path(__file__).parents[1] / "quality/discussion-reconciliation/example.json"
            ).read_bytes()
        )

    def tearDown(self) -> None:
        self.repo.close()

    def test_positive_schema_runtime_and_cli_are_deterministic(self) -> None:
        schema = json.loads(
            (
                Path(__file__).parents[1] / "schemas/discussion-reconciliation.schema.json"
            ).read_bytes()
        )
        jsonschema.Draft202012Validator(schema).validate(self.value)
        self.assertEqual(self.value, discussion_reconciliation.validate(copy.deepcopy(self.value)))
        target = self.repo.root / "quality/discussion-reconciliation/gate.json"
        target.parent.mkdir(parents=True)
        target.write_bytes(
            (json.dumps(self.value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
        result = discussion_reconciliation.evaluate_file(
            self.repo.root, "quality/discussion-reconciliation/gate.json"
        )
        self.assertEqual("pass", result["status"])
        self.assertEqual(
            result,
            discussion_reconciliation.evaluate_file(
                self.repo.root, "quality/discussion-reconciliation/gate.json"
            ),
        )

    def test_changed_artifacts_require_new_formal_result(self) -> None:
        mutations: tuple[tuple[str, Any], ...] = (
            ("changed_artifacts", ["plan"]),
            ("formal_spec", {**self.value["formal_spec"], "task_revision": 3}),
            (
                "formal_spec",
                {**self.value["formal_spec"], "specification_sha256": "6" * 64},
            ),
            ("prior_formal_result_sha256", self.value["formal_spec"]["result_sha256"]),
            ("acceptance", {"user_guidance": "accepted", "quality_evidence": "pass"}),
            (
                "affected_ars",
                [
                    {
                        "id": "AR-0036",
                        "before_revision": 3,
                        "after_revision": 2,
                        "disposition": "closed",
                    }
                ],
            ),
            ("limitations", ["user_intent_not_proven"]),
            (
                "privacy_projection",
                {"public_safe": False, "projection_sha256": "c" * 64, "redacted_fields": []},
            ),
        )
        for field, replacement in mutations:
            value = copy.deepcopy(self.value)
            value[field] = replacement
            with self.subTest(field=field), self.assertRaises(ProjectError):
                discussion_reconciliation.validate(value)

    def test_noncanonical_and_empty_declarations_fail_closed(self) -> None:
        target = self.repo.root / "quality/discussion-reconciliation"
        target.mkdir(parents=True)
        malformed = target / "malformed.json"
        malformed.write_text("{", encoding="utf-8")
        with self.assertRaises(ProjectError):
            discussion_reconciliation.evaluate_file(
                self.repo.root, "quality/discussion-reconciliation/malformed.json"
            )
        noncanonical = target / "noncanonical.json"
        noncanonical.write_text(json.dumps(self.value, indent=2), encoding="utf-8")
        with self.assertRaisesRegex(ProjectError, "canonical"):
            discussion_reconciliation.evaluate_file(
                self.repo.root, "quality/discussion-reconciliation/noncanonical.json"
            )
        self.assertEqual(
            "missing-discussion-reconciliation",
            discussion_reconciliation.check(self.repo.root, [])[0]["code"],
        )

    def test_validator_rejects_each_hostile_context_and_identity_shape(self) -> None:
        mutations: tuple[tuple[str, Any], ...] = (
            ("prior_formal_result_sha256", "not-a-digest"),
            ("before", {"plan_sha256": self.value["before"]["plan_sha256"]}),
            ("task", {"id": self.value["task"]["id"]}),
            ("task", {**self.value["task"], "id": "AR-nope"}),
            ("formal_spec", {**self.value["formal_spec"], "status": "fail"}),
            ("affected_ars", []),
            ("affected_ars", [{"id": "AR-0036"}]),
            ("discussion_id", "DISC"),
            ("event_refs", ["EV-ONE", "EV-ONE"]),
            ("changed_artifacts", []),
            ("changed_artifacts", ["unknown"]),
        )
        for field, replacement in mutations:
            value = copy.deepcopy(self.value)
            value[field] = replacement
            with self.subTest(field=field, replacement=replacement), self.assertRaises(
                ProjectError
            ):
                discussion_reconciliation.validate(value)

    def test_check_reports_invalid_declared_records(self) -> None:
        target = self.repo.root / "quality/discussion-reconciliation"
        target.mkdir(parents=True)
        invalid = target / "invalid.json"
        invalid.write_text("{}\n", encoding="utf-8")
        findings = discussion_reconciliation.check(self.repo.root, [invalid])
        self.assertEqual("invalid-discussion-reconciliation", findings[0]["code"])
        self.assertEqual("quality/discussion-reconciliation/invalid.json", findings[0]["path"])
