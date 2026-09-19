# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Positive and hostile tests for discussion persistence evidence."""

import copy
import json
import unittest
from pathlib import Path

import jsonschema

from awq import discussion_persistence
from awq.project import ProjectError
from tests.support import Repository


class DiscussionPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repository()
        self.value = json.loads(
            (
                Path(__file__).parents[1] / "quality/discussion-persistence/ar-0064-example.json"
            ).read_bytes()
        )

    def tearDown(self) -> None:
        self.repo.close()

    def test_positive_schema_runtime_and_cli_shape(self) -> None:
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/discussion-persistence.schema.json").read_bytes()
        )
        jsonschema.Draft202012Validator(schema).validate(self.value)
        self.assertEqual(self.value, discussion_persistence.validate(copy.deepcopy(self.value)))

    def test_stale_resume_partial_save_and_unmapped_request_fail_closed(self) -> None:
        cases = [
            ("resume_revision", 1),
            ("safe_exit", {**self.value["safe_exit"], "complete": False}),
            ("future_requests", [{**self.value["future_requests"][0], "ar_ref": None}]),
        ]
        for field, replacement in cases:
            value = copy.deepcopy(self.value)
            value[field] = replacement
            with self.subTest(field=field), self.assertRaises(ProjectError):
                discussion_persistence.validate(value)

    def test_private_projection_and_unknown_fields_fail_closed(self) -> None:
        for field, replacement in (
            ("privacy_projection", {**self.value["privacy_projection"], "public_safe": False}),
            ("__extra__", True),
            ("reask", {**self.value["reask"], "point_ids": ["POINT-MISSING"]}),
        ):
            value = copy.deepcopy(self.value)
            value[field] = replacement
            with self.subTest(field=field), self.assertRaises(ProjectError):
                discussion_persistence.validate(value)

    def test_canonical_file_and_missing_gate(self) -> None:
        target = self.repo.root / "quality/discussion-persistence/record.json"
        target.parent.mkdir(parents=True)
        target.write_bytes(
            (json.dumps(self.value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
        self.assertEqual(
            "pass",
            discussion_persistence.evaluate_file(
                self.repo.root, "quality/discussion-persistence/record.json"
            )["status"],
        )
        self.assertEqual(
            "missing-discussion-persistence",
            discussion_persistence.check(self.repo.root, [])[0]["code"],
        )

    def test_every_persistence_boundary_has_a_hostile_fixture(self) -> None:
        cases = [
            ("task", None),
            ("task", {"id": "AR-X", "revision": 1}),
            ("task", {"id": "AR-0064", "revision": 0}),
            ("journal_id", "bad"),
            ("revision", 0),
            ("status", "active"),
            ("points", []),
            ("points", [{"id": "POINT-X"}]),
            ("points", [{**self.value["points"][0], "id": "bad"}]),
            ("points", [{**self.value["points"][0], "proposals": []}]),
            ("points", [{**self.value["points"][0], "response": {}}]),
            (
                "points",
                [
                    {
                        **self.value["points"][0],
                        "response": {**self.value["points"][0]["response"], "disposition": "bad"},
                    }
                ],
            ),
            ("points", [{**self.value["points"][0], "unresolved": "yes"}]),
            ("safe_exit", {}),
            ("safe_exit", {**self.value["safe_exit"], "commit_sha256": "bad"}),
            ("reask", {}),
            ("reask", {**self.value["reask"], "point_ids": ["POINT-NOPE"]}),
            ("future_requests", [{}]),
            ("future_requests", [{**self.value["future_requests"][0], "request_sha256": "bad"}]),
            ("future_requests", [{**self.value["future_requests"][0], "reason": ""}]),
            ("future_requests", [{**self.value["future_requests"][1], "ar_ref": "AR-0064"}]),
            (
                "future_requests",
                [
                    {
                        **self.value["future_requests"][0],
                        "classification": "existing-ar",
                        "ar_ref": "bad",
                    }
                ],
            ),
            ("formal_spec", {}),
            ("formal_spec", {**self.value["formal_spec"], "status": "fail"}),
            ("formal_spec", {**self.value["formal_spec"], "result_sha256": "bad"}),
            ("privacy_projection", {}),
            (
                "privacy_projection",
                {**self.value["privacy_projection"], "redacted_fields": ["x", "x"]},
            ),
            ("privacy_projection", {**self.value["privacy_projection"], "redacted_fields": [""]}),
            ("limitations", []),
        ]
        for field, replacement in cases:
            value = copy.deepcopy(self.value)
            value[field] = replacement
            with self.subTest(field=field), self.assertRaises(ProjectError):
                discussion_persistence.validate(value)

    def test_file_parser_and_invalid_candidate_findings_are_bounded(self) -> None:
        invalid = self.repo.root / "quality/discussion-persistence/invalid.json"
        invalid.parent.mkdir(parents=True)
        invalid.write_text("{", encoding="utf-8")
        with self.assertRaises(ProjectError):
            discussion_persistence.evaluate_file(
                self.repo.root, "quality/discussion-persistence/invalid.json"
            )
        findings = discussion_persistence.check(self.repo.root, [invalid])
        self.assertEqual("invalid-discussion-persistence", findings[0]["code"])
        noncanonical = self.repo.root / "quality/discussion-persistence/noncanonical.json"
        noncanonical.write_text(json.dumps(self.value, indent=2), encoding="utf-8")
        with self.assertRaises(ProjectError):
            discussion_persistence.evaluate_file(
                self.repo.root, "quality/discussion-persistence/noncanonical.json"
            )
