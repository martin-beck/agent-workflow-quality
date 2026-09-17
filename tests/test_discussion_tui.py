# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT
"""Positive and hostile tests for the discussion TUI contract."""

import copy
import json
import unittest
from pathlib import Path

import jsonschema

from awq import discussion_tui
from awq.project import ProjectError
from tests.support import Repository


class DiscussionTuiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repository()
        self.value = json.loads(
            (Path(__file__).parents[1] / "quality/discussion-tui/ar-0062-example.json").read_bytes()
        )

    def tearDown(self) -> None:
        self.repo.close()

    def test_positive_schema_runtime_and_deterministic_evaluation(self) -> None:
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/discussion-tui.schema.json").read_bytes()
        )
        jsonschema.Draft202012Validator(schema).validate(self.value)
        self.assertEqual(self.value, discussion_tui.validate(copy.deepcopy(self.value)))
        target = self.repo.root / "quality/discussion-tui/record.json"
        target.parent.mkdir(parents=True)
        target.write_bytes(
            (json.dumps(self.value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
        result = discussion_tui.evaluate_file(self.repo.root, "quality/discussion-tui/record.json")
        self.assertEqual(
            result,
            discussion_tui.evaluate_file(self.repo.root, "quality/discussion-tui/record.json"),
        )

    def test_stale_anchor_missing_highlight_and_unresolved_resolution_fail_closed(self) -> None:
        for field, replacement in (
            (
                "left_anchor",
                {"document_sha256": "3" * 64, "offset": 4, "point_id": "POINT-AR0062-1"},
            ),
            ("render", {**self.value["render"], "highlighted_point_id": "POINT-OTHER"}),
            ("render", {**self.value["render"], "highlighted_unresolved": True}),
            ("render", {**self.value["render"], "unresolved_point_ids": ["POINT-AR0062-1"]}),
            ("privacy_projection", {**self.value["privacy_projection"], "public_safe": False}),
            ("limitations", ["ui_behavior_not_proven"]),
        ):
            value = copy.deepcopy(self.value)
            value[field] = replacement
            with self.subTest(field=field), self.assertRaises(ProjectError):
                discussion_tui.validate(value)

    def test_empty_directory_fails_closed(self) -> None:
        self.assertEqual(
            "missing-discussion-tui", discussion_tui.check(self.repo.root, [])[0]["code"]
        )
