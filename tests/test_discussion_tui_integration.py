# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT
"""Positive and hostile tests for the end-to-end discussion TUI trace."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from awq import discussion_tui_integration as subject
from awq.project import ProjectError
from tests.support import Repository


class DiscussionTuiIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repository()
        self.value = json.loads(
            (
                Path(__file__).parents[1]
                / "quality/discussion-tui-integration/ar-0065-example.json"
            ).read_bytes()
        )

    def tearDown(self) -> None:
        self.repo.close()

    def test_positive_evaluation_is_deterministic(self) -> None:
        self.assertEqual(self.value, subject.validate(copy.deepcopy(self.value)))
        target = self.repo.root / "quality/discussion-tui-integration/trace.json"
        target.parent.mkdir(parents=True)
        target.write_bytes(
            (json.dumps(self.value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
        self.assertEqual(
            subject.evaluate_file(self.repo.root, "quality/discussion-tui-integration/trace.json"),
            subject.evaluate_file(self.repo.root, "quality/discussion-tui-integration/trace.json"),
        )

    def test_hostile_stage_pane_proposal_and_authorization_paths_fail(self) -> None:
        cases: list[dict[str, object]] = []
        for field, replacement in (
            ("session_mode", "unknown"),
            ("stages", self.value["stages"][:-1]),
            ("panes", {"synchronized": False}),
            (
                "batch",
                {
                    "point_count": 2,
                    "candidate_count": 1,
                    "custom_count": 0,
                    "independent_evaluation": True,
                },
            ),
            ("handoff", {"ar_ref": "AR-0066", "authorized": True, "classification": "new-ar"}),
            (
                "privacy_projection",
                {"public_safe": False, "projection_sha256": "4" * 64, "redacted_fields": []},
            ),
        ):
            value = copy.deepcopy(self.value)
            value[field] = replacement
            cases.append(value)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ProjectError):
                subject.validate(value)

    def test_unknown_fields_and_missing_trace_fail_closed(self) -> None:
        unknown = copy.deepcopy(self.value)
        unknown["extra"] = True
        with self.assertRaises(ProjectError):
            subject.validate(unknown)
        self.assertEqual(
            "missing-discussion-tui-integration", subject.check(self.repo.root, [])[0]["code"]
        )

    def test_noncanonical_and_malformed_files_are_rejected(self) -> None:
        target = self.repo.root / "quality/discussion-tui-integration"
        target.mkdir(parents=True)
        malformed = target / "bad.json"
        malformed.write_text("{", encoding="utf-8")
        with self.assertRaises(ProjectError):
            subject.evaluate_file(self.repo.root, "quality/discussion-tui-integration/bad.json")
        noncanonical = target / "noncanonical.json"
        noncanonical.write_text(json.dumps(self.value, indent=2), encoding="utf-8")
        with self.assertRaisesRegex(ProjectError, "canonical"):
            subject.evaluate_file(
                self.repo.root, "quality/discussion-tui-integration/noncanonical.json"
            )
