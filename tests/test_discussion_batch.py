# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT
"""Positive and hostile tests for the batched discussion quality contract."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from typing import Any

import jsonschema

from awq import discussion_batch
from awq.project import ProjectError
from tests.support import Repository


class DiscussionBatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repository()
        self.value = json.loads(
            (
                Path(__file__).parents[1] / "quality/discussion-batch/ar-0063-example.json"
            ).read_bytes()
        )

    def tearDown(self) -> None:
        self.repo.close()

    def test_positive_schema_runtime_and_deterministic_evaluation(self) -> None:
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/discussion-batch.schema.json").read_bytes()
        )
        jsonschema.Draft202012Validator(schema).validate(self.value)
        self.assertEqual(self.value, discussion_batch.validate(copy.deepcopy(self.value)))
        target = self.repo.root / "quality/discussion-batch/record.json"
        target.parent.mkdir(parents=True)
        target.write_bytes(
            (json.dumps(self.value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
        result = discussion_batch.evaluate_file(
            self.repo.root, "quality/discussion-batch/record.json"
        )
        self.assertEqual(
            result,
            discussion_batch.evaluate_file(self.repo.root, "quality/discussion-batch/record.json"),
        )

    def test_independent_binding_and_quality_fields_fail_closed(self) -> None:
        mutations: tuple[tuple[str, Any], ...] = (
            ("batch", {**self.value["batch"], "query_count": 2}),
            ("points", self.value["points"][:1]),
            (
                "points",
                [
                    {
                        **self.value["points"][0],
                        "proposals": self.value["points"][0]["proposals"][:1],
                    },
                    self.value["points"][1],
                ],
            ),
            (
                "responses",
                [
                    {**self.value["responses"][0], "point_id": "POINT-OTHER"},
                    self.value["responses"][1],
                ],
            ),
            (
                "responses",
                [
                    {**self.value["responses"][0], "proposal_id": "PROP-AR0063-2-A"},
                    self.value["responses"][1],
                ],
            ),
            (
                "responses",
                [
                    {
                        **self.value["responses"][0],
                        "authorized": True,
                        "proposal_id": None,
                        "user_proposal": None,
                    },
                    self.value["responses"][1],
                ],
            ),
            (
                "responses",
                [
                    {
                        **self.value["responses"][0],
                        "user_proposal": {
                            "id": "USER-X",
                            "summary": "unreviewed",
                            "evaluation": None,
                        },
                    },
                    self.value["responses"][1],
                ],
            ),
            ("formal_spec", {**self.value["formal_spec"], "status": "unverified"}),
            ("limitations", []),
            ("privacy_projection", {**self.value["privacy_projection"], "public_safe": False}),
            ("extra", True),
        )
        for field, replacement in mutations:
            value = copy.deepcopy(self.value)
            if field == "extra":
                value[field] = replacement
            else:
                value[field] = replacement
            with self.subTest(field=field), self.assertRaises(ProjectError):
                discussion_batch.validate(value)

    def test_partial_responses_are_explicit_and_empty_declaration_fails(self) -> None:
        value = copy.deepcopy(self.value)
        value["responses"] = [value["responses"][0]]
        self.assertEqual(value, discussion_batch.validate(value))
        self.assertEqual(
            "missing-discussion-batch", discussion_batch.check(self.repo.root, [])[0]["code"]
        )

    def test_point_proposal_evaluation_and_response_boundaries_fail_closed(self) -> None:
        cases: tuple[tuple[str, Any], ...] = (
            ("task", None),
            ("task", {"id": "bad", "revision": 1}),
            ("task", {"id": "AR-0063", "revision": True}),
            ("task", {"id": "AR-0063", "revision": 0}),
            ("batch", {**self.value["batch"], "id": "bad"}),
            ("batch", {**self.value["batch"], "relation": "coupled"}),
            ("batch", {**self.value["batch"], "point_ids": ["POINT-AR0063-1"]}),
            (
                "batch",
                {
                    **self.value["batch"],
                    "point_ids": [
                        "POINT-AR0063-1",
                        "POINT-AR0063-2",
                        "POINT-AR0063-3",
                    ],
                },
            ),
            ("points", {"bad": True}),
            (
                "points",
                [
                    {
                        **self.value["points"][0],
                        "proposals": [
                            {
                                **self.value["points"][0]["proposals"][0],
                                "evaluation": {
                                    **self.value["points"][0]["proposals"][0]["evaluation"],
                                    "confidence": {"applicability": 0.5},
                                },
                            },
                            self.value["points"][0]["proposals"][1],
                        ],
                    },
                    self.value["points"][1],
                ],
            ),
            (
                "points",
                [{**self.value["points"][0], "id": "POINT-AR0063-2"}, self.value["points"][1]],
            ),
            (
                "points",
                [
                    {
                        **self.value["points"][0],
                        "proposals": [{"bad": True}, self.value["points"][0]["proposals"][1]],
                    },
                    self.value["points"][1],
                ],
            ),
            (
                "points",
                [
                    {
                        **self.value["points"][0],
                        "proposals": [
                            {**self.value["points"][0]["proposals"][0], "rank": 3},
                            self.value["points"][0]["proposals"][1],
                        ],
                    },
                    self.value["points"][1],
                ],
            ),
            (
                "points",
                [
                    {
                        **self.value["points"][0],
                        "proposals": [
                            {
                                **self.value["points"][0]["proposals"][0],
                                "evaluation": {"bad": True},
                            },
                            self.value["points"][0]["proposals"][1],
                        ],
                    },
                    self.value["points"][1],
                ],
            ),
            (
                "points",
                [
                    {
                        **self.value["points"][0],
                        "proposals": [
                            {
                                **self.value["points"][0]["proposals"][0],
                                "evaluation": {
                                    **self.value["points"][0]["proposals"][0]["evaluation"],
                                    "confidence": {
                                        "applicability": 2,
                                        "outcome": 0,
                                        "downstream": 0,
                                    },
                                },
                            },
                            self.value["points"][0]["proposals"][1],
                        ],
                    },
                    self.value["points"][1],
                ],
            ),
            (
                "points",
                [
                    {
                        **self.value["points"][0],
                        "proposals": [
                            {
                                **self.value["points"][0]["proposals"][0],
                                "evaluation": {
                                    **self.value["points"][0]["proposals"][0]["evaluation"],
                                    "implications": [],
                                },
                            },
                            self.value["points"][0]["proposals"][1],
                        ],
                    },
                    self.value["points"][1],
                ],
            ),
            (
                "responses",
                [
                    {**self.value["responses"][0], "disposition": "reject", "authorized": True},
                    self.value["responses"][1],
                ],
            ),
            (
                "responses",
                [
                    {**self.value["responses"][0], "proposal_id": None, "user_proposal": None},
                    self.value["responses"][1],
                ],
            ),
            (
                "responses",
                [
                    {**self.value["responses"][0], "user_proposal": {"bad": True}},
                    self.value["responses"][1],
                ],
            ),
            (
                "responses",
                [
                    {
                        **self.value["responses"][0],
                        "user_proposal": {
                            "id": "BAD",
                            "summary": "x",
                            "evaluation": self.value["points"][0]["proposals"][0]["evaluation"],
                        },
                    },
                    self.value["responses"][1],
                ],
            ),
            ("responses", [self.value["responses"][0], self.value["responses"][0]]),
            ("responses", {"bad": True}),
            ("formal_spec", None),
            ("formal_spec", {**self.value["formal_spec"], "specification_sha256": "bad"}),
            ("privacy_projection", {**self.value["privacy_projection"], "redacted_fields": [""]}),
            ("limitations", ["bad"]),
        )
        for field, replacement in cases:
            value = copy.deepcopy(self.value)
            value[field] = replacement
            with (
                self.subTest(field=field, replacement=repr(replacement)[:40]),
                self.assertRaises(ProjectError),
            ):
                discussion_batch.validate(value)

    def test_file_and_check_failures_are_bounded_and_content_minimized(self) -> None:
        target = self.repo.root / "quality/discussion-batch"
        target.mkdir(parents=True)
        malformed = target / "malformed.json"
        malformed.write_text("{", encoding="utf-8")
        with self.assertRaises(ProjectError):
            discussion_batch.evaluate_file(
                self.repo.root, "quality/discussion-batch/malformed.json"
            )
        noncanonical = target / "noncanonical.json"
        noncanonical.write_text(json.dumps(self.value, indent=2), encoding="utf-8")
        with self.assertRaisesRegex(ProjectError, "canonical"):
            discussion_batch.evaluate_file(
                self.repo.root, "quality/discussion-batch/noncanonical.json"
            )
        invalid = target / "invalid.json"
        invalid.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
        findings = discussion_batch.check(self.repo.root, [malformed, noncanonical, invalid])
        self.assertEqual(3, len(findings))
