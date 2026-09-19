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
