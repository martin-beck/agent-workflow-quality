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
