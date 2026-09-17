# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Positive and hostile tests for typed oracle interaction gates."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from typing import Any

import jsonschema

from awq import interaction_gate
from awq.project import ProjectError
from tests.support import Repository


class InteractionGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repository()
        self.value = json.loads(
            (
                Path(__file__).parents[1] / "quality/interaction-gates/ar-0058-example.json"
            ).read_bytes()
        )

    def tearDown(self) -> None:
        self.repo.close()

    def test_positive_record_schema_runtime_and_cli_are_deterministic(self) -> None:
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/interaction-gate.schema.json").read_bytes()
        )
        jsonschema.Draft202012Validator(schema).validate(self.value)
        self.assertEqual(self.value, interaction_gate.validate(copy.deepcopy(self.value)))
        target = self.repo.root / "quality/interaction-gates/gate.json"
        target.parent.mkdir(parents=True)
        target.write_bytes(
            (json.dumps(self.value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
        result = interaction_gate.evaluate_file(
            self.repo.root, "quality/interaction-gates/gate.json"
        )
        self.assertEqual("pass", result["status"])
        self.assertEqual(
            result,
            interaction_gate.evaluate_file(self.repo.root, "quality/interaction-gates/gate.json"),
        )

    def test_missing_formal_review_and_private_projection_fail_closed(self) -> None:
        mutations: tuple[tuple[str, Any], ...] = (
            ("root", None),
            ("schema_version", 2),
            ("gate_type", "unknown"),
            ("task", None),
            ("task", {"id": "bad", "revision": 1}),
            ("task", {"id": "AR-0058", "revision": True}),
            ("task", {"id": "AR-0058", "revision": 0}),
            ("event_refs", None),
            ("event_refs", []),
            ("event_refs", ["EV-X", "EV-X"]),
            ("event_refs", ["BAD"]),
            ("context", None),
            ("context", {"objective_sha256": "bad"}),
            ("before", None),
            ("before", {"plan_sha256": "1" * 64}),
            ("before", {"plan_sha256": "bad", "design_sha256": "1" * 64}),
            ("formal_spec", None),
            ("formal_spec", {"status": "incomplete"}),
            ("formal_spec", {"status": "pass", "specification_sha256": "bad"}),
            ("user_disposition", "deferred"),
            ("privacy_projection", None),
            (
                "privacy_projection",
                {"public_safe": False, "projection_sha256": "b" * 64, "redacted_fields": []},
            ),
            (
                "privacy_projection",
                {"public_safe": True, "projection_sha256": "bad", "redacted_fields": []},
            ),
            (
                "privacy_projection",
                {"public_safe": True, "projection_sha256": "b" * 64, "redacted_fields": None},
            ),
            (
                "privacy_projection",
                {"public_safe": True, "projection_sha256": "b" * 64, "redacted_fields": [""]},
            ),
            ("unresolved", True),
            ("extra", True),
        )
        for field, replacement in mutations:
            value = copy.deepcopy(self.value)
            if field == "root":
                value = replacement
            else:
                value[field] = replacement
            with self.subTest(field=field), self.assertRaises(ProjectError):
                interaction_gate.validate(value)

    def test_evaluator_rejects_malformed_noncanonical_and_invalid_records(self) -> None:
        target = self.repo.root / "quality/interaction-gates"
        target.mkdir(parents=True)
        malformed = target / "malformed.json"
        malformed.write_text("{", encoding="utf-8")
        with self.assertRaises(ProjectError):
            interaction_gate.evaluate_file(
                self.repo.root, "quality/interaction-gates/malformed.json"
            )
        noncanonical = target / "noncanonical.json"
        noncanonical.write_text(json.dumps(self.value, indent=2), encoding="utf-8")
        with self.assertRaisesRegex(ProjectError, "canonical"):
            interaction_gate.evaluate_file(
                self.repo.root, "quality/interaction-gates/noncanonical.json"
            )
        invalid = target / "invalid.json"
        invalid.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
        paths = [malformed, noncanonical, invalid]
        findings = interaction_gate.check(self.repo.root, paths)
        self.assertEqual(3, len(findings))

    def test_empty_directory_is_a_quality_failure(self) -> None:
        self.assertEqual(
            "missing-interaction-gate", interaction_gate.check(self.repo.root, [])[0]["code"]
        )
