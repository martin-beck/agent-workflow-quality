# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Positive and hostile tests for contradiction and reopen evidence."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from typing import Any

import jsonschema

from awq import guidance_resolution, guidance_resolution_model
from awq.project import ProjectError
from tests.support import Repository


class GuidanceResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repository()
        self.value = json.loads(
            (Path(__file__).parents[1] / "quality/guidance-resolution/example.json").read_bytes()
        )

    def tearDown(self) -> None:
        self.repo.close()

    def test_reopen_record_matches_schema_runtime_and_is_deterministic(self) -> None:
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/guidance-resolution.schema.json").read_bytes()
        )
        jsonschema.Draft202012Validator(schema).validate(self.value)
        self.assertEqual(self.value, guidance_resolution.validate(copy.deepcopy(self.value)))
        target = self.repo.root / "quality/guidance-resolution/gate.json"
        target.parent.mkdir(parents=True)
        target.write_bytes(
            (json.dumps(self.value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
        self.assertEqual(
            "pass",
            guidance_resolution.evaluate_file(
                self.repo.root, "quality/guidance-resolution/gate.json"
            )["status"],
        )

    def test_unresolved_states_are_never_authorizing(self) -> None:
        for state, result in (
            ("pending_clarification", "clarification"),
            ("rejected_proposal", "rejection"),
            ("user_added_alternative", "alternative"),
            ("reopened", "reopen"),
        ):
            value = copy.deepcopy(self.value)
            value["before_state"] = "reconciled"
            value["after_state"] = state
            value["user_result"] = result
            value["authorization"] = "authorizing"
            with (
                self.subTest(state=state),
                self.assertRaisesRegex(ProjectError, "cannot authorize"),
            ):
                guidance_resolution.validate(value)

    def test_state_result_stale_and_material_noop_fail_closed(self) -> None:
        mutations: tuple[tuple[str, Any], ...] = (
            ("user_result", "rejection"),
            ("after_state", "reconciled"),
            ("issue", "no_op"),
            ("formal_spec", {**self.value["formal_spec"], "task_revision": 2}),
            ("limitations", ["user_intent_not_proven"]),
            ("privacy_projection", {**self.value["privacy_projection"], "public_safe": False}),
        )
        for field, replacement in mutations:
            value = copy.deepcopy(self.value)
            value[field] = replacement
            with self.subTest(field=field), self.assertRaises(ProjectError):
                guidance_resolution.validate(value)
        no_op = copy.deepcopy(self.value)
        no_op["issue"], no_op["before_state"] = "scope_change", "reopened"
        no_op["after_state"], no_op["user_result"] = "reopened", "reopen"
        with self.assertRaisesRegex(ProjectError, "did not change"):
            guidance_resolution.validate(no_op)

    def test_unknown_fields_canonical_bytes_and_missing_declaration_fail_closed(self) -> None:
        unknown = copy.deepcopy(self.value)
        unknown["transcript"] = "secret"
        with self.assertRaises(ProjectError):
            guidance_resolution.validate(unknown)
        target = self.repo.root / "quality/guidance-resolution"
        target.mkdir(parents=True)
        malformed = target / "malformed.json"
        malformed.write_text("{}\n", encoding="utf-8")
        self.assertEqual(
            "invalid-guidance-resolution",
            guidance_resolution.check(self.repo.root, [malformed])[0]["code"],
        )
        self.assertEqual(
            "missing-guidance-resolution", guidance_resolution.check(self.repo.root, [])[0]["code"]
        )

    def test_bounded_state_model_and_safety_oracle_cover_transitions(self) -> None:
        for before, after, result, issue in (
            ("pending_clarification", "reopened", "reopen", "contradiction"),
            ("rejected_proposal", "user_added_alternative", "alternative", "scope_change"),
            ("reopened", "reconciled", "reconciliation", "repeated_discussion"),
        ):
            record = guidance_resolution_model.transition(before, after, result, issue)
            self.assertTrue(guidance_resolution_model.safety_oracle(record))
        with self.assertRaises(ValueError):
            guidance_resolution_model.transition(
                "pending_clarification", "pending_clarification", "clarification", "contradiction"
            )

    def test_each_boundary_rejects_bad_shape_or_stale_authority(self) -> None:
        mutations: tuple[tuple[str, Any], ...] = (
            ("discussion_id", "DISC"),
            ("task", {}),
            ("task", {"id": "AR-0060", "revision": True}),
            ("event_refs", ["bad"]),
            ("issue", "unknown"),
            ("before_state", "unknown"),
            ("user_result", "unknown"),
            ("authorization", "maybe"),
            ("formal_spec", {"status": "fail"}),
            ("affected_ars", []),
            ("affected_ars", [{"id": "AR-0060"}]),
            ("limitations", []),
            ("privacy_projection", {}),
            ("formal_spec", {**self.value["formal_spec"], "result_sha256": "bad"}),
            ("affected_ars", [{**self.value["affected_ars"][0], "after_revision": 1}]),
        )
        for field, replacement in mutations:
            value = copy.deepcopy(self.value)
            value[field] = replacement
            with (
                self.subTest(field=field, replacement=replacement),
                self.assertRaises(ProjectError),
            ):
                guidance_resolution.validate(value)
        duplicate = copy.deepcopy(self.value)
        duplicate["affected_ars"].append(copy.deepcopy(duplicate["affected_ars"][0]))
        with self.assertRaises(ProjectError):
            guidance_resolution.validate(duplicate)
        authorizing = copy.deepcopy(self.value)
        authorizing.update(
            before_state="reopened",
            after_state="reconciled",
            user_result="reconciliation",
            issue="repeated_discussion",
            authorization="authorizing",
        )
        self.assertEqual(authorizing, guidance_resolution.validate(authorizing))

    def test_file_errors_and_model_rejections_are_bounded(self) -> None:
        target = self.repo.root / "quality/guidance-resolution"
        target.mkdir(parents=True)
        missing = target / "missing.json"
        with self.assertRaises(ProjectError):
            guidance_resolution.evaluate_file(
                self.repo.root, missing.relative_to(self.repo.root).as_posix()
            )
        malformed = target / "malformed.json"
        malformed.write_text("{", encoding="utf-8")
        with self.assertRaises(ProjectError):
            guidance_resolution.evaluate_file(
                self.repo.root, malformed.relative_to(self.repo.root).as_posix()
            )
        noncanonical = target / "noncanonical.json"
        noncanonical.write_text(json.dumps(self.value, indent=2), encoding="utf-8")
        with self.assertRaisesRegex(ProjectError, "canonical"):
            guidance_resolution.evaluate_file(
                self.repo.root, noncanonical.relative_to(self.repo.root).as_posix()
            )
        for args in (
            ("bad", "reopened", "reopen", "contradiction"),
            ("reopened", "bad", "reopen", "scope_change"),
            ("reopened", "reconciled", "bad", "scope_change"),
            ("reopened", "reopened", "reopen", "scope_change"),
            ("pending_clarification", "reopened", "reopen", "no_op"),
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                guidance_resolution_model.transition(*args)
