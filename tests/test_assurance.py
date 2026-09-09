# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Bounded exploration, independent counterexample replay and hostile evidence tests."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest import mock

from awq import assurance, formal_model
from awq.cli import main
from awq.project import ProjectError
from awq.registry import canonical_bytes
from scripts import check_assurance_models
from scripts.validate_contracts import validate

ROOT = Path(__file__).resolve().parents[1]
COUNTEREXAMPLES = {
    "stale-review": (["begin-review-1", "edit", "finish-review", "enforce"], "current-revision"),
    "expired-review": (["begin-review-1", "tick", "finish-review", "enforce"], "unexpired-review"),
    "self-review": (["begin-review-0", "finish-review", "enforce"], "independent-reviewer"),
}


def contract(kind: str = "model") -> dict[str, Any]:
    return dict(
        json.loads((ROOT / "fixtures/conforming/assurance" / (kind + ".json")).read_bytes())
    )


class FormalAssuranceTests(unittest.TestCase):
    def test_reviewed_counterexample_gate_and_changed_expectations(self) -> None:
        self.assertEqual("pass", check_assurance_models.check(ROOT)["status"])
        with mock.patch("scripts.check_assurance_models.strict_json", return_value={}):
            self.assertEqual("fail", check_assurance_models.check(ROOT)["status"])
        for status, code in (("pass", 0), ("fail", 1)):
            with (
                mock.patch("scripts.check_assurance_models.check", return_value={"status": status}),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(code, check_assurance_models.main())

    def test_complete_exploration_is_exact_and_deterministic(self) -> None:
        value = contract()
        validate(value, "assurance-contract.schema.json")
        first = assurance.evaluate(value)
        self.assertEqual(first, assurance.evaluate(copy.deepcopy(value)))
        self.assertEqual("pass", first["status"])
        self.assertEqual("exhausted", first["outcome"])
        self.assertEqual((256, 514), (first["states"], first["transitions"]))
        self.assertEqual([], first["counterexample"])
        self.assertEqual("not-proven", first["refinement"])
        self.assertIn("not an implementation refinement proof", first["limitation"])
        self.assertEqual(formal_model.State(), formal_model.State())

    def test_known_bad_mutations_match_reviewed_minimal_counterexamples(self) -> None:
        for mutation, (trace, invariant) in COUNTEREXAMPLES.items():
            with self.subTest(mutation=mutation):
                value = json.loads(
                    (ROOT / "fixtures/nonconforming/assurance" / (mutation + ".json")).read_bytes()
                )
                validate(value, "assurance-contract.schema.json")
                result = assurance.evaluate(value)
                self.assertEqual("fail", result["status"])
                self.assertEqual("counterexample", result["outcome"])
                self.assertEqual(trace, result["counterexample"])
                self.assertEqual([invariant], result["violated_invariants"])
                state = formal_model.State()
                for action in trace:
                    state = dict(formal_model.successors(state, value["bounds"], mutation))[action]
                self.assertTrue(state.enforced)
                if mutation == "stale-review":
                    self.assertNotEqual(state.revision, state.reviewed_revision)
                elif mutation == "expired-review":
                    self.assertGreaterEqual(
                        state.tick - state.review_tick, value["bounds"]["review_ttl"]
                    )
                else:
                    self.assertEqual(0, state.reviewer)
                self.assertNotIn(
                    "enforce",
                    dict(
                        formal_model.successors(
                            replace(state, enforced=False), value["bounds"], "none"
                        )
                    ),
                )

    def test_budget_exhaustion_is_not_proof_and_surviving_mutant_fails(self) -> None:
        value = contract()
        value["bounds"]["max_states"] = 1
        result = assurance.evaluate(value)
        self.assertEqual("fail", result["status"])
        self.assertEqual("incomplete", result["outcome"])
        self.assertEqual([], result["counterexample"])
        with mock.patch("awq.formal_model.MAX_TRANSITIONS", 1):
            self.assertEqual("incomplete", assurance.evaluate(contract())["outcome"])
        value = contract()
        value["bounds"].update(ticks=1, review_ttl=3)
        value["mutation"] = "expired-review"
        self.assertEqual("surviving-mutant", assurance.evaluate(value)["outcome"])
        self.assertEqual("fail", assurance.evaluate(value)["status"])

    def test_independent_oracle_detects_each_and_combined_invariant(self) -> None:
        self.assertEqual([], formal_model.violations(formal_model.State(), 1))
        bad = formal_model.State(enforced=True)
        self.assertEqual(
            sorted(formal_model.INVARIANTS)[1:],
            sorted(item for item in formal_model.violations(bad, 1) if item != "current-revision"),
        )
        bad = replace(bad, reviewed_revision=1)
        self.assertEqual(sorted(formal_model.INVARIANTS), formal_model.violations(bad, 1))
        good = formal_model.State(reviewed_revision=0, review_tick=0, reviewer=1, enforced=True)
        self.assertEqual([], formal_model.violations(good, 1))

    def test_unknown_bounds_and_kind_fail_before_exploration(self) -> None:
        mutations: list[tuple[list[str], Any]] = [
            (["kind"], "unknown"),
            (["schema_version"], True),
            (["schema_version"], 2),
            (["model"], "arbitrary-script"),
            (["mutation"], "shell-command"),
            (["bounds", "actors"], 1),
            (["bounds", "actors"], 4),
            (["bounds", "revisions"], 0),
            (["bounds", "revisions"], 4),
            (["bounds", "ticks"], 0),
            (["bounds", "ticks"], 7),
            (["bounds", "review_ttl"], 0),
            (["bounds", "review_ttl"], 4),
            (["bounds", "max_states"], 0),
            (["bounds", "max_states"], 20001),
            (["bounds", "actors"], 2.0),
            (["bounds", "ticks"], True),
            (["assumptions"], []),
            (["assumptions"], list(reversed(formal_model.ASSUMPTIONS))),
        ]
        for path, replacement in mutations:
            with self.subTest(path=path, replacement=replacement):
                value = contract()
                target: Any = value
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = replacement
                with mock.patch("awq.formal_model.explore") as explore:
                    with self.assertRaises(ProjectError):
                        assurance.evaluate(value)
                    explore.assert_not_called()
        invalid_values: list[object] = [None, [], {}]
        for invalid_value in invalid_values:
            with self.assertRaises(ProjectError):
                assurance.evaluate(invalid_value)

    def test_unknown_fields_never_echo_private_values(self) -> None:
        for kind, path in (
            ("model", []),
            ("model", ["bounds"]),
            ("refactor", []),
            ("refactor", ["identities"]),
            ("refactor", ["records", 0]),
        ):
            value = contract(kind)
            target: Any = value
            for key in path:
                target = target[key]
            target["logs"] = "PRIVATE_FIXTURE_39"
            with self.assertRaises(ProjectError) as caught:
                assurance.evaluate(value)
            self.assertNotIn("PRIVATE_FIXTURE_39", str(caught.exception))

    def test_files_cli_templates_and_input_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "contract.json"
            path.write_bytes(canonical_bytes(contract()))
            for format_name in ("json", "text"):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(
                        0,
                        main(
                            [
                                "--root",
                                str(root),
                                "assurance-check",
                                "contract.json",
                                "--format",
                                format_name,
                            ]
                        ),
                    )
                self.assertIn("exhausted", output.getvalue())
                self.assertNotIn(str(root), output.getvalue())
            for name in ("formal-model.json", "refactor-evidence.json"):
                value = json.loads((ROOT / "templates" / name).read_bytes())
                validate(value, "assurance-contract.schema.json")
                self.assertEqual("pass", assurance.evaluate(value)["status"])
            for relative in (
                "../contract.json",
                "/outside/contract.json",
                "x/../contract.json",
                "a\\contract.json",
                "a//contract.json",
                "a.txt",
                "missing.json",
            ):
                with self.assertRaises(ProjectError):
                    assurance.evaluate_file(root, relative)
            link = root / "link.json"
            link.symlink_to(path)
            with self.assertRaises(ProjectError):
                assurance.evaluate_file(root, "link.json")
            for raw in (
                b" " * 256001,
                b'{"kind":"model","kind":"refactor"}\n',
                b'{"x":NaN}\n',
                b"\xff",
                canonical_bytes(contract()).rstrip(),
                b'{"logs":"PRIVATE_FIXTURE_39"}\n',
                b"[" * 1500 + b"]" * 1500,
            ):
                path.write_bytes(raw)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(
                        1,
                        main(
                            [
                                "--root",
                                str(root),
                                "assurance-check",
                                "contract.json",
                                "--format",
                                "json",
                            ]
                        ),
                    )
                self.assertNotIn("PRIVATE_FIXTURE_39", output.getvalue())
            root_link = root / "linked"
            root_link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ProjectError):
                assurance.evaluate_file(root_link, "contract.json")


class RefactoringEvidenceTests(unittest.TestCase):
    def test_all_four_methods_and_before_after_bindings_are_required(self) -> None:
        value = contract("refactor")
        validate(value, "assurance-contract.schema.json")
        result = assurance.evaluate(value)
        self.assertEqual("pass", result["status"])
        self.assertEqual("caller-declared-not-run", result["execution"])
        self.assertEqual(list(assurance.METHODS), result["methods"])
        self.assertNotIn("owner", result)
        for records in (
            [],
            value["records"][:3],
            list(reversed(value["records"])),
            [value["records"][0]] * 4,
        ):
            candidate = {**value, "records": records}
            with self.assertRaises(ProjectError):
                assurance.evaluate(candidate)

    def test_mismatches_failures_and_surviving_mutants_fail(self) -> None:
        for method in assurance.METHODS:
            for field, replacement in (
                ("before_failures", 1),
                ("after_failures", 1),
                ("mismatches", 1),
                ("after_result_sha256", "0" * 64),
            ):
                value = contract("refactor")
                record = next(item for item in value["records"] if item["method"] == method)
                record[field] = replacement
                result = assurance.evaluate(value)
                self.assertEqual("fail", result["status"])
                self.assertTrue(result["findings"])
        value = contract("refactor")
        value["records"][2]["killed"] = 1
        self.assertEqual(["mutation:surviving-mutant"], assurance.evaluate(value)["findings"])

    def test_malformed_identities_reviews_methods_and_counts_rejected(self) -> None:
        mutations: list[tuple[list[str | int], Any]] = [
            (["identities", "after_source_sha256"], "a" * 64),
            (["identities", "before_source_sha256"], "A" * 64),
            (["review_sha256"], "private/path"),
            (["owner"], "private@example.invalid"),
            (["owner"], 1),
            (["scope"], "universal-equivalence"),
            (["records"], {}),
            (["records", 0, "method"], "format-only"),
            (["records", 0, "cases"], 0),
            (["records", 0, "cases"], 100001),
            (["records", 0, "before_failures"], 11),
            (["records", 0, "mismatches"], True),
            (["records", 0, "tool_sha256"], False),
            (["records", 0, "mutants"], 1),
            (["records", 2, "mutants"], 0),
            (["records", 2, "killed"], 3),
            (["records", 2, "mutants"], 10001),
        ]
        for path, replacement in mutations:
            value = contract("refactor")
            target: Any = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = replacement
            with self.assertRaises(ProjectError):
                assurance.evaluate(value)
