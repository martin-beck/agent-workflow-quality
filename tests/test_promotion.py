# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Controlled, hostile, deterministic and privacy-boundary promotion tests."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from awq import commands, promotion
from awq.cli import main
from awq.project import ProjectError, load_project
from awq.registry import canonical_bytes
from scripts.validate_contracts import validate
from tests.support import Repository

ROOT = Path(__file__).resolve().parents[1]
AS_OF = "2026-09-09T00:00:00Z"


def document() -> dict[str, Any]:
    return dict(json.loads((ROOT / "fixtures/conforming/consumer-equivalence.json").read_bytes()))


def decision(value: dict[str, Any]) -> dict[str, Any]:
    return dict(promotion.evaluate(value, AS_OF)["gates"][0])


def fp_review(count: int = 1) -> dict[str, Any]:
    review = copy.deepcopy(document()["gates"][0]["rollback"]["review"])
    review["expires_at"] = "2026-09-20T00:00:00Z"
    return {
        "category": "configuration",
        "count": count,
        "remediation": "repair-adapter",
        "review": review,
    }


class PromotionTests(unittest.TestCase):
    def test_example_schema_canonical_and_determinism(self) -> None:
        value = document()
        validate(value, "consumer-equivalence.schema.json")
        raw = canonical_bytes(value)
        self.assertEqual(value, promotion.load(raw))
        first = promotion.evaluate(value, AS_OF)
        self.assertEqual(first, promotion.evaluate(promotion.load(raw), AS_OF))
        self.assertEqual("pass", first["status"])
        self.assertEqual("enforce", first["gates"][0]["decision"])
        self.assertEqual("retain", first["gates"][0]["native_gate"])
        self.assertIn("not trusted clock", first["limitation"])
        self.assertEqual([], first["gates"][0]["factors"])
        self.assertNotIn("owner", first["gates"][0])
        template = json.loads((ROOT / "templates/consumer-equivalence.json").read_bytes())
        validate(template, "consumer-equivalence.schema.json")
        self.assertEqual("shadow", decision(template)["decision"])

    def test_gate_independence_and_no_native_removal(self) -> None:
        value = document()
        other = copy.deepcopy(value["gates"][0])
        other["id"] = "AWQ-CORE-002"
        other["requested"] = "retain"
        value["gates"].append(other)
        value["gates"][0]["observation"]["days"][0]["counts"]["false_negative"] = 1
        result = promotion.evaluate(value, AS_OF)
        self.assertEqual("fail", result["status"])
        self.assertEqual(["block", "retain"], [item["decision"] for item in result["gates"]])
        self.assertTrue(all(item["native_gate"] == "retain" for item in result["gates"]))

    def test_controlled_false_negative_always_blocks(self) -> None:
        for requested in ("retain", "shadow", "enforce"):
            value = document()
            gate = value["gates"][0]
            gate["requested"] = requested
            case = next(case for case in gate["cases"] if case["expected"] == "fail")
            case["awq"] = "pass"
            self.assertEqual(["false-negative"], decision(value)["blocking"])

    def test_false_positive_requires_exact_active_owned_review(self) -> None:
        value = document()
        gate = value["gates"][0]
        case = next(case for case in gate["cases"] if case["expected"] == "pass")
        case["awq"] = "fail"
        self.assertEqual("block", decision(value)["decision"])
        gate["false_positive_reviews"] = [fp_review()]
        result = decision(value)
        self.assertEqual("enforce", result["decision"])
        self.assertEqual(["reviewed-false-positive"], result["factors"])
        self.assertEqual(["configuration"], result["false_positive_categories"])
        for change in (
            {"count": 2},
            {
                "count": 1,
                "review": {
                    **fp_review()["review"],
                    "expires_at": AS_OF,
                },
            },
        ):
            gate["false_positive_reviews"] = [{**fp_review(), **change}]
            self.assertEqual("block", decision(value)["decision"])
        gate["false_positive_reviews"] = [fp_review()]
        gate["observation"]["days"][0]["counts"]["false_positive"] = 1
        self.assertEqual("block", decision(value)["decision"])
        gate["false_positive_reviews"][0]["count"] = 2
        self.assertEqual("enforce", decision(value)["decision"])

    def test_native_oracle_failure_and_inconclusive_are_not_success(self) -> None:
        for native, awq in (("fail", "fail"), ("error", "pass"), ("skip", "skip")):
            value = document()
            case = next(case for case in value["gates"][0]["cases"] if case["expected"] == "pass")
            case.update(native=native, awq=awq)
            self.assertIn("controlled-native-oracle", decision(value)["blocking"])
        for outcome in ("error", "skip"):
            value = document()
            value["gates"][0]["cases"][0]["awq"] = outcome
            self.assertEqual("shadow", decision(value)["decision"])
            self.assertIn("inconclusive", decision(value)["factors"])
        value = document()
        value["gates"][0]["observation"]["days"][0]["counts"]["inconclusive"] = 1
        self.assertEqual("shadow", decision(value)["decision"])

    def test_observation_corpus_age_and_requested_decisions(self) -> None:
        value = document()
        gate = value["gates"][0]
        for requested in ("retain", "shadow"):
            gate["requested"] = requested
            self.assertEqual(requested, decision(value)["decision"])
        gate["requested"] = "enforce"
        gate["policy"]["minimum_runs"] = 71
        self.assertIn("observation-insufficient", decision(value)["factors"])
        gate["policy"]["minimum_runs"] = 20
        gate["observation"]["days"].pop()
        self.assertEqual("shadow", decision(value)["decision"])
        value = document()
        value["gates"][0]["policy"]["minimum_positive"] = 6
        self.assertIn("controlled-corpus-insufficient", decision(value)["factors"])
        value["gates"][0]["policy"]["minimum_positive"] = 5
        value["gates"][0]["policy"]["minimum_negative"] = 6
        self.assertIn("controlled-corpus-insufficient", decision(value)["factors"])
        value = document()
        value["gates"][0]["policy"]["max_age_seconds"] = 86399
        self.assertIn("observation-stale", decision(value)["factors"])

    def test_exact_integer_runtime_and_flake_boundaries(self) -> None:
        value = document()
        gate = value["gates"][0]
        for day in gate["observation"]["days"]:
            day["awq_ms"] = 200
        self.assertEqual("enforce", decision(value)["decision"])
        gate["observation"]["days"][0]["awq_ms"] += 1
        self.assertIn("runtime-budget", decision(value)["factors"])
        gate["observation"]["days"][0]["awq_ms"] -= 1
        gate["policy"]["flake_ratio"] = {"numerator": 1, "denominator": 20}
        gate["observation"]["days"][0]["flaky_runs"] = 3
        self.assertEqual("enforce", decision(value)["decision"])
        gate["observation"]["days"][0]["flaky_runs"] = 4
        self.assertIn("flake-budget", decision(value)["factors"])

    def test_review_and_rollback_expiry(self) -> None:
        value = document()
        gate = value["gates"][0]
        gate["rollback"]["deadline"] = AS_OF
        self.assertIn("rollback-expired", decision(value)["blocking"])
        gate["rollback"]["review"]["expires_at"] = AS_OF
        self.assertEqual("block", decision(value)["decision"])

    def test_invalid_fields_tokens_types_counts_and_enumerations(self) -> None:
        mutations: list[tuple[list[str | int], Any]] = [
            (["schema_version"], True),
            (["schema_version"], 2),
            (["consumer_sha256"], "private/path"),
            (["source_commit"], "a" * 39),
            (["gates", 0, "id"], "AWQ-CORE-01"),
            (["gates", 0, "native_definition_sha256"], "A" * 64),
            (["gates", 0, "awq_definition_sha256"], "b" * 63),
            (["gates", 0, "requested"], "remove"),
            (["gates", 0, "cases", 0, "sha256"], "a" * 63),
            (["gates", 0, "cases", 0, "expected"], "unknown"),
            (["gates", 0, "cases", 0, "native"], 0),
            (["gates", 0, "observation", "days", 0, "counts", "both_pass"], -1),
            (["gates", 0, "observation", "days", 0, "counts", "both_pass"], 0.5),
            (["gates", 0, "observation", "days", 0, "awq_ms"], 1_000_000_001),
            (["gates", 0, "observation", "days", 0, "flaky_runs"], 11),
            (["gates", 0, "policy", "minimum_days"], 6),
            (["gates", 0, "policy", "minimum_runs"], 19),
            (["gates", 0, "policy", "minimum_positive"], 4),
            (["gates", 0, "policy", "minimum_negative"], 4),
            (["gates", 0, "policy", "max_age_seconds"], 604801),
            (["gates", 0, "policy", "runtime_ratio"], {"numerator": 11, "denominator": 1}),
            (["gates", 0, "policy", "runtime_ratio"], {"numerator": 0, "denominator": 1}),
            (["gates", 0, "policy", "runtime_ratio"], {"numerator": 1, "denominator": 0}),
            (["gates", 0, "policy", "flake_ratio"], {"numerator": 1, "denominator": 19}),
            (["gates", 0, "rollback", "review", "owner"], "@private-email"),
            (["gates", 0, "rollback", "review", "reviewer"], "OWNER-MAINTAINER"),
            (["gates", 0, "rollback", "review", "approval_sha256"], "secret"),
            (["gates", 0, "rollback", "review", "created_at"], "2026-09-10T00:00:00Z"),
            (["gates", 0, "rollback", "review", "expires_at"], "2027-01-01T00:00:00Z"),
            (["gates", 0, "rollback", "review", "expires_at"], "2026-08-01T00:00:00Z"),
            (["gates", 0, "rollback", "deadline"], "2026-11-01T00:00:00Z"),
            (["gates", 0, "rollback", "triggers"], ["runtime-budget"]),
            (["gates", 0, "rollback", "triggers"], ["false-negative", "false-negative"]),
            (["gates", 0, "rollback", "triggers"], ["unknown"]),
            (["gates"], []),
            (["gates"], {}),
            (["gates", 0, "cases"], []),
            (["gates", 0, "policy"], {"prompt": "PRIVATE_MARKER_75"}),
        ]
        for path, replacement in mutations:
            with self.subTest(path=path, replacement=replacement):
                value = document()
                target: Any = value
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = replacement
                with self.assertRaises(ProjectError) as caught:
                    promotion.evaluate(value, AS_OF)
                self.assertNotIn("PRIVATE_MARKER_75", str(caught.exception))

    def test_invalid_windows_dates_and_duplicate_ordering(self) -> None:
        for field, stamp in (
            ("started_at", "2026-09-09T00:00:00Z"),
            ("started_at", "2025-09-01T00:00:00Z"),
            ("ended_at", "2026-09-10T00:00:00Z"),
            ("ended_at", "2026-09-01T00:00:00Z"),
        ):
            value = document()
            value["gates"][0]["observation"][field] = stamp
            with self.assertRaises(ProjectError):
                promotion.evaluate(value, AS_OF)
        invalid_stamps: list[Any] = [
            "2026-02-30T00:00:00Z",
            "2026-09-09T24:00:00Z",
            "2026-09-09T00:00:00+00:00",
            "2026-09-09",
            True,
        ]
        for invalid_stamp in invalid_stamps:
            with self.assertRaises(ProjectError):
                promotion.evaluate(document(), invalid_stamp)
        for key in ("cases", "days", "gates"):
            value = document()
            items = (
                value["gates"]
                if key == "gates"
                else value["gates"][0]["cases"]
                if key == "cases"
                else value["gates"][0]["observation"]["days"]
            )
            items.append(copy.deepcopy(items[0]))
            with self.assertRaises(ProjectError):
                promotion.evaluate(value, AS_OF)
        value = document()
        value["gates"][0]["cases"].reverse()
        with self.assertRaises(ProjectError):
            promotion.evaluate(value, AS_OF)

    def test_unknown_fields_at_every_object_boundary(self) -> None:
        paths = [
            [],
            ["gates", 0],
            ["gates", 0, "cases", 0],
            ["gates", 0, "policy"],
            ["gates", 0, "policy", "runtime_ratio"],
            ["gates", 0, "observation"],
            ["gates", 0, "observation", "days", 0],
            ["gates", 0, "observation", "days", 0, "counts"],
            ["gates", 0, "rollback"],
            ["gates", 0, "rollback", "review"],
        ]
        for path in paths:
            value = document()
            target: Any = value
            for key in path:
                target = target[key]
            target["logs"] = "PRIVATE_MARKER_75"
            with self.assertRaises(ProjectError) as caught:
                promotion.evaluate(value, AS_OF)
            self.assertNotIn("PRIVATE_MARKER_75", str(caught.exception))
        invalid_values: list[object] = [None, [], {"schema_version": 1}]
        for invalid_value in invalid_values:
            with self.assertRaises(ProjectError):
                promotion.evaluate(invalid_value, AS_OF)

    def test_canonical_duplicate_encoding_and_input_bounds(self) -> None:
        invalid = [
            b"{}",
            b"null\n",
            b'{"gates":1,"gates":2}\n',
            b'{"a":NaN}\n',
            b'{"a":Infinity}\n',
            b"\xff\n",
            b"not json",
            canonical_bytes(document()).rstrip(),
            b" " + canonical_bytes(document()),
            b"[" * 1500 + b"]" * 1500,
            b'"\\ud800"\n',
            b" " * (promotion.MAX_BYTES + 1),
        ]
        for raw in invalid:
            with self.assertRaises(ProjectError):
                promotion.load(raw)
        value = document()
        value["gates"] *= 201
        with self.assertRaises(ProjectError):
            promotion.evaluate(value, AS_OF)

    def test_review_bounds_and_inconsistent_totals(self) -> None:
        value = document()
        gate = value["gates"][0]
        for update in (
            {"remediation": "execute-secret"},
            {"category": "private-log"},
            {"count": 0},
            {"extra": "private"},
        ):
            gate["false_positive_reviews"] = [{**fp_review(), **update}]
            with self.assertRaises(ProjectError):
                promotion.evaluate(value, AS_OF)
        gate["false_positive_reviews"] = [fp_review()]
        gate["false_positive_reviews"][0]["review"]["expires_at"] = "2026-10-02T00:00:00Z"
        with self.assertRaises(ProjectError):
            promotion.evaluate(value, AS_OF)
        gate["false_positive_reviews"] = [fp_review(), fp_review()]
        with self.assertRaises(ProjectError):
            promotion.evaluate(value, AS_OF)
        gate["false_positive_reviews"] = []
        gate["observation"]["days"][0]["counts"] = dict.fromkeys(promotion.MATRIX, 0)
        with self.assertRaises(ProjectError):
            promotion.evaluate(value, AS_OF)
        gate["observation"]["days"][0]["counts"]["both_pass"] = 1_000_000
        with self.assertRaises(ProjectError):
            promotion.evaluate(value, AS_OF)

    def test_confined_cli_file_and_minimized_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "evidence.json"
            path.write_bytes(canonical_bytes(document()))
            for format_name in ("json", "text"):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    result = main(
                        [
                            "--root",
                            str(root),
                            "promotion-evaluate",
                            "evidence.json",
                            "--as-of",
                            AS_OF,
                            "--format",
                            format_name,
                        ]
                    )
                self.assertEqual(0, result)
                self.assertIn("enforce", output.getvalue())
                self.assertNotIn(str(root), output.getvalue())
            for relative in (
                "../evidence.json",
                "/outside/evidence.json",
                "x/../evidence.json",
                "x//evidence.json",
                "x\\evidence.json",
                "x.txt",
                "missing.json",
            ):
                with self.assertRaises(ProjectError):
                    promotion.evaluate_file(root, relative, AS_OF)
            link = root / "link.json"
            link.symlink_to(path)
            with self.assertRaises(ProjectError):
                promotion.evaluate_file(root, "link.json", AS_OF)
            path.write_bytes(b'{"logs":"PRIVATE_MARKER_75"}\n')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(
                    [
                        "--root",
                        str(root),
                        "promotion-evaluate",
                        "evidence.json",
                        "--as-of",
                        AS_OF,
                        "--format",
                        "json",
                    ]
                )
            self.assertEqual(1, result)
            self.assertNotIn("PRIVATE_MARKER_75", output.getvalue())


class SelectedRequirementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repository()
        self.repo.write("README.md", "# Fixture\n")
        self.repo.commit("base")
        commands.initialize(self.repo.root, ["core"], False)
        self.repo.commit("policy")

    def tearDown(self) -> None:
        self.repo.close()

    def test_selection_is_explicit_and_runs_only_requested_locked_gates(self) -> None:
        result = commands.check(self.repo.root, "pr", ["AWQ-CORE-001"])
        self.assertEqual(["AWQ-CORE-001"], result["selection"])
        self.assertEqual(["AWQ-CORE-001"], [item["id"] for item in result["requirements"]])
        self.assertEqual("not-selected", result["local_gates"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(
                0,
                main(
                    [
                        "--root",
                        str(self.repo.root),
                        "check",
                        "--requirement",
                        "AWQ-CORE-001",
                        "--format",
                        "json",
                    ]
                ),
            )
        self.assertEqual(["AWQ-CORE-001"], json.loads(output.getvalue())["selection"])
        self.assertNotIn("selection", commands.check(self.repo.root, "pr"))

    def test_unknown_duplicate_empty_unlocked_and_tier_ineligible_fail_before_execution(
        self,
    ) -> None:
        _, lock = load_project(self.repo.root)
        for selection in (
            [],
            ["AWQ-CORE-001"] * 2,
            ["AWQ-UNKNOWN-999"],
            ["AWQ-RUST-001"],
            [123],
            ["AWQ-CORE-001"] * 2001,
        ):
            with mock.patch("awq.commands.run_checks") as run:
                with self.assertRaises(ProjectError):
                    commands.check(self.repo.root, "pr", selection)  # type: ignore[arg-type]
                run.assert_not_called()
        from awq.registry import load_registry

        requirements, _, _ = load_registry()
        later = next(item for item in lock["requirements"] if requirements[item]["tier"] != "local")
        with mock.patch("awq.commands.run_checks") as run:
            with self.assertRaises(ProjectError):
                commands.check(self.repo.root, "local", [later])
            run.assert_not_called()
        with self.assertRaises(ProjectError):
            commands.check(self.repo.root, "invalid", ["AWQ-CORE-001"])

    def test_nonpass_or_incomplete_selected_result_fails_closed(self) -> None:
        for status in ("fail", "skip", "unknown"):
            with mock.patch(
                "awq.commands.run_checks", return_value=[{"id": "AWQ-CORE-001", "status": status}]
            ):
                self.assertEqual(
                    "fail", commands.check(self.repo.root, "pr", ["AWQ-CORE-001"])["status"]
                )
        with (
            mock.patch("awq.commands.run_checks", return_value=[]),
            self.assertRaises(ProjectError),
        ):
            commands.check(self.repo.root, "pr", ["AWQ-CORE-001"])
