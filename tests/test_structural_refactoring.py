# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Contract and hostile tests for language-neutral structural refactoring verification."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

from awq import structural_refactoring as subject
from awq.cli import main
from awq.project import ProjectError
from awq.registry import canonical_bytes
from scripts.validate_contracts import validate

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = tuple(
    ROOT / "fixtures/conforming" / f"structural-refactoring-{language}.json"
    for language in ("json", "python", "rust")
)


def contract(index: int = 0) -> dict[str, Any]:
    return dict(json.loads(FIXTURES[index].read_bytes()))


def replace(value: dict[str, Any], path: tuple[str | int, ...], replacement: object) -> None:
    target: Any = value
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement


class StructuralRefactoringTests(unittest.TestCase):
    def test_language_neutral_fixtures_and_python_mapping_are_deterministic(self) -> None:
        schema = json.loads((ROOT / "schemas/structural-refactoring.schema.json").read_bytes())
        Draft202012Validator.check_schema(schema)
        observed = []
        for fixture in FIXTURES:
            value = json.loads(fixture.read_bytes())
            validate(value, "structural-refactoring.schema.json")
            result = subject.evaluate(value)
            self.assertEqual(result, subject.evaluate(json.loads(canonical_bytes(value))))
            self.assertEqual("pass", result["status"])
            self.assertEqual("retain", result["native_gate"])
            self.assertEqual("read-only", result["execution"])
            observed.append(result["language"])
            rendered = json.dumps(result, sort_keys=True)
            for forbidden in ("include_paths", "fixtures/", "source_excerpt", "argv"):
                self.assertNotIn(forbidden, rendered)
        self.assertEqual(["json", "python", "rust"], observed)
        self.assertEqual("python-refactoring", contract(1)["native_mapping"]["family"])

    def test_stale_identities_budgets_output_and_convergence_fail_closed(self) -> None:
        mutations: tuple[tuple[tuple[str | int, ...], object], ...] = (
            (("result", "base_commit"), "f" * 40),
            (("result", "catalog_sha256"), "f" * 64),
            (("result", "input_tree_sha256"), "f" * 64),
            (("result", "output_tree_sha256"), "f" * 64),
            (("result", "changed_files"), 21),
            (("result", "changed_lines"), 401),
            (("result", "matches"), 201),
            (("result", "elapsed_seconds"), 61),
            (("result", "second_plan_output_sha256"), "f" * 64),
            (("result", "convergence"), "changed"),
        )
        for path, replacement in mutations:
            value = contract()
            replace(value, path, replacement)
            with self.subTest(path=path), self.assertRaises(ProjectError):
                subject.evaluate(value)

    def test_command_strings_unsafe_scope_and_prohibited_changes_fail_closed(self) -> None:
        mutations: tuple[tuple[tuple[str | int, ...], object], ...] = (
            (("recipe", "verification", "focused_argv", 0), "python -m unittest"),
            (("recipe", "verification", "full_argv", 0, 0), "sh -c"),
            (("recipe", "verification", "full_argv", 0), ["sh", "-c", "echo"]),
            (("recipe", "scope", "include_paths", 0), "../private"),
            (("recipe", "scope", "include_paths", 0), "src/.hidden"),
            (("recipe", "scope", "include_paths", 0), "src/./hidden"),
            (("recipe", "scope", "include_paths", 0), "src/private marker"),
            (("recipe", "scope", "exclude_paths", 0), "other/generated"),
            (("recipe", "prohibited_classes"), ["syntax-rewrite"]),
            (("recipe", "application"), "apply"),
            (("native_mapping", "retained"), False),
        )
        semantic_only = {
            ("recipe", "scope", "exclude_paths", 0),
        }
        for path, replacement in mutations:
            value = contract()
            replace(value, path, replacement)
            with self.subTest(path=path):
                if path in semantic_only:
                    validate(value, "structural-refactoring.schema.json")
                else:
                    with self.assertRaises(ValidationError):
                        validate(value, "structural-refactoring.schema.json")
                with self.assertRaises(ProjectError):
                    subject.evaluate(value)
        for version in ("1.2-SNAPSHOT", "1.2-main", "1.x"):
            value = contract()
            value["recipe"]["tool"]["version"] = version
            with self.subTest(version=version):
                with self.assertRaises(ValidationError):
                    validate(value, "structural-refactoring.schema.json")
                with self.assertRaises(ProjectError):
                    subject.evaluate(value)

    def test_fixture_and_commitment_identity_coverage_is_exact(self) -> None:
        values = []
        value = contract()
        value["recipe"]["fixtures"]["golden"][0]["id"] = "FIXTURE-NEGATIVE"
        values.append(value)
        value = contract()
        value["result"]["fixture_results"].pop()
        values.append(value)
        value = contract()
        value["result"]["fixture_results"][0]["status"] = "fail"
        values.append(value)
        value = contract()
        value["recipe"]["preconditions"] *= 2
        values.append(value)
        value = contract()
        value["recipe"]["invariants"][0]["evidence_sha256"] = "bad"
        values.append(value)
        for value in values:
            with self.assertRaises(ProjectError):
                subject.evaluate(value)

    def test_closed_types_versions_order_and_bounds_match_schema(self) -> None:
        mutations: tuple[tuple[tuple[str | int, ...], object], ...] = (
            (("schema_version",), True),
            (("recipe", "risk"), []),
            (("recipe", "tool", "version"), "latest"),
            (("recipe", "parser", "version"), "main"),
            (("recipe", "language"), "Python"),
            (("recipe", "behavior_claim", "evidence_refs"), []),
            (("recipe", "budgets", "max_files"), True),
            (("result", "transformation_classes"), {}),
        )
        for path, replacement in mutations:
            value = contract()
            replace(value, path, replacement)
            with self.subTest(path=path):
                with self.assertRaises(ValidationError):
                    validate(value, "structural-refactoring.schema.json")
                with self.assertRaises(ProjectError):
                    subject.evaluate(value)
        value = contract()
        value["unknown"] = "not-retained"
        with self.assertRaises(ProjectError):
            subject.evaluate(value)
        value = contract()
        value["recipe"]["behavior_claim"]["evidence_refs"].reverse()
        with self.assertRaises(ProjectError):
            subject.evaluate(value)

    def test_evaluate_file_cli_canonical_bounds_and_privacy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "quality.json"
            path.write_bytes(canonical_bytes(contract()))
            expected = subject.evaluate(contract())
            self.assertEqual(expected, subject.evaluate_file(root, "quality.json"))
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(
                    0,
                    main(
                        [
                            "--root",
                            str(root),
                            "structural-refactor-verify",
                            "quality.json",
                            "--format",
                            "json",
                        ]
                    ),
                )
            self.assertEqual("pass", json.loads(output.getvalue())["status"])
            self.assertNotIn(str(root), output.getvalue())
            for raw in (
                b" " + canonical_bytes(contract()),
                b'{"schema_version":1,"schema_version":1}\n',
                b"x" * (subject.MAX_BYTES + 1),
            ):
                path.write_bytes(raw)
                with (
                    redirect_stdout(io.StringIO()) as output,
                    redirect_stderr(io.StringIO()),
                ):
                    self.assertEqual(
                        1,
                        main(
                            [
                                "--root",
                                str(root),
                                "structural-refactor-verify",
                                "quality.json",
                                "--format",
                                "json",
                            ]
                        ),
                    )
                self.assertNotIn(str(root), output.getvalue())
            with self.assertRaises(ProjectError):
                subject.evaluate_file(root, "../private.json")

    def test_evidence_identity_changes_are_material_without_disclosing_paths(self) -> None:
        baseline = subject.evaluate(contract())
        value = contract()
        value["result"]["evidence_sha256"] = "0" * 64
        changed = subject.evaluate(value)
        self.assertNotEqual(baseline["verification_sha256"], changed["verification_sha256"])
        self.assertEqual("0" * 64, changed["result_evidence_sha256"])
        self.assertNotIn("src/generated", json.dumps(changed))

    def test_remaining_helper_bounds_and_normalized_file_failure(self) -> None:
        calls = (
            lambda: subject._identifier(1, "PLAN"),
            lambda: subject._commit("bad"),
            lambda: subject._token([]),
            lambda: subject._path({}),
            lambda: subject._commitments([], "INVARIANT"),
            lambda: subject._argv([]),
            lambda: subject._argv([["python", "\n"]]),
        )
        for call in calls:
            with self.assertRaises(ProjectError):
                call()
        value = contract()
        value["recipe"]["fixtures"]["positive"] = []
        with self.assertRaises(ProjectError):
            subject.evaluate(value)
        value = contract()
        value["recipe"]["fixtures"]["positive"] = [
            {
                "id": "FIXTURE-ZZZ",
                "path": "fixtures/z.json",
                "sha256": "1" * 64,
            },
            {
                "id": "FIXTURE-AAA",
                "path": "fixtures/a.json",
                "sha256": "2" * 64,
            },
        ]
        with self.assertRaises(ProjectError):
            subject.evaluate(value)
        value = contract()
        value["recipe"]["prohibited_classes"] = ["unknown-change"]
        with self.assertRaises(ProjectError):
            subject.evaluate(value)
        value = contract()
        value["recipe"]["prohibited_classes"].append("syntax-rewrite")
        with self.assertRaises(ProjectError):
            subject.evaluate(value)
        value = contract()
        value["recipe"]["behavior_claim"]["kind"] = "proved"
        with self.assertRaises(ProjectError):
            subject.evaluate(value)
        value = contract()
        value["result"]["fixture_results"][0]["id"] = "FIXTURE-OTHER"
        with self.assertRaises(ProjectError):
            subject.evaluate(value)
        value = contract()
        value["recipe"]["scope"]["include_paths"] = ["src", "src/library"]
        with self.assertRaises(ProjectError):
            subject.evaluate(value)
        value = contract()
        value["recipe"]["fixtures"]["positive"][0]["sha256"] = value["recipe"]["fixtures"][
            "negative"
        ][0]["sha256"]
        with self.assertRaises(ProjectError):
            subject.evaluate(value)
        value = contract()
        value["recipe"]["verification"]["full_argv"] = value["recipe"]["verification"][
            "focused_argv"
        ]
        with self.assertRaises(ProjectError):
            subject.evaluate(value)
        value = contract()
        value["result"]["changed_files"] = 0
        with self.assertRaises(ProjectError):
            subject.evaluate(value)
        value = contract()
        value["proposed_output_tree_sha256"] = value["input_tree_sha256"]
        value["result"]["output_tree_sha256"] = value["input_tree_sha256"]
        value["result"]["second_plan_output_sha256"] = value["input_tree_sha256"]
        with self.assertRaises(ProjectError):
            subject.evaluate(value)
        value = contract()
        value["result"]["fixture_results"][0]["evidence_sha256"] = value["result"][
            "fixture_results"
        ][1]["evidence_sha256"]
        with self.assertRaises(ProjectError):
            subject.evaluate(value)
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ProjectError):
            subject.evaluate_file(Path(directory).resolve(), "missing.json")


if __name__ == "__main__":
    unittest.main()
