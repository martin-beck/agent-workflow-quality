# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Independent construction oracles and bounded adversarial regressions."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any
from unittest import mock

from awq import adversarial as subject
from awq.cli import main
from awq.project import ProjectError
from awq.registry import canonical_bytes
from scripts import adversarial_campaign
from scripts.validate_contracts import validate

ROOT = Path(__file__).resolve().parents[1]


def contract(profile: str = "pr") -> dict[str, Any]:
    return dict(json.loads((ROOT / ("templates/adversarial-" + profile + ".json")).read_bytes()))


class AdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.scratch = Path(self.temporary.name).resolve()

    def test_pr_and_scheduled_are_deterministic_and_bounded(self) -> None:
        for profile, count in (("pr", 112), ("scheduled", 896)):
            value = contract(profile)
            validate(value, "adversarial-campaign.schema.json")
            result = subject.campaign(value, self.scratch)
            self.assertEqual("pass", result["status"])
            self.assertEqual(count, result["cases"])
            self.assertEqual({"numerator": 7, "denominator": 7}, result["mutation_score"])
            self.assertTrue(result["mutation_score_valid"])
            self.assertEqual([], result["reproducers"])
            self.assertEqual("retain", result["native_gate"])
            self.assertIn("awq.sbom", result["target_sha256"])
            self.assertEqual(subject.generate(value), subject.generate(value))
            if profile == "scheduled":
                for family, operators in subject.OPERATORS.items():
                    for operator in operators:
                        variants = {
                            case.variant
                            for case in subject.generate(value)
                            if case.family == family and case.operator == operator
                        }
                        self.assertEqual(set(range(1, 33)), variants)
        value = contract()
        result = subject.campaign(value, self.scratch)
        self.assertEqual(result, subject.campaign(value, self.scratch))
        self.assertEqual(
            "02fb0dfeb4486472bf7f79ff34b4d1d3e31016ce454305e381ee047046db1e67",
            result["corpus_sha256"],
        )
        value["seed"] = 0
        self.assertNotEqual(subject.generate(contract()), subject.generate(value))

    def test_independent_labels_and_each_boundary_mutation(self) -> None:
        expected = {
            "safe": "accept",
            "valid": "accept",
            "canonical": "accept",
            "pinned": "accept",
            "clean": "accept",
            "unchanged": "none",
            "relax-formats": "weakening",
            "strengthen-formats": "strengthening",
            "exclude-fixture": "weakening",
        }
        for family, operators in subject.OPERATORS.items():
            killed = False
            for operator in operators:
                case = subject.Case(family, operator, 1)
                label = expected.get(operator, "reject")
                self.assertEqual(label, subject.oracle(case))
                self.assertEqual(label, subject.observe(case, self.scratch))
                killed |= label != subject.observe(case, self.scratch, True)
            self.assertTrue(killed, family)

    def test_original_action_value_leak_is_regression_and_minimizes(self) -> None:
        case = subject.Case("redaction", "workflow-credential", 20)
        self.assertEqual("reject", subject.observe(case, self.scratch))
        original = subject._requirement

        def leaking(root: Path, path: Path, command: str) -> dict[str, Any]:
            result = original(root, path, command)
            if command == "action-pins" and "gh" + "p_" in path.read_text():
                result["untrusted"] = path.read_text()
            return result

        with mock.patch.object(subject, "_requirement", side_effect=leaking):
            result = subject.campaign(contract(), self.scratch)
            self.assertEqual("fail", result["status"])
            self.assertFalse(result["mutation_score_valid"])
            self.assertEqual(1, len(result["reproducers"]))
            recipe = result["reproducers"][0]
            self.assertEqual(1, recipe["variant"])
            self.assertEqual(case.family, recipe["family"])
            self.assertEqual(case.operator, recipe["operator"])
            validate(recipe, "adversarial-campaign.schema.json")
            self.assertNotIn(str(self.scratch), json.dumps(result))
            self.assertNotIn("gh" + "p_", json.dumps(result))
            (self.scratch / "recipe.json").write_bytes(canonical_bytes(recipe))
            replay = subject.replay_file(self.scratch, "recipe.json", self.scratch)
            self.assertEqual("fail", replay["status"])
        self.assertEqual(
            "pass", subject.replay_file(self.scratch, "recipe.json", self.scratch)["status"]
        )

    def test_shrink_order_fallback_and_surviving_mutants(self) -> None:
        case = subject.Case("paths", "safe", 20)

        def fault(item: subject.Case, _scratch: Path, _mutant: bool = False) -> str:
            return "reject" if item.variant >= 5 else "accept"

        with mock.patch.object(subject, "observe", side_effect=fault):
            self.assertEqual(5, subject.minimize(case, self.scratch).variant)

        def normal(item: subject.Case, _scratch: Path, _mutant: bool = False) -> str:
            return subject.oracle(item)

        with mock.patch.object(subject, "observe", side_effect=normal):
            self.assertEqual(case, subject.minimize(case, self.scratch))
            result = subject.campaign(contract(), self.scratch)
        self.assertEqual("fail", result["status"])
        self.assertEqual(0, result["mutation_score"]["numerator"])
        self.assertEqual({"survived"}, {item["status"] for item in result["mutations"]})

    def test_unknown_types_bounds_and_floor_fail_before_execution(self) -> None:
        changes: list[tuple[str, Any]] = [
            ("extra", "PRIVATE-MARKER"),
            ("schema_version", True),
            ("schema_version", 2),
            ("profile", []),
            ("profile", "unbounded"),
            ("seed", True),
            ("seed", 1.0),
            ("seed", -1),
            ("seed", 2**31),
            ("samples_per_operator", True),
            ("samples_per_operator", 3),
            ("samples_per_operator", 32),
            ("mutation_threshold", None),
            ("mutation_threshold", {"numerator": 6, "denominator": 7}),
            ("mutation_threshold", {"numerator": 7.0, "denominator": 7}),
        ]
        for key, replacement in changes:
            value = contract()
            value[key] = replacement
            with (
                self.subTest(key=key, replacement=replacement),
                mock.patch.object(subject, "observe") as observer,
            ):
                with self.assertRaises(ProjectError):
                    subject.campaign(value, self.scratch)
                observer.assert_not_called()
        invalid_values: list[Any] = [[], None, {}]
        for invalid in invalid_values:
            with self.assertRaises(ProjectError):
                subject.validate(invalid)

    def test_hostile_files_paths_and_redacted_unexpected_errors(self) -> None:
        good = canonical_bytes(contract())
        for raw in (b" " + good, b'{"seed":0,"seed":1}\n', b"x" * 100001):
            (self.scratch / "input.json").write_bytes(raw)
            with self.assertRaises(ProjectError):
                subject.run_file(self.scratch, "input.json", self.scratch)
        (self.scratch / "input.json").write_bytes(good)
        (self.scratch / "link.json").symlink_to(self.scratch / "input.json")
        (self.scratch / "linked").symlink_to(self.scratch, target_is_directory=True)
        for relative in (
            "../input.json",
            str(self.scratch / "input.json"),
            "link.json",
            "linked/input.json",
            "missing.json",
        ):
            with self.assertRaises(ProjectError):
                subject.run_file(self.scratch, relative, self.scratch)
        for scratch in (
            Path(),
            self.scratch / "absent",
            self.scratch / "input.json",
            self.scratch / "linked",
        ):
            with self.assertRaises(ProjectError):
                subject.run_file(self.scratch, "input.json", scratch)
        with (
            mock.patch.object(subject, "campaign", side_effect=RuntimeError("PRIVATE-MARKER")),
            self.assertRaisesRegex(ProjectError, "^adversarial request is invalid or unavailable$"),
        ):
            subject.run_file(self.scratch, "input.json", self.scratch)
        with self.assertRaises(ProjectError):
            subject._source_digest(None)

    def test_reproducer_shape_digest_and_retained_regression(self) -> None:
        relative = "fixtures/conforming/adversarial/workflow-redaction.json"
        self.assertEqual("pass", subject.replay_file(ROOT, relative, self.scratch)["status"])
        recipe = json.loads((ROOT / relative).read_bytes())
        for key, value in (
            ("extra", "PRIVATE"),
            ("schema_version", True),
            ("family", []),
            ("family", "unknown"),
            ("operator", "missing"),
            ("variant", 0),
            ("variant", 33),
            ("variant", True),
            ("code", "raw"),
            ("case_sha256", "0" * 64),
        ):
            altered = {**recipe, key: value}
            with self.assertRaises(ProjectError):
                subject._case(altered)
        with self.assertRaises(ProjectError):
            subject._case([])
        (self.scratch / "recipe.json").write_bytes(canonical_bytes(recipe))
        with (
            mock.patch.object(subject, "observe", side_effect=RuntimeError("PRIVATE-MARKER")),
            self.assertRaisesRegex(
                ProjectError, "^adversarial reproducer is invalid or unavailable$"
            ),
        ):
            subject.replay_file(self.scratch, "recipe.json", self.scratch)

    def test_cli_and_script_fail_closed(self) -> None:
        for command, relative in (
            ("adversarial-check", "templates/adversarial-pr.json"),
            ("adversarial-replay", "fixtures/conforming/adversarial/workflow-redaction.json"),
        ):
            for format_name in ("json", "text"):
                with redirect_stdout(io.StringIO()) as output:
                    status = main(
                        [
                            "--root",
                            str(ROOT),
                            command,
                            relative,
                            "--scratch",
                            str(self.scratch),
                            "--format",
                            format_name,
                        ]
                    )
                self.assertEqual(0, status)
                self.assertIn("pass", output.getvalue())
        for outcome in ("pass", "fail"):
            with (
                mock.patch.object(subject, "run_file", return_value={"status": outcome}),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(
                    0 if outcome == "pass" else 1,
                    adversarial_campaign.main(["--scratch", str(self.scratch)]),
                )
        with (
            mock.patch.object(subject, "run_file", side_effect=ProjectError("PRIVATE-MARKER")),
            redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(1, adversarial_campaign.main(["--scratch", str(self.scratch)]))
        self.assertNotIn("PRIVATE-MARKER", output.getvalue())


if __name__ == "__main__":
    unittest.main()
