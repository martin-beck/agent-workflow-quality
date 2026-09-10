# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Lifecycle component exploration, independent counterexample replay and hostile contracts."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest import mock

from awq import assurance
from awq import lifecycle_model as model
from awq.cli import main
from awq.project import ProjectError
from awq.registry import canonical_bytes
from scripts.validate_contracts import validate

ROOT = Path(__file__).resolve().parents[1]


def contract() -> dict[str, Any]:
    return dict(json.loads((ROOT / "fixtures/conforming/lifecycle/model.json").read_bytes()))


def replay[T](
    initial: T, steps: Callable[[T], Iterator[tuple[str, T]]], trace: list[str]
) -> tuple[T, str, T]:
    before = after = initial
    action = ""
    for action in trace:
        before = after
        after = dict(steps(before))[action]
    return before, action, after


class LifecycleTests(unittest.TestCase):
    def test_default_components_exhaustive_deterministic_and_noncompositional(self) -> None:
        value = contract()
        validate(value, "lifecycle-model.schema.json")
        validate(value, "assurance-contract.schema.json")
        result = assurance.evaluate(value)
        self.assertEqual(result, assurance.evaluate(copy.deepcopy(value)))
        self.assertEqual("pass", result["status"])
        self.assertEqual("exhausted", result["outcome"])
        self.assertEqual("not-proven", result["composition"])
        self.assertEqual("not-proven", result["refinement"])
        expected = {"exceptions": (89, 220), "publication": (138, 250), "tiers": (1086, 4512)}
        self.assertEqual(
            expected,
            {
                name: (item["states"], item["transitions"])
                for name, item in result["components"].items()
            },
        )
        self.assertTrue(
            all(item["outcome"] == "exhausted" for item in result["components"].values())
        )
        self.assertEqual(64, len(result["model_sha256"]))

    def test_all_ten_reviewed_mutations_have_exact_counterexamples(self) -> None:
        expected = json.loads((ROOT / "formal/lifecycle-counterexamples.json").read_bytes())
        self.assertEqual(10, len(expected["mutations"]))
        for mutation in model.MUTATIONS[1:]:
            with self.subTest(mutation=mutation):
                value = json.loads(
                    (ROOT / "fixtures/nonconforming/lifecycle" / (mutation + ".json")).read_bytes()
                )
                validate(value, "lifecycle-model.schema.json")
                validate(value, "assurance-contract.schema.json")
                result = assurance.evaluate(value)
                self.assertEqual("fail", result["status"])
                self.assertEqual("counterexample", result["outcome"])
                self.assertEqual(expected["mutations"][mutation], result["components"])
                for component, item in result["components"].items():
                    if item["outcome"] == "counterexample":
                        self._independent_violation(component, mutation, item["counterexample"])

    def _independent_violation(self, component: str, mutation: str, trace: list[str]) -> None:
        bounds = contract()["bounds"]
        if component == "exceptions":
            before, action, after = replay(
                model.ExceptionState(),
                lambda state: model.exception_steps(state, bounds, mutation),
                trace,
            )
            self.assertTrue(
                after.tick >= after.expiry
                if mutation == "exception-expiry"
                else after.approval_generation != after.generation - 1
            )
            self.assertNotIn((action, after), list(model.exception_steps(before, bounds, "none")))
        elif component == "tiers":
            prior, action, following = replay(
                model.TierState(),
                lambda state: model.tier_steps(state, bounds, mutation),
                trace,
            )
            if mutation in ("stale-review", "review-quorum"):
                self.assertTrue(
                    prior.review_a != prior.revision or prior.review_b != prior.revision
                )
            elif mutation == "stale-evidence":
                self.assertGreaterEqual(prior.tick - prior.evidence_tick, bounds["ttl"])
            elif mutation == "tier-skip":
                self.assertGreater(following.tier, prior.tier + 1)
            else:
                self.assertGreaterEqual(prior.tick, bounds["rollback_deadline"])
            self.assertNotIn((action, following), list(model.tier_steps(prior, bounds, "none")))
        else:
            old, action, new = replay(
                model.PublicationState(),
                lambda state: model.publication_steps(state, bounds, mutation),
                trace,
            )
            if mutation == "lost-update":
                self.assertLessEqual(new.policy, old.policy)
            else:
                self.assertNotEqual(new.policy, new.receipt)
            if mutation == "restart-uncommitted":
                self.assertTrue(old.crashed)
                self.assertNotEqual((old.policy, old.receipt), (new.policy, new.receipt))
            self.assertNotIn((action, new), list(model.publication_steps(old, bounds, "none")))

    def test_crash_before_and_after_commit_preserves_durable_pair(self) -> None:
        bounds = contract()["bounds"]
        for prefix, expected in (
            (["begin-a", "stage-a"], 0),
            (["begin-a", "stage-a", "stage-a", "commit-a"], 1),
        ):
            _, _, after = replay(
                model.PublicationState(),
                lambda state: model.publication_steps(state, bounds, "none"),
                [*prefix, "crash", "restart"],
            )
            self.assertEqual((expected, expected), (after.policy, after.receipt))
            self.assertEqual(
                (-1, -1, 0, 0), (after.base_a, after.base_b, after.stage_a, after.stage_b)
            )
            self.assertFalse(after.crashed)

    def test_reviewed_renewal_after_expiry_and_revocation(self) -> None:
        bounds = contract()["bounds"]
        _, _, expired = replay(
            model.ExceptionState(),
            lambda state: model.exception_steps(state, bounds, "none"),
            ["review-renewal", "publish-renewal", "tick"],
        )
        self.assertNotIn("use-exception", dict(model.exception_steps(expired, bounds, "none")))
        _, _, renewed = replay(
            expired,
            lambda state: model.exception_steps(state, bounds, "none"),
            ["review-renewal", "publish-renewal", "use-exception"],
        )
        self.assertTrue(renewed.used)
        self.assertLess(renewed.tick, renewed.expiry)
        self.assertEqual(2, renewed.generation)

    def test_partial_search_and_surviving_mutant_never_pass(self) -> None:
        value = contract()
        value["bounds"]["max_states"] = 1
        result = assurance.evaluate(value)
        self.assertEqual("incomplete", result["outcome"])
        self.assertEqual("fail", result["status"])
        self.assertTrue(
            all(item["outcome"] == "incomplete" for item in result["components"].values())
        )
        with mock.patch("awq.lifecycle_model.MAX_TRANSITIONS", 1):
            self.assertEqual("incomplete", assurance.evaluate(contract())["outcome"])
        value = contract()
        value["mutation"] = "exception-expiry"
        value["bounds"].update(ticks=1, ttl=3)
        self.assertEqual("surviving-mutant", assurance.evaluate(value)["outcome"])
        self.assertEqual("fail", assurance.evaluate(value)["status"])

    def test_invalid_model_bounds_and_assumptions_fail_before_exploration(self) -> None:
        changes: list[tuple[str, Any]] = [
            ("mutation", "arbitrary-command"),
            ("assumptions", []),
            ("assumptions", list(reversed(model.ASSUMPTIONS))),
            ("schema_version", True),
            ("schema_version", 2),
            ("kind", "unknown"),
            ("model", "unknown"),
            ("bounds", {"unknown": 1}),
        ]
        for key, value in changes:
            candidate = {**contract(), key: value}
            with mock.patch("awq.lifecycle_model.explore") as explore:
                with self.assertRaises(ProjectError):
                    assurance.evaluate(candidate)
                explore.assert_not_called()
        for key, high in (
            ("ticks", 3),
            ("revisions", 3),
            ("ttl", 3),
            ("tiers", 2),
            ("rollback_deadline", 3),
            ("max_states", 20000),
        ):
            for invalid in (0, high + 1, True, 1.5, "1"):
                value = contract()
                value["bounds"][key] = invalid
                with mock.patch("awq.lifecycle_model.explore") as explore:
                    with self.assertRaises(ProjectError):
                        assurance.evaluate(value)
                    explore.assert_not_called()

    def test_explicit_oracles_reject_unauthorized_transitions(self) -> None:
        bounds = contract()["bounds"]
        prior = model.TierState(tick=2, target=2)
        self.assertEqual(
            [
                "current-fresh-evidence",
                "one-tier-at-a-time",
                "rollback-before-deadline",
                "two-current-reviewers",
            ],
            sorted(model.tier_violations(prior, "promote", replace(prior, tier=2), bounds)),
        )
        self.assertEqual([], model.tier_violations(prior, "observe", prior, bounds))
        publication = model.PublicationState()
        self.assertEqual(
            ["recovery-preserves-commit"],
            model.publication_violations(
                publication, "crash", replace(publication, policy=1, receipt=1)
            ),
        )

    def test_canonical_privacy_file_and_cli_boundaries(self) -> None:
        template = json.loads((ROOT / "templates/lifecycle-model.json").read_bytes())
        self.assertEqual(contract(), template)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "model.json"
            path.write_bytes(canonical_bytes(contract()))
            for output_format in ("text", "json"):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(
                        0,
                        main(
                            [
                                "--root",
                                str(root),
                                "assurance-check",
                                "model.json",
                                "--format",
                                output_format,
                            ]
                        ),
                    )
                self.assertNotIn(str(root), output.getvalue())
                self.assertIn("not-proven", output.getvalue())
            for relative in (
                "../model.json",
                "/outside/model.json",
                "a/../model.json",
                "a\\model.json",
                "missing.json",
            ):
                with self.assertRaises(ProjectError):
                    assurance.evaluate_file(root, relative)
            link = root / "link.json"
            link.symlink_to(path)
            with self.assertRaises(ProjectError):
                assurance.evaluate_file(root, "link.json")
            for raw in (
                canonical_bytes({**contract(), "logs": "PRIVATE_FIXTURE_81"}),
                b" " * 256001,
                b'{"model":1,"model":2}\n',
                b'{"x":NaN}\n',
                canonical_bytes(contract()).rstrip(),
                b"\xff",
            ):
                path.write_bytes(raw)
                with self.assertRaises(ProjectError) as caught:
                    assurance.evaluate_file(root, "model.json")
                self.assertNotIn("PRIVATE_FIXTURE_81", str(caught.exception))
