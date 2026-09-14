# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""GitHub Actions trust-transition contract tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

from awq import checks
from awq.workflow_trust import (
    SHA_EXPRESSION,
    WorkflowTrustError,
    evaluate_workflow,
    load_policy,
    validate_policy,
)
from tests.support import Repository, base_policy

ROOT = Path(__file__).resolve().parents[1]


def policy() -> dict[str, object]:
    return {
        "schema_version": 1,
        "events": {
            "untrusted": ["pull_request"],
            "environmental": ["schedule"],
            "trusted": ["push", "workflow_call", "workflow_dispatch"],
            "prohibited": ["pull_request_target"],
        },
        "runners": {
            "disposable": ["ubuntu-24.04", "macos-14", "windows-2022"],
            "trusted": ["trusted-linux"],
            "persistent": ["persistent-linux"],
        },
        "protected_branches": ["main"],
        "publication_events": ["push-tags"],
        "required_gate_workflows": [".github/workflows/verify.yml"],
        "publication_workflows": [".github/workflows/release.yml"],
    }


def workflow(
    *,
    event: str = "pull_request",
    runner: str = "ubuntu-24.04",
    permission: str = "contents: read",
    checkout: str = "",
    extra: str = "",
) -> str:
    checkout = checkout or (
        "      - uses: actions/checkout@" + "a" * 40 + "\n"
        "        with:\n"
        f"          ref: {SHA_EXPRESSION}\n"
        "          persist-credentials: false\n"
    )
    return (
        "name: Trust fixture\n"
        f'"on": {event}\n'
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  verify:\n"
        f"    runs-on: {runner}\n"
        "    timeout-minutes: 5\n"
        + (f"    permissions:\n      {permission}\n" if permission != "contents: read" else "")
        + "    steps:\n"
        + checkout
        + extra
    )


class WorkflowTrustTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = validate_policy(policy())

    def codes(self, text: str, path: str = ".github/workflows/verify.yml") -> set[str]:
        return {code for code, _ in evaluate_workflow(path, text, self.policy)}

    def test_schema_runtime_and_valid_trust_classes(self) -> None:
        schema = json.loads((ROOT / "schemas/workflow-trust-policy.schema.json").read_text())
        Draft202012Validator(schema).validate(policy())
        self.assertEqual(set(), self.codes(workflow()))
        scheduled = workflow(event="schedule").replace(f"          ref: {SHA_EXPRESSION}\n", "")
        self.assertEqual(set(), self.codes(scheduled, ".github/workflows/environment.yml"))
        manual = (
            workflow(event="workflow_dispatch", runner="trusted-linux")
            .replace(
                "    runs-on: trusted-linux\n",
                "    runs-on: trusted-linux\n    if: github.ref == 'refs/heads/main'\n",
            )
            .replace(f"          ref: {SHA_EXPRESSION}\n", "")
        )
        self.assertEqual(set(), self.codes(manual, ".github/workflows/manual.yml"))
        release = (
            workflow(event="push", permission="id-token: write")
            .replace('"on": push\n', '"on":\n  push:\n    tags: ["v*"]\n')
            .replace(f"          ref: {SHA_EXPRESSION}\n", "")
        )
        self.assertEqual(set(), self.codes(release, ".github/workflows/release.yml"))

    def test_native_observations_are_optional_and_non_authorizing(self) -> None:
        documentation = (ROOT / "docs/WORKFLOW_TRUST.md").read_text(encoding="utf-8")
        self.assertIn("optional environmental inputs", documentation)
        self.assertIn("non-authorizing", documentation)
        self.assertIn("never turn an AWQ result into a certification", documentation)
        self.assertIn("retained native gate", documentation)
        self.assertNotIn("native evidence authorizes", documentation.casefold())

    def test_policy_unknowns_overlaps_paths_and_bounds_fail_closed(self) -> None:
        cases: list[dict[str, object]] = []
        unknown = copy.deepcopy(policy())
        unknown["unknown"] = True
        cases.append(unknown)
        overlap = copy.deepcopy(policy())
        overlap["runners"]["trusted"] = ["ubuntu-24.04"]  # type: ignore[index]
        cases.append(overlap)
        unsafe = copy.deepcopy(policy())
        unsafe["required_gate_workflows"] = ["../verify.yml"]
        cases.append(unsafe)
        missing = copy.deepcopy(policy())
        missing["events"]["environmental"] = []  # type: ignore[index]
        cases.append(missing)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(WorkflowTrustError):
                validate_policy(value)
        schema = json.loads((ROOT / "schemas/workflow-trust-policy.schema.json").read_text())
        with self.assertRaises(ValidationError):
            Draft202012Validator(schema).validate(unknown)

    def test_every_hostile_transition_fails_independently(self) -> None:
        cases = {
            "pull-request-target": (
                workflow(event="pull_request_target"),
                "prohibited-trust-event",
            ),
            "trusted-public": (
                workflow(runner="persistent-linux"),
                "untrusted-code-trusted-runner",
            ),
            "write-on-pr": (workflow(permission="contents: write"), "privilege-boundary"),
            "dynamic-permissions": (
                workflow().replace("    steps:\n", "    permissions: write-all\n    steps:\n"),
                "widened-job-permissions",
            ),
            "dynamic-permissions-block": (
                workflow().replace(
                    "    steps:\n",
                    "    permissions:\n      contents: ${{ inputs.access }}\n    steps:\n",
                ),
                "widened-job-permissions",
            ),
            "empty-job-permissions": (
                workflow().replace("    steps:\n", "    permissions:\n    steps:\n"),
                "widened-job-permissions",
            ),
            "dynamic-top-permissions": (
                workflow().replace("permissions:\n  contents: read\n", "permissions: write-all\n"),
                "widened-workflow-permissions",
            ),
            "empty-top-permissions": (
                workflow().replace("permissions:\n  contents: read\n", "permissions:\n"),
                "widened-workflow-permissions",
            ),
            "caller-privilege": (
                workflow(
                    event="workflow_dispatch",
                    runner="trusted-linux",
                    extra="      - run: echo ${{ inputs.target }}\n",
                ),
                "caller-controlled-privilege",
            ),
            "fail-open": (
                workflow(extra="      - run: true\n        continue-on-error: true\n"),
                "required-gate-fail-open",
            ),
            "unsafe-expression": (
                workflow(extra="      - run: echo ${{ github.event.pull_request.title }}\n"),
                "caller-controlled-expression",
            ),
            "secret-expression": (
                workflow(extra="      - run: echo ${{ secrets.SYNTHETIC }}\n"),
                "caller-controlled-expression",
            ),
            "secret-with": (
                workflow(
                    extra=(
                        "      - uses: ./local\n"
                        "        with:\n"
                        "          value: ${{ secrets.SYNTHETIC }}\n"
                    )
                ),
                "secret-exposure",
            ),
            "mutable-container": (
                workflow(extra="    container: python:3.12\n"),
                "mutable-container-image",
            ),
            "credentials": (
                workflow(checkout=("      - uses: actions/checkout@" + "a" * 40 + "\n")),
                "checkout-credentials",
            ),
            "not-exact-head": (
                workflow(
                    checkout=(
                        "      - uses: actions/checkout@"
                        + "a" * 40
                        + "\n        with:\n          persist-credentials: false\n"
                    )
                ),
                "checkout-not-exact-head",
            ),
            "required-gate-no-checkout": (
                workflow(checkout="      - run: python -m awq\n"),
                "required-gate-checkout",
            ),
            "required-gate-ambiguous-checkouts": (
                workflow(
                    checkout=(
                        "      - uses: actions/checkout@" + "a" * 40 + "\n"
                        "        with:\n"
                        "          ref: ${{ github.event.pull_request.head.sha }}\n"
                        "          persist-credentials: false\n"
                        "      - uses: actions/checkout@" + "b" * 40 + "\n"
                        "        with:\n"
                        "          ref: ${{ github.event.pull_request.head.sha }}\n"
                        "          persist-credentials: false\n"
                    )
                ),
                "required-gate-checkout",
            ),
            "dynamic-runner": (workflow(runner="${{ inputs.runner }}"), "unknown-runner-class"),
            "unsupported-event": (
                workflow(event="repository_dispatch"),
                "unsupported-workflow-event",
            ),
            "unprotected-push": (workflow(event="push"), "unprotected-push"),
            "unguarded-manual": (
                workflow(event="workflow_dispatch", runner="trusted-linux"),
                "unguarded-manual-trusted-runner",
            ),
            "yaml-alias": (workflow() + "x: &shared value\n", "unsupported-workflow-syntax"),
            "duplicate-top-permissions": (
                workflow() + "permissions: write-all\n",
                "unsupported-workflow-syntax",
            ),
            "duplicate-runner": (
                workflow().replace(
                    "    runs-on: ubuntu-24.04\n",
                    "    runs-on: ubuntu-24.04\n    runs-on: trusted-linux\n",
                ),
                "unsupported-workflow-syntax",
            ),
            "prohibited-event-after-comment": (
                workflow(event="pull_request").replace(
                    '"on": pull_request\n',
                    '"on":\n  pull_request:\n# retained comment\n  pull_request_target:\n',
                ),
                "prohibited-trust-event",
            ),
        }
        for name, (text, expected) in cases.items():
            with self.subTest(name=name):
                self.assertIn(expected, self.codes(text))

    def test_matrix_exact_checkout_and_content_minimized_findings(self) -> None:
        matrix = workflow(runner="${{ matrix.os }}").replace(
            "  verify:\n",
            "  verify:\n    strategy:\n      matrix:\n        os: [ubuntu-24.04, macos-14]\n",
        )
        self.assertEqual(set(), self.codes(matrix))
        private_label = "persistent-private-machine"
        value = copy.deepcopy(policy())
        value["runners"]["persistent"] = [private_label]  # type: ignore[index]
        checked = validate_policy(value)
        findings = evaluate_workflow(
            ".github/workflows/verify.yml", workflow(runner=private_label), checked
        )
        self.assertTrue(findings)
        self.assertNotIn(private_label, json.dumps(findings))

    def test_repository_check_requires_valid_policy(self) -> None:
        repository = Repository()
        self.addCleanup(repository.close)
        path = repository.write(".github/workflows/verify.yml", workflow())
        result = checks.workflow_policy(repository.root, [path], base_policy())
        self.assertEqual("workflow-trust-policy", result[0].code)
        repository.json("quality/workflow-trust.json", policy())
        self.assertEqual([], checks.workflow_policy(repository.root, [path], base_policy()))

    def test_policy_file_is_bounded_strict_and_not_symlinked(self) -> None:
        repository = Repository()
        self.addCleanup(repository.close)
        policy_path = repository.json("quality/workflow-trust.json", policy())
        self.assertEqual(1, load_policy(repository.root)["schema_version"])
        policy_path.write_bytes(b"x" * 16385)
        with self.assertRaisesRegex(WorkflowTrustError, "exceeds the byte limit"):
            load_policy(repository.root)
        policy_path.write_text('{"schema_version":1,"schema_version":1}\n')
        with self.assertRaisesRegex(WorkflowTrustError, "duplicate keys"):
            load_policy(repository.root)
        target = repository.json("outside.json", policy())
        policy_path.unlink()
        policy_path.symlink_to(target)
        with self.assertRaisesRegex(WorkflowTrustError, "path is unsafe"):
            load_policy(repository.root)

    def test_policy_file_is_bounded_and_not_symlinked(self) -> None:
        repository = Repository()
        self.addCleanup(repository.close)
        repository.write("outside.json", json.dumps(policy()))
        trust_path = repository.root / "quality/workflow-trust.json"
        trust_path.parent.mkdir(parents=True)
        trust_path.symlink_to(repository.root / "outside.json")
        with self.assertRaisesRegex(WorkflowTrustError, "path is unsafe"):
            load_policy(repository.root)
        trust_path.unlink()
        trust_path.write_text("{" + " " * 16384 + "}", encoding="utf-8")
        with self.assertRaisesRegex(WorkflowTrustError, "exceeds the byte limit"):
            load_policy(repository.root)
