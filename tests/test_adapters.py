# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Shared adapter contract, runner, and semantic-change tests."""

from __future__ import annotations

import contextlib
import io
import json
import os
import platform
import socket
import subprocess
import sys
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any
from unittest import mock

import jsonschema

from awq import adapters, commands
from awq.cli import main
from awq.project import ProjectError, validate_policy
from scripts.validate_contracts import validate
from tests.support import Repository, base_policy


def python_contract(**updates: Any) -> dict[str, Any]:
    tool = Path(sys.executable).name
    version = platform.python_version()
    value: dict[str, Any] = {
        "id": "ADAPTER-SYNTHETIC-PYTHON",
        "tool": tool,
        "version": version,
        "version_argv": [tool, "--version"],
        "version_output": f"Python {version}",
        "argv": [tool, "-c", "raise SystemExit(0)"],
        "timeout_seconds": 2,
        "tier": "pr",
        "evidence": "contract-test",
        "limitation": "Synthetic runner contract only.",
        "remediation": "Repair the synthetic command.",
        "formats": [".py"],
        "config_paths": ["pyproject.toml"],
    }
    value.update(updates)
    return value


def finding_code(result: dict[str, Any]) -> str:
    return str(result["findings"][0]["code"])


class AdapterContractTests(unittest.TestCase):
    def test_runtime_and_schema_accept_the_same_contract(self) -> None:
        contract = python_contract()
        adapters.validate_adapter(contract)
        validate(contract, "adapter-contract.schema.json")
        policy = base_policy(adapters=[contract])
        validate_policy(policy)
        validate(policy, "project-policy.schema.json")

    def test_invalid_contract_dimensions_fail_closed(self) -> None:
        base = python_contract()
        mutations: list[dict[str, Any]] = [
            {},
            {**base, "id": "bad"},
            {**base, "tool": "../python"},
            {**base, "version": ""},
            {**base, "version_output": "different"},
            {**base, "version_argv": ["other", "--version"]},
            {**base, "argv": []},
            {**base, "argv": [base["tool"], "\0"]},
            {**base, "timeout_seconds": 0},
            {**base, "timeout_seconds": True},
            {**base, "tier": "never"},
            {**base, "evidence": "claim"},
            {**base, "limitation": ""},
            {**base, "formats": []},
            {**base, "formats": [".PY"]},
            {**base, "formats": [".py", ".py"]},
            {**base, "config_paths": ["../outside"]},
            {**base, "config_paths": [r"C:\\outside"]},
            {**base, "config_paths": ["C:/outside"]},
            {**base, "config_paths": ["./config.toml"]},
            {**base, "config_paths": ["path//config.toml"]},
            {**base, "config_paths": ["same", "same"]},
            {**base, "input_mode": "unbounded"},
        ]
        runtime_only_cross_field_cases = {4, 5}
        for number, contract in enumerate(mutations):
            with self.subTest(case=number), self.assertRaises(adapters.AdapterError):
                adapters.validate_adapter(contract)
            if number not in runtime_only_cross_field_cases:
                with (
                    self.subTest(schema_case=number),
                    self.assertRaises(jsonschema.ValidationError),
                ):
                    validate(contract, "adapter-contract.schema.json")

    def test_policy_rejects_non_object_and_duplicate_adapters(self) -> None:
        contract = python_contract()
        with self.assertRaises(ProjectError):
            validate_policy(base_policy(adapters=["bad"]))
        with self.assertRaises(ProjectError):
            validate_policy(base_policy(adapters=[contract, contract]))


class AdapterRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repository()
        self.repo.write("pyproject.toml", "[project]\nname='fixture'\n")

    def tearDown(self) -> None:
        self.repo.close()

    def test_native_and_adapter_results_agree_and_redact_output(self) -> None:
        positive = python_contract(
            argv=[
                Path(sys.executable).name,
                "-c",
                "print('private source excerpt that must be discarded')",
            ]
        )
        native = subprocess.run(
            [sys.executable, *positive["argv"][1:]],
            cwd=self.repo.root,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with mock.patch.object(
            socket, "create_connection", side_effect=AssertionError("network used")
        ):
            result = adapters.run_adapter(self.repo.root, positive)
        self.assertEqual(native.returncode == 0, result["status"] == "pass")
        self.assertNotIn("private source excerpt", json.dumps(result))
        validate(result, "adapter-result.schema.json")

        negative = python_contract(argv=[Path(sys.executable).name, "-c", "raise SystemExit(7)"])
        native = subprocess.run(
            [sys.executable, *negative["argv"][1:]],
            cwd=self.repo.root,
            check=False,
        )
        result = adapters.run_adapter(self.repo.root, negative)
        self.assertEqual(native.returncode == 0, result["status"] == "pass")
        self.assertEqual("adapter-failed", finding_code(result))

    def test_policy_check_plan_and_direct_cli_share_the_runner(self) -> None:
        contract = python_contract()
        commands.initialize(self.repo.root, ["core"], False)
        policy = json.loads((self.repo.root / "quality/awq.json").read_text())
        policy["adapters"] = [contract]
        self.repo.json("quality/awq.json", policy)
        self.repo.json("adapter.json", contract)

        result = commands.check(self.repo.root, "pr")
        adapter_result = next(
            item for item in result["requirements"] if item["id"] == contract["id"]
        )
        self.assertEqual("pass", adapter_result["status"])
        self.assertEqual(
            [
                {
                    "id": contract["id"],
                    "tier": "pr",
                    "tool": contract["tool"],
                    "version": contract["version"],
                }
            ],
            commands.plan(self.repo.root, False, "HEAD")["adapters"],
        )

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(
                [
                    "--root",
                    str(self.repo.root),
                    "adapter-run",
                    "adapter.json",
                    "--format",
                    "json",
                ]
            )
        self.assertEqual(0, code)
        self.assertEqual("pass", json.loads(output.getvalue())["status"])

        self.repo.json("invalid-adapter.json", {})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(
                [
                    "--root",
                    str(self.repo.root),
                    "adapter-run",
                    "invalid-adapter.json",
                    "--format",
                    "json",
                ]
            )
        self.assertEqual(1, code)
        self.assertEqual("error", json.loads(output.getvalue())["status"])

    def test_policy_and_evidence_order_adapters_by_identifier(self) -> None:
        first = python_contract(id="ADAPTER-SYNTHETIC-A")
        last = python_contract(id="ADAPTER-SYNTHETIC-Z")
        commands.initialize(self.repo.root, ["core"], False)
        policy = json.loads((self.repo.root / "quality/awq.json").read_text())
        policy["adapters"] = [last, first]
        self.repo.json("quality/awq.json", policy)

        planned = commands.plan(self.repo.root, False, "HEAD")["adapters"]
        self.assertEqual([first["id"], last["id"]], [item["id"] for item in planned])
        checked = commands.check(self.repo.root, "pr")["requirements"]
        observed = [item["id"] for item in checked if item["id"].startswith("ADAPTER-")]
        self.assertEqual([first["id"], last["id"]], observed)

    def test_unavailable_skew_missing_config_and_unsafe_config(self) -> None:
        unavailable = python_contract(
            tool="definitely-missing-awq-tool",
            version_argv=["definitely-missing-awq-tool", "--version"],
            argv=["definitely-missing-awq-tool", "check"],
        )
        self.assertEqual(
            "adapter-tool-unavailable",
            finding_code(adapters.run_adapter(self.repo.root, unavailable)),
        )
        self.assertEqual(
            "adapter-version-mismatch",
            finding_code(
                adapters.run_adapter(
                    self.repo.root,
                    python_contract(version="0", version_output="Python 0"),
                )
            ),
        )
        self.assertEqual(
            "adapter-config-missing",
            finding_code(
                adapters.run_adapter(
                    self.repo.root,
                    python_contract(config_paths=["missing/directory/config.toml"]),
                )
            ),
        )

        outside = self.repo.root.parent / "awq-adapter-outside"
        outside.mkdir(exist_ok=True)
        link = self.repo.root / "linked"
        link.symlink_to(outside, target_is_directory=True)
        try:
            result = adapters.run_adapter(
                self.repo.root, python_contract(config_paths=["linked/config.toml"])
            )
            self.assertEqual("adapter-config-unsafe", finding_code(result))
        finally:
            link.unlink()
            outside.rmdir()

    def test_version_and_execution_resource_failures_are_classified(self) -> None:
        tool = Path(sys.executable).name
        version_timeout = python_contract(
            version_argv=[tool, "-c", "import time; time.sleep(2)"],
            version_output="Python 1",
            version="1",
            timeout_seconds=1,
        )
        self.assertEqual(
            "adapter-version-timeout",
            finding_code(adapters.run_adapter(self.repo.root, version_timeout)),
        )
        overflow = python_contract(
            version_argv=[tool, "-c", "print('1' * 5000)"],
            version_output="1",
            version="1",
        )
        self.assertEqual(
            "adapter-version-output-limit",
            finding_code(adapters.run_adapter(self.repo.root, overflow)),
        )
        execution_timeout = python_contract(
            argv=[tool, "-c", "import time; time.sleep(2)"],
            timeout_seconds=1,
        )
        self.assertEqual(
            "adapter-timeout",
            finding_code(adapters.run_adapter(self.repo.root, execution_timeout)),
        )

    def test_start_failures_and_probe_invariants_are_normalized(self) -> None:
        contract = python_contract()
        with mock.patch("awq.adapters._bounded_probe", side_effect=OSError("missing")):
            self.assertEqual(
                "adapter-tool-unavailable",
                finding_code(adapters.run_adapter(self.repo.root, contract)),
            )
        with mock.patch("awq.adapters.subprocess.run", side_effect=OSError("missing")):
            self.assertEqual(
                "adapter-tool-unavailable",
                finding_code(adapters.run_adapter(self.repo.root, contract)),
            )
        process = mock.Mock(stdout=None)
        with (
            mock.patch("awq.adapters.subprocess.Popen", return_value=process),
            self.assertRaises(adapters.AdapterError),
        ):
            adapters._bounded_probe(["tool"], self.repo.root, {}, 1)
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with()
        process.reset_mock()
        with mock.patch("awq.adapters.subprocess.Popen", return_value=process):
            self.assertEqual(
                "adapter-version-failed",
                finding_code(adapters.run_adapter(self.repo.root, contract)),
            )

        stream = io.BytesIO(b"tool 1\n")
        process = mock.Mock(stdout=stream)
        process.wait.return_value = 0
        with mock.patch("awq.adapters.subprocess.Popen", return_value=process):
            self.assertEqual(
                (0, "tool 1", False, False),
                adapters._bounded_probe(["tool"], self.repo.root, {}, 1),
            )
        self.assertTrue(stream.closed)

    def test_environment_is_minimal_and_does_not_forward_credentials(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "PATH": os.environ.get("PATH", ""),
                "HOME": "/private/home",
                "GITHUB_TOKEN": "secret",
                "AWS_SECRET_ACCESS_KEY": "secret",
            },
            clear=True,
        ):
            environment = adapters._environment()
            self.assertEqual({"PATH", "LANG", "LC_ALL", "NO_COLOR"}, set(environment))
            result = adapters.run_adapter(
                self.repo.root,
                python_contract(
                    argv=[
                        Path(sys.executable).name,
                        "-c",
                        "import os; raise SystemExit('GITHUB_TOKEN' in os.environ)",
                    ]
                ),
            )
        self.assertEqual("pass", result["status"])


class AdapterSemanticDiffTests(unittest.TestCase):
    def classifications(
        self, old: list[dict[str, Any]], new: list[dict[str, Any]], field: str
    ) -> set[str]:
        changes: list[dict[str, str]] = []
        commands._compare_adapters(old, new, changes)
        return {
            item["classification"]
            for item in changes
            if item["field"] == field or item["field"].startswith(field + ".")
        }

    def test_every_adapter_weakening_dimension_is_detected(self) -> None:
        base = python_contract(formats=[".py", ".pyi"])
        mutations: list[tuple[str, Any]] = [
            ("formats", lambda item: item["formats"].remove(".pyi")),
            ("tier", lambda item: item.__setitem__("tier", "scheduled")),
            ("timeout_seconds", lambda item: item.__setitem__("timeout_seconds", 1)),
            ("tool", lambda item: item.__setitem__("tool", "other")),
            ("version", lambda item: item.__setitem__("version", "other")),
            ("version_argv", lambda item: item.__setitem__("version_argv", ["other"])),
            ("version_output", lambda item: item.__setitem__("version_output", "other")),
            ("argv", lambda item: item.__setitem__("argv", ["other"])),
            ("evidence", lambda item: item.__setitem__("evidence", "environmental")),
            ("limitation", lambda item: item.__setitem__("limitation", "Changed.")),
            ("config_paths", lambda item: item.__setitem__("config_paths", [])),
        ]
        for field, mutate in mutations:
            changed = deepcopy(base)
            mutate(changed)
            with self.subTest(field=field):
                self.assertIn(
                    "weakening",
                    self.classifications([base], [changed], f"adapters.{base['id']}.{field}"),
                )
        self.assertEqual({"weakening"}, self.classifications([base], [], f"adapters.{base['id']}"))

    def test_additions_and_expansions_are_review_visible(self) -> None:
        base = python_contract()
        self.assertEqual(
            {"strengthening"}, self.classifications([], [base], f"adapters.{base['id']}")
        )
        changed = deepcopy(base)
        changed["formats"].append(".pyi")
        changed["tier"] = "local"
        changed["timeout_seconds"] = 3
        classes = self.classifications([base], [changed], f"adapters.{base['id']}")
        self.assertEqual({"strengthening"}, classes)
        changed = deepcopy(base)
        changed["remediation"] = "Use the reviewed repair."
        self.assertEqual(
            {"review"},
            self.classifications([base], [changed], f"adapters.{base['id']}.remediation"),
        )

    def test_input_mode_changes_are_semantically_classified(self) -> None:
        explicit = python_contract()
        tracked = python_contract(input_mode="tracked-shell")
        self.assertEqual(
            {"strengthening"},
            self.classifications(
                [explicit],
                [tracked],
                f"adapters.{explicit['id']}.input_mode",
            ),
        )
        self.assertEqual(
            {"weakening"},
            self.classifications(
                [tracked],
                [explicit],
                f"adapters.{explicit['id']}.input_mode",
            ),
        )


if __name__ == "__main__":
    unittest.main()
