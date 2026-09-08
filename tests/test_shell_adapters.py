# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Executable contract tests for the reviewed shell adapter family."""

from __future__ import annotations

import os
import shutil
import subprocess
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any
from unittest import mock

from awq import adapters, commands
from scripts.validate_contracts import validate
from tests.support import Repository

EXPECTED_IDS = [
    "ADAPTER-SHELL-BATS",
    "ADAPTER-SHELL-SHELLCHECK",
    "ADAPTER-SHELL-SHFMT",
]


class ShellAdapterExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        families, _ = adapters.load_adapter_catalog()
        self.contracts: dict[str, dict[str, Any]] = {
            item["id"]: item for item in families["shell"]["contracts"]
        }
        self.repositories: list[Repository] = []

    def tearDown(self) -> None:
        for repository in self.repositories:
            repository.close()

    def fixture(self) -> Repository:
        repository = Repository()
        self.repositories.append(repository)
        repository.write(".shellcheckrc", "# Project-owned ShellCheck configuration.\n")
        repository.write(
            ".editorconfig",
            """root = true

[*.sh]
indent_style = space
indent_size = 2
shell_variant = posix

[tools/run]
indent_style = space
indent_size = 2
shell_variant = posix
""",
        )
        repository.write(
            "scripts/library.sh",
            """#!/bin/sh

greet() {
  printf '%s\\n' "$1"
}
""",
        )
        repository.write(
            "tools/run",
            """#!/usr/bin/env sh
set -eu

printf '%s\\n' "ok"
""",
            executable=True,
        )
        repository.write(
            "tests/smoke.bats",
            """#!/usr/bin/env bats

@test "prints output" {
  run sh -c 'printf ok'
  [ "$status" -eq 0 ]
  [ "$output" = "ok" ]
}
""",
        )
        repository.write(
            "fixtures/broken/bad.sh",
            """#!/bin/sh
echo $unquoted
""",
            executable=True,
        )
        commands.initialize(repository.root, ["core", "shell"], False)
        policy_path = repository.root / "quality/awq.json"
        policy = __import__("json").loads(policy_path.read_text())
        policy["fixture_paths"] = ["fixtures/broken"]
        repository.json("quality/awq.json", policy)
        repository.commit()
        return repository

    def native(self, root: Path, contract: dict[str, Any]) -> bool:
        inputs = adapters._selected_inputs(root, contract)
        completed = subprocess.run(
            [*contract["argv"], *inputs],
            cwd=root,
            env=os.environ.copy(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=contract["timeout_seconds"],
            check=False,
        )
        return completed.returncode == 0

    def test_tracked_selection_and_every_contract_match_native_success(self) -> None:
        repository = self.fixture()
        for identifier in EXPECTED_IDS:
            with self.subTest(identifier=identifier):
                contract = self.contracts[identifier]
                if contract.get("input_mode") == "tracked-shell":
                    selected = adapters._selected_inputs(repository.root, contract)
                    self.assertIn("scripts/library.sh", selected)
                    self.assertIn("tools/run", selected)
                    self.assertNotIn("fixtures/broken/bad.sh", selected)
                self.assertTrue(self.native(repository.root, contract))
                result = adapters.run_adapter(repository.root, contract)
                self.assertEqual("pass", result["status"])
                self.assertEqual(contract["remediation"], result["remediation"])
                validate(result, "adapter-result.schema.json")

    def test_every_contract_matches_native_failure(self) -> None:
        for identifier in EXPECTED_IDS:
            with self.subTest(identifier=identifier):
                repository = self.fixture()
                if identifier == "ADAPTER-SHELL-BATS":
                    repository.write(
                        "tests/smoke.bats",
                        """#!/usr/bin/env bats

@test "fails" {
  [ 1 -eq 2 ]
}
""",
                    )
                elif identifier == "ADAPTER-SHELL-SHELLCHECK":
                    repository.write(
                        "scripts/library.sh",
                        """#!/bin/sh
unquoted="two words"
printf '%s\\n' $unquoted
""",
                    )
                else:
                    repository.write(
                        "scripts/library.sh",
                        """#!/bin/sh
if true;then
echo bad
fi
""",
                    )
                repository.commit("negative")
                contract = self.contracts[identifier]
                self.assertFalse(self.native(repository.root, contract))
                result = adapters.run_adapter(repository.root, contract)
                self.assertEqual("fail", result["status"])
                self.assertEqual("adapter-failed", result["findings"][0]["code"])
                self.assertEqual(contract["remediation"], result["remediation"])

    def test_missing_config_tool_version_and_inputs_are_stable(self) -> None:
        for identifier in EXPECTED_IDS:
            contract = self.contracts[identifier]
            with self.subTest(identifier=identifier, case="tool"):
                repository = self.fixture()
                with mock.patch.object(shutil, "which", return_value=None):
                    result = adapters.run_adapter(repository.root, contract)
                self.assertEqual("adapter-tool-unavailable", result["findings"][0]["code"])
            with self.subTest(identifier=identifier, case="version"):
                repository = self.fixture()
                skewed = deepcopy(contract)
                skewed["version"] = "999"
                skewed["version_output"] = f"{contract['tool']} 999"
                result = adapters.run_adapter(repository.root, skewed)
                self.assertEqual("adapter-version-mismatch", result["findings"][0]["code"])
            if contract["config_paths"]:
                with self.subTest(identifier=identifier, case="config"):
                    repository = self.fixture()
                    (repository.root / contract["config_paths"][0]).unlink()
                    result = adapters.run_adapter(repository.root, contract)
                    self.assertEqual("adapter-config-missing", result["findings"][0]["code"])

        for identifier in ("ADAPTER-SHELL-SHELLCHECK", "ADAPTER-SHELL-SHFMT"):
            with self.subTest(identifier=identifier, case="inputs"):
                repository = Repository()
                self.repositories.append(repository)
                contract = self.contracts[identifier]
                for config in contract["config_paths"]:
                    repository.write(config, "# configuration\n")
                repository.commit()
                result = adapters.run_adapter(repository.root, contract)
                self.assertEqual("adapter-inputs-missing", result["findings"][0]["code"])

    def test_contracts_are_offline_and_do_not_install(self) -> None:
        forbidden = {"curl", "download", "git", "install", "pip", "uv", "wget"}
        for identifier, contract in self.contracts.items():
            with self.subTest(identifier=identifier):
                arguments = {str(item).lower() for item in contract["argv"]}
                self.assertTrue(forbidden.isdisjoint(arguments))
                self.assertFalse(any("://" in item for item in arguments))
