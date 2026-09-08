# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Executable contract tests for the reviewed documentation adapter family."""

from __future__ import annotations

import json
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
    "ADAPTER-DOCUMENTATION-RUMDL-LINKS",
    "ADAPTER-DOCUMENTATION-RUMDL-STYLE",
    "ADAPTER-DOCUMENTATION-VALE",
]


class DocumentationAdapterExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        families, _ = adapters.load_adapter_catalog()
        self.family = families["documentation"]
        self.contracts: dict[str, dict[str, Any]] = {
            item["id"]: item for item in self.family["contracts"]
        }
        self.repositories: list[Repository] = []

    def tearDown(self) -> None:
        for repository in self.repositories:
            repository.close()

    def fixture(self) -> Repository:
        repository = Repository()
        self.repositories.append(repository)
        repository.write(
            ".rumdl.toml",
            """[global]
line-length = 100
disable = ["MD013"]
""",
        )
        repository.write(
            ".vale.ini",
            """StylesPath = styles
MinAlertLevel = suggestion
Vocab = AWQ

[*.md]
BasedOnStyles = AWQ

[*.txt]
BasedOnStyles = AWQ
""",
        )
        repository.write(
            "styles/AWQ/Terms.yml",
            """extends: substitution
message: "Use preferred terminology instead of '%s'."
level: error
ignorecase: true
swap:
  whitelist: allowlist
""",
        )
        repository.write("styles/config/vocabularies/AWQ/accept.txt", "AWQ\n")
        repository.write(
            "README.md",
            """# Documentation

See the local [details](docs/details.md#details).

AWQ uses allowlist terminology.

An external [reference](https://example.invalid/not-contacted) remains observational.
""",
        )
        repository.write("docs/details.md", "# Details\n\nThe local target exists.\n")
        repository.write("notes.txt", "AWQ uses allowlist terminology.\n")
        repository.write(
            "fixtures/broken/bad.md",
            "#Bad\n\n[missing](missing.md)\n\nThe whitelist remains.\n",
        )
        commands.initialize(repository.root, ["core", "docs"], False)
        policy_path = repository.root / "quality/awq.json"
        policy = json.loads(policy_path.read_text())
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

    def test_catalog_schema_order_and_offline_boundary(self) -> None:
        document = {"schema_version": 1, "families": [self.family]}
        validate(document, "adapter-catalog.schema.json")
        self.assertEqual(EXPECTED_IDS, list(self.contracts))
        links = self.contracts["ADAPTER-DOCUMENTATION-RUMDL-LINKS"]
        self.assertIn("MD051,MD057", links["argv"])
        self.assertIn("external URL availability", links["limitation"])

    def test_tracked_selection_and_every_contract_match_native_success(self) -> None:
        repository = self.fixture()
        for identifier in EXPECTED_IDS:
            with self.subTest(identifier=identifier):
                contract = self.contracts[identifier]
                selected = adapters._selected_inputs(repository.root, contract)
                self.assertIn("README.md", selected)
                self.assertNotIn("fixtures/broken/bad.md", selected)
                if identifier == "ADAPTER-DOCUMENTATION-VALE":
                    self.assertIn("notes.txt", selected)
                else:
                    self.assertNotIn("notes.txt", selected)
                self.assertTrue(self.native(repository.root, contract))
                result = adapters.run_adapter(repository.root, contract)
                self.assertEqual("pass", result["status"])
                validate(result, "adapter-result.schema.json")

    def test_every_contract_matches_native_failure(self) -> None:
        for identifier in EXPECTED_IDS:
            with self.subTest(identifier=identifier):
                repository = self.fixture()
                if identifier == "ADAPTER-DOCUMENTATION-RUMDL-LINKS":
                    repository.write("README.md", "# Links\n\nSee [missing](missing.md).\n")
                elif identifier == "ADAPTER-DOCUMENTATION-RUMDL-STYLE":
                    repository.write("README.md", "#Bad heading\n")
                else:
                    repository.write("README.md", "# Prose\n\nThe whitelist remains.\n")
                repository.commit("negative")
                contract = self.contracts[identifier]
                self.assertFalse(self.native(repository.root, contract))
                result = adapters.run_adapter(repository.root, contract)
                self.assertEqual("fail", result["status"])
                self.assertEqual("adapter-failed", result["findings"][0]["code"])

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
            with self.subTest(identifier=identifier, case="config"):
                repository = self.fixture()
                (repository.root / contract["config_paths"][0]).unlink()
                result = adapters.run_adapter(repository.root, contract)
                self.assertEqual("adapter-config-missing", result["findings"][0]["code"])

            with self.subTest(identifier=identifier, case="inputs"):
                repository = Repository()
                self.repositories.append(repository)
                for config in contract["config_paths"]:
                    repository.write(config, "# project configuration\n")
                repository.commit()
                result = adapters.run_adapter(repository.root, contract)
                self.assertEqual("adapter-inputs-missing", result["findings"][0]["code"])

    def test_contracts_never_install_download_or_launch_configured_tools(self) -> None:
        forbidden = {"curl", "download", "git", "install", "pip", "sync", "uv", "wget"}
        for identifier, contract in self.contracts.items():
            with self.subTest(identifier=identifier):
                arguments = {str(item).lower() for item in contract["argv"]}
                self.assertTrue(forbidden.isdisjoint(arguments))
                self.assertFalse(any("://" in item for item in arguments))
                self.assertEqual("tracked-formats", contract["input_mode"])
        for identifier in (
            "ADAPTER-DOCUMENTATION-RUMDL-LINKS",
            "ADAPTER-DOCUMENTATION-RUMDL-STYLE",
        ):
            self.assertIn("--no-code-block-tools", self.contracts[identifier]["argv"])
            self.assertIn("--no-cache", self.contracts[identifier]["argv"])
        self.assertIn("--no-global", self.contracts["ADAPTER-DOCUMENTATION-VALE"]["argv"])


if __name__ == "__main__":
    unittest.main()
