# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Executable contract tests for the reviewed schema adapter family."""

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
from tests.support import Repository, base_policy

EXPECTED_IDS = [
    "ADAPTER-SCHEMA-JSONSCHEMA-INSTANCE",
    "ADAPTER-SCHEMA-JSONSCHEMA-METASCHEMA",
    "ADAPTER-SCHEMA-STRICT-JSON",
    "ADAPTER-SCHEMA-STRICT-YAML",
]


class SchemaAdapterExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        families, _ = adapters.load_adapter_catalog()
        self.family = families["schema"]
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
        commands.initialize(repository.root, ["core"], False)
        repository.write(
            "quality/schemas/defs.schema.json",
            json.dumps(
                {
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "$defs": {"positive": {"type": "integer", "minimum": 1}},
                }
            )
            + "\n",
        )
        repository.write(
            "quality/schemas/project.schema.json",
            json.dumps(
                {
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "type": "object",
                    "properties": {
                        "email": {"type": "string", "format": "email"},
                        "count": {"$ref": "defs.schema.json#/$defs/positive"},
                    },
                    "required": ["email", "count"],
                    "additionalProperties": False,
                }
            )
            + "\n",
        )
        repository.write("data/config.json", '{"enabled": true}\n')
        repository.write("data/config.yaml", "enabled: yes\nname: quality\n")
        repository.write("good.instance.json", '{"email": "a@example.com", "count": 2}\n')
        repository.write("good.instance.yaml", "email: b@example.com\ncount: 3\n")
        repository.write("fixtures/broken/ignored.instance.json", "not json\n")
        policy = base_policy(fixture_paths=["fixtures/broken"])
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

    def test_catalog_schema_order_mapping_and_offline_boundary(self) -> None:
        validate({"schema_version": 1, "families": [self.family]}, "adapter-catalog.schema.json")
        self.assertEqual(EXPECTED_IDS, list(self.contracts))
        mapping = self.contracts["ADAPTER-SCHEMA-JSONSCHEMA-INSTANCE"]
        self.assertEqual("quality/schemas/project.schema.json", mapping["argv"][2])
        self.assertEqual(["quality/schemas/project.schema.json"], mapping["config_paths"])
        self.assertIn(".instance.yaml", mapping["formats"])
        for contract in self.contracts.values():
            self.assertEqual("tracked-formats", contract["input_mode"])
            arguments = " ".join(contract["argv"]).lower()
            self.assertNotIn("http", arguments)
            self.assertNotIn("install", arguments)

    def test_tracked_selection_and_every_contract_match_native_success(self) -> None:
        repository = self.fixture()
        for identifier in EXPECTED_IDS:
            with self.subTest(identifier=identifier):
                contract = self.contracts[identifier]
                selected = adapters._selected_inputs(repository.root, contract)
                self.assertTrue(selected)
                self.assertNotIn("fixtures/broken/ignored.instance.json", selected)
                if identifier == "ADAPTER-SCHEMA-JSONSCHEMA-METASCHEMA":
                    self.assertIn("quality/schemas/project.schema.json", selected)
                    self.assertNotIn("data/config.json", selected)
                if identifier == "ADAPTER-SCHEMA-JSONSCHEMA-INSTANCE":
                    self.assertIn("good.instance.yaml", selected)
                    self.assertNotIn("data/config.yaml", selected)
                self.assertTrue(self.native(repository.root, contract))
                result = adapters.run_adapter(repository.root, contract)
                self.assertEqual("pass", result["status"])
                validate(result, "adapter-result.schema.json")

    def test_every_contract_matches_native_independent_failure(self) -> None:
        mutations = {
            "ADAPTER-SCHEMA-STRICT-JSON": ("data/config.json", '{"secret": 1, "secret": 2}\n'),
            "ADAPTER-SCHEMA-STRICT-YAML": (
                "data/config.yaml",
                "shared: &item value\ncopy: *item\n",
            ),
            "ADAPTER-SCHEMA-JSONSCHEMA-METASCHEMA": (
                "quality/schemas/project.schema.json",
                '{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"https://example.invalid/schema"}\n',
            ),
            "ADAPTER-SCHEMA-JSONSCHEMA-INSTANCE": (
                "good.instance.json",
                '{"email": "not-an-email", "count": 0}\n',
            ),
        }
        for identifier, (path, content) in mutations.items():
            with self.subTest(identifier=identifier):
                repository = self.fixture()
                repository.write(path, content)
                repository.commit("negative")
                contract = self.contracts[identifier]
                self.assertFalse(self.native(repository.root, contract))
                result = adapters.run_adapter(repository.root, contract)
                self.assertEqual("fail", result["status"])
                finding = result["findings"][0]
                self.assertEqual("adapter-failed", finding["code"])
                self.assertNotIn("secret", json.dumps(result))
                self.assertNotIn("not-an-email", json.dumps(result))

    def test_missing_tool_version_config_and_inputs_are_stable(self) -> None:
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
                skewed["version_output"] = "awq-schema-check 999"
                result = adapters.run_adapter(repository.root, skewed)
                self.assertEqual("adapter-version-mismatch", result["findings"][0]["code"])
            if contract["config_paths"]:
                with self.subTest(identifier=identifier, case="config"):
                    repository = self.fixture()
                    (repository.root / contract["config_paths"][0]).unlink()
                    result = adapters.run_adapter(repository.root, contract)
                    self.assertEqual("adapter-config-missing", result["findings"][0]["code"])
            with self.subTest(identifier=identifier, case="inputs"):
                repository = Repository()
                self.repositories.append(repository)
                repository.write("README.txt", "unmatched input\n")
                for config in contract["config_paths"]:
                    repository.write(config, "{}\n")
                repository.commit()
                result = adapters.run_adapter(repository.root, contract)
                self.assertEqual("adapter-inputs-missing", result["findings"][0]["code"])


if __name__ == "__main__":
    unittest.main()
