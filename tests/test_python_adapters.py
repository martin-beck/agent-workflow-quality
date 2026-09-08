# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT


"""Executable contract tests for the reviewed Python adapter family."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any
from unittest import mock

import jsonschema

from awq import adapters, commands
from awq.cli import main
from awq.registry import canonical_bytes
from scripts.validate_contracts import validate

EXPECTED_IDS = [
    "ADAPTER-PYTHON-COVERAGE-01-RUN",
    "ADAPTER-PYTHON-COVERAGE-02-REPORT",
    "ADAPTER-PYTHON-MYPY",
    "ADAPTER-PYTHON-RUFF-FORMAT",
    "ADAPTER-PYTHON-RUFF-LINT",
    "ADAPTER-PYTHON-UNITTEST",
]


class PythonCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.families, self.digest = adapters.load_adapter_catalog()
        self.document: dict[str, Any] = {
            "schema_version": 1,
            "families": list(self.families.values()),
        }

    def test_catalog_runtime_schema_digest_order_and_cli(self) -> None:
        validate(self.document, "adapter-catalog.schema.json")
        self.assertEqual(hashlib.sha256(canonical_bytes(self.document)).hexdigest(), self.digest)
        self.assertEqual(["python"], list(self.families))
        self.assertEqual(
            EXPECTED_IDS,
            [item["id"] for item in self.families["python"]["contracts"]],
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands.initialize(root, ["core"], False)
            policy = json.loads((root / "quality/awq.json").read_text())
            self.assertEqual([], policy["adapters"])
            self.assertEqual(self.digest, commands.doctor(root)["adapter_catalog_sha256"])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(
                    [
                        "--root",
                        str(root),
                        "adapter-catalog",
                        "--family",
                        "python",
                        "--format",
                        "json",
                    ]
                )
            payload = json.loads(output.getvalue())
            self.assertEqual(0, code)
            self.assertEqual(
                EXPECTED_IDS, [item["id"] for item in payload["families"][0]["contracts"]]
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(
                    [
                        "--root",
                        str(root),
                        "adapter-catalog",
                        "--family",
                        "missing",
                        "--format",
                        "json",
                    ]
                )
            self.assertEqual(1, code)
            self.assertEqual("error", json.loads(output.getvalue())["status"])

    def test_catalog_hostile_shapes_fail_closed(self) -> None:
        cases: list[object] = [
            {},
            {"schema_version": 2, "families": self.document["families"]},
            {"schema_version": 1, "families": []},
            {**self.document, "extra": True},
        ]
        family_extra = deepcopy(self.document)
        family_extra["families"][0]["extra"] = True
        cases.append(family_extra)
        duplicate_assumption = deepcopy(self.document)
        assumption = duplicate_assumption["families"][0]["assumptions"][0]
        duplicate_assumption["families"][0]["assumptions"].append(assumption)
        cases.append(duplicate_assumption)
        for case in cases:
            with self.subTest(case=case), self.assertRaises(adapters.AdapterError):
                adapters._validate_adapter_catalog(case)
            with self.subTest(schema_case=case), self.assertRaises(jsonschema.ValidationError):
                validate(case, "adapter-catalog.schema.json")

        reversed_contracts = deepcopy(self.document)
        reversed_contracts["families"][0]["contracts"].reverse()
        with self.assertRaisesRegex(adapters.AdapterError, "ordered"):
            adapters._validate_adapter_catalog(reversed_contracts)
        wrong_family = deepcopy(self.document)
        wrong_family["families"][0]["contracts"][0]["id"] = "ADAPTER-SHELL-COVERAGE"
        with self.assertRaisesRegex(adapters.AdapterError, "wrong family"):
            adapters._validate_adapter_catalog(wrong_family)


class PythonAdapterExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        families, _ = adapters.load_adapter_catalog()
        self.contracts: dict[str, dict[str, Any]] = {
            item["id"]: item for item in families["python"]["contracts"]
        }
        self.temporary: list[tempfile.TemporaryDirectory[str]] = []

    def tearDown(self) -> None:
        for item in self.temporary:
            item.cleanup()

    def fixture(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.temporary.append(temporary)
        root = Path(temporary.name)
        (root / "sample").mkdir()
        (root / "tests").mkdir()
        (root / "pyproject.toml").write_text(
            """[tool.ruff]
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F"]

[tool.mypy]
python_version = "3.12"
strict = true
files = ["sample", "tests"]

[tool.coverage.run]
branch = true
source = ["sample"]

[tool.coverage.report]
fail_under = 100
show_missing = true
""",
            encoding="utf-8",
        )
        (root / "sample/__init__.py").write_text(
            """# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT


def choose(flag: bool) -> int:
    if flag:
        return 1
    return 0
""",
            encoding="utf-8",
        )
        (root / "tests/test_sample.py").write_text(
            """# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT


import unittest

from sample import choose


class SampleTests(unittest.TestCase):
    def test_choose(self) -> None:
        self.assertEqual(1, choose(True))
        self.assertEqual(0, choose(False))


if __name__ == "__main__":
    unittest.main()
""",
            encoding="utf-8",
        )
        return root

    def native(self, root: Path, contract: dict[str, Any]) -> bool:
        completed = subprocess.run(
            contract["argv"],
            cwd=root,
            env=os.environ.copy(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=int(contract["timeout_seconds"]),
            check=False,
        )
        return completed.returncode == 0

    def test_every_contract_matches_native_success(self) -> None:
        root = self.fixture()
        with mock.patch.object(
            socket, "create_connection", side_effect=AssertionError("network used")
        ):
            for identifier in EXPECTED_IDS:
                with self.subTest(identifier=identifier):
                    contract = self.contracts[identifier]
                    self.assertTrue(self.native(root, contract))
                    result = adapters.run_adapter(root, contract)
                    self.assertEqual("pass", result["status"])
                    self.assertEqual(contract["remediation"], result["remediation"])
                    validate(result, "adapter-result.schema.json")

    def test_every_contract_matches_native_failure(self) -> None:
        for identifier in EXPECTED_IDS:
            with self.subTest(identifier=identifier):
                root = self.fixture()
                if identifier == "ADAPTER-PYTHON-RUFF-FORMAT":
                    (root / "bad.py").write_text("def bad( ) :\n return 1\n")
                elif identifier == "ADAPTER-PYTHON-RUFF-LINT":
                    (root / "bad.py").write_text("import os\n")
                elif identifier == "ADAPTER-PYTHON-MYPY":
                    path = root / "sample/__init__.py"
                    path.write_text(path.read_text().replace("return 1", 'return "bad"'))
                elif identifier in {
                    "ADAPTER-PYTHON-UNITTEST",
                    "ADAPTER-PYTHON-COVERAGE-01-RUN",
                }:
                    path = root / "tests/test_sample.py"
                    path.write_text(
                        path.read_text().replace(
                            "self.assertEqual(1, choose(True))",
                            "self.assertEqual(999, choose(True))",
                        )
                    )
                else:
                    (root / "tests/test_sample.py").write_text(
                        """import unittest

from sample import choose


class SampleTests(unittest.TestCase):
    def test_choose(self) -> None:
        self.assertEqual(1, choose(True))
""",
                        encoding="utf-8",
                    )
                    self.assertTrue(
                        self.native(
                            root,
                            self.contracts["ADAPTER-PYTHON-COVERAGE-01-RUN"],
                        )
                    )
                contract = self.contracts[identifier]
                self.assertFalse(self.native(root, contract))
                result = adapters.run_adapter(root, contract)
                self.assertEqual("fail", result["status"])
                self.assertEqual("adapter-failed", result["findings"][0]["code"])
                self.assertEqual(contract["remediation"], result["remediation"])

    def test_missing_config_tool_and_version_skew_are_stable(self) -> None:
        for identifier in EXPECTED_IDS:
            contract = self.contracts[identifier]
            with self.subTest(identifier=identifier, case="config"):
                root = self.fixture()
                (root / "pyproject.toml").unlink()
                result = adapters.run_adapter(root, contract)
                self.assertEqual("adapter-config-missing", result["findings"][0]["code"])
                self.assertEqual(contract["remediation"], result["remediation"])
            with self.subTest(identifier=identifier, case="tool"):
                root = self.fixture()
                with mock.patch.object(shutil, "which", return_value=None):
                    result = adapters.run_adapter(root, contract)
                self.assertEqual("adapter-tool-unavailable", result["findings"][0]["code"])
                self.assertEqual(contract["remediation"], result["remediation"])
            with self.subTest(identifier=identifier, case="version"):
                root = self.fixture()
                skewed = deepcopy(contract)
                skewed["version"] = "999"
                skewed["version_output"] = f"{contract['tool']} 999"
                result = adapters.run_adapter(root, skewed)
                self.assertEqual("adapter-version-mismatch", result["findings"][0]["code"])
                self.assertEqual(contract["remediation"], result["remediation"])

    def test_contracts_are_offline_and_never_resolve_packages(self) -> None:
        forbidden = {"download", "install", "update", "upgrade", "uv", "pip", "pipx"}
        for identifier, contract in self.contracts.items():
            with self.subTest(identifier=identifier):
                arguments = {str(item).lower() for item in contract["argv"][1:]}
                self.assertTrue(forbidden.isdisjoint(arguments))
                self.assertFalse(any("://" in item for item in arguments))
