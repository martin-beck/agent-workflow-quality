# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Executable contracts for the bounded TLC formal-model adapter."""

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

import jsonschema

from awq import adapters
from scripts.validate_contracts import validate
from tests.support import Repository

ROOT = Path(__file__).resolve().parents[1]
TOOL = """#!/usr/bin/env python3
import pathlib
import sys
import time

if sys.argv[1:] == ["--version"]:
    print("TLC 1.8.0")
    raise SystemExit(0)
private_names = ("HOME", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY")
if any(name in __import__("os").environ for name in private_names):
    raise SystemExit(90)
model = pathlib.Path(sys.argv[-1]).read_text(encoding="utf-8")
if "TimeoutFixture" in model:
    time.sleep(2)
elif "MalformedFixture" in model:
    print("PRIVATE_MODEL_OUTPUT_39")
elif "SuccessPrefixFixture" in model:
    print("prefix Model checking completed. No error has been found.")
elif "SuccessSuffixFixture" in model:
    print("Model checking completed. No error has been found. suffix")
elif "SuccessSplitFixture" in model:
    print("Model checking completed. No error")
    print("has been found.")
elif "FailurePrefixFixture" in model:
    print("prefix Error: Invariant PrivateInvariantName is violated.")
    raise SystemExit(12)
elif "FailureSuffixFixture" in model:
    print("Error: Invariant PrivateInvariantName is violated. suffix")
    raise SystemExit(12)
elif "ContradictoryFixture" in model:
    print("Error: Invariant PrivateInvariantName is violated.")
    print("Model checking completed. No error has been found.")
elif "FailureFixture" in model:
    print("Error: Invariant PrivateInvariantName is violated.")
    raise SystemExit(12)
else:
    print("Model checking completed. No error has been found.")
"""


class FormalAdapterExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        families, _ = adapters.load_adapter_catalog()
        self.family = families["formal-model"]
        self.contract: dict[str, Any] = self.family["contracts"][0]
        self.repositories: list[Repository] = []

    def tearDown(self) -> None:
        for repository in self.repositories:
            repository.close()

    def fixture(self, marker: str = "") -> tuple[Repository, Path]:
        repository = Repository()
        self.repositories.append(repository)
        source = ROOT / "fixtures/conforming/formal-adapter"
        for path in sorted(candidate for candidate in source.rglob("*") if candidate.is_file()):
            content = path.read_text(encoding="utf-8")
            if path.suffix == ".tla" and marker:
                content = content.replace(
                    "---- MODULE Model ----", f"---- MODULE Model ----\n\\* {marker}"
                )
            repository.write(path.relative_to(source).as_posix(), content)
        tool_dir = repository.root / "tools"
        repository.write("tools/tlc", TOOL, executable=True)
        repository.commit()
        return repository, tool_dir

    def adapter_run(
        self,
        repository: Repository,
        tool_dir: Path,
        contract: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with mock.patch.dict(
            os.environ,
            {
                "PATH": f"{tool_dir}:{os.environ.get('PATH', '')}",
                "HOME": "/private/home",
                "GITHUB_TOKEN": "PRIVATE_TOKEN_39",
            },
        ):
            return adapters.run_adapter(repository.root, contract or self.contract)

    def native(self, repository: Repository, tool_dir: Path) -> bool:
        completed = subprocess.run(
            [str(tool_dir / "tlc"), *self.contract["argv"][1:]],
            cwd=repository.root,
            env=adapters._environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=self.contract["timeout_seconds"],
            check=False,
        )
        return (
            completed.returncode == 0
            and b"Model checking completed. No error has been found."
            in completed.stdout.splitlines()
        )

    def test_catalog_profile_schema_and_fixed_native_success(self) -> None:
        self.assertEqual("ADAPTER-FORMAL-MODEL-TLC", self.contract["id"])
        validate(self.contract, "adapter-contract.schema.json")
        validate(self.contract, "formal-adapter-contract.schema.json")
        repository, tool_dir = self.fixture()
        self.assertTrue(self.native(repository, tool_dir))
        result = self.adapter_run(repository, tool_dir)
        self.assertEqual("pass", result["status"])
        self.assertEqual("bounded-model", result["evidence"])
        self.assertEqual([], result["findings"])
        validate(result, "adapter-result.schema.json")
        serialized = json.dumps(result)
        self.assertNotIn(str(repository.root), serialized)
        self.assertNotIn("PRIVATE", serialized)
        profiles = json.loads((ROOT / "src/awq/data/profiles.json").read_bytes())
        formal = next(item for item in profiles["profiles"] if item["name"] == "formal-model")
        self.assertEqual(["AWQ-FORMAL-001"], formal["requirements"])

    def test_model_failure_matches_independent_native_failure(self) -> None:
        repository, tool_dir = self.fixture("FailureFixture")
        self.assertFalse(self.native(repository, tool_dir))
        result = self.adapter_run(repository, tool_dir)
        self.assertEqual("fail", result["status"])
        self.assertEqual("adapter-model-failed", result["findings"][0]["code"])
        self.assertNotIn("PrivateInvariantName", json.dumps(result))

    def test_missing_tool_version_skew_and_missing_model_are_distinct(self) -> None:
        repository, tool_dir = self.fixture()
        with mock.patch.object(shutil, "which", return_value=None):
            missing = adapters.run_adapter(repository.root, self.contract)
        self.assertEqual("adapter-tool-unavailable", missing["findings"][0]["code"])

        skewed = deepcopy(self.contract)
        skewed["version"] = "1.8.1"
        skewed["version_output"] = "TLC 1.8.1"
        version = self.adapter_run(repository, tool_dir, skewed)
        self.assertEqual("adapter-version-mismatch", version["findings"][0]["code"])

        (repository.root / "formal/Model.tla").unlink()
        absent = self.adapter_run(repository, tool_dir)
        self.assertEqual("adapter-config-missing", absent["findings"][0]["code"])

    def test_timeout_and_malformed_output_are_normalized(self) -> None:
        repository, tool_dir = self.fixture("TimeoutFixture")
        timed = deepcopy(self.contract)
        timed["timeout_seconds"] = 1
        timeout = self.adapter_run(repository, tool_dir, timed)
        self.assertEqual("adapter-timeout", timeout["findings"][0]["code"])

        repository, tool_dir = self.fixture("MalformedFixture")
        malformed = self.adapter_run(repository, tool_dir)
        self.assertEqual("adapter-result-invalid", malformed["findings"][0]["code"])
        self.assertNotIn("PRIVATE_MODEL_OUTPUT_39", json.dumps(malformed))

    def test_terminal_markers_require_exact_noncontradictory_lines(self) -> None:
        for marker in (
            "SuccessPrefixFixture",
            "SuccessSuffixFixture",
            "SuccessSplitFixture",
            "FailurePrefixFixture",
            "FailureSuffixFixture",
            "ContradictoryFixture",
        ):
            with self.subTest(marker=marker):
                repository, tool_dir = self.fixture(marker)
                result = self.adapter_run(repository, tool_dir)
                self.assertEqual("fail", result["status"])
                self.assertEqual("adapter-result-invalid", result["findings"][0]["code"])
                self.assertNotIn("PrivateInvariantName", json.dumps(result))

    def test_unsupported_or_dynamic_model_contracts_fail_closed(self) -> None:
        cases: list[dict[str, Any]] = []
        for index, replacement in (
            (0, "sh"),
            (2, "all"),
            (4, "0"),
            (6, "formal/Model.tla"),
            (7, "formal/Model.pcal"),
        ):
            candidate = deepcopy(self.contract)
            candidate["argv"][index] = replacement
            if index == 0:
                candidate["tool"] = replacement
                candidate["version_argv"][0] = replacement
            if index in (6, 7):
                candidate["config_paths"][index - 6] = replacement
            cases.append(candidate)
        for candidate in cases:
            with self.subTest(argv=candidate["argv"]):
                with self.assertRaises(adapters.AdapterError):
                    adapters.validate_adapter(candidate)
                with self.assertRaises(jsonschema.ValidationError):
                    validate(candidate, "formal-adapter-contract.schema.json")


if __name__ == "__main__":
    unittest.main()
