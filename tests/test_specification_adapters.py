# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Executable positive and hostile checks for acceptance specifications."""

from __future__ import annotations

import json
import os
import shutil
import unittest
from unittest import mock

from awq import adapters
from scripts.validate_contracts import validate
from tests.support import Repository


class SpecificationAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        families, _ = adapters.load_adapter_catalog()
        self.family = families["specification"]
        self.contract = self.family["contracts"][0]
        self.repositories: list[Repository] = []

    def tearDown(self) -> None:
        for repository in self.repositories:
            repository.close()

    def fixture(self, *, failing: bool = False) -> tuple[Repository, str]:
        repository = Repository()
        self.repositories.append(repository)
        repository.write(
            "quality/acceptance-spec.json", '{"schema_version":1,"predicates":[]}' + "\n"
        )
        tool = """#!/usr/bin/env python3
import sys
if sys.argv[1:] == ["--version"]:
    print("awq-spec-check 1.0.0")
    raise SystemExit(0)
raise SystemExit(3 if {failing} else 0)
""".format(failing="True" if failing else "False")
        repository.write("tools/awq-spec-check", tool, executable=True)
        repository.commit()
        return repository, str(repository.root / "tools")

    def test_catalog_contract_schema_and_positive_native_equivalence(self) -> None:
        self.assertEqual("specification", self.family["id"])
        self.assertEqual("ADAPTER-SPECIFICATION-ACCEPTANCE", self.contract["id"])
        validate(self.contract, "adapter-contract-v2.schema.json")
        repository, tool_dir = self.fixture()
        with mock.patch.dict(os.environ, {"PATH": f"{tool_dir}:{os.environ.get('PATH', '')}"}):
            result = adapters.run_adapter(repository.root, self.contract)
        self.assertEqual("pass", result["status"])
        self.assertEqual("contract-test", result["evidence"])
        self.assertEqual([], result["findings"])
        self.assertNotIn(str(repository.root), json.dumps(result))
        validate(result, "adapter-result.schema.json")

    def test_predicate_failure_is_normalized_without_output(self) -> None:
        repository, tool_dir = self.fixture(failing=True)
        with mock.patch.dict(os.environ, {"PATH": f"{tool_dir}:{os.environ.get('PATH', '')}"}):
            result = adapters.run_adapter(repository.root, self.contract)
        self.assertEqual("fail", result["status"])
        self.assertEqual("adapter-failed", result["findings"][0]["code"])
        self.assertNotIn(str(repository.root), json.dumps(result))

    def test_missing_tool_version_and_spec_are_distinct(self) -> None:
        repository, tool_dir = self.fixture()
        with mock.patch.object(shutil, "which", return_value=None):
            missing_tool = adapters.run_adapter(repository.root, self.contract)
        self.assertEqual("adapter-tool-unavailable", missing_tool["findings"][0]["code"])
        with mock.patch.dict(os.environ, {"PATH": f"{tool_dir}:{os.environ.get('PATH', '')}"}):
            skewed = dict(self.contract)
            skewed["version"] = "9.9.9"
            skewed["version_output"] = "awq-spec-check 9.9.9"
            version = adapters.run_adapter(repository.root, skewed)
        self.assertEqual("adapter-version-mismatch", version["findings"][0]["code"])
        (repository.root / "quality/acceptance-spec.json").unlink()
        with mock.patch.dict(os.environ, {"PATH": f"{tool_dir}:{os.environ.get('PATH', '')}"}):
            absent = adapters.run_adapter(repository.root, self.contract)
        self.assertEqual("adapter-config-missing", absent["findings"][0]["code"])

    def test_family_contract_is_ordered_and_offline(self) -> None:
        self.assertEqual([self.contract["id"]], [c["id"] for c in self.family["contracts"]])
        self.assertTrue(all("://" not in item for item in self.contract["argv"]))
        self.assertNotIn("install", " ".join(self.contract["argv"]))
