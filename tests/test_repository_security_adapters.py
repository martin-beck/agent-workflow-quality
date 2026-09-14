# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Executable positive and hostile checks for the repository-security catalog."""

from __future__ import annotations

import copy
import unittest

from awq import adapters


class RepositorySecurityAdapterTests(unittest.TestCase):
    def test_catalog_has_ordered_pinned_offline_contracts(self) -> None:
        families, _ = adapters.load_adapter_catalog()
        family = families["repository-security"]
        self.assertIn("optional and non-authorizing", " ".join(family["assumptions"]))
        contracts = family["contracts"]
        self.assertEqual(
            [
                "ADAPTER-REPOSITORY-SECURITY-ACTIONLINT",
                "ADAPTER-REPOSITORY-SECURITY-GITLEAKS",
                "ADAPTER-REPOSITORY-SECURITY-ZIZMOR",
            ],
            [item["id"] for item in contracts],
        )
        for contract in contracts:
            adapters.validate_adapter(contract)
            self.assertRegex(contract["version"], r"^\d+\.\d+\.\d+$")

    def test_security_contracts_reject_mutable_or_unsafe_changes(self) -> None:
        families, _ = adapters.load_adapter_catalog()
        for original in families["repository-security"]["contracts"]:
            for field, value in (
                ("version_output", "latest"),
                ("argv", ["sh", "-c", "unsafe"]),
                ("formats", [".YML"]),
            ):
                contract = copy.deepcopy(original)
                contract[field] = value
                with (
                    self.subTest(identifier=original["id"], field=field),
                    self.assertRaises(adapters.AdapterError),
                ):
                    adapters.validate_adapter(contract)

    def test_gitleaks_contract_is_redacted_and_range_bound(self) -> None:
        families, _ = adapters.load_adapter_catalog()
        contract = next(
            item
            for item in families["repository-security"]["contracts"]
            if item["tool"] == "gitleaks"
        )
        self.assertIn("--redact", contract["argv"])
        self.assertIn("{base}..{head}", contract["argv"][-1])
        self.assertEqual("mechanical", contract["evidence"])


if __name__ == "__main__":
    unittest.main()
