# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Executable positive and hostile checks for the repository-security catalog."""

from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from awq import adapters
from awq.registry import canonical_bytes
from scripts import install_repository_security_tools as installer


class RepositorySecurityAdapterTests(unittest.TestCase):
    def test_versioned_catalog_loader_preserves_v1_history(self) -> None:
        data = Path(__file__).parents[1] / "src/awq/data"
        historical = json.loads((data / "adapter_catalog.json").read_bytes())
        current = json.loads((data / "adapter_catalog_v2.json").read_bytes())
        self.assertNotIn("repository-security", {item["id"] for item in historical["families"]})
        self.assertIn("repository-security", {item["id"] for item in current["families"]})
        loaded, digest = adapters.load_adapter_catalog()
        self.assertEqual(current["families"], list(loaded.values()))
        self.assertEqual(
            digest,
            __import__("hashlib").sha256(canonical_bytes(current)).hexdigest(),
        )
        with self.assertRaises(adapters.AdapterError):
            adapters.validate_adapter_catalog({**historical, "schema_version": 2})

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

    def test_gitleaks_rejects_missing_or_ambiguous_revisions(self) -> None:
        families, _ = adapters.load_adapter_catalog()
        contract = next(
            item
            for item in families["repository-security"]["contracts"]
            if item["tool"] == "gitleaks"
        )
        for base, head in ((None, None), ("a" * 39, "b" * 40), ("a" * 40, "a" * 40)):
            with self.subTest(base=base, head=head):
                result = adapters.run_adapter(
                    Path.cwd(), contract, base_revision=base, head_revision=head
                )
                self.assertEqual("adapter-range-invalid", result["findings"][0]["code"])

    def test_gitleaks_substitutes_exact_revisions_without_literal_placeholders(self) -> None:
        families, _ = adapters.load_adapter_catalog()
        contract = next(
            item
            for item in families["repository-security"]["contracts"]
            if item["tool"] == "gitleaks"
        )
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        base = subprocess.check_output(["git", "rev-parse", f"{head}^"], text=True).strip()
        updated, failure = adapters._security_contract(Path.cwd(), contract, base, head)
        self.assertIsNone(failure)
        assert updated is not None
        self.assertIn(base + ".." + head, updated["argv"][-1])
        self.assertNotIn("{base}", " ".join(updated["argv"]))

    def test_installer_has_complete_official_linux_matrix_and_real_pins(self) -> None:
        expected = {
            "x86_64": {
                "actionlint": "023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757",
                "zizmor": "e65324f4430c2717591937edcec90ccbefaf14c174f8ec9415e03ca875b46e1a",
                "gitleaks": "a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb",
            },
            "aarch64": {
                "actionlint": "401942f9c24ed71e4fe71b76c7d638f66d8633575c4016efd2977ce7c28317d0",
                "zizmor": "7ff1dce33bdd18fd2a4affe63bdd47efcccca97b2cec1c1863ec26e9e2647540",
                "gitleaks": "eff65261156100e5d94a6b3dec313d532fddfe19ae1590bf7a2b4f2699128356",
            },
        }
        for architecture, artifacts in installer.ARTIFACTS.items():
            with self.subTest(architecture=architecture):
                self.assertEqual(
                    expected[architecture], {item.name: item.sha256 for item in artifacts}
                )
                self.assertEqual(
                    {"actionlint", "zizmor", "gitleaks"}, {item.name for item in artifacts}
                )
                for item in artifacts:
                    self.assertIn("github.com/", item.url)
                    self.assertNotIn("latest", item.url)
                    self.assertRegex(item.sha256, r"^[0-9a-f]{64}$")

    def test_installer_digest_fixture_rejects_tampering(self) -> None:
        with tempfile.NamedTemporaryFile() as fixture:
            fixture.write(b"tampered artifact")
            fixture.flush()
            with self.assertRaises(installer.InstallError):
                installer.verify(Path(fixture.name), installer.ARTIFACTS["x86_64"][0].sha256)


if __name__ == "__main__":
    unittest.main()
