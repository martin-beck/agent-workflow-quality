# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Executable positive and hostile checks for the repository-security catalog."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

    def test_installer_rejects_unsupported_architecture(self) -> None:
        with self.assertRaisesRegex(installer.InstallError, "unsupported architecture"):
            installer.install(Path(tempfile.mkdtemp()) / "prefix", "mips64")

    def test_gitleaks_clean_defect_and_later_removed_secret_ranges_are_exact(self) -> None:
        families, _ = adapters.load_adapter_catalog()
        contract = next(
            item
            for item in families["repository-security"]["contracts"]
            if item["tool"] == "gitleaks"
        )
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        base = subprocess.check_output(["git", "rev-parse", f"{head}^"], text=True).strip()
        cases = (
            ("clean", base, head),
            ("introduced-secret", base, head),
            ("later-removed-secret", base, head),
        )
        for case, base, head in cases:
            updated, failure = adapters._security_contract(Path.cwd(), contract, base, head)
            with self.subTest(case=case):
                self.assertIsNone(failure)
            assert updated is not None
            self.assertNotIn("{base}", " ".join(updated["argv"]))
            self.assertNotIn("{head}", " ".join(updated["argv"]))
            self.assertIn("--redact", updated["argv"])

    def test_security_tool_absence_and_skew_fail_closed_without_diagnostics(self) -> None:
        families, _ = adapters.load_adapter_catalog()
        for contract in families["repository-security"]["contracts"]:
            kwargs: dict[str, str] = {}
            if contract["tool"] == "gitleaks":
                head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
                base = subprocess.check_output(["git", "rev-parse", f"{head}^"], text=True).strip()
                kwargs = {"base_revision": base, "head_revision": head}
            with (
                self.subTest(tool=contract["tool"]),
                mock.patch.object(adapters.shutil, "which", return_value=None),
            ):
                result = adapters.run_adapter(Path.cwd(), contract, **kwargs)
                self.assertEqual("adapter-tool-unavailable", result["findings"][0]["code"])
                self.assertNotIn("PRIVATE_SECRET_DIAGNOSTIC", json.dumps(result))

    def test_gitleaks_hostile_diagnostic_is_not_retained(self) -> None:
        families, _ = adapters.load_adapter_catalog()
        contract = copy.deepcopy(
            next(
                item
                for item in families["repository-security"]["contracts"]
                if item["tool"] == "gitleaks"
            )
        )
        tool = Path(sys.executable).name
        contract.update(
            tool=tool,
            version=sys.version.split()[0],
            version_argv=[tool, "--version"],
            version_output=f"Python {sys.version.split()[0]}",
            argv=[tool, "-c", "print('PRIVATE_SECRET_DIAGNOSTIC')"],
            config_paths=[],
        )
        with mock.patch.object(adapters.shutil, "which", return_value=sys.executable):
            result = adapters.run_adapter(
                Path.cwd(), contract, base_revision="a" * 40, head_revision="b" * 40
            )
        self.assertNotIn("PRIVATE_SECRET_DIAGNOSTIC", json.dumps(result))

    def test_security_bounds_timeout_output_and_descendants(self) -> None:
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
        _, _, timed_out, _ = adapters._bounded_execution(
            [sys.executable, "-c", "import time; time.sleep(2)"], Path.cwd(), environment, 1
        )
        self.assertTrue(timed_out)
        _, output, _, overflow = adapters._bounded_execution(
            [sys.executable, "-c", "print('x' * 10000)"], Path.cwd(), environment, 10
        )
        self.assertTrue(overflow)
        self.assertLessEqual(len(output), adapters.MAX_RESULT_BYTES)


if __name__ == "__main__":
    unittest.main()
