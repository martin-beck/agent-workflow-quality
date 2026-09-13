# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Distribution archive privacy and integrity tests."""

from __future__ import annotations

import contextlib
import importlib.metadata
import io
import stat
import tarfile
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path

from awq import __version__
from awq.release import (
    ADVERSARIAL_SCHEMA_ASSETS,
    CONTRACT_CATALOG_DATA_ASSETS,
    CONTRACT_CATALOG_SCHEMA_ASSETS,
    EXECUTION_SCHEMA_ASSETS,
    FORMAL_SCHEMA_ASSETS,
    LIFECYCLE_SCHEMA_ASSETS,
    ONBOARDING_SCHEMA_ASSETS,
    PROMOTION_SCHEMA_ASSETS,
    PROVENANCE_SCHEMA_ASSETS,
    PYTHON_REFACTOR_SCHEMA_ASSETS,
    REFINEMENT_SCHEMA_ASSETS,
    RELIABILITY_SCHEMA_ASSETS,
    REQUIRED_SCHEMAS,
    SBOM_SCHEMA_ASSETS,
    TEST_REPORT_SCHEMA_ASSETS,
)
from scripts.verify_distribution import DistributionError, inspect_archive, main
from tests.support import packaged_schema_bytes


class DistributionVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def wheel(
        self,
        name: str,
        members: list[tuple[str, bytes]],
        *,
        symlink: str | None = None,
    ) -> Path:
        path = self.root / name
        with zipfile.ZipFile(path, mode="w") as archive:
            for member, content in members:
                archive.writestr(member, content)
            if symlink:
                info = zipfile.ZipInfo(symlink)
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, "target")
        return path

    def tarball(
        self,
        name: str,
        members: list[tuple[str, bytes]],
        *,
        symlink: str | None = None,
    ) -> Path:
        path = self.root / name
        with tarfile.open(path, mode="w:gz") as archive:
            for member, content in members:
                info = tarfile.TarInfo(member)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
            if symlink:
                info = tarfile.TarInfo(symlink)
                info.type = tarfile.SYMTYPE
                info.linkname = "target"
                archive.addfile(info)
        return path

    def test_project_runtime_and_installed_versions_match(self) -> None:
        project = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text("utf-8"))
        self.assertEqual(project["project"]["version"], __version__)
        self.assertEqual(
            importlib.metadata.version("agent-workflow-quality"),
            __version__,
        )

    def test_valid_archives_include_adapter_schemas_and_empty_files(self) -> None:
        wheel = self.wheel(
            "awq.whl",
            [
                ("awq/__init__.py", b""),
                ("awq/schemas/adapter-catalog.schema.json", b"{}\n"),
                ("awq/schemas/contract-catalog.schema.json", b"{}\n"),
                ("awq/schemas/adapter-contract.schema.json", b"{}\n"),
                ("awq/schemas/adapter-result.schema.json", b"{}\n"),
                ("awq/schemas/release-manifest.schema.json", b"{}\n"),
                ("awq/schemas/release-license-inventory.schema.json", b"{}\n"),
                ("awq/schemas/release-provenance.schema.json", b"{}\n"),
                ("awq/schemas/release-trust-policy.schema.json", b"{}\n"),
                ("awq/schemas/consumer-equivalence.schema.json", b"{}\n"),
                ("awq/schemas/evidence-identity.schema.json", b"{}\n"),
                ("awq/schemas/native-gate-mapping.schema.json", b"{}\n"),
                ("awq/schemas/assurance-contract.schema.json", b"{}\n"),
                ("awq/schemas/lifecycle-model.schema.json", b"{}\n"),
                ("awq/schemas/refinement-map.schema.json", b"{}\n"),
                ("awq/schemas/python-refactor.schema.json", b"{}\n"),
                ("awq/schemas/adversarial-campaign.schema.json", b"{}\n"),
                ("awq/schemas/reliability-budget.schema.json", b"{}\n"),
                ("awq/schemas/onboarding.schema.json", b"{}\n"),
                ("awq/schemas/test-report-evidence.schema.json", b"{}\n"),
                ("awq/schemas/execution-receipt.schema.json", b"{}\n"),
                ("awq/data/compatibility.json", b"{}\n"),
                ("awq/data/agent_recipes.json", b"{}\n"),
                (
                    "awq/schemas/spdx-3.0.1.schema.zip",
                    packaged_schema_bytes("spdx-3.0.1.schema.zip"),
                ),
                ("awq/data/adapter_catalog.json", b"{}\n"),
                ("awq/data/contract_catalog.json", b"{}\n"),
            ],
        )
        source = self.tarball(
            "awq.tar.gz",
            [
                ("awq/src/awq/__init__.py", b""),
                ("awq/src/awq/data/adapter_catalog.json", b"{}\n"),
                ("awq/src/awq/data/contract_catalog.json", b"{}\n"),
                ("awq/schemas/adapter-catalog.schema.json", b"{}\n"),
                ("awq/schemas/contract-catalog.schema.json", b"{}\n"),
                ("awq/schemas/adapter-contract.schema.json", b"{}\n"),
                ("awq/schemas/adapter-result.schema.json", b"{}\n"),
                ("awq/schemas/release-manifest.schema.json", b"{}\n"),
                ("awq/schemas/release-license-inventory.schema.json", b"{}\n"),
                ("awq/schemas/release-provenance.schema.json", b"{}\n"),
                ("awq/schemas/release-trust-policy.schema.json", b"{}\n"),
                ("awq/schemas/consumer-equivalence.schema.json", b"{}\n"),
                ("awq/schemas/evidence-identity.schema.json", b"{}\n"),
                ("awq/schemas/native-gate-mapping.schema.json", b"{}\n"),
                ("awq/schemas/assurance-contract.schema.json", b"{}\n"),
                ("awq/schemas/lifecycle-model.schema.json", b"{}\n"),
                ("awq/schemas/refinement-map.schema.json", b"{}\n"),
                ("awq/schemas/python-refactor.schema.json", b"{}\n"),
                ("awq/schemas/adversarial-campaign.schema.json", b"{}\n"),
                ("awq/schemas/reliability-budget.schema.json", b"{}\n"),
                ("awq/schemas/onboarding.schema.json", b"{}\n"),
                ("awq/schemas/test-report-evidence.schema.json", b"{}\n"),
                ("awq/schemas/execution-receipt.schema.json", b"{}\n"),
                ("awq/data/compatibility.json", b"{}\n"),
                ("awq/data/agent_recipes.json", b"{}\n"),
                (
                    "awq/schemas/spdx-3.0.1.schema.zip",
                    packaged_schema_bytes("spdx-3.0.1.schema.zip"),
                ),
            ],
        )
        self.assertEqual([], inspect_archive(wheel))
        self.assertEqual([], inspect_archive(source))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(0, main([str(source), str(wheel)]))
        self.assertIn("Verified 2", output.getvalue())

    def test_hostile_paths_duplicates_and_symlinks_fail(self) -> None:
        archive = self.tarball(
            "hostile.tar.gz",
            [
                ("../escape", b"x"),
                (r"C:\escape", b"x"),
                ("awq/./noncanonical", b"x"),
                ("awq/.git", b"worktree metadata"),
                ("awq/duplicate", b"first"),
                ("awq/duplicate", b"second"),
                ("awq/schemas/adapter-catalog.schema.json", b"{}\n"),
                ("awq/schemas/contract-catalog.schema.json", b"{}\n"),
                ("awq/schemas/adapter-contract.schema.json", b"{}\n"),
                ("awq/schemas/adapter-result.schema.json", b"{}\n"),
                ("awq/schemas/release-manifest.schema.json", b"{}\n"),
                ("awq/schemas/release-license-inventory.schema.json", b"{}\n"),
                ("awq/schemas/release-provenance.schema.json", b"{}\n"),
                ("awq/schemas/release-trust-policy.schema.json", b"{}\n"),
                ("awq/schemas/consumer-equivalence.schema.json", b"{}\n"),
                ("awq/schemas/evidence-identity.schema.json", b"{}\n"),
                ("awq/schemas/native-gate-mapping.schema.json", b"{}\n"),
                ("awq/schemas/assurance-contract.schema.json", b"{}\n"),
                ("awq/schemas/lifecycle-model.schema.json", b"{}\n"),
                ("awq/schemas/refinement-map.schema.json", b"{}\n"),
                ("awq/schemas/python-refactor.schema.json", b"{}\n"),
                ("awq/schemas/adversarial-campaign.schema.json", b"{}\n"),
                ("awq/schemas/reliability-budget.schema.json", b"{}\n"),
                ("awq/schemas/onboarding.schema.json", b"{}\n"),
                ("awq/schemas/test-report-evidence.schema.json", b"{}\n"),
                ("awq/schemas/execution-receipt.schema.json", b"{}\n"),
                ("awq/data/compatibility.json", b"{}\n"),
                ("awq/data/agent_recipes.json", b"{}\n"),
                (
                    "awq/schemas/spdx-3.0.1.schema.zip",
                    packaged_schema_bytes("spdx-3.0.1.schema.zip"),
                ),
                ("awq/data/adapter_catalog.json", b"{}\n"),
                ("awq/data/contract_catalog.json", b"{}\n"),
            ],
            symlink="awq/link",
        )
        issues = inspect_archive(archive)
        self.assertTrue(any("unsafe archive path" in issue for issue in issues))
        self.assertTrue(any("forbidden development artifact" in issue for issue in issues))
        self.assertTrue(any("duplicate archive path" in issue for issue in issues))
        self.assertTrue(any("non-regular" in issue for issue in issues))
        wheel = self.wheel(
            "symlink.whl",
            [
                ("awq/schemas/adapter-catalog.schema.json", b"{}\n"),
                ("awq/schemas/contract-catalog.schema.json", b"{}\n"),
                ("awq/schemas/adapter-contract.schema.json", b"{}\n"),
                ("awq/schemas/adapter-result.schema.json", b"{}\n"),
                ("awq/schemas/release-manifest.schema.json", b"{}\n"),
                ("awq/schemas/release-license-inventory.schema.json", b"{}\n"),
                ("awq/schemas/release-provenance.schema.json", b"{}\n"),
                ("awq/schemas/release-trust-policy.schema.json", b"{}\n"),
                ("awq/schemas/consumer-equivalence.schema.json", b"{}\n"),
                ("awq/schemas/evidence-identity.schema.json", b"{}\n"),
                ("awq/schemas/native-gate-mapping.schema.json", b"{}\n"),
                ("awq/schemas/assurance-contract.schema.json", b"{}\n"),
                ("awq/schemas/lifecycle-model.schema.json", b"{}\n"),
                ("awq/schemas/refinement-map.schema.json", b"{}\n"),
                ("awq/schemas/python-refactor.schema.json", b"{}\n"),
                ("awq/schemas/adversarial-campaign.schema.json", b"{}\n"),
                ("awq/schemas/reliability-budget.schema.json", b"{}\n"),
                ("awq/schemas/onboarding.schema.json", b"{}\n"),
                ("awq/schemas/test-report-evidence.schema.json", b"{}\n"),
                ("awq/schemas/execution-receipt.schema.json", b"{}\n"),
                ("awq/data/compatibility.json", b"{}\n"),
                ("awq/data/agent_recipes.json", b"{}\n"),
                (
                    "awq/schemas/spdx-3.0.1.schema.zip",
                    packaged_schema_bytes("spdx-3.0.1.schema.zip"),
                ),
                ("awq/data/adapter_catalog.json", b"{}\n"),
                ("awq/data/contract_catalog.json", b"{}\n"),
            ],
            symlink="awq/link",
        )
        self.assertTrue(any("non-regular" in issue for issue in inspect_archive(wheel)))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(1, main([str(archive), str(wheel)]))

    def test_missing_schema_bad_and_unsupported_archives_fail(self) -> None:
        missing = self.wheel(
            "missing.whl",
            [("awq/schemas/adapter-contract.schema.json", b"{}\n")],
        )
        self.assertTrue(
            any("required packaged schema" in item for item in inspect_archive(missing))
        )
        missing_data = self.wheel(
            "missing-data.whl",
            [
                ("awq/schemas/adapter-catalog.schema.json", b"{}\n"),
                ("awq/schemas/contract-catalog.schema.json", b"{}\n"),
                ("awq/schemas/adapter-contract.schema.json", b"{}\n"),
                ("awq/schemas/adapter-result.schema.json", b"{}\n"),
                ("awq/schemas/release-manifest.schema.json", b"{}\n"),
                ("awq/schemas/release-license-inventory.schema.json", b"{}\n"),
                ("awq/schemas/release-provenance.schema.json", b"{}\n"),
                ("awq/schemas/release-trust-policy.schema.json", b"{}\n"),
                ("awq/schemas/consumer-equivalence.schema.json", b"{}\n"),
                ("awq/schemas/evidence-identity.schema.json", b"{}\n"),
                ("awq/schemas/native-gate-mapping.schema.json", b"{}\n"),
                ("awq/schemas/assurance-contract.schema.json", b"{}\n"),
                ("awq/schemas/lifecycle-model.schema.json", b"{}\n"),
                ("awq/schemas/refinement-map.schema.json", b"{}\n"),
                ("awq/schemas/python-refactor.schema.json", b"{}\n"),
                ("awq/schemas/adversarial-campaign.schema.json", b"{}\n"),
                ("awq/schemas/reliability-budget.schema.json", b"{}\n"),
                ("awq/schemas/onboarding.schema.json", b"{}\n"),
                ("awq/schemas/test-report-evidence.schema.json", b"{}\n"),
                ("awq/schemas/execution-receipt.schema.json", b"{}\n"),
                ("awq/data/compatibility.json", b"{}\n"),
                ("awq/data/agent_recipes.json", b"{}\n"),
                (
                    "awq/schemas/spdx-3.0.1.schema.zip",
                    packaged_schema_bytes("spdx-3.0.1.schema.zip"),
                ),
            ],
        )
        self.assertTrue(
            any("required packaged data" in item for item in inspect_archive(missing_data))
        )
        misplaced_data = self.wheel(
            "misplaced-data.whl",
            [
                ("awq/schemas/adapter-catalog.schema.json", b"{}\n"),
                ("awq/schemas/contract-catalog.schema.json", b"{}\n"),
                ("awq/schemas/adapter-contract.schema.json", b"{}\n"),
                ("awq/schemas/adapter-result.schema.json", b"{}\n"),
                ("awq/schemas/release-manifest.schema.json", b"{}\n"),
                ("awq/schemas/release-license-inventory.schema.json", b"{}\n"),
                ("awq/schemas/release-provenance.schema.json", b"{}\n"),
                ("awq/schemas/release-trust-policy.schema.json", b"{}\n"),
                ("awq/schemas/consumer-equivalence.schema.json", b"{}\n"),
                ("awq/schemas/evidence-identity.schema.json", b"{}\n"),
                ("awq/schemas/native-gate-mapping.schema.json", b"{}\n"),
                ("awq/schemas/assurance-contract.schema.json", b"{}\n"),
                ("awq/schemas/lifecycle-model.schema.json", b"{}\n"),
                ("awq/schemas/refinement-map.schema.json", b"{}\n"),
                ("awq/schemas/python-refactor.schema.json", b"{}\n"),
                ("awq/schemas/adversarial-campaign.schema.json", b"{}\n"),
                ("awq/schemas/reliability-budget.schema.json", b"{}\n"),
                ("awq/schemas/onboarding.schema.json", b"{}\n"),
                ("awq/schemas/test-report-evidence.schema.json", b"{}\n"),
                ("awq/schemas/execution-receipt.schema.json", b"{}\n"),
                ("awq/data/compatibility.json", b"{}\n"),
                ("awq/data/agent_recipes.json", b"{}\n"),
                (
                    "awq/schemas/spdx-3.0.1.schema.zip",
                    packaged_schema_bytes("spdx-3.0.1.schema.zip"),
                ),
                ("other/data/adapter_catalog.json", b"{}\n"),
            ],
        )
        self.assertTrue(
            any("required packaged data" in item for item in inspect_archive(misplaced_data))
        )
        bad = self.root / "bad.whl"
        bad.write_bytes(b"not a zip")
        with self.assertRaisesRegex(DistributionError, "cannot inspect"):
            inspect_archive(bad)
        with self.assertRaisesRegex(DistributionError, "unsupported"):
            inspect_archive(self.root / "archive.txt")

    def test_each_sbom_schema_asset_is_required_in_both_archive_formats(self) -> None:
        for omitted in sorted(
            SBOM_SCHEMA_ASSETS
            | PROVENANCE_SCHEMA_ASSETS
            | PROMOTION_SCHEMA_ASSETS
            | FORMAL_SCHEMA_ASSETS
            | LIFECYCLE_SCHEMA_ASSETS
            | REFINEMENT_SCHEMA_ASSETS
            | ONBOARDING_SCHEMA_ASSETS
            | RELIABILITY_SCHEMA_ASSETS
            | ADVERSARIAL_SCHEMA_ASSETS
            | PYTHON_REFACTOR_SCHEMA_ASSETS
            | TEST_REPORT_SCHEMA_ASSETS
            | EXECUTION_SCHEMA_ASSETS
        ):
            members = [
                (f"awq/schemas/{name}", packaged_schema_bytes(name))
                for name in sorted(REQUIRED_SCHEMAS)
                if name != omitted
            ]
            members.extend(
                (f"awq/data/{name}", b"{}\n")
                for name in (
                    "adapter_catalog.json",
                    "contract_catalog.json",
                    "compatibility.json",
                    "agent_recipes.json",
                )
            )
            for archive in (
                self.wheel("missing-sbom-asset.whl", members),
                self.tarball("missing-sbom-asset.tar.gz", members),
            ):
                with self.subTest(omitted=omitted, archive=archive.suffix):
                    findings = inspect_archive(archive)
                    self.assertEqual(
                        [f"{archive.name}: required packaged schema is missing: {omitted}"],
                        findings,
                    )

    def test_onboarding_data_is_required_and_historical_contract_is_preserved(self) -> None:
        schemas = [
            (f"awq/schemas/{name}", packaged_schema_bytes(name))
            for name in sorted(REQUIRED_SCHEMAS)
        ]
        data = [
            (f"awq/data/{name}", b"{}\n")
            for name in (
                "adapter_catalog.json",
                "contract_catalog.json",
                "compatibility.json",
                "agent_recipes.json",
            )
        ]
        for omitted in ("compatibility.json", "agent_recipes.json"):
            members = schemas + [item for item in data if not item[0].endswith("/" + omitted)]
            for archive in (
                self.wheel("onboarding.whl", members),
                self.tarball("onboarding.tar.gz", members),
            ):
                self.assertEqual(
                    [f"{archive.name}: required packaged data is missing: {omitted}"],
                    inspect_archive(archive),
                )
        historical = [
            item
            for item in schemas + data
            if not item[0].endswith(
                ("onboarding.schema.json", "compatibility.json", "agent_recipes.json")
            )
        ]
        for archive in (
            self.wheel("historical.whl", historical),
            self.tarball("historical.tar.gz", historical),
        ):
            self.assertEqual([], inspect_archive(archive, require_onboarding_assets=False))
            self.assertEqual(3, len(inspect_archive(archive)))

    def test_public_v029_archives_retain_their_original_asset_contract(self) -> None:
        schemas = frozenset(
            {
                "adapter-catalog.schema.json",
                "adapter-contract.schema.json",
                "adapter-result.schema.json",
                "adversarial-campaign.schema.json",
                "assurance-contract.schema.json",
                "consumer-equivalence.schema.json",
                "evidence-identity.schema.json",
                "lifecycle-model.schema.json",
                "native-gate-mapping.schema.json",
                "onboarding.schema.json",
                "python-refactor.schema.json",
                "refinement-map.schema.json",
                "release-license-inventory.schema.json",
                "release-manifest.schema.json",
                "release-provenance.schema.json",
                "release-trust-policy.schema.json",
                "reliability-budget.schema.json",
                "spdx-3.0.1.schema.zip",
            }
        )
        data = frozenset({"adapter_catalog.json", "agent_recipes.json", "compatibility.json"})
        self.assertEqual(
            {"contract-catalog.schema.json"},
            CONTRACT_CATALOG_SCHEMA_ASSETS,
        )
        self.assertEqual({"contract_catalog.json"}, CONTRACT_CATALOG_DATA_ASSETS)
        members = [
            (f"awq/schemas/{name}", packaged_schema_bytes(name)) for name in sorted(schemas)
        ] + [(f"awq/data/{name}", b"{}\n") for name in sorted(data)]
        for archive in (
            self.wheel("agent_workflow_quality-0.29.0-py3-none-any.whl", members),
            self.tarball("agent_workflow_quality-0.29.0.tar.gz", members),
        ):
            self.assertEqual(
                [],
                inspect_archive(
                    archive,
                    require_contract_catalog_assets=False,
                    require_test_report_assets=False,
                    require_execution_assets=False,
                ),
            )
            self.assertEqual(
                [
                    f"{archive.name}: required packaged schema is missing: "
                    "contract-catalog.schema.json",
                    f"{archive.name}: required packaged schema is missing: "
                    "execution-receipt.schema.json",
                    f"{archive.name}: required packaged schema is missing: "
                    "test-report-evidence.schema.json",
                    f"{archive.name}: required packaged data is missing: contract_catalog.json",
                ],
                inspect_archive(archive),
            )

    def test_execution_schema_is_required_and_historical_contract_is_preserved(self) -> None:
        members = [
            (f"awq/schemas/{name}", packaged_schema_bytes(name))
            for name in sorted(REQUIRED_SCHEMAS)
            if name not in EXECUTION_SCHEMA_ASSETS
        ]
        members.extend(
            (f"awq/data/{name}", b"{}\n")
            for name in (
                "adapter_catalog.json",
                "compatibility.json",
                "agent_recipes.json",
                "contract_catalog.json",
            )
        )
        for archive in (
            self.wheel("pre-execution-receipt.whl", members),
            self.tarball("pre-execution-receipt.tar.gz", members),
        ):
            self.assertEqual([], inspect_archive(archive, require_execution_assets=False))
            self.assertEqual(
                [
                    f"{archive.name}: required packaged schema is missing: "
                    "execution-receipt.schema.json"
                ],
                inspect_archive(archive),
            )


if __name__ == "__main__":
    unittest.main()
