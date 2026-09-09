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
from awq.release import REQUIRED_SCHEMAS, SBOM_SCHEMA_ASSETS
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
                ("awq/schemas/adapter-contract.schema.json", b"{}\n"),
                ("awq/schemas/adapter-result.schema.json", b"{}\n"),
                ("awq/schemas/release-manifest.schema.json", b"{}\n"),
                ("awq/schemas/release-license-inventory.schema.json", b"{}\n"),
                (
                    "awq/schemas/spdx-3.0.1.schema.zip",
                    packaged_schema_bytes("spdx-3.0.1.schema.zip"),
                ),
                ("awq/data/adapter_catalog.json", b"{}\n"),
            ],
        )
        source = self.tarball(
            "awq.tar.gz",
            [
                ("awq/src/awq/__init__.py", b""),
                ("awq/src/awq/data/adapter_catalog.json", b"{}\n"),
                ("awq/schemas/adapter-catalog.schema.json", b"{}\n"),
                ("awq/schemas/adapter-contract.schema.json", b"{}\n"),
                ("awq/schemas/adapter-result.schema.json", b"{}\n"),
                ("awq/schemas/release-manifest.schema.json", b"{}\n"),
                ("awq/schemas/release-license-inventory.schema.json", b"{}\n"),
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
                ("awq/schemas/adapter-contract.schema.json", b"{}\n"),
                ("awq/schemas/adapter-result.schema.json", b"{}\n"),
                ("awq/schemas/release-manifest.schema.json", b"{}\n"),
                ("awq/schemas/release-license-inventory.schema.json", b"{}\n"),
                (
                    "awq/schemas/spdx-3.0.1.schema.zip",
                    packaged_schema_bytes("spdx-3.0.1.schema.zip"),
                ),
                ("awq/data/adapter_catalog.json", b"{}\n"),
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
                ("awq/schemas/adapter-contract.schema.json", b"{}\n"),
                ("awq/schemas/adapter-result.schema.json", b"{}\n"),
                ("awq/schemas/release-manifest.schema.json", b"{}\n"),
                ("awq/schemas/release-license-inventory.schema.json", b"{}\n"),
                (
                    "awq/schemas/spdx-3.0.1.schema.zip",
                    packaged_schema_bytes("spdx-3.0.1.schema.zip"),
                ),
                ("awq/data/adapter_catalog.json", b"{}\n"),
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
                ("awq/schemas/adapter-contract.schema.json", b"{}\n"),
                ("awq/schemas/adapter-result.schema.json", b"{}\n"),
                ("awq/schemas/release-manifest.schema.json", b"{}\n"),
                ("awq/schemas/release-license-inventory.schema.json", b"{}\n"),
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
                ("awq/schemas/adapter-contract.schema.json", b"{}\n"),
                ("awq/schemas/adapter-result.schema.json", b"{}\n"),
                ("awq/schemas/release-manifest.schema.json", b"{}\n"),
                ("awq/schemas/release-license-inventory.schema.json", b"{}\n"),
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
        for omitted in sorted(SBOM_SCHEMA_ASSETS):
            members = [
                (f"awq/schemas/{name}", packaged_schema_bytes(name))
                for name in sorted(REQUIRED_SCHEMAS)
                if name != omitted
            ]
            members.append(("awq/data/adapter_catalog.json", b"{}\n"))
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


if __name__ == "__main__":
    unittest.main()
