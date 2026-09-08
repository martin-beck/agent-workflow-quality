# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Distribution archive privacy and integrity tests."""

from __future__ import annotations

import contextlib
import io
import stat
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.verify_distribution import DistributionError, inspect_archive, main


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

    def test_valid_archives_include_adapter_schemas_and_empty_files(self) -> None:
        wheel = self.wheel(
            "awq.whl",
            [
                ("awq/__init__.py", b""),
                ("awq/schemas/adapter-contract.schema.json", b"{}\n"),
                ("awq/schemas/adapter-result.schema.json", b"{}\n"),
            ],
        )
        source = self.tarball(
            "awq.tar.gz",
            [
                ("awq/src/awq/__init__.py", b""),
                ("awq/schemas/adapter-contract.schema.json", b"{}\n"),
                ("awq/schemas/adapter-result.schema.json", b"{}\n"),
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
                ("awq/schemas/adapter-contract.schema.json", b"{}\n"),
                ("awq/schemas/adapter-result.schema.json", b"{}\n"),
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
                ("awq/schemas/adapter-contract.schema.json", b"{}\n"),
                ("awq/schemas/adapter-result.schema.json", b"{}\n"),
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
        bad = self.root / "bad.whl"
        bad.write_bytes(b"not a zip")
        with self.assertRaisesRegex(DistributionError, "cannot inspect"):
            inspect_archive(bad)
        with self.assertRaisesRegex(DistributionError, "unsupported"):
            inspect_archive(self.root / "archive.txt")


if __name__ == "__main__":
    unittest.main()
