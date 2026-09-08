# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Hostile and success tests for documentation tool installation."""

from __future__ import annotations

import hashlib
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Literal
from unittest import mock

from scripts import install_documentation_tools as installer


class Response(io.BytesIO):
    def __init__(self, content: bytes, url: str) -> None:
        super().__init__(content)
        self.url = url

    def geturl(self) -> str:
        return self.url


class DocumentationToolInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def archive(
        self,
        name: str,
        members: list[tuple[str, bytes]],
        *,
        mode: Literal["w:gz"] = "w:gz",
        symlink: tuple[str, str] | None = None,
    ) -> Path:
        path = self.root / name
        with tarfile.open(path, mode=mode) as archive:
            for member_name, content in members:
                member = tarfile.TarInfo(member_name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
            if symlink is not None:
                member = tarfile.TarInfo(symlink[0])
                member.type = tarfile.SYMTYPE
                member.linkname = symlink[1]
                archive.addfile(member)
        return path

    def artifact(self, member: str = "root/tool") -> installer.Artifact:
        return installer.Artifact(
            "tool.tar.gz",
            "https://github.com/example/tool",
            "0" * 64,
            member,
            "tool",
        )

    def test_download_is_bounded_by_host_digest_and_size(self) -> None:
        content = b"reviewed tool"
        artifact = installer.Artifact(
            "tool.tar.gz",
            "https://github.com/example/tool",
            hashlib.sha256(content).hexdigest(),
            "tool",
            "tool",
        )
        destination = self.root / artifact.name
        with mock.patch.object(
            installer,
            "urlopen",
            return_value=Response(content, "https://release-assets.githubusercontent.com/tool"),
        ):
            installer.download(artifact, destination)
        self.assertEqual(content, destination.read_bytes())

        for name, response, error in (
            ("host", Response(content, "https://example.invalid/tool"), "host"),
            ("digest", Response(b"different", "https://github.com/tool"), "SHA-256"),
        ):
            target = self.root / name
            with (
                self.subTest(case=name),
                mock.patch.object(installer, "urlopen", return_value=response),
                self.assertRaisesRegex(installer.DocumentationToolInstallError, error),
            ):
                installer.download(artifact, target)
            self.assertFalse(target.with_suffix(target.suffix + ".part").exists())

        target = self.root / "large"
        with (
            mock.patch.object(installer, "MAX_DOWNLOAD_BYTES", 3),
            mock.patch.object(
                installer,
                "urlopen",
                return_value=Response(b"four", "https://github.com/tool"),
            ),
            self.assertRaisesRegex(installer.DocumentationToolInstallError, "size bound"),
        ):
            installer.download(artifact, target)

    def test_extracts_only_the_exact_reviewed_executable(self) -> None:
        archive = self.archive(
            "tool.tar.gz",
            [("root/tool", b"executable"), ("root/README", b"not installed")],
        )
        prefix = self.root / "prefix"
        installer._install_archive(self.artifact(), archive, prefix)
        executable = prefix / "bin/tool"
        self.assertEqual(b"executable", executable.read_bytes())
        self.assertTrue(executable.stat().st_mode & 0o111)
        self.assertFalse((prefix / "README").exists())

        with self.assertRaisesRegex(
            installer.DocumentationToolInstallError, "lacks the reviewed executable"
        ):
            installer._install_archive(self.artifact("missing"), archive, self.root / "missing")

    def test_archive_paths_types_duplicates_and_aggregate_fail_closed(self) -> None:
        cases = [
            self.archive("traversal.tar.gz", [("../escape", b"x")]),
            self.archive(
                "duplicate.tar.gz",
                [("root/same", b"one"), ("root/same", b"two")],
            ),
            self.archive(
                "symlink.tar.gz",
                [("root/file", b"x")],
                symlink=("root/link", "file"),
            ),
        ]
        for archive_path in cases:
            with (
                self.subTest(archive=archive_path.name),
                tarfile.open(archive_path, mode="r:gz") as archive,
                self.assertRaises(installer.DocumentationToolInstallError),
            ):
                installer._checked_members(archive)

        aggregate = self.archive(
            "aggregate.tar.gz",
            [("root/one", b"123"), ("root/two", b"456")],
        )
        with (
            mock.patch.object(installer, "MAX_ARCHIVE_BYTES", 5),
            tarfile.open(aggregate, mode="r:gz") as archive,
            self.assertRaisesRegex(installer.DocumentationToolInstallError, "unsafe"),
        ):
            installer._checked_members(archive)

    def test_existing_prefix_and_failed_install_leave_no_partial_output(self) -> None:
        existing = self.root / "existing"
        existing.mkdir()
        with self.assertRaisesRegex(installer.DocumentationToolInstallError, "new path"):
            installer.install(existing)

        prefix = self.root / "failed"
        with (
            mock.patch.object(
                installer,
                "download",
                side_effect=installer.DocumentationToolInstallError("download failed"),
            ),
            self.assertRaisesRegex(installer.DocumentationToolInstallError, "download failed"),
        ):
            installer.install(prefix)
        self.assertFalse(prefix.exists())

    def test_bad_digest_is_rejected(self) -> None:
        payload = self.root / "payload"
        payload.write_bytes(b"value")
        with self.assertRaisesRegex(installer.DocumentationToolInstallError, "SHA-256"):
            installer.verify_digest(payload, "0" * 64)


if __name__ == "__main__":
    unittest.main()
