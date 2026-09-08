# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Hostile and success tests for checksum-pinned shell tool installation."""

from __future__ import annotations

import hashlib
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Literal
from unittest import mock

from scripts import install_shell_tools as installer


class Response(io.BytesIO):
    def __init__(self, content: bytes, url: str) -> None:
        super().__init__(content)
        self.url = url

    def geturl(self) -> str:
        return self.url


class ShellToolInstallerTests(unittest.TestCase):
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
        mode: Literal["w:gz", "w:xz"] = "w:gz",
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

    def test_download_is_bounded_by_host_and_digest(self) -> None:
        content = b"reviewed tool"
        artifact = installer.Artifact(
            "tool",
            "https://github.com/example/tool",
            hashlib.sha256(content).hexdigest(),
        )
        destination = self.root / "tool"
        with mock.patch.object(
            installer,
            "urlopen",
            return_value=Response(content, "https://release-assets.githubusercontent.com/tool"),
        ):
            installer.download(artifact, destination)
        self.assertEqual(content, destination.read_bytes())

        bad_host = self.root / "bad-host"
        with (
            mock.patch.object(
                installer,
                "urlopen",
                return_value=Response(content, "https://example.invalid/tool"),
            ),
            self.assertRaisesRegex(installer.ShellToolInstallError, "host"),
        ):
            installer.download(artifact, bad_host)
        self.assertFalse(bad_host.with_suffix(".part").exists())

        too_large = self.root / "too-large"
        with (
            mock.patch.object(installer, "MAX_DOWNLOAD_BYTES", 3),
            mock.patch.object(
                installer,
                "urlopen",
                return_value=Response(b"four", "https://github.com/tool"),
            ),
            self.assertRaisesRegex(installer.ShellToolInstallError, "size bound"),
        ):
            installer.download(artifact, too_large)
        self.assertFalse(too_large.with_suffix(".part").exists())

        mismatch = self.root / "mismatch"
        with (
            mock.patch.object(
                installer,
                "urlopen",
                return_value=Response(b"different", "https://github.com/tool"),
            ),
            self.assertRaisesRegex(installer.ShellToolInstallError, "SHA-256"),
        ):
            installer.download(artifact, mismatch)
        self.assertFalse(mismatch.with_suffix(".part").exists())

    def test_extracts_only_required_shellcheck_and_bats_payloads(self) -> None:
        shellcheck = self.archive(
            "shellcheck.tar.xz",
            [
                ("shellcheck-v0.11.0/shellcheck", b"shellcheck"),
                ("shellcheck-v0.11.0/README", b"not installed"),
            ],
            mode="w:xz",
        )
        prefix = self.root / "prefix"
        installer.install_shellcheck(shellcheck, prefix)
        self.assertEqual(b"shellcheck", (prefix / "bin/shellcheck").read_bytes())
        self.assertFalse((prefix / "README").exists())

        bats_members = [
            (f"{installer.BATS_ROOT}/bin/bats", b"bats"),
            *[
                (f"{installer.BATS_ROOT}/libexec/bats-core/tool-{number}", b"tool")
                for number in range(5)
            ],
            *[
                (f"{installer.BATS_ROOT}/lib/bats-core/lib-{number}", b"library")
                for number in range(5)
            ],
            (f"{installer.BATS_ROOT}/README.md", b"not installed"),
        ]
        bats = self.archive("bats.tar.gz", bats_members)
        installer.install_bats(bats, prefix)
        self.assertEqual(b"bats", (prefix / "bin/bats").read_bytes())
        self.assertFalse((prefix / "README.md").exists())

    def test_archive_paths_types_and_symlinks_fail_closed(self) -> None:
        unsafe = self.archive("unsafe.tar.gz", [("../escape", b"x")])
        with (
            tarfile.open(unsafe, mode="r:gz") as archive,
            self.assertRaisesRegex(installer.ShellToolInstallError, "unsafe"),
        ):
            installer._checked_members(archive)

        escaping = self.archive(
            "escaping.tar.gz",
            [("root/file", b"x")],
            symlink=("root/link", "../../outside"),
        )
        with (
            tarfile.open(escaping, mode="r:gz") as archive,
            self.assertRaisesRegex(installer.ShellToolInstallError, "symlink"),
        ):
            installer._checked_members(archive)

        foreign = self.archive(
            "foreign.tar.gz",
            [("different-root/bin/bats", b"bats")],
        )
        with self.assertRaisesRegex(installer.ShellToolInstallError, "reviewed root"):
            installer.install_bats(foreign, self.root / "foreign-prefix")

        duplicate = self.archive(
            "duplicate.tar.gz",
            [("root/same", b"one"), ("root/same", b"two")],
        )
        with (
            tarfile.open(duplicate, mode="r:gz") as archive,
            self.assertRaisesRegex(installer.ShellToolInstallError, "unsafe"),
        ):
            installer._checked_members(archive)

    def test_failed_install_leaves_no_partial_prefix(self) -> None:
        prefix = self.root / "failed-prefix"

        def fake_download(_artifact: installer.Artifact, destination: Path) -> None:
            destination.write_bytes(b"downloaded")

        with (
            mock.patch.object(installer, "download", side_effect=fake_download),
            mock.patch.object(
                installer,
                "install_shellcheck",
                side_effect=installer.ShellToolInstallError("invalid archive"),
            ),
            self.assertRaisesRegex(installer.ShellToolInstallError, "invalid archive"),
        ):
            installer.install(prefix)

        self.assertFalse(prefix.exists())

    def test_existing_prefix_and_bad_digest_fail_without_overwrite(self) -> None:
        existing = self.root / "existing"
        existing.mkdir()
        with self.assertRaisesRegex(installer.ShellToolInstallError, "new path"):
            installer.install(existing)
        payload = self.root / "payload"
        payload.write_bytes(b"value")
        with self.assertRaisesRegex(installer.ShellToolInstallError, "SHA-256"):
            installer.verify_digest(payload, "0" * 64)
