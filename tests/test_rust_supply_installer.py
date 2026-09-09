# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Hostile and success tests for the pinned Rust supply installer."""

from __future__ import annotations

import hashlib
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import awq.rust_supply_helper as helper
from scripts import install_rust_supply_tools as installer


class Response(io.BytesIO):
    def __init__(self, content: bytes, url: str) -> None:
        super().__init__(content)
        self.url = url

    def geturl(self) -> str:
        return self.url


class RustSupplyInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def archive(self, members: list[tuple[tarfile.TarInfo, bytes]]) -> Path:
        path = self.root / f"archive-{len(list(self.root.glob('archive-*')))}.tgz"
        with tarfile.open(path, "w:gz") as archive:
            for member, content in members:
                archive.addfile(member, io.BytesIO(content) if member.isfile() else None)
        return path

    def test_download_is_source_redirect_digest_and_size_bounded(self) -> None:
        content = b"reviewed"
        artifact = installer.Artifact(
            "tool.tgz",
            "https://github.com/owner/project/releases/tool.tgz",
            hashlib.sha256(content).hexdigest(),
            len(content) + 1,
            frozenset({"release-assets.githubusercontent.com"}),
        )
        destination = self.root / "tool.tgz"
        with mock.patch.object(
            installer,
            "urlopen",
            return_value=Response(
                content,
                "https://release-assets.githubusercontent.com/reviewed",
            ),
        ):
            installer.download(artifact, destination)
        self.assertEqual(content, destination.read_bytes())

        cases = [
            (
                installer.Artifact(
                    "bad",
                    "http://github.com/owner/tool",
                    artifact.sha256,
                    100,
                    artifact.final_hosts,
                ),
                Response(content, artifact.url),
                "unreviewed source",
            ),
            (
                artifact,
                Response(content, "https://example.invalid/tool"),
                "redirected",
            ),
            (
                artifact,
                Response(b"different", "https://release-assets.githubusercontent.com/tool"),
                "SHA-256",
            ),
            (
                installer.Artifact(
                    artifact.name,
                    artifact.url,
                    artifact.sha256,
                    2,
                    artifact.final_hosts,
                ),
                Response(content, "https://release-assets.githubusercontent.com/tool"),
                "size bound",
            ),
        ]
        for number, (tested, response, message) in enumerate(cases):
            target = self.root / f"bad-{number}"
            with (
                self.subTest(case=number),
                mock.patch.object(installer, "urlopen", return_value=response),
                self.assertRaisesRegex(installer.RustSupplyInstallError, message),
            ):
                installer.download(tested, target)
            self.assertFalse(target.with_suffix(target.suffix + ".part").exists())

    def test_binary_extraction_requires_exact_regular_member_and_digest(self) -> None:
        content = b"reviewed executable"
        member = tarfile.TarInfo("release/tool")
        member.size = len(content)
        archive = self.archive([(member, content)])
        staging = self.root / "staging"
        staging.mkdir()
        artifact = installer.Artifact(
            "tool.tgz",
            "https://github.com/owner/project/tool",
            "0" * 64,
            100,
            installer.ASSET_HOSTS,
        )
        bundle = installer.BinaryArtifact(artifact, "tool", "release/tool")
        with mock.patch.dict(
            helper.TOOL_METADATA,
            {"tool": {"binary_sha256": hashlib.sha256(content).hexdigest()}},
        ):
            installer.extract_binary(bundle, archive, staging)
        installed = staging / "bin/tool"
        self.assertEqual(content, installed.read_bytes())
        self.assertTrue(installed.stat().st_mode & 0o100)

        traversal = tarfile.TarInfo("../tool")
        traversal.size = len(content)
        with self.assertRaisesRegex(installer.RustSupplyInstallError, "unsafe path"):
            installer.extract_binary(
                bundle,
                self.archive([(traversal, content)]),
                self.root / "bad-staging",
            )

    def test_archive_links_and_duplicate_executable_fail_closed(self) -> None:
        content = b"tool"
        regular = tarfile.TarInfo("release/tool")
        regular.size = len(content)
        duplicate = tarfile.TarInfo("release/tool")
        duplicate.size = len(content)
        link = tarfile.TarInfo("release/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/private"
        artifact = installer.Artifact(
            "tool.tgz",
            "https://github.com/owner/project/tool",
            "0" * 64,
            100,
            installer.ASSET_HOSTS,
        )
        bundle = installer.BinaryArtifact(artifact, "tool", "release/tool")
        for number, members in enumerate(
            (
                [(regular, content), (duplicate, content)],
                [(regular, content), (link, b"")],
            )
        ):
            staging = self.root / f"staging-{number}"
            staging.mkdir()
            with (
                self.subTest(case=number),
                self.assertRaises(installer.RustSupplyInstallError),
            ):
                installer.extract_binary(bundle, self.archive(members), staging)

    def test_advisory_archive_requires_reviewed_root_and_tree_digest(self) -> None:
        root = installer.DATABASE_ROOT
        directory = tarfile.TarInfo(f"{root}/")
        directory.type = tarfile.DIRTYPE
        content = b"reviewed advisory"
        member = tarfile.TarInfo(f"{root}/crates/example.md")
        member.size = len(content)
        archive = self.archive([(directory, b""), (member, content)])
        staging = self.root / "database-staging"
        staging.mkdir()
        expected_tree = self.root / "expected"
        (expected_tree / "crates").mkdir(parents=True)
        (expected_tree / "crates/example.md").write_bytes(content)
        with mock.patch.object(
            helper,
            "ADVISORY_TREE_SHA256",
            helper._tree_sha256(expected_tree),
        ):
            installer.extract_advisory_database(archive, staging)
        self.assertEqual(
            content,
            (staging / "advisory-db/crates/example.md").read_bytes(),
        )

        bad = tarfile.TarInfo("other/file")
        bad.size = 1
        target = self.root / "bad-db"
        target.mkdir()
        with self.assertRaisesRegex(installer.RustSupplyInstallError, "unreviewed root"):
            installer.extract_advisory_database(self.archive([(bad, b"x")]), target)

    def test_install_is_atomic_and_uses_existing_pinned_rust_prefix(self) -> None:
        prefix = self.root / "installed"
        rust = self.root / "rust"
        rust.mkdir()
        observed: list[Path] = []

        def fake_download(
            artifact: installer.Artifact,
            destination: Path,
        ) -> None:
            destination.write_bytes(artifact.name.encode())

        def fake_binary(
            bundle: installer.BinaryArtifact,
            archive: Path,
            staging: Path,
        ) -> None:
            self.assertTrue(archive.is_file())
            path = staging / "bin" / bundle.executable
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"tool")

        def fake_database(archive: Path, staging: Path) -> None:
            self.assertTrue(archive.is_file())
            (staging / "advisory-db").mkdir()

        def verify(staging: Path) -> None:
            self.assertFalse(prefix.exists())
            observed.append(staging)
            self.assertTrue((staging / "manifest.json").is_file())

        with (
            mock.patch.object(installer, "_verify_rust_prefix", return_value=rust),
            mock.patch.object(installer, "download", side_effect=fake_download),
            mock.patch.object(installer, "extract_binary", side_effect=fake_binary),
            mock.patch.object(
                installer,
                "extract_advisory_database",
                side_effect=fake_database,
            ),
            mock.patch.object(installer, "verify_versions", side_effect=verify),
        ):
            installer.install(prefix, rust)
        self.assertTrue((prefix / "bin/awq-rust-supply-check").is_file())
        self.assertEqual(1, len(observed))
        self.assertFalse(observed[0].exists())
        manifest = json_load(prefix / "manifest.json")
        self.assertEqual(str(rust), manifest["rust_tools_prefix"])

        with self.assertRaisesRegex(installer.RustSupplyInstallError, "new path"):
            installer.install(prefix, rust)


def json_load(path: Path) -> dict[str, object]:
    import json

    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError("manifest is not an object")
    return value


if __name__ == "__main__":
    unittest.main()
