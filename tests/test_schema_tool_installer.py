# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Hostile and success tests for the schema tool installer."""

from __future__ import annotations

import hashlib
import io
import stat
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from scripts import install_schema_tools as installer


class Response(io.BytesIO):
    def __init__(self, content: bytes, url: str) -> None:
        super().__init__(content)
        self.url = url

    def geturl(self) -> str:
        return self.url


class SchemaToolInstallerTests(unittest.TestCase):
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
        directory: str | None = None,
        mode: int | None = None,
    ) -> Path:
        path = self.root / name
        with zipfile.ZipFile(path, "w") as archive:
            if directory:
                info = zipfile.ZipInfo(directory)
                info.external_attr = (stat.S_IFDIR | 0o755) << 16
                archive.writestr(info, b"")
            for member_name, content in members:
                info = zipfile.ZipInfo(member_name)
                if mode is not None:
                    info.external_attr = mode << 16
                archive.writestr(info, content)
        return path

    def artifact(self) -> installer.Artifact:
        return installer.Artifact("tool.whl", "https://files.pythonhosted.org/tool", "0" * 64)

    def test_download_is_bounded_by_source_redirect_digest_and_size(self) -> None:
        content = b"reviewed tool"
        artifact = installer.Artifact(
            "tool.whl",
            "https://files.pythonhosted.org/tool",
            hashlib.sha256(content).hexdigest(),
        )
        destination = self.root / artifact.name
        with mock.patch.object(
            installer,
            "urlopen",
            return_value=Response(content, artifact.url),
        ):
            installer.download(artifact, destination)
        self.assertEqual(content, destination.read_bytes())

        bad_source = installer.Artifact("bad", "http://example.invalid/tool", artifact.sha256)
        with self.assertRaisesRegex(installer.SchemaToolInstallError, "unreviewed source"):
            installer.download(bad_source, self.root / "bad-source")
        for case, response, error in (
            ("redirect", Response(content, "https://example.invalid/tool"), "redirected"),
            ("digest", Response(b"different", artifact.url), "SHA-256"),
        ):
            target = self.root / case
            with (
                self.subTest(case=case),
                mock.patch.object(installer, "urlopen", return_value=response),
                self.assertRaisesRegex(installer.SchemaToolInstallError, error),
            ):
                installer.download(artifact, target)
            self.assertFalse(target.with_suffix(target.suffix + ".part").exists())
        with (
            mock.patch.object(installer, "MAX_DOWNLOAD_BYTES", 3),
            mock.patch.object(installer, "urlopen", return_value=Response(b"four", artifact.url)),
            self.assertRaisesRegex(installer.SchemaToolInstallError, "size bound"),
        ):
            installer.download(artifact, self.root / "large")

    def test_zip_validation_accepts_directories_and_rejects_hostile_members(self) -> None:
        accepted = self.archive("accepted.zip", [("root/tool", b"x")], directory="root/")
        with zipfile.ZipFile(accepted) as archive:
            self.assertEqual(2, len(installer._checked_members(archive)))
        cases = [
            self.archive("traversal.zip", [("../escape", b"x")]),
            self.archive("redundant.zip", [("root//tool", b"x")]),
            self.archive("absolute.zip", [("/root/tool", b"x")]),
            self.archive("symlink.zip", [("root/link", b"target")], mode=stat.S_IFLNK | 0o777),
        ]
        duplicate = self.root / "duplicate.zip"
        with zipfile.ZipFile(duplicate, "w") as archive, mock.patch("warnings.warn"):
            archive.writestr("root/tool", b"one")
            archive.writestr("root/tool", b"two")
        cases.append(duplicate)
        for archive_path in cases:
            with (
                self.subTest(archive=archive_path.name),
                zipfile.ZipFile(archive_path) as archive,
                self.assertRaisesRegex(installer.SchemaToolInstallError, "unsafe member"),
            ):
                installer._checked_members(archive)

    def test_archive_limits_fail_closed(self) -> None:
        archive_path = self.archive("limits.zip", [("one", b"123"), ("two", b"456")])
        for setting, value, error in (
            ("MAX_ARCHIVE_MEMBERS", 1, "member count"),
            ("MAX_MEMBER_BYTES", 2, "unsafe member"),
            ("MAX_ARCHIVE_BYTES", 5, "unsafe member"),
        ):
            with (
                self.subTest(setting=setting),
                mock.patch.object(installer, setting, value),
                zipfile.ZipFile(archive_path) as archive,
                self.assertRaisesRegex(installer.SchemaToolInstallError, error),
            ):
                installer._checked_members(archive)

    def test_installers_copy_only_exact_reviewed_payloads(self) -> None:
        schema_zip = self.archive(
            "jsonschema.zip",
            [(installer.JSONSCHEMA_MEMBER, b"binary"), ("root/README", b"ignored")],
        )
        prefix = self.root / "schema"
        installer._install_jsonschema(schema_zip, prefix)
        self.assertEqual(b"binary", (prefix / "bin/jsonschema").read_bytes())
        self.assertTrue((prefix / "bin/jsonschema").stat().st_mode & 0o111)
        missing = self.archive("missing.zip", [("bin/other", b"x")])
        with self.assertRaisesRegex(installer.SchemaToolInstallError, "lacks the reviewed"):
            installer._install_jsonschema(missing, self.root / "missing")

        cases = (
            (installer.STRICTYAML, "strictyaml/main.py"),
            (installer.DATEUTIL, "dateutil/data.txt"),
            (installer.SIX, "six.py"),
        )
        for artifact, member in cases:
            with self.subTest(artifact=artifact.name):
                wheel = self.archive(
                    artifact.name, [(member, b"reviewed"), ("x.dist-info/RECORD", b"ignored")]
                )
                target = self.root / (artifact.name + "-prefix")
                installer._install_python_artifact(artifact, wheel, target)
                self.assertEqual(b"reviewed", (target / "lib" / member).read_bytes())
                self.assertFalse((target / "lib/x.dist-info/RECORD").exists())
        empty = self.archive("empty.whl", [("x.dist-info/RECORD", b"x")])
        with self.assertRaisesRegex(installer.SchemaToolInstallError, "lacks reviewed"):
            installer._install_python_artifact(installer.STRICTYAML, empty, self.root / "empty")

    def test_wrapper_atomic_failure_and_version_skew(self) -> None:
        wrapper = self.root / "wrapper"
        installer._install_wrapper(wrapper)
        helper = Path(installer.__file__).parents[1] / "src/awq/schema_helper.py"
        self.assertEqual(helper.read_bytes(), (wrapper / "lib/awq_schema_helper.py").read_bytes())
        self.assertEqual(installer.WRAPPER, (wrapper / "bin/awq-schema-check").read_bytes())

        existing = self.root / "existing"
        existing.mkdir()
        with self.assertRaisesRegex(installer.SchemaToolInstallError, "new path"):
            installer.install(existing)
        failed = self.root / "failed"
        with (
            mock.patch.object(
                installer, "download", side_effect=installer.SchemaToolInstallError("failed")
            ),
            self.assertRaisesRegex(installer.SchemaToolInstallError, "failed"),
        ):
            installer.install(failed)
        self.assertFalse(failed.exists())
        completed = mock.Mock(returncode=0, stdout="wrong\n", stderr="")
        with (
            mock.patch.object(subprocess, "run", return_value=completed),
            self.assertRaisesRegex(installer.SchemaToolInstallError, "version probe mismatch"),
        ):
            installer.verify_versions(self.root)


if __name__ == "__main__":
    unittest.main()
