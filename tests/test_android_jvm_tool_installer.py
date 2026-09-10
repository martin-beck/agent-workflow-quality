# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Hostile and success tests for the Android/JVM tool installer."""

from __future__ import annotations

import hashlib
import io
import json
import stat
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from awq import android_jvm_helper as helper_metadata
from scripts import install_android_jvm_tools as installer


class Response(io.BytesIO):
    def __init__(self, content: bytes, url: str) -> None:
        super().__init__(content)
        self.url = url

    def geturl(self) -> str:
        return self.url


class AndroidJvmInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def artifact(self, content: bytes = b"reviewed") -> installer.Artifact:
        return installer.Artifact(
            "tool.zip",
            "https://github.com/owner/repo/releases/tool.zip",
            hashlib.sha256(content).hexdigest(),
            len(content) + 1,
            "zip",
        )

    def test_download_rejects_source_redirect_digest_and_size(self) -> None:
        artifact = self.artifact()
        target = self.root / artifact.name
        with mock.patch.object(
            installer, "urlopen", return_value=Response(b"reviewed", artifact.url)
        ):
            installer.download(artifact, target)
        self.assertEqual(b"reviewed", target.read_bytes())
        cases = [
            (
                installer.Artifact("x", "http://github.com/x", "0" * 64, 9, "zip"),
                Response(b"x", "http://github.com/x"),
                "unreviewed source",
            ),
            (artifact, Response(b"reviewed", "https://example.invalid/x"), "redirected"),
            (artifact, Response(b"different", artifact.url), "SHA-256"),
            (
                installer.Artifact(artifact.name, artifact.url, artifact.sha256, 2, artifact.kind),
                Response(b"too-large", artifact.url),
                "size bound",
            ),
        ]
        for index, (tested, response, message) in enumerate(cases):
            destination = self.root / f"bad-{index}"
            with (
                self.subTest(message=message),
                mock.patch.object(installer, "urlopen", return_value=response),
                self.assertRaisesRegex(installer.AndroidJvmInstallError, message),
            ):
                installer.download(tested, destination)
            self.assertFalse(destination.with_suffix(destination.suffix + ".part").exists())

    def test_tar_extraction_accepts_internal_links_and_rejects_escapes(self) -> None:
        archive_path = self.root / "jdk.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            root = tarfile.TarInfo("jdk/")
            root.type = tarfile.DIRTYPE
            archive.addfile(root)
            data = b"binary"
            file_info = tarfile.TarInfo("jdk/bin/java")
            file_info.mode = 0o755
            file_info.size = len(data)
            archive.addfile(file_info, io.BytesIO(data))
            link = tarfile.TarInfo("jdk/bin/java-link")
            link.type = tarfile.SYMTYPE
            link.linkname = "java"
            archive.addfile(link)
        destination = self.root / "installed-jdk"
        destination.mkdir()
        installer._extract_tar(archive_path, destination, "jdk")
        self.assertEqual(data, (destination / "bin/java").read_bytes())
        self.assertTrue((destination / "bin/java-link").is_symlink())
        bounded = self.root / "bounded"
        bounded.mkdir()
        with (
            mock.patch.object(installer, "MAX_ARCHIVE_BYTES", 1),
            mock.patch.object(installer, "_copy") as copy,
            self.assertRaisesRegex(installer.AndroidJvmInstallError, "exceeds"),
        ):
            installer._extract_tar(archive_path, bounded, "jdk")
        copy.assert_not_called()

        hostile = self.root / "hostile.tar.gz"
        with tarfile.open(hostile, "w:gz") as archive:
            link = tarfile.TarInfo("jdk/bin/escape")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../../outside"
            archive.addfile(link)
        with self.assertRaisesRegex(installer.AndroidJvmInstallError, "escapes"):
            installer._extract_tar(hostile, destination, "jdk")

    def test_zip_extraction_rejects_paths_and_symlinks(self) -> None:
        archive_path = self.root / "gradle.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("gradle/", b"")
            executable = zipfile.ZipInfo("gradle/bin/gradle")
            executable.create_system = 3
            executable.external_attr = (stat.S_IFREG | 0o755) << 16
            archive.writestr(executable, b"binary")
        destination = self.root / "installed-gradle"
        destination.mkdir()
        installer._extract_zip(archive_path, destination, "gradle")
        self.assertEqual(b"binary", (destination / "bin/gradle").read_bytes())

        hostile = self.root / "hostile.zip"
        with zipfile.ZipFile(hostile, "w") as archive:
            info = zipfile.ZipInfo("gradle/link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "target")
        with self.assertRaisesRegex(installer.AndroidJvmInstallError, "unsafe"):
            installer._extract_zip(hostile, destination, "gradle")
        with self.assertRaisesRegex(installer.AndroidJvmInstallError, "unsafe"):
            installer._member_path("gradle/../../escape", "gradle")

    def test_wrapper_manifest_and_probe_are_exact(self) -> None:
        prefix = self.root / "prefix"
        prefix.mkdir()
        installer._install_wrapper(prefix)
        installer._write_manifest(prefix)
        self.assertEqual(
            (Path(installer.__file__).parents[1] / "src/awq/android_jvm_helper.py").read_bytes(),
            (prefix / "lib/awq_android_jvm_helper.py").read_bytes(),
        )
        self.assertEqual(
            (Path(installer.__file__).parents[1] / "src/awq/test_reports.py").read_bytes(),
            (prefix / "lib/awq_test_reports.py").read_bytes(),
        )
        manifest = json.loads((prefix / "manifest.json").read_text())
        self.assertEqual(helper_metadata.JAVA_ARCHIVE_SHA256, manifest["java_archive_sha256"])
        self.assertEqual(
            hashlib.sha256((prefix / "lib/awq_test_reports.py").read_bytes()).hexdigest(),
            manifest["test_reports_sha256"],
        )
        completed = subprocess.run(
            [str(prefix / "bin/awq-android-jvm-check"), "--version"],
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(1, completed.returncode)
        self.assertEqual("awq-android-jvm-check: validation failed\n", completed.stderr)
        (prefix / "lib/awq_test_reports.py").unlink()
        missing = subprocess.run(
            [str(prefix / "bin/awq-android-jvm-check"), "--version"],
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(0, missing.returncode)
        self.assertIn("awq_test_reports", missing.stderr)
        success = mock.Mock(
            returncode=0,
            stdout=helper_metadata.VERSION_OUTPUT + "\n",
            stderr="",
        )
        with mock.patch.object(subprocess, "run", return_value=success) as run:
            installer.verify_versions(prefix)
        self.assertEqual(
            [str(prefix / "bin/awq-android-jvm-check"), "--version"],
            run.call_args.args[0],
        )
        self.assertNotIn("HOME", run.call_args.kwargs["env"])
        with (
            mock.patch.object(
                subprocess,
                "run",
                return_value=mock.Mock(returncode=0, stdout="latest\n", stderr=""),
            ),
            self.assertRaisesRegex(installer.AndroidJvmInstallError, "probe mismatch"),
        ):
            installer.verify_versions(prefix)

    def test_install_is_atomic_and_rejects_existing_prefix(self) -> None:
        prefix = self.root / "installed"

        def fake_download(artifact: installer.Artifact, destination: Path) -> None:
            destination.write_bytes(artifact.name.encode())

        def fake_tar(_archive: Path, destination: Path, top: str) -> None:
            self.assertEqual("jdk-17.0.20.1+1", top)
            binary = destination / "bin/java"
            binary.parent.mkdir()
            binary.write_text("java")
            binary.chmod(0o755)

        def fake_zip(_archive: Path, destination: Path, top: str) -> None:
            self.assertEqual("gradle-9.1.0", top)
            binary = destination / "bin/gradle"
            binary.parent.mkdir()
            binary.write_text("gradle")
            binary.chmod(0o755)

        def verify(staging: Path) -> None:
            self.assertFalse(prefix.exists())
            self.assertTrue((staging / "runtime-gradle").is_dir())
            self.assertTrue((staging / "android-sdk").is_dir())
            self.assertTrue((staging / "manifest.json").is_file())

        with (
            mock.patch.object(installer, "download", side_effect=fake_download),
            mock.patch.object(installer, "_extract_tar", side_effect=fake_tar),
            mock.patch.object(installer, "_extract_zip", side_effect=fake_zip),
            mock.patch.object(installer, "verify_versions", side_effect=verify),
        ):
            installer.install(prefix)
        self.assertTrue((prefix / "bin/awq-android-jvm-check").is_file())
        with self.assertRaisesRegex(installer.AndroidJvmInstallError, "must be new"):
            installer.install(prefix)


if __name__ == "__main__":
    unittest.main()
