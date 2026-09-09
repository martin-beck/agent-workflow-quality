# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Hostile and success tests for the advanced Rust installer."""

from __future__ import annotations

import hashlib
import io
import json
import os
import signal
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import awq.rust_advanced_helper as helper
from scripts import install_rust_advanced_tools as installer


class Response(io.BytesIO):
    def __init__(self, content: bytes, url: str) -> None:
        super().__init__(content)
        self.url = url

    def geturl(self) -> str:
        return self.url


class RustAdvancedInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def archive(self, name: str, content: bytes, *, kind: bytes | None = None) -> Path:
        path = self.root / f"{name.replace('/', '-')}.tgz"
        member = tarfile.TarInfo(name)
        member.size = len(content)
        if kind is not None:
            member.type = kind
        with tarfile.open(path, "w:gz") as archive:
            archive.addfile(member, io.BytesIO(content) if member.isfile() else None)
        return path

    def test_download_is_source_redirect_size_and_digest_bounded(self) -> None:
        content = b"reviewed"
        artifact = installer.Artifact(
            "tool.tgz",
            "https://github.com/owner/project/tool.tgz",
            hashlib.sha256(content).hexdigest(),
            len(content),
        )
        destination = self.root / "tool.tgz"
        with mock.patch.object(
            installer,
            "urlopen",
            return_value=Response(content, "https://release-assets.githubusercontent.com/reviewed"),
        ):
            installer.download(artifact, destination)
        self.assertEqual(content, destination.read_bytes())
        cases = [
            (
                installer.Artifact("bad", "http://github.com/owner/tool", artifact.sha256, 100),
                Response(content, artifact.url),
                "unreviewed source",
            ),
            (artifact, Response(content, "https://example.invalid/tool"), "redirected"),
            (
                artifact,
                Response(b"changed!", "https://release-assets.githubusercontent.com/tool"),
                "SHA-256",
            ),
            (
                installer.Artifact(artifact.name, artifact.url, artifact.sha256, len(content) - 1),
                Response(content, "https://release-assets.githubusercontent.com/tool"),
                "size bound",
            ),
        ]
        for number, (tested, response, message) in enumerate(cases):
            target = self.root / f"bad-{number}"
            with (
                self.subTest(case=number),
                mock.patch.object(installer, "urlopen", return_value=response),
                self.assertRaisesRegex(installer.RustAdvancedInstallError, message),
            ):
                installer.download(tested, target)
            self.assertFalse(target.with_suffix(target.suffix + ".part").exists())

    def test_binary_archive_requires_one_exact_regular_digest_bound_member(self) -> None:
        content = b"executable"
        artifact = installer.Artifact(
            "tool.tgz",
            "https://github.com/owner/tool",
            "0" * 64,
            100,
            "cargo-fuzz",
        )
        staging = self.root / "staging"
        (staging / "bin").mkdir(parents=True)
        with mock.patch.dict(
            helper.TOOL_METADATA,
            {"cargo-fuzz": {"binary_sha256": hashlib.sha256(content).hexdigest()}},
        ):
            installer._extract_binary(artifact, self.archive("cargo-fuzz", content), staging)
        self.assertEqual(content, (staging / "bin/cargo-fuzz").read_bytes())
        unsafe = [
            self.archive("../cargo-fuzz", content),
            self.archive("cargo-fuzz", b"", kind=tarfile.SYMTYPE),
            self.archive("other", content),
        ]
        for path in unsafe:
            with self.subTest(path=path), self.assertRaises(installer.RustAdvancedInstallError):
                installer._extract_binary(artifact, path, staging)

    def test_bounded_process_kills_its_session_on_timeout(self) -> None:
        process = mock.Mock(pid=73, returncode=0)
        process.communicate.return_value = ("out", "err")
        with mock.patch.object(subprocess, "Popen", return_value=process):
            completed = installer._bounded_process(
                ["/tool"], {"PATH": "/usr/bin:/bin"}, 1, capture_output=True
            )
        self.assertEqual(("out", "err"), (completed.stdout, completed.stderr))
        process.communicate.side_effect = [
            subprocess.TimeoutExpired("/tool", 1),
            ("", ""),
        ]
        with (
            mock.patch.object(subprocess, "Popen", return_value=process),
            mock.patch.object(os, "killpg") as kill,
            self.assertRaisesRegex(installer.RustAdvancedInstallError, "deadline"),
        ):
            installer._bounded_process(["/tool"], {}, 1)
        kill.assert_called_once_with(73, signal.SIGKILL)

    def test_rustup_environment_and_component_manifest_are_exact(self) -> None:
        staging = self.root / "staging"
        temporary = self.root / "tmp"
        environment = installer._rustup_environment(staging, temporary)
        self.assertNotIn("HOME", environment)
        self.assertEqual("0", environment["RUSTUP_AUTO_INSTALL"])
        hashes = staging / "rustup/update-hashes"
        hashes.mkdir(parents=True)
        for key, channel in (
            ("stable", helper.STABLE_TOOLCHAIN),
            ("nightly", helper.NIGHTLY_TOOLCHAIN),
        ):
            (hashes / f"{channel}-{helper.HOST_TARGET}").write_text(
                str(helper.TOOLCHAIN_METADATA[key]["manifest_sha256"])[:20],
                encoding="ascii",
            )
        with mock.patch.object(installer, "_rustup") as rustup:
            installer._install_toolchains(staging, temporary)
        self.assertEqual(3, rustup.call_count)
        (hashes / f"{helper.NIGHTLY_TOOLCHAIN}-{helper.HOST_TARGET}").write_text(
            "drift", encoding="ascii"
        )
        with (
            mock.patch.object(installer, "_rustup"),
            self.assertRaisesRegex(installer.RustAdvancedInstallError, "manifest"),
        ):
            installer._install_toolchains(staging, temporary)

    def test_rustup_stable_and_version_failures_are_normalized(self) -> None:
        completed = subprocess.CompletedProcess([], 1, "", "")
        with mock.patch.object(installer, "_bounded_process", return_value=completed):
            with self.assertRaisesRegex(installer.RustAdvancedInstallError, "rustup"):
                installer._rustup(self.root, self.root, ["show"])
            with self.assertRaisesRegex(installer.RustAdvancedInstallError, "stable"):
                installer._install_stable(self.root)
            with self.assertRaisesRegex(installer.RustAdvancedInstallError, "version"):
                installer.verify_versions(self.root)
        good = subprocess.CompletedProcess([], 0, helper.VERSION_OUTPUT + "\n", "")
        with mock.patch.object(installer, "_bounded_process", return_value=good):
            installer.verify_versions(self.root)

    def test_wrapper_manifest_and_atomic_install(self) -> None:
        staging = self.root / "staging"
        (staging / "bin").mkdir(parents=True)
        installer._install_wrapper(staging)
        installer._write_manifest(staging)
        self.assertTrue((staging / "bin/awq-rust-advanced-check").stat().st_mode & 0o100)
        manifest = json.loads((staging / "manifest.json").read_text())
        self.assertEqual(1, manifest["schema_version"])

        prefix = self.root / "installed"

        def stable(target: Path) -> None:
            (target / "bin").mkdir(parents=True)
            (target / "cargo").mkdir()
            (target / "runtime-cargo").mkdir()

        def download(_artifact: installer.Artifact, destination: Path) -> None:
            destination.write_bytes(b"archive")

        def extract(artifact: installer.Artifact, _archive: Path, target: Path) -> None:
            path = target / "bin" / artifact.executable
            path.write_bytes(b"tool")
            path.chmod(0o755)

        observed: list[Path] = []
        with (
            mock.patch.object(installer, "_install_stable", side_effect=stable),
            mock.patch.object(installer, "download", side_effect=download),
            mock.patch.object(installer, "_extract_binary", side_effect=extract),
            mock.patch.object(installer, "_install_toolchains"),
            mock.patch.object(
                installer, "verify_versions", side_effect=lambda path: observed.append(path)
            ),
        ):
            installer.install(prefix)
        self.assertTrue((prefix / "manifest.json").is_file())
        self.assertEqual(1, len(observed))
        self.assertFalse(observed[0].exists())
        with self.assertRaisesRegex(installer.RustAdvancedInstallError, "new path"):
            installer.install(prefix)

    def test_main_reports_normalized_success_and_failure(self) -> None:
        with mock.patch.object(installer, "install"):
            self.assertEqual(0, installer.main(["--prefix", str(self.root / "ok")]))
        with mock.patch.object(
            installer,
            "install",
            side_effect=installer.RustAdvancedInstallError("reviewed failure"),
        ):
            self.assertEqual(1, installer.main(["--prefix", str(self.root / "bad")]))


if __name__ == "__main__":
    unittest.main()
