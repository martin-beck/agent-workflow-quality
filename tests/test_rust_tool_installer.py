# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Hostile and success tests for the pinned Rust toolchain installer."""

from __future__ import annotations

import contextlib
import hashlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import install_rust_tools as installer


class Response(io.BytesIO):
    def __init__(self, content: bytes, url: str) -> None:
        super().__init__(content)
        self.url = url

    def geturl(self) -> str:
        return self.url


class RustToolInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def artifact(self, content: bytes = b"reviewed") -> installer.Artifact:
        return installer.Artifact(
            "rustup-init",
            "https://static.rust-lang.org/reviewed/rustup-init",
            hashlib.sha256(content).hexdigest(),
            len(content) + 1,
        )

    def test_download_is_bounded_by_source_redirect_digest_and_size(self) -> None:
        content = b"reviewed"
        artifact = self.artifact(content)
        destination = self.root / artifact.name
        with mock.patch.object(
            installer,
            "urlopen",
            return_value=Response(content, artifact.url),
        ):
            installer.download(artifact, destination)
        self.assertEqual(content, destination.read_bytes())
        installer.verify_digest(destination, artifact.sha256)
        with self.assertRaisesRegex(installer.RustToolInstallError, "SHA-256"):
            installer.verify_digest(destination, "0" * 64)

        bad_source = installer.Artifact(
            "bad",
            "http://static.rust-lang.org/tool",
            artifact.sha256,
            100,
        )
        with self.assertRaisesRegex(installer.RustToolInstallError, "unreviewed source"):
            installer.download(bad_source, self.root / "bad-source")
        for case, response, error in (
            (
                "redirect",
                Response(content, "https://example.invalid/tool"),
                "redirected",
            ),
            (
                "digest",
                Response(b"different", artifact.url),
                "SHA-256",
            ),
            (
                "size",
                Response(b"too-large", artifact.url),
                "size bound",
            ),
        ):
            target = self.root / case
            tested = artifact
            if case == "size":
                tested = installer.Artifact(
                    artifact.name,
                    artifact.url,
                    artifact.sha256,
                    2,
                )
            with (
                self.subTest(case=case),
                mock.patch.object(installer, "urlopen", return_value=response),
                self.assertRaisesRegex(installer.RustToolInstallError, error),
            ):
                installer.download(tested, target)
            self.assertFalse(target.with_suffix(target.suffix + ".part").exists())

    def test_install_command_is_absolute_minimal_and_bounded(self) -> None:
        rustup_init = self.root / "rustup-init"
        rustup_init.write_bytes(b"binary")
        staging = self.root / "staging"
        temporary = self.root / "tmp"
        staging.mkdir()
        temporary.mkdir()
        completed: subprocess.CompletedProcess[bytes] = subprocess.CompletedProcess([], 0)
        with mock.patch.object(subprocess, "run", return_value=completed) as run:
            installer._install_toolchain(rustup_init, staging, temporary)
        argv = run.call_args.args[0]
        self.assertEqual(str(rustup_init), argv[0])
        self.assertTrue(Path(argv[0]).is_absolute())
        self.assertNotIn("executable", run.call_args.kwargs)
        self.assertEqual(900, run.call_args.kwargs["timeout"])
        self.assertEqual(subprocess.DEVNULL, run.call_args.kwargs["stdin"])
        environment = run.call_args.kwargs["env"]
        self.assertEqual(str(temporary), environment["TMPDIR"])
        self.assertEqual(str(staging / "rustup"), environment["RUSTUP_HOME"])
        self.assertNotIn("HOME", environment)
        self.assertEqual(
            [
                "-y",
                "--no-modify-path",
                "--profile",
                "minimal",
                "--default-toolchain",
                "1.93.0",
                "--component",
                "rustfmt",
                "--component",
                "clippy",
            ],
            argv[1:],
        )

        with (
            mock.patch.object(
                subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 1),
            ),
            self.assertRaisesRegex(installer.RustToolInstallError, "rustup-init failed"),
        ):
            installer._install_toolchain(rustup_init, staging, temporary)

    def test_manifest_consumption_record_fails_closed(self) -> None:
        staging = self.root / "staging"
        update_directory = staging / "rustup/update-hashes"
        update_directory.mkdir(parents=True)
        update_hash = update_directory / f"{installer.TOOLCHAIN}-{installer.HOST_TARGET}"
        expected = installer.TOOLCHAIN_MANIFEST.sha256[:20]
        update_hash.write_text(expected, encoding="ascii")
        installer._verify_manifest_use(staging)

        update_hash.write_text("0" * 20, encoding="ascii")
        with self.assertRaisesRegex(installer.RustToolInstallError, "unreviewed"):
            installer._verify_manifest_use(staging)
        update_hash.write_text("x" * 129, encoding="ascii")
        with self.assertRaisesRegex(installer.RustToolInstallError, "invalid"):
            installer._verify_manifest_use(staging)
        update_hash.unlink()
        with self.assertRaisesRegex(installer.RustToolInstallError, "did not record"):
            installer._verify_manifest_use(staging)
        target = update_directory / "target"
        target.write_text(expected, encoding="ascii")
        update_hash.symlink_to(target.name)
        with self.assertRaisesRegex(installer.RustToolInstallError, "did not record"):
            installer._verify_manifest_use(staging)

    def test_wrapper_and_version_probe_are_exact(self) -> None:
        prefix = self.root / "prefix"
        prefix.mkdir()
        installer._install_wrapper(prefix)
        helper = Path(installer.__file__).parents[1] / "src/awq/rust_helper.py"
        self.assertEqual(
            helper.read_bytes(),
            (prefix / "lib/awq_rust_helper.py").read_bytes(),
        )
        self.assertEqual(
            installer.WRAPPER,
            (prefix / "bin/awq-rust-check").read_bytes(),
        )
        success = mock.Mock(
            returncode=0,
            stdout=(
                "awq-rust-check 1.0.0 (Rust 1.93.0; Cargo 1.93.0; "
                "rustfmt 1.8.0-stable; Clippy 0.1.93)\n"
            ),
            stderr="",
        )
        with mock.patch.object(subprocess, "run", return_value=success) as run:
            installer.verify_versions(prefix)
        self.assertEqual(
            [str(prefix / "bin/awq-rust-check"), "--version"],
            run.call_args.args[0],
        )
        self.assertNotIn("HOME", run.call_args.kwargs["env"])

        failure = mock.Mock(returncode=0, stdout="private skew\n", stderr="")
        with (
            mock.patch.object(subprocess, "run", return_value=failure),
            self.assertRaisesRegex(installer.RustToolInstallError, "version probe mismatch"),
        ):
            installer.verify_versions(prefix)

    def test_install_is_atomic_and_rejects_existing_prefix(self) -> None:
        prefix = self.root / "installed"

        def fake_download(
            artifact: installer.Artifact,
            destination: Path,
        ) -> None:
            destination.write_bytes(artifact.name.encode())

        def fake_install(
            rustup_init: Path,
            staging: Path,
            temporary: Path,
        ) -> None:
            self.assertEqual("rustup-init", rustup_init.name)
            self.assertTrue(temporary.is_dir())
            update_directory = staging / "rustup/update-hashes"
            update_directory.mkdir(parents=True)
            (update_directory / f"{installer.TOOLCHAIN}-{installer.HOST_TARGET}").write_text(
                installer.TOOLCHAIN_MANIFEST.sha256[:20],
                encoding="ascii",
            )

        verified: list[tuple[Path, int, int]] = []

        def verify_before_publish(staging: Path) -> None:
            self.assertFalse(prefix.exists())
            self.assertFalse(prefix.is_symlink())
            self.assertEqual("installed", staging.name)
            self.assertEqual(prefix.parent, staging.parent.parent)
            self.assertTrue((staging / "bin/awq-rust-check").is_file())
            self.assertTrue((staging / "runtime-cargo").is_dir())
            self.assertFalse((staging / "runtime-cargo/bin").exists())
            metadata = staging.stat()
            verified.append((staging, metadata.st_dev, metadata.st_ino))

        with (
            mock.patch.object(installer, "download", side_effect=fake_download),
            mock.patch.object(installer, "_install_toolchain", side_effect=fake_install),
            mock.patch.object(
                installer,
                "verify_versions",
                side_effect=verify_before_publish,
            ) as versions,
        ):
            installer.install(prefix)
        self.assertTrue((prefix / "bin/awq-rust-check").is_file())
        versions.assert_called_once()
        self.assertEqual(1, len(verified))
        staging, device, inode = verified[0]
        self.assertEqual((device, inode), (prefix.stat().st_dev, prefix.stat().st_ino))
        self.assertFalse(staging.exists())
        self.assertFalse(staging.parent.exists())

        unpublished = self.root / "unpublished"

        def fail_before_publish(staging: Path) -> None:
            self.assertTrue((staging / "bin/awq-rust-check").is_file())
            self.assertFalse(unpublished.exists())
            raise installer.RustToolInstallError("version failure")

        with (
            mock.patch.object(installer, "download", side_effect=fake_download),
            mock.patch.object(installer, "_install_toolchain", side_effect=fake_install),
            mock.patch.object(
                installer,
                "verify_versions",
                side_effect=fail_before_publish,
            ),
            self.assertRaisesRegex(installer.RustToolInstallError, "version failure"),
        ):
            installer.install(unpublished)
        self.assertFalse(unpublished.exists())
        self.assertEqual([], list(self.root.glob("awq-rust-tools-*")))

        with self.assertRaisesRegex(installer.RustToolInstallError, "new path"):
            installer.install(prefix)
        failed = self.root / "failed"
        with (
            mock.patch.object(
                installer,
                "download",
                side_effect=installer.RustToolInstallError("private failure"),
            ),
            self.assertRaisesRegex(installer.RustToolInstallError, "private failure"),
        ):
            installer.install(failed)
        self.assertFalse(failed.exists())

        dangling = self.root / "dangling"
        dangling.symlink_to("missing")
        with (
            mock.patch.object(
                installer,
                "download",
                side_effect=AssertionError("unexpected acquisition"),
            ) as download,
            self.assertRaisesRegex(installer.RustToolInstallError, "new path"),
        ):
            installer.install(dangling)
        download.assert_not_called()
        self.assertTrue(dangling.is_symlink())
        self.assertFalse(dangling.exists())

        output = io.StringIO()
        with (
            mock.patch.object(
                installer,
                "download",
                side_effect=AssertionError("unexpected acquisition"),
            ) as cli_download,
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(
                1,
                installer.main(["--prefix", str(dangling)]),
            )
        cli_download.assert_not_called()
        self.assertIn("new path", output.getvalue())

    def test_main_reports_bounded_success_and_failure(self) -> None:
        output = io.StringIO()
        with (
            mock.patch.object(installer, "install"),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(
                0,
                installer.main(["--prefix", str(self.root / "success")]),
            )
        self.assertEqual(
            "Installed checksum-pinned AWQ Rust stable toolchain.\n",
            output.getvalue(),
        )
        output = io.StringIO()
        with (
            mock.patch.object(
                installer,
                "install",
                side_effect=installer.RustToolInstallError("bounded"),
            ),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(
                1,
                installer.main(["--prefix", str(self.root / "failure")]),
            )
        self.assertEqual("Rust tool installation failed: bounded\n", output.getvalue())


if __name__ == "__main__":
    unittest.main()
