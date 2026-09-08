# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Unit tests for the pinned Rust stable-toolchain helper."""

from __future__ import annotations

import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from awq import rust_helper as helper


class RustHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.prefix = self.root / "prefix"
        self.tool_bin = (
            self.prefix / "rustup/toolchains" / f"{helper.TOOLCHAIN}-{helper.HOST_TARGET}" / "bin"
        )
        self.tool_bin.mkdir(parents=True)
        (self.prefix / "runtime-cargo").mkdir()
        for name in helper.TOOL_NAMES:
            path = self.tool_bin / name
            path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            path.chmod(0o755)
        self.project = self.root / "project"
        self.project.mkdir()
        self.write_project()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_project(self) -> None:
        (self.project / ".cargo").mkdir(exist_ok=True)
        (self.project / "rust-toolchain.toml").write_text(
            '[toolchain]\nchannel = "1.93.0"\nprofile = "minimal"\n'
            'components = ["clippy", "rustfmt"]\n',
            encoding="utf-8",
        )
        (self.project / "Cargo.toml").write_text(
            '[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2024"\n',
            encoding="utf-8",
        )
        (self.project / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        (self.project / ".cargo/config.toml").write_text(
            "[net]\noffline = true\n", encoding="utf-8"
        )

    def test_direct_tools_and_minimal_environment_reject_unsafe_paths(self) -> None:
        with mock.patch.object(helper, "_prefix", return_value=self.prefix):
            self.assertEqual(self.tool_bin / "cargo", helper._tool("cargo"))
            environment = helper._base_environment()
            self.assertEqual(
                {
                    "PATH",
                    "LANG",
                    "LC_ALL",
                    "NO_COLOR",
                    "CARGO",
                    "CARGO_HOME",
                    "CARGO_NET_OFFLINE",
                    "CARGO_TERM_COLOR",
                    "RUSTC",
                    "RUSTDOC",
                },
                set(environment),
            )
            self.assertNotIn("rustup", Path(environment["RUSTC"]).name)
            self.assertEqual(str(self.tool_bin / "cargo"), environment["CARGO"])
            self.assertEqual(
                str(self.prefix / "runtime-cargo"),
                environment["CARGO_HOME"],
            )
            with self.assertRaises(helper.RustCheckError):
                helper._tool("rustup")

            runtime_bin = self.prefix / "runtime-cargo/bin"
            runtime_bin.mkdir()
            with self.assertRaisesRegex(helper.RustCheckError, "unsafe"):
                helper._base_environment()
            runtime_bin.rmdir()
            runtime_config = self.prefix / "runtime-cargo/config.toml"
            runtime_config.write_text("[net]\n", encoding="utf-8")
            with self.assertRaisesRegex(helper.RustCheckError, "unsafe"):
                helper._base_environment()
            runtime_config.unlink()

            cargo = self.tool_bin / "cargo"
            cargo.unlink()
            cargo.symlink_to("rustc")
            with self.assertRaises(helper.RustCheckError):
                helper._tool("cargo")
            cargo.unlink()
            cargo.write_text("#!/bin/sh\n", encoding="utf-8")
            cargo.chmod(0o644)
            with self.assertRaises(helper.RustCheckError):
                helper._tool("cargo")

        other = self.tool_bin.parent / "real-bin"
        self.tool_bin.rename(other)
        self.tool_bin.symlink_to(other.name, target_is_directory=True)
        with (
            mock.patch.object(helper, "_prefix", return_value=self.prefix),
            self.assertRaises(helper.RustCheckError),
        ):
            helper._tool_bin()

    def test_toolset_uses_exact_direct_commands_and_rejects_version_skew(self) -> None:
        with (
            mock.patch.object(helper, "_prefix", return_value=self.prefix),
            mock.patch.object(helper, "_run_probe") as probe,
        ):
            helper._verify_toolset()
        self.assertEqual(
            [
                mock.call("rustc", [str(self.tool_bin / "rustc"), "--version"]),
                mock.call("cargo", [str(self.tool_bin / "cargo"), "--version"]),
                mock.call(
                    "rustfmt",
                    [str(self.tool_bin / "rustfmt"), "--version"],
                ),
                mock.call(
                    "clippy",
                    [
                        str(self.tool_bin / "cargo-clippy"),
                        "clippy",
                        "--version",
                    ],
                ),
            ],
            probe.call_args_list,
        )
        self.assertNotIn("+1.93.0", repr(probe.call_args_list))

        completed = subprocess.CompletedProcess([], 0, "private skew\n", "")
        with (
            mock.patch.object(helper, "_prefix", return_value=self.prefix),
            mock.patch.object(subprocess, "run", return_value=completed) as run,
            self.assertRaisesRegex(helper.RustCheckError, "version mismatch"),
        ):
            helper._run_probe("cargo", [str(self.tool_bin / "cargo"), "--version"])
        self.assertNotIn("HOME", run.call_args.kwargs["env"])
        self.assertEqual(subprocess.DEVNULL, run.call_args.kwargs["stdin"])

    def test_project_requires_exact_regular_bounded_configuration(self) -> None:
        helper._verify_project(self.project)
        (self.project / "rust-toolchain.toml").write_text(
            '[toolchain]\nchannel = "stable"\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(helper.RustCheckError, "reviewed contract"):
            helper._verify_project(self.project)
        self.write_project()

        (self.project / "Cargo.lock").unlink()
        with self.assertRaisesRegex(helper.RustCheckError, "unavailable"):
            helper._verify_project(self.project)
        (self.project / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        with (
            mock.patch.object(helper, "MAX_CONFIG_BYTES", 2),
            self.assertRaisesRegex(helper.RustCheckError, "size bound"),
        ):
            helper._verify_project(self.project)

        cargo_directory = self.project / ".cargo"
        real_directory = self.project / ".cargo-real"
        cargo_directory.rename(real_directory)
        cargo_directory.symlink_to(real_directory.name, target_is_directory=True)
        with self.assertRaisesRegex(helper.RustCheckError, "unavailable"):
            helper._verify_project(self.project)

    def test_each_mode_has_exact_offline_arguments(self) -> None:
        with (
            mock.patch.object(helper, "_tool", side_effect=lambda name: Path("/tools") / name),
            mock.patch.object(helper, "_base_environment", return_value={"BASE": "1"}),
        ):
            observed = {mode: helper._arguments(mode) for mode in helper_modes()}
            with self.assertRaisesRegex(helper.RustCheckError, "unsupported"):
                helper._arguments("unknown")
        self.assertEqual(
            ["/tools/cargo-fmt", "fmt", "--all", "--", "--check"],
            observed["fmt"][0],
        )
        self.assertEqual(
            [
                "/tools/cargo-clippy",
                "clippy",
                "--locked",
                "--offline",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
            observed["clippy"][0],
        )
        self.assertEqual(
            ["/tools/cargo", "test", "--locked", "--offline", "--workspace"],
            observed["test"][0],
        )
        self.assertEqual(
            [
                "/tools/cargo",
                "doc",
                "--locked",
                "--offline",
                "--workspace",
                "--no-deps",
            ],
            observed["doc"][0],
        )
        self.assertEqual("-D warnings", observed["doc"][1]["RUSTDOCFLAGS"])
        self.assertEqual(
            [
                "/tools/cargo",
                "build",
                "--locked",
                "--offline",
                "--workspace",
                "--release",
            ],
            observed["build"][0],
        )
        for argv, _ in observed.values():
            self.assertNotIn("rustup", " ".join(argv))
            self.assertFalse(any(argument.startswith("+") for argument in argv))

    def test_invocation_uses_confined_scratch_and_normalizes_nonzero(self) -> None:
        def completed(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            environment = kwargs["env"]
            self.assertIsInstance(environment, dict)
            assert isinstance(environment, dict)
            target = Path(environment["CARGO_TARGET_DIR"])
            temporary = Path(environment["TMPDIR"])
            self.assertTrue(target.is_dir())
            self.assertTrue(temporary.is_dir())
            self.assertEqual(self.root, target.parents[1])
            self.assertEqual(self.root, temporary.parents[1])
            self.assertEqual(self.project, kwargs["cwd"])
            return subprocess.CompletedProcess(argv, 0)

        with (
            mock.patch.dict("os.environ", {"TMPDIR": str(self.root)}, clear=True),
            mock.patch.object(helper, "_arguments", return_value=(["/tool"], {})),
            mock.patch.object(subprocess, "run", side_effect=completed),
        ):
            helper._invoke(self.project, "fmt")

        with (
            mock.patch.dict("os.environ", {"TMPDIR": str(self.root)}, clear=True),
            mock.patch.object(helper, "_arguments", return_value=(["/tool"], {})),
            mock.patch.object(
                subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 2),
            ),
            self.assertRaisesRegex(helper.RustCheckError, "rejected"),
        ):
            helper._invoke(self.project, "fmt")

    def test_temporary_parent_and_main_fail_closed_without_content(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertIsNone(helper._temporary_parent())
        for value in ("relative", str(self.root / "missing")):
            with (
                self.subTest(value=value),
                mock.patch.dict("os.environ", {"TMPDIR": value}, clear=True),
                self.assertRaises(helper.RustCheckError),
            ):
                helper._temporary_parent()
        linked = self.root / "linked"
        linked.symlink_to(self.root, target_is_directory=True)
        with (
            mock.patch.dict("os.environ", {"TMPDIR": str(linked)}, clear=True),
            self.assertRaises(helper.RustCheckError),
        ):
            helper._temporary_parent()

        with mock.patch.object(helper, "_verify_toolset"):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(0, helper.main(["--version"]))
            self.assertEqual(helper.VERSION_OUTPUT + "\n", output.getvalue())

        errors = io.StringIO()
        with (
            contextlib.chdir(self.project),
            mock.patch.object(helper, "_verify_toolset"),
            mock.patch.object(helper, "_verify_project"),
            mock.patch.object(
                helper,
                "_invoke",
                side_effect=subprocess.TimeoutExpired(["private-secret"], 1),
            ),
            contextlib.redirect_stderr(errors),
        ):
            self.assertEqual(1, helper.main(["fmt"]))
        self.assertEqual("awq-rust-check: validation failed\n", errors.getvalue())
        self.assertNotIn("private-secret", errors.getvalue())
        with mock.patch.object(helper, "_verify_toolset"):
            self.assertEqual(1, helper.main([]))
            self.assertEqual(1, helper.main(["fmt", "extra"]))


def helper_modes() -> tuple[str, ...]:
    return ("fmt", "clippy", "test", "doc", "build")


if __name__ == "__main__":
    unittest.main()
