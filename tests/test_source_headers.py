# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Tests for exact first-party source-header verification."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


def load_checker() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts" / "check_source_headers.py"
    spec = importlib.util.spec_from_file_location("check_source_headers", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load source-header checker")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = load_checker()


class SourceHeaderTests(unittest.TestCase):
    def test_comment_prefix_applies_reviewed_formats_and_exclusions(self) -> None:
        self.assertEqual(checker.comment_prefix(Path("src/tool.py")), "# ")
        self.assertEqual(checker.comment_prefix(Path("scripts/check.sh")), "# ")
        self.assertEqual(checker.comment_prefix(Path("tools/awq")), "# ")
        self.assertIsNone(checker.comment_prefix(Path("nested/tools/awq")))
        self.assertIsNone(checker.comment_prefix(Path("tools/awq.exe")))
        self.assertIsNone(checker.comment_prefix(Path("fixtures/broken.py")))
        self.assertIsNone(checker.comment_prefix(Path("generated/tool.py")))
        self.assertIsNone(checker.comment_prefix(Path("vendor/tool.py")))
        self.assertIsNone(checker.comment_prefix(Path("schema.json")))

    def test_check_file_accepts_header_and_leading_shebang(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plain = Path("plain.py")
            shell = Path("tool.sh")
            (root / plain).write_text(
                f"# {checker.COPYRIGHT}\n# {checker.SPDX}\n\npass\n", encoding="utf-8"
            )
            (root / shell).write_text(
                f"#!/bin/sh\n# {checker.COPYRIGHT}\n# {checker.SPDX}\n\nexit 0\n",
                encoding="utf-8",
            )
            self.assertEqual(checker.check_file(root, plain), [])
            self.assertEqual(checker.check_file(root, shell), [])

    def test_check_file_reports_malformed_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = Path("tool.py")
            (root / path).write_text(
                f"# {checker.SPDX}\n# {checker.COPYRIGHT}\n# {checker.SPDX}\n",
                encoding="utf-8",
            )
            issues = checker.check_file(root, path)
            self.assertEqual(len(issues), 1)
            self.assertIn("expected exact Huawei/MIT header", issues[0])

    def test_check_file_accepts_standalone_spdx_test_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = Path("tool.py")
            (root / path).write_text(
                f'# {checker.COPYRIGHT}\n# {checker.SPDX}\n\ndata = """\n# {checker.SPDX}\n"""\n',
                encoding="utf-8",
            )
            self.assertEqual(checker.check_file(root, path), [])

    def test_check_file_rejects_duplicate_header_pair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = Path("tool.py")
            pair = f"# {checker.COPYRIGHT}\n# {checker.SPDX}\n"
            (root / path).write_text(pair + "\npass\n" + pair, encoding="utf-8")
            issues = checker.check_file(root, path)
            self.assertEqual(len(issues), 1)
            self.assertIn("exactly one canonical Huawei/MIT header pair", issues[0])

    def test_check_file_reports_non_utf8_and_unsupported_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = Path("tool.py")
            (root / binary).write_bytes(b"\xff")
            self.assertIn("not valid UTF-8", checker.check_file(root, binary)[0])
            with self.assertRaisesRegex(checker.HeaderCheckError, "unsupported source"):
                checker.check_file(root, Path("fixtures/tool.py"))

    def test_tracked_files_are_nul_safe_and_main_reports_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            source = root / "source with space.py"
            source.write_text(f"# {checker.COPYRIGHT}\n# {checker.SPDX}\n", encoding="utf-8")
            fixture = root / "fixtures" / "broken.py"
            fixture.parent.mkdir()
            fixture.write_text("not python\n", encoding="utf-8")
            subprocess.run(
                ["git", "add", "source with space.py", "fixtures/broken.py"],
                cwd=root,
                check=True,
            )
            self.assertEqual(checker.tracked_source_files(root), (Path("source with space.py"),))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(checker.main(["--root", str(root)]), 0)
            self.assertIn("1 tracked first-party source files", stdout.getvalue())

            bad = root / "bad.py"
            bad.write_text("pass\n", encoding="utf-8")
            subprocess.run(["git", "add", "bad.py"], cwd=root, check=True)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(checker.main(["--root", str(root)]), 1)
            self.assertIn("bad.py: expected exact Huawei/MIT header", stderr.getvalue())

    def test_exact_extensionless_launcher_is_selected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            launcher = root / "tools" / "awq"
            launcher.parent.mkdir()
            launcher.write_text(
                f"#!/bin/sh\n# {checker.COPYRIGHT}\n# {checker.SPDX}\n\nexit 0\n",
                encoding="utf-8",
            )
            lookalike = root / "nested" / "tools" / "awq"
            lookalike.parent.mkdir(parents=True)
            lookalike.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            self.assertEqual(checker.tracked_source_files(root), (Path("tools/awq"),))

    def test_main_reports_git_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(checker.main(["--root", directory]), 2)
            self.assertIn("git ls-files failed", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
