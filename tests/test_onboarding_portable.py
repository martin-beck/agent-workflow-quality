# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Narrow fresh-core smoke paths shared by Linux, macOS and Windows CI."""

from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from awq import commands, onboarding
from awq.cli import main, parser


class PortableOnboardingTests(unittest.TestCase):
    def test_fresh_checkout_inspect_preview_adopt_check_explain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            subprocess.run(
                ["git", "-c", "core.autocrlf=false", "init", "-q", str(root)], check=True
            )
            subprocess.run(["git", "-C", str(root), "config", "core.autocrlf", "false"], check=True)
            (root / "README.md").write_text(
                "Public onboarding fixture.\n", encoding="utf-8", newline="\n"
            )
            diagnosis = onboarding.diagnose()
            self.assertEqual("pass", diagnosis["status"], diagnosis["findings"])
            before = sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))
            preview = commands.initialize(root, ["core"], True)
            self.assertTrue(preview["dry_run"])
            self.assertEqual(
                before, sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))
            )
            commands.initialize(root, ["core"], False)
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            self.assertEqual("pass", commands.check(root, "pr")["status"])
            for command in (["inspect"], ["onboarding"], ["explain", "AWQ-CORE-001"]):
                with redirect_stdout(io.StringIO()) as output:
                    status = main(["--root", str(root), *command, "--format", "json"])
                self.assertEqual(0, status)
                self.assertIsInstance(json.loads(output.getvalue()), dict)
            self.assertEqual([], list(root.glob("**/*.pyc")))

    def test_checkout_attributes_preserve_canonical_and_binary_bytes(self) -> None:
        attributes = (Path(__file__).resolve().parents[1] / ".gitattributes").read_bytes()
        canonical = onboarding._data("compatibility.json")
        binary = b"PK\x00\r\nopaque\xff\r\n"
        for use_attributes in (False, True):
            with (
                self.subTest(attributes=use_attributes),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory).resolve()
                subprocess.run(["git", "init", "-q", str(root)], check=True)
                subprocess.run(
                    ["git", "-C", str(root), "config", "core.autocrlf", "true"], check=True
                )
                if use_attributes:
                    (root / ".gitattributes").write_bytes(attributes)
                (root / "metadata.json").write_bytes(canonical)
                (root / "schema.zip").write_bytes(binary)
                subprocess.run(
                    ["git", "-C", str(root), "add", "."], check=True, capture_output=True
                )
                (root / "metadata.json").unlink()
                (root / "schema.zip").unlink()
                subprocess.run(
                    ["git", "-C", str(root), "checkout-index", "--all", "--force"], check=True
                )
                expected = canonical if use_attributes else canonical.replace(b"\n", b"\r\n")
                self.assertEqual(expected, (root / "metadata.json").read_bytes())
                self.assertEqual(binary, (root / "schema.zip").read_bytes())

    def test_all_agent_argv_recipes_match_the_actual_parser(self) -> None:
        for recipe in onboarding.recipes()["recipes"]:
            self.assertEqual(["python", "-m", "awq"], recipe["argv"][:3])
            arguments = parser().parse_args(recipe["argv"][3:])
            self.assertTrue(arguments.command)
        for recipe in onboarding.recipes()["recipes"]:
            if recipe["id"] == "authenticated-dry-run":
                self.assertIn("--dry-run", recipe["argv"])
                self.assertIn("--tag-object", recipe["argv"])
                self.assertIn("{external-trust-policy}", recipe["argv"])


if __name__ == "__main__":
    unittest.main()
