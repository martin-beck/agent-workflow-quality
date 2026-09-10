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
            detail = {
                "findings": diagnosis["findings"],
                "package": diagnosis["package"],
                "metadata_crlf": {
                    name: b"\r\n" in onboarding._data(name)
                    for name in ("compatibility.json", "agent_recipes.json")
                },
            }
            self.assertEqual("pass", diagnosis["status"], detail)
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
