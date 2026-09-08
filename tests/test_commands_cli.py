# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Command and CLI end-to-end tests."""

from __future__ import annotations

import contextlib
import io
import json
import unittest
from datetime import UTC, datetime, timedelta
from unittest import mock

from awq import __version__, commands
from awq.cli import main
from awq.project import ProjectError, load_project
from tests.support import Repository, base_exception


class CommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repository()
        self.repo.write("README.md", "# Fixture\n")
        self.repo.write("tool.py", "value = 1\n")
        self.repo.commit("base")

    def tearDown(self) -> None:
        self.repo.close()

    def initialize(self) -> None:
        commands.initialize(
            self.repo.root, ["core", "docs", "python", "privacy", "supply-chain"], False
        )
        self.repo.commit("policy")

    def test_inspect_init_plan_check_evidence_explain(self) -> None:
        inventory = commands.inspect(self.repo.root)
        self.assertEqual("ok", inventory["status"])
        self.assertIn("python", inventory["recommended_profiles"])
        dry = commands.initialize(self.repo.root, ["core"], True)
        self.assertTrue(dry["dry_run"])
        self.assertFalse((self.repo.root / "quality").exists())
        self.initialize()
        self.assertEqual("ok", commands.plan(self.repo.root, False, "HEAD~1")["status"])
        self.repo.write("change.txt", "changed\n")
        self.repo.commit("change")
        changed = commands.plan(self.repo.root, True, "HEAD~1")
        self.assertEqual(["change.txt"], changed["paths"])
        self.assertEqual("pass", commands.check(self.repo.root, "pr")["status"])
        envelope = commands.evidence(self.repo.root, "pr")
        self.assertEqual("pass", envelope["result"])
        explanation = commands.explain("AWQ-CORE-001")
        self.assertEqual("Portable text", explanation["requirement"]["title"])
        self.assertTrue(explanation["traceability"])
        standards = commands.standards()
        self.assertEqual("alignment-not-certification", standards["claim"])
        self.assertTrue(standards["sources"])
        self.assertTrue(standards["mappings"])
        with self.assertRaises(ProjectError):
            commands.explain("AWQ-NOPE-999")

    def test_doctor_update_and_expired_exception(self) -> None:
        self.initialize()
        self.assertEqual("pass", commands.doctor(self.repo.root)["status"])
        self.assertFalse(commands.update(self.repo.root, __version__, True)["changed"])
        with self.assertRaisesRegex(ProjectError, "install"):
            commands.update(self.repo.root, "9.9.9", False)
        policy, _ = load_project(self.repo.root)
        policy["exceptions"] = [
            base_exception(
                owner="@project-maintainers",
                created_at="2020-01-01T00:00:00+00:00",
                expires_at="2020-01-02T00:00:00+00:00",
            )
        ]
        self.repo.json("quality/awq.json", policy)
        self.assertEqual(
            "expired-exception", commands.doctor(self.repo.root)["findings"][0]["code"]
        )

    def test_policy_diff_detects_weakening_and_pin_review(self) -> None:
        self.initialize()
        base = self.repo.head()
        policy, lock = load_project(self.repo.root)
        policy["profiles"].remove("docs")
        policy["unknown_formats"] = "advisory"
        policy["exceptions"] = [
            base_exception(
                id="EX-0002",
                owner="@project-maintainers",
                created_at=datetime.now(UTC).isoformat(),
                expires_at=(datetime.now(UTC) + timedelta(days=1)).isoformat(),
            )
        ]
        lock["awq_version"] = "0.1.1"
        self.repo.json("quality/awq.json", policy)
        self.repo.json("quality/awq.lock.json", lock)
        head = self.repo.commit("weaken")
        result = commands.policy_diff(self.repo.root, base, head)
        self.assertEqual("fail", result["status"])
        self.assertEqual(
            {"weakening", "review"}, {item["classification"] for item in result["changes"]}
        )

    def test_cli_json_success_failure_and_error(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(
                0, main(["--root", str(self.repo.root), "inspect", "--format", "json"])
            )
        self.assertEqual("ok", json.loads(buffer.getvalue())["status"])
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(
                0,
                main(["--root", str(self.repo.root), "standards", "--format", "json"]),
            )
        self.assertEqual("alignment-not-certification", json.loads(buffer.getvalue())["claim"])
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(1, main(["--root", str(self.repo.root), "doctor", "--format", "json"]))
        self.assertEqual("error", json.loads(buffer.getvalue())["status"])
        self.initialize()
        with mock.patch(
            "awq.commands.check", return_value={"status": "fail", "requirements": [], "tier": "pr"}
        ):
            self.assertEqual(1, main(["--root", str(self.repo.root), "check", "--format", "text"]))
