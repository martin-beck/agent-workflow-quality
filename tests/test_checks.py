# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Shared check success and failure tests."""

from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from awq import checks
from awq.project import make_policy, write_initialization
from awq.registry import load_registry
from tests.support import Repository, base_exception, base_policy


class CheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repository()
        self.policy = base_policy()

    def tearDown(self) -> None:
        self.repo.close()

    def run_one(self, function: object, *paths: Path) -> list[checks.Finding]:
        result: list[checks.Finding] = function(  # type: ignore[operator]
            self.repo.root, list(paths), self.policy
        )
        return result

    def test_portable_text(self) -> None:
        good = self.repo.write("good.txt", "ok\n")
        bad = self.repo.write("bad.txt", b"bad\r\n")
        missing = self.repo.write("missing.txt", b"missing")
        self.assertEqual([], self.run_one(checks.portable_text, good))
        codes = [item.code for item in self.run_one(checks.portable_text, bad, missing)]
        self.assertEqual(["non-lf", "missing-final-newline"], codes)
        script = self.repo.write("tool", b"#!/bin/sh\r\n", executable=True)
        self.assertEqual("non-lf", self.run_one(checks.portable_text, script)[0].code)
        self.assertEqual([], self.run_one(checks.classified_formats, script))

    def test_path_integrity(self) -> None:
        first = self.repo.write("Name.txt", "one\n")
        second = self.repo.write("name.txt", "two\n")
        broken = self.repo.root / "broken.txt"
        broken.symlink_to("absent")
        codes = {item.code for item in self.run_one(checks.path_integrity, first, second, broken)}
        self.assertEqual({"case-collision", "broken-symlink"}, codes)
        outside = self.repo.root.parent / "outside-awq-fixture"
        outside.write_text("x", encoding="utf-8")
        escaping = self.repo.root / "escaping.txt"
        escaping.symlink_to(outside)
        self.assertEqual("escaping-symlink", self.run_one(checks.path_integrity, escaping)[0].code)
        outside.unlink()

    def test_merge_format_action_and_workflow(self) -> None:
        marker = self.repo.write("merge.txt", "<<<<<<< ours\n=======\n>>>>>>> theirs\n")
        tla = self.repo.write(
            "formal/Model.tla",
            "---- MODULE Model ----\n"
            "=============================================================================\n",
        )
        self.assertTrue(self.run_one(checks.merge_markers, marker))
        self.assertEqual([], self.run_one(checks.merge_markers, tla))
        unknown = self.repo.write("data.odd", "x\n")
        workflow = self.repo.write(
            ".github/workflows/test.yml",
            "name: Test\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - uses: actions/checkout@main\n"
            "      - run: python tools/missing.py\n",
        )
        self.assertTrue(self.run_one(checks.merge_markers, marker))
        self.assertEqual("unknown-format", self.run_one(checks.classified_formats, unknown)[0].code)
        self.assertEqual("mutable-action", self.run_one(checks.action_pins, workflow)[0].code)
        self.assertEqual(
            {"missing-permissions", "missing-timeout"},
            {item.code for item in self.run_one(checks.workflow_policy, workflow)},
        )
        self.assertEqual(
            "missing-workflow-path",
            self.run_one(checks.workflow_local_paths, workflow)[0].code,
        )

    def test_language_document_schema_and_privacy(self) -> None:
        python = self.repo.write("bad.py", "def broken(\n")
        shell = self.repo.write("run.sh", "echo bad\n", executable=True)
        markdown = self.repo.write("README.md", "[missing](absent.md)\n")
        document = self.repo.write("bad.json", "{\n")
        private = self.repo.write("leak.txt", "-----BEGIN " + "PRIVATE KEY-----\n")
        self.assertTrue(self.run_one(checks.python_syntax, python))
        self.assertTrue(self.run_one(checks.shell_entrypoints, shell))
        self.assertTrue(self.run_one(checks.local_links, markdown))
        self.assertTrue(self.run_one(checks.json_parse, document))
        for ambiguous in ('{"key": 1, "key": 2}\n', '{"value": NaN}\n'):
            with self.subTest(ambiguous=ambiguous):
                document.write_text(ambiguous, encoding="utf-8")
                self.assertEqual("invalid-json", self.run_one(checks.json_parse, document)[0].code)
        self.assertTrue(self.run_one(checks.privacy_patterns, private))

    def test_ecosystem_and_formal_checks(self) -> None:
        cargo = self.repo.write("Cargo.toml", "[workspace]\n")
        gradle = self.repo.write("settings.gradle.kts", 'rootProject.name = "x"\n')
        model = self.repo.write("formal/Model.tla", "---- MODULE Model ----\n====\n")
        formal_readme = self.repo.write("formal/README.md", "This is verified.\n")
        self.assertTrue(checks.rust_lock(self.repo.root, [cargo], self.policy))
        self.assertTrue(checks.gradle_integrity(self.repo.root, [gradle], self.policy))
        missing = checks.formal_claims(self.repo.root, [model, formal_readme], self.policy)
        self.assertEqual("formal-evidence-metadata", missing[0].code)
        metadata = self.repo.json(
            "formal/evidence.json",
            {
                "schema_version": 1,
                "evidence_class": "bounded-model",
                "scope": "handoffctl-model",
                "bounds": {"max_states": 1000},
                "assumptions": ["finite model scope"],
                "correspondence": "not-proven",
                "non_claims": ["does not prove implementation correctness"],
                "limitations": ["bounded execution only"],
            },
        )
        self.repo.write("Cargo.lock", "version = 4\n")
        self.repo.write("gradle/verification-metadata.xml", "<verification-metadata/>\n")
        self.assertEqual([], checks.rust_lock(self.repo.root, [], self.policy))
        self.assertEqual([], checks.gradle_integrity(self.repo.root, [], self.policy))
        self.assertEqual(
            [], checks.formal_claims(self.repo.root, [model, formal_readme, metadata], self.policy)
        )
        invalid_cases = [
            ({"schema_version": 1}, "invalid evidence fields"),
            (
                {**json.loads(metadata.read_text()), "schema_version": 2},
                "invalid evidence classification",
            ),
            ({**json.loads(metadata.read_text()), "scope": "Bad Scope"}, "invalid evidence scope"),
            (
                {**json.loads(metadata.read_text()), "bounds": {"max_states": 0}},
                "invalid evidence bounds",
            ),
            (
                {**json.loads(metadata.read_text()), "limitations": []},
                "invalid evidence limitations",
            ),
        ]
        for value, message in invalid_cases:
            with self.subTest(message=message):
                metadata.write_text(json.dumps(value), encoding="utf-8")
                finding = checks.formal_claims(
                    self.repo.root, [model, formal_readme, metadata], self.policy
                )[0]
                self.assertEqual("formal-evidence-metadata", finding.code)
                self.assertEqual(message, finding.message)
        metadata.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "evidence_class": "bounded-model",
                    "scope": "handoffctl-model",
                    "bounds": {"max_states": 1000},
                    "assumptions": ["finite model scope"],
                    "correspondence": "not-proven",
                    "non_claims": ["does not prove implementation correctness"],
                    "limitations": ["bounded execution only"],
                }
            ),
            encoding="utf-8",
        )

    def test_lock_exception_and_extensions(self) -> None:
        policy, lock = make_policy(["core", "supply-chain"])
        write_initialization(self.repo.root, policy, lock)
        self.assertEqual([], checks.lock_integrity(self.repo.root, [], policy))
        lock["registry_sha256"] = "0" * 64
        self.repo.json("quality/awq.lock.json", lock)
        self.assertEqual("stale-lock", checks.lock_integrity(self.repo.root, [], policy)[0].code)
        requirement = load_registry()[0]["AWQ-CORE-001"]
        bad = self.repo.write("bad.txt", "bad")
        expires = (datetime.now(UTC) + timedelta(days=1)).isoformat()
        exception = base_exception(
            scope=["bad.txt"],
            created_at=datetime.now(UTC).isoformat(),
            expires_at=expires,
        )
        result = checks.run_requirement(
            self.repo.root, {**self.policy, "exceptions": [exception]}, requirement, [bad]
        )
        self.assertEqual("pass", result["status"])
        self.assertEqual(["EX-0001"], result["exceptions"])
        extension = {
            "id": "LOCAL-PASS",
            "tier": "pr",
            "argv": ["/bin/true"],
            "timeout_seconds": 1,
            "evidence": "contract-test",
            "limitation": "Synthetic.",
            "remediation": "Repair.",
            "formats": [],
        }
        self.assertEqual("pass", checks.run_extension(self.repo.root, extension)["status"])
        self.assertEqual(
            "fail",
            checks.run_extension(self.repo.root, {**extension, "argv": ["/bin/false"]})["status"],
        )
        self.assertEqual(
            "fail",
            checks.run_extension(
                self.repo.root, {**extension, "argv": ["/bin/sleep", "2"], "timeout_seconds": 1}
            )["status"],
        )

    def test_fixture_exclusion_and_advisory_unknown_format(self) -> None:
        bad = self.repo.write("fixtures/broken/file.txt", "bad")
        policy = {**self.policy, "fixture_paths": ["fixtures/broken"]}
        self.assertEqual([], checks.portable_text(self.repo.root, [bad], policy))
        unknown = self.repo.write("file.odd", "x\n")
        requirement = load_registry()[0]["AWQ-CORE-004"]
        result = checks.run_requirement(
            self.repo.root, {**policy, "unknown_formats": "advisory"}, requirement, [unknown]
        )
        self.assertEqual("pass", result["status"])
        self.assertTrue(result["findings"])
