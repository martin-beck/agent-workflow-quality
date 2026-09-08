# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Defensive and boundary-path coverage for the runtime policy engine."""

from __future__ import annotations

import unittest
from unittest import mock

from awq import __version__, checks, commands, project, registry
from awq.project import ProjectError
from awq.registry import RegistryError
from tests.support import Repository, base_policy


class FailurePathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repository()

    def tearDown(self) -> None:
        self.repo.close()

    def test_text_workflow_link_and_format_boundaries(self) -> None:
        binary = self.repo.write("binary.txt", b"\x00\xff")
        unreadable = self.repo.write("gone.txt", "gone\n")
        unreadable.unlink()
        self.assertIsNone(checks._read_text(binary))
        self.assertIsNone(checks._read_text(unreadable))
        self.assertFalse(checks._is_shebang_script(unreadable))
        self.assertEqual(
            "invalid-utf8", checks.portable_text(self.repo.root, [binary], base_policy())[0].code
        )
        image = self.repo.write("asset.png", b"\x89PNG")
        custom = self.repo.write("data.custom", "ok\n")
        policy = base_policy(extensions=[{"formats": [".custom"]}])
        self.assertEqual([], checks.classified_formats(self.repo.root, [image, custom], policy))
        workflow = self.repo.write(
            ".github/workflows/ok.yml",
            "permissions: {}\njobs:\n  t:\n    timeout-minutes: 1\n    steps:\n"
            "      - uses: ./local\n"
            "      - uses: actions/checkout@" + "a" * 40 + "\n",
        )
        self.assertEqual([], checks.action_pins(self.repo.root, [workflow], policy))
        self.assertEqual([], checks.workflow_policy(self.repo.root, [workflow], policy))
        doc = self.repo.write(
            "docs/page.md",
            "[anchor](#x) [mail](mailto:a@example.invalid) [web](https://example.invalid)\n",
        )
        self.assertEqual([], checks.local_links(self.repo.root, [doc], policy))

    def test_lock_extensions_exceptions_and_tiers(self) -> None:
        invalid = checks.lock_integrity(self.repo.root, [], base_policy())
        self.assertEqual("invalid-lock", invalid[0].code)
        extension = {
            "id": "missing",
            "tier": "local",
            "argv": ["/definitely/missing/awq-command"],
            "timeout_seconds": 1,
            "evidence": "mechanical",
            "limitation": "test",
            "remediation": "test",
            "formats": [],
        }
        self.assertEqual("fail", checks.run_extension(self.repo.root, extension)["status"])
        finding = checks.Finding("x", "file.txt", "x" * 600)
        self.assertEqual(500, len(finding.json()["message"]))
        malformed = base_policy(
            exceptions=[
                {
                    "id": "bad-date",
                    "requirement": "AWQ-CORE-001",
                    "scope": ["*"],
                    "expires_at": "never",
                }
            ]
        )
        self.assertEqual([], checks._exceptions(malformed, "AWQ-CORE-001", finding))
        selected = checks.run_checks(self.repo.root, base_policy(), ["AWQ-CORE-001"], "pr")
        self.assertEqual("AWQ-CORE-001", selected[0]["id"])

    def test_project_json_validation_and_fallback(self) -> None:
        with self.assertRaises(ProjectError):
            project.confined_root(self.repo.root / "missing")
        for unsafe in ("../escape", str(self.repo.root / "absolute")):
            with self.assertRaises(ProjectError):
                project.confined_path(self.repo.root, unsafe)
        bad = self.repo.write("bad.json", "{")
        with self.assertRaises(ProjectError):
            project.load_json(bad)
        self.repo.write("list.json", "[]\n")
        with self.assertRaises(ProjectError):
            project.load_json(self.repo.root / "list.json")
        with mock.patch("awq.project.shutil.which", return_value=None):
            self.assertIn(bad, project.tracked_files(self.repo.root))
        policy, lock = project.make_policy(["core"])
        project.write_initialization(self.repo.root, policy, lock)
        with self.assertRaisesRegex(ProjectError, "overwrite"):
            project.write_initialization(self.repo.root, policy, lock)
        invalid_policies = [
            {},
            {**policy, "unknown_formats": "ignore"},
            {**policy, "profiles": []},
            {**policy, "fixture_paths": "fixtures"},
            {**policy, "extensions": [{}]},
            {
                **policy,
                "extensions": [
                    {
                        "id": "x",
                        "tier": "local",
                        "argv": [],
                        "timeout_seconds": 1,
                        "evidence": "mechanical",
                        "limitation": "x",
                        "remediation": "x",
                        "formats": [],
                    }
                ],
            },
            {**policy, "exceptions": [{}]},
        ]
        for value in invalid_policies:
            with self.subTest(value=value), self.assertRaises((ProjectError, RegistryError)):
                project.validate_policy(value)
        for value in ({}, {**lock, "requirements": ["x", "x"]}):
            with self.assertRaises(ProjectError):
                project.validate_lock(value)

    def test_registry_rejects_malformed_documents(self) -> None:
        requirements, profiles, _ = registry.load_registry()
        requirement = next(iter(requirements.values()))
        profile = next(iter(profiles.values()))
        invalid_requirements: list[list[object]] = [
            [{}],
            [{**requirement, "tier": "unknown"}],
            [requirement, requirement],
        ]
        for items in invalid_requirements:
            with self.assertRaises(RegistryError):
                registry._validated_requirements(items)
        invalid_profiles: list[list[object]] = [
            [{}],
            [{**profile, "requirements": ["AWQ-NOPE-999"]}],
            [profile, profile],
        ]
        for items in invalid_profiles:
            with self.assertRaises(RegistryError):
                registry._validated_profiles(items, requirements)
        with mock.patch("awq.registry.files") as resources:
            resources.return_value.joinpath.return_value.read_text.return_value = "[]"
            with self.assertRaises(RegistryError):
                registry._read("bad.json")
        with (
            mock.patch(
                "awq.registry._read", side_effect=[{}, {"schema_version": 1, "profiles": []}]
            ),
            self.assertRaises(RegistryError),
        ):
            registry.load_registry()
        with (
            mock.patch(
                "awq.registry._read",
                side_effect=[
                    {"schema_version": 2, "requirements": []},
                    {"schema_version": 1, "profiles": []},
                ],
            ),
            self.assertRaises(RegistryError),
        ):
            registry.load_registry()

    def test_command_error_and_drift_paths(self) -> None:
        self.repo.write("Cargo.toml", "[package]\nname='x'\n")
        self.repo.write("settings.gradle.kts", "rootProject.name='x'\n")
        self.repo.write("formal/M.tla", "---- MODULE M ----\n====\n")
        self.repo.write("run.sh", "#!/bin/sh\n", executable=True)
        self.repo.write(".github/workflows/x.yml", "permissions: {}\n")
        self.repo.commit("formats")
        detected, _ = commands.detected_profiles(self.repo.root)
        self.assertTrue({"rust", "android-jvm", "formal-evidence", "shell"} <= set(detected))
        with (
            mock.patch("awq.commands.shutil.which", return_value=None),
            self.assertRaises(ProjectError),
        ):
            commands._git()
        with self.assertRaises(ProjectError):
            commands.plan(self.repo.root, True, "missing")
        with self.assertRaises(ProjectError):
            commands._git_json(self.repo.root, "HEAD", "missing.json")
        policy, lock = project.make_policy(["core"])
        project.write_initialization(self.repo.root, policy, lock)
        lock["awq_version"] = "9.9.9"
        lock["registry_sha256"] = "0" * 64
        lock["requirements"] = []
        self.repo.json("quality/awq.lock.json", lock)
        result = commands.doctor(self.repo.root)
        self.assertEqual("fail", result["status"])
        self.assertEqual(
            {"version-drift", "registry-drift", "lock-drift"},
            {item["code"] for item in result["findings"]},
        )
        updated = commands.update(self.repo.root, __version__, False)
        self.assertTrue(updated["changed"])


if __name__ == "__main__":
    unittest.main()
