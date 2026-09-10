# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Hostile onboarding metadata, package diagnostics and migration review boundaries."""

from __future__ import annotations

import copy
import importlib.metadata
import io
import json
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from awq import onboarding as subject
from awq.cli import main
from awq.project import ProjectError
from awq.registry import canonical_bytes
from scripts import generate_onboarding
from scripts.validate_contracts import validate

ROOT = Path(__file__).resolve().parents[1]
HEALTHY = {
    "version_matches": True,
    "zero_runtime_dependencies": True,
    "assets_complete": True,
    "assets_sha256": "a" * 64,
}


def migration() -> dict[str, Any]:
    return dict(json.loads((ROOT / "templates/migration-preview.json").read_bytes()))


class OnboardingTests(unittest.TestCase):
    def test_packaged_metadata_schema_and_exact_closed_profile(self) -> None:
        for value, kind in (
            (subject.compatibility(), "awq-compatibility"),
            (subject.recipes(), "awq-agent-recipes"),
        ):
            validate(value, "onboarding.schema.json")
            self.assertEqual(value, subject.validate_metadata(value, kind))
            for altered in (
                {**value, "private": "PRIVATE"},
                {**value, "schema_version": True},
                {**value, "awq_version": "99.0.0"},
            ):
                with self.assertRaises(ProjectError):
                    subject.validate_metadata(altered, kind)
        with self.assertRaises(ProjectError):
            subject.validate_metadata({}, "unknown")
        self.assertEqual((subject.compatibility(), subject.recipes()), subject.load_metadata())
        self.assertTrue(subject.package_diagnostic()["assets_complete"])

    def test_actual_environment_is_normalized_without_host_details(self) -> None:
        for system, machine, expected in (
            ("linux", "x86_64", ("linux", "x86_64")),
            ("darwin", "arm64", ("macos", "arm64")),
            ("win32", "AMD64", ("windows", "x86_64")),
            ("private-host", "private-machine", ("unsupported", "unsupported")),
        ):
            with (
                mock.patch.object(sys, "platform", system),
                mock.patch.object(platform, "machine", return_value=machine),
            ):
                observed = subject.environment()
            self.assertEqual(expected, (observed["platform"], observed["architecture"]))
            self.assertNotIn("private", json.dumps(observed))

    def test_unsupported_python_platform_native_tools_and_git_fail_closed(self) -> None:
        observed = {"platform": "linux", "architecture": "x86_64", "python_minor": "3.12"}
        with (
            mock.patch.object(subject, "environment", return_value=observed),
            mock.patch.object(subject, "package_diagnostic", return_value=HEALTHY),
            mock.patch.object(shutil, "which", return_value="/reviewed/bin/tool"),
        ):
            for capability in ("core", "verified-update", "reliability-collect"):
                self.assertEqual("pass", subject.diagnose(capability)["status"])
            self.assertEqual(
                ["native-tools-not-probed"], subject.diagnose("pinned-adapters")["findings"]
            )
            for field, replacement, finding in (
                ("platform", "unsupported", "unsupported-platform"),
                ("architecture", "unsupported", "unsupported-platform"),
                ("python_minor", "3.14", "unreviewed-python"),
            ):
                with mock.patch.object(
                    subject, "environment", return_value={**observed, field: replacement}
                ):
                    self.assertIn(finding, subject.diagnose()["findings"])
            with mock.patch.object(
                subject, "environment", return_value={**observed, "platform": "macos"}
            ):
                self.assertIn(
                    "native-environment-unreviewed", subject.diagnose("verified-update")["findings"]
                )
            with mock.patch.object(shutil, "which", return_value=None):
                self.assertEqual(
                    ["git-unavailable", "ssh-verifier-unavailable"],
                    subject.diagnose("verified-update")["findings"],
                )
            with mock.patch.object(
                subject, "package_diagnostic", return_value={**HEALTHY, "version_matches": False}
            ):
                self.assertIn("package-integrity-or-metadata", subject.diagnose()["findings"])
        with self.assertRaises(ProjectError):
            subject.diagnose("PRIVATE")

    def test_package_missing_mismatched_dependency_and_resource_failures(self) -> None:
        with mock.patch.object(
            importlib.metadata, "distribution", side_effect=importlib.metadata.PackageNotFoundError
        ):
            self.assertFalse(subject.package_diagnostic()["assets_complete"])
        distribution = mock.Mock(version="99.0.0", requires=["private-package"])
        with mock.patch.object(importlib.metadata, "distribution", return_value=distribution):
            result = subject.package_diagnostic()
        self.assertFalse(result["version_matches"])
        self.assertFalse(result["zero_runtime_dependencies"])
        self.assertNotIn("private", json.dumps(result))
        resource = mock.Mock()
        resource.joinpath.return_value = resource
        resource.open.return_value.__enter__ = mock.Mock(return_value=io.BytesIO(b"x" * 65537))
        resource.open.return_value.__exit__ = mock.Mock(return_value=False)
        with (
            mock.patch.object(subject, "files", return_value=resource),
            self.assertRaises(ProjectError),
        ):
            subject._data("compatibility.json")
        resource.is_file.return_value = True
        resource.open.return_value.__enter__.return_value = io.BytesIO(b"x" * 1000001)
        with (
            mock.patch.object(subject, "files", return_value=resource),
            self.assertRaises(ProjectError),
        ):
            subject._schema_bytes("onboarding.schema.json")
        resource.open.return_value.__enter__.return_value = io.BytesIO(b"{}\n")
        with mock.patch.object(subject, "files", return_value=resource):
            self.assertEqual(b"{}\n", subject._schema_bytes("onboarding.schema.json"))
        with mock.patch.object(subject, "_schema_bytes", side_effect=OSError("PRIVATE")):
            self.assertFalse(subject.package_diagnostic()["assets_complete"])

    def test_upgrade_same_downgrade_legacy_and_changed_policy_are_explicit(self) -> None:
        for folder, name, status in (
            ("conforming", "upgrade", "pass"),
            ("conforming", "same", "pass"),
            ("nonconforming", "downgrade", "fail"),
            ("nonconforming", "legacy-policy", "fail"),
            ("nonconforming", "policy-change", "fail"),
            ("nonconforming", "future", "fail"),
        ):
            value = json.loads(
                (ROOT / "fixtures" / folder / "onboarding" / (name + ".json")).read_bytes()
            )
            validate(value, "onboarding.schema.json")
            before = canonical_bytes(value)
            result = subject.migration(value)
            self.assertEqual(status, result["status"])
            self.assertTrue(result["review_required"])
            self.assertEqual("not-granted", result["authorization"])
            self.assertFalse(result["source_authenticated"])
            self.assertEqual("none", result["mutation"])
            self.assertEqual("retain", result["native_gate"])
            self.assertEqual(before, canonical_bytes(value))
            self.assertEqual(result, subject.migration(copy.deepcopy(value)))
        for from_version, to_version in (
            ("0.14.0", "0.25.0"),
            ("0.25.0", "0.14.0"),
            ("0.25.0", "1.0.0"),
        ):
            self.assertIn(
                "unsupported-version-family",
                subject.migration(
                    {**migration(), "from_version": from_version, "to_version": to_version}
                )["findings"],
            )

    def test_malformed_migrations_and_confined_inputs_never_mutate(self) -> None:
        changes: list[tuple[str, Any]] = [
            ("private", "PRIVATE"),
            ("schema_version", True),
            ("schema_version", 2),
            ("from_version", "main"),
            ("to_version", "00.25.0"),
            ("to_version", "0.25.0rc1"),
            ("policy_schema", True),
            ("lock_schema", 0),
            ("current_policy_sha256", "../PRIVATE"),
            ("source_commit", "main"),
            ("tag_object", "v0.25.0"),
        ]
        for field, value in changes:
            with self.subTest(field=field), self.assertRaises(ProjectError):
                subject.migration({**migration(), field: value})
        with self.assertRaises(ProjectError):
            subject.migration([])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "migration.json"
            raw = canonical_bytes(migration())
            path.write_bytes(raw)
            self.assertEqual("pass", subject.migration_file(root, "migration.json")["status"])
            for relative in ("../migration.json", str(path), "missing.json"):
                with self.assertRaises(ProjectError):
                    subject.migration_file(root, relative)
            for invalid in (b" " + raw, b'{"schema_version":1,"schema_version":1}\n', b"x" * 16385):
                path.write_bytes(invalid)
                with self.assertRaises(ProjectError):
                    subject.migration_file(root, "migration.json")
                self.assertEqual(invalid, path.read_bytes())
            path.write_bytes(raw)
            with (
                mock.patch.object(subject, "migration", side_effect=RuntimeError("PRIVATE")),
                self.assertRaisesRegex(ProjectError, "^migration input is invalid or unavailable$"),
            ):
                subject.migration_file(root, "migration.json")
            for name, status in (("upgrade", 0), ("downgrade", 1)):
                relative = (
                    "fixtures/"
                    + ("conforming" if name == "upgrade" else "nonconforming")
                    + "/onboarding/"
                    + name
                    + ".json"
                )
                with mock.patch.object(sys, "stdout", new_callable=io.StringIO) as output:
                    self.assertEqual(
                        status,
                        main(
                            ["--root", str(ROOT), "migration-preview", relative, "--format", "json"]
                        ),
                    )
                self.assertNotIn(str(root), output.getvalue())

    def test_missing_wheel_schema_cannot_fall_back_to_unrelated_directory(self) -> None:
        resource = mock.Mock()
        resource.joinpath.return_value = resource
        resource.is_file.return_value = False
        with (
            mock.patch.object(subject, "files", return_value=resource),
            mock.patch.object(subject, "__file__", "/installed/awq/onboarding.py"),
            self.assertRaisesRegex(ProjectError, "installed schema"),
        ):
            subject._schema_bytes("onboarding.schema.json")

    def test_workflow_pin_guard_and_generated_metadata_drift(self) -> None:
        text = (ROOT / "templates/github-workflow.yml").read_text()
        marker = "run: python -c '"
        line = next(line.strip() for line in text.splitlines() if line.strip().startswith(marker))
        program = line.removeprefix(marker).removesuffix("'")
        for pin, status in (
            ("a" * 40, 0),
            ("a" * 39, 1),
            ("main", 1),
            ("v0.25.0", 1),
            ("PRIVATE; exit 0", 1),
        ):
            result = subprocess.run(
                [sys.executable, "-O", "-c", program],
                env={"AWQ_COMMIT": pin},
                capture_output=True,
                timeout=5,
            )
            self.assertEqual(status, result.returncode)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "schemas").mkdir()
            (root / "src/awq/data").mkdir(parents=True)
            (root / "schemas/onboarding.schema.json").write_bytes(
                (ROOT / "schemas/onboarding.schema.json").read_bytes()
            )
            with mock.patch.object(generate_onboarding, "ROOT", root):
                self.assertEqual(0, generate_onboarding.main([]))
                self.assertEqual(0, generate_onboarding.main(["--check"]))
                changed = root / "src/awq/data/compatibility.json"
                changed.write_bytes(b"{}\n")
                with mock.patch.object(sys, "stdout", new_callable=io.StringIO):
                    self.assertEqual(1, generate_onboarding.main(["--check"]))
                self.assertEqual(b"{}\n", changed.read_bytes())


if __name__ == "__main__":
    unittest.main()
