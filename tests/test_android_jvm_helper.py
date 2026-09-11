# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Contract, hostile-input, and execution tests for Android/JVM assurance."""

from __future__ import annotations

import datetime
import hashlib
import json
import pathlib
import resource
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from awq import android_jvm_helper as helper
from awq import test_reports


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class AndroidJvmHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.project = self.root / "project"
        self.prefix = self.root / "prefix"
        self.project.mkdir()
        self.prefix.mkdir()
        self._write_tools()
        self.config = self._write_project()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_tools(self) -> None:
        (self.prefix / "jdk/bin").mkdir(parents=True)
        (self.prefix / "gradle/bin").mkdir(parents=True)
        (self.prefix / "runtime-gradle").mkdir()
        (self.prefix / "android-sdk").mkdir()
        java = self.prefix / "jdk/bin/java"
        java.write_text(
            "#!/bin/sh\n"
            "echo '    java.version = 17.0.20.1' >&2\n"
            "echo '    java.vendor = Eclipse Adoptium' >&2\n",
            encoding="utf-8",
        )
        gradle = self.prefix / "gradle/bin/gradle"
        gradle.write_text(
            "#!/bin/sh\n"
            'case " $* " in *" --version "*) echo \'Gradle 9.1.0\'; '
            "echo 'Launcher JVM:  17.0.20.1 (Eclipse Adoptium)' ;; esac\n",
            encoding="utf-8",
        )
        java.chmod(0o755)
        gradle.chmod(0o755)
        manifest = {
            "gradle_archive_sha256": helper.GRADLE_ARCHIVE_SHA256,
            "gradle_version": helper.GRADLE_VERSION,
            "helper_sha256": hashlib.sha256(Path(helper.__file__).read_bytes()).hexdigest(),
            "host": helper.HOST,
            "java_archive_sha256": helper.JAVA_ARCHIVE_SHA256,
            "java_version": helper.JAVA_VERSION,
            "schema_version": 1,
            "test_reports_sha256": hashlib.sha256(
                Path(test_reports.__file__).read_bytes()
            ).hexdigest(),
        }
        (self.prefix / "manifest.json").write_bytes(canonical(manifest))

    def _write_project(self) -> dict[str, object]:
        files = {
            "gradle/libs.versions.toml": ('androidGradlePlugin = "9.0.1"\nkotlin = "2.3.20"\n'),
            "gradle/verification-metadata.xml": (
                '<verification-metadata xmlns="https://schema.gradle.org/dependency-verification">'
                "<configuration><verify-metadata>true</verify-metadata>"
                "<verify-signatures>false</verify-signatures></configuration>"
                '<components><component group="g" name="n" version="1"><artifact name="a">'
                f'<sha256 value="{"1" * 64}"/></artifact></component></components>'
                "</verification-metadata>"
            ),
            "gradle/wrapper/gradle-wrapper.jar": "jar",
            "gradle/wrapper/gradle-wrapper.properties": (
                "distributionBase=GRADLE_USER_HOME\n"
                "distributionPath=wrapper/dists\n"
                f"distributionSha256Sum={helper.GRADLE_ARCHIVE_SHA256}\n"
                "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.1.0-bin.zip\n"
                "networkTimeout=10000\n"
                "validateDistributionUrl=true\n"
                "zipStoreBase=GRADLE_USER_HOME\n"
                "zipStorePath=wrapper/dists\n"
            ),
            "settings.gradle.kts": (
                "dependencyResolutionManagement {\n"
                " repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)\n"
                " repositories { google(); mavenCentral() }\n"
                "}\npluginManagement { repositories {\n"
                " gradlePluginPortal(); google(); mavenCentral()\n} }\n"
            ),
            "app/gradle.lockfile": "locked=true\n",
            "app/src/main/kotlin/App.kt": "class App\n",
        }
        for relative, text in files.items():
            path = self.project / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(self.project)], check=True)
        subprocess.run(["git", "-C", str(self.project), "add", "."], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.project),
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-qm",
                "fixture",
            ],
            check=True,
        )
        integrity_files = [
            {
                "path": relative,
                "sha256": hashlib.sha256((self.project / relative).read_bytes()).hexdigest(),
            }
            for relative in (
                "gradle/libs.versions.toml",
                "gradle/verification-metadata.xml",
                "gradle/wrapper/gradle-wrapper.jar",
                "gradle/wrapper/gradle-wrapper.properties",
                "settings.gradle.kts",
            )
        ]
        config: dict[str, object] = {
            "device": {
                "abi": "x86_64",
                "api_level": 36,
                "form_factor": "phone",
                "image_sha256": "2" * 64,
                "locale": "en-US",
                "max_age_hours": 24,
                "minimum_executed": 2,
                "minimum_tests": 2,
                "observation_path": "build/awq/device-observation.json",
                "report_glob": "*/build/outputs/androidTest-results/**/*.xml",
                "required_modules": ["app"],
            },
            "integrity": {
                "allowed_repositories": ["google", "gradlePluginPortal", "mavenCentral"],
                "files": integrity_files,
                "locks": [
                    {
                        "path": "app/gradle.lockfile",
                        "sha256": hashlib.sha256(
                            (self.project / "app/gradle.lockfile").read_bytes()
                        ).hexdigest(),
                    }
                ],
            },
            "resources": {
                "cpu_seconds": 30,
                "file_size_mib": 10,
                "memory_mib": 1024,
                "open_files": 128,
                "outer_timeout_seconds": 30,
                "tracked_file_limit": 100,
                "tracked_mib": 10,
            },
            "schema_version": 1,
            "tasks": {
                mode: [f"awq{mode.title().replace('-', '')}"] for mode in sorted(helper.TASK_MODES)
            },
            "toolchain": {
                "agp_version": helper.AGP_VERSION,
                "gradle_distribution_sha256": helper.GRADLE_ARCHIVE_SHA256,
                "gradle_version": helper.GRADLE_VERSION,
                "host": helper.HOST,
                "java_version": helper.JAVA_VERSION,
                "kotlin_version": helper.KOTLIN_VERSION,
                "wrapper_jar_sha256": integrity_files[2]["sha256"],
            },
        }
        quality = self.project / "quality"
        quality.mkdir()
        (quality / "android-jvm.json").write_bytes(canonical(config))
        return config

    def test_configuration_project_and_installation_are_exact(self) -> None:
        config, digest = helper._configuration(self.project)
        self.assertEqual(self.config, config)
        self.assertEqual(64, len(digest))
        helper._verify_project(self.project, config)
        with mock.patch.object(helper, "_prefix", return_value=self.prefix):
            helper._verify_installation()
            self.assertEqual(self.prefix / "gradle/bin/gradle", helper._tool("gradle"))
            self.assertEqual(self.prefix / "runtime-gradle", helper._runtime_gradle())

    def test_all_non_device_modes_execute_offline_in_a_copy(self) -> None:
        config, digest = helper._configuration(self.project)
        with mock.patch.object(helper, "_prefix", return_value=self.prefix):
            for mode in sorted(helper.TASK_MODES):
                with self.subTest(mode=mode):
                    result = helper._execute(self.project, mode, config, digest)
                    self.assertEqual("gradle-task-plan", result[0]["kind"])
        self.assertFalse((self.project / ".gradle").exists())

    def test_integrity_and_device_plan_do_not_execute_gradle(self) -> None:
        config, digest = helper._configuration(self.project)
        with mock.patch.object(helper, "_run_gradle") as run:
            integrity = helper._execute(self.project, "integrity", config, digest)
            plan = helper._execute(self.project, "device-plan", config, digest)
        run.assert_not_called()
        self.assertEqual("gradle-project", integrity[0]["kind"])
        self.assertEqual("android-device-plan", plan[0]["kind"])

    def test_connected_evidence_binds_reports_revision_and_time(self) -> None:
        config, digest = helper._configuration(self.project)
        report = self.project / "app/build/outputs/androidTest-results/device/result.xml"
        report.parent.mkdir(parents=True)
        report.write_text(
            '<testsuite name="device" tests="3" failures="0" errors="0" skipped="1">'
            '<testcase name="one"/><testcase name="two"/>'
            '<testcase name="three"><skipped/></testcase></testsuite>',
            encoding="utf-8",
        )
        records = [
            {"path": report.relative_to(self.project).as_posix(), "sha256": helper._sha256(report)}
        ]
        report_digest = hashlib.sha256(canonical(records)).hexdigest()
        observation = {
            "abi": "x86_64",
            "accessibility_assertions": True,
            "api_level": 36,
            "form_factor": "phone",
            "image_sha256": "2" * 64,
            "locale": "en-US",
            "observed_at": datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z"),
            "report_sha256": report_digest,
            "schema_version": 1,
            "source_revision": subprocess.check_output(
                ["git", "-C", str(self.project), "rev-parse", "HEAD"], text=True
            ).strip(),
            "task_status": "success",
            "ui_assertions": True,
        }
        path = self.project / "build/awq/device-observation.json"
        path.parent.mkdir(parents=True)
        path.write_bytes(canonical(observation))
        result = helper._execute(self.project, "connected-tests", config, digest)
        self.assertEqual(
            ["android-device-plan", "connected-test-summary"], [x["kind"] for x in result]
        )
        observation["report_sha256"] = "0" * 64
        path.write_bytes(canonical(observation))
        with self.assertRaisesRegex(helper.AndroidJvmError, "reviewed plan"):
            helper._execute(self.project, "connected-tests", config, digest)
        observation["report_sha256"] = report_digest
        observation["observed_at"] = "2000-01-01T00:00:00Z"
        path.write_bytes(canonical(observation))
        with self.assertRaisesRegex(helper.AndroidJvmError, "stale"):
            helper._execute(self.project, "connected-tests", config, digest)

    def test_xml_and_repository_bypasses_fail_closed(self) -> None:
        metadata = self.project / "gradle/verification-metadata.xml"
        metadata.write_bytes('<?xml version="1.0"?><!DOCTYPE x><x/>'.encode("utf-16"))
        with self.assertRaisesRegex(helper.AndroidJvmError, "not UTF-8"):
            helper._verification_metadata(self.project)
        self._write_project_reset()
        settings = self.project / "settings.gradle.kts"
        settings.write_text(
            "// RepositoriesMode.FAIL_ON_PROJECT_REPOS google() mavenCentral() "
            "gradlePluginPortal()\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(helper.AndroidJvmError, "centrally denied"):
            helper._repositories(self.project, ["google", "gradlePluginPortal", "mavenCentral"])
        settings.write_text(
            "RepositoriesMode.FAIL_ON_PROJECT_REPOS\n"
            'google();mavenCentral();gradlePluginPortal();maven { url = uri("https://x") }\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(helper.AndroidJvmError, "custom"):
            helper._repositories(self.project, ["google", "gradlePluginPortal", "mavenCentral"])

    def _write_project_reset(self) -> None:
        subprocess.run(["git", "-C", str(self.project), "checkout", "-q", "--", "."], check=True)

    def test_runtime_global_policy_and_manifest_skew_fail(self) -> None:
        init = self.prefix / "runtime-gradle/init.d"
        init.mkdir()
        with (
            mock.patch.object(helper, "_prefix", return_value=self.prefix),
            self.assertRaisesRegex(helper.AndroidJvmError, "global policy"),
        ):
            helper._runtime_gradle()
        init.rmdir()
        manifest = json.loads((self.prefix / "manifest.json").read_text())
        manifest["gradle_version"] = "latest"
        (self.prefix / "manifest.json").write_bytes(canonical(manifest))
        with (
            mock.patch.object(helper, "_prefix", return_value=self.prefix),
            self.assertRaisesRegex(helper.AndroidJvmError, "manifest differs"),
        ):
            helper._verify_installation()

    def test_configuration_unknowns_duplicates_and_unsafe_paths_fail(self) -> None:
        policy = self.project / "quality/android-jvm.json"
        raw = policy.read_text()
        value = json.loads(raw)
        value["unknown"] = True
        policy.write_bytes(canonical(value))
        with self.assertRaisesRegex(helper.AndroidJvmError, "unknown or missing"):
            helper._configuration(self.project)
        policy.write_text(
            raw.replace('"schema_version":1', '"schema_version":1,"schema_version":1')
        )
        with self.assertRaisesRegex(helper.AndroidJvmError, "duplicate"):
            helper._configuration(self.project)
        value = json.loads(raw)
        value["device"]["observation_path"] = "../escape"
        policy.write_bytes(canonical(value))
        with self.assertRaisesRegex(helper.AndroidJvmError, "escapes"):
            helper._configuration(self.project)

    def test_tracked_changes_and_copied_lock_mutation_fail(self) -> None:
        config, digest = helper._configuration(self.project)
        source = self.project / "app/src/main/kotlin/App.kt"
        source.write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(helper.AndroidJvmError, "clean tracked"):
            helper._execute(self.project, "integrity", config, digest)
        self._write_project_reset()

        def mutate(project: Path, *_args: object) -> None:
            (project / "app/gradle.lockfile").write_text("changed\n", encoding="utf-8")

        with (
            mock.patch.object(helper, "_run_gradle", side_effect=mutate),
            self.assertRaisesRegex(helper.AndroidJvmError, "integrity digest"),
        ):
            helper._execute(self.project, "test", config, digest)

    def test_main_protocol_is_content_minimized(self) -> None:
        with (
            mock.patch.object(helper, "_verify_installation"),
            mock.patch.object(helper, "_configuration", return_value=(self.config, "3" * 64)),
            mock.patch.object(
                helper,
                "_execute",
                return_value=[{"id": "test", "kind": "gradle-task-plan", "sha256": "3" * 64}],
            ),
            mock.patch.object(pathlib.Path, "cwd", return_value=self.project),
            mock.patch("sys.stdout.buffer.write") as write,
        ):
            self.assertEqual(0, helper.main(["test"]))
        self.assertIn(b'"status":"pass"', write.call_args.args[0])
        with mock.patch.object(helper, "_verify_installation", side_effect=OSError("private")):
            self.assertEqual(1, helper.main(["test"]))

    def test_validation_primitives_fail_closed(self) -> None:
        missing = self.root / "missing.json"
        for action, message in (
            (lambda: helper._load_json(missing), "unavailable"),
            (lambda: helper._relative(""), "repository-relative"),
            (lambda: helper._relative("../x"), "escapes"),
            (lambda: helper._integer(True, 1, 2, "integer"), "outside"),
            (lambda: helper._strings("x"), "string list"),
            (lambda: helper._strings(["b", "a"]), "not sorted"),
            (lambda: helper._digest("x", "digest"), "SHA-256"),
            (lambda: helper._file_records([], "files"), "records"),
        ):
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(helper.AndroidJvmError, message),
            ):
                action()
        missing.write_bytes(b"{")
        with self.assertRaisesRegex(helper.AndroidJvmError, "invalid"):
            helper._load_json(missing)
        missing.write_text("{}\n\n")
        with self.assertRaisesRegex(helper.AndroidJvmError, "not canonical"):
            helper._load_json(missing)
        duplicate = [{"path": "a", "sha256": "0" * 64}] * 2
        with self.assertRaisesRegex(helper.AndroidJvmError, "duplicated"):
            helper._file_records(duplicate, "files")
        unsorted = [
            {"path": "b", "sha256": "0" * 64},
            {"path": "a", "sha256": "0" * 64},
        ]
        with self.assertRaisesRegex(helper.AndroidJvmError, "not sorted"):
            helper._file_records(unsorted, "files")

    def test_structural_policy_variants_fail_closed(self) -> None:
        value = json.loads(json.dumps(self.config))
        cases = [
            ("toolchain", "java_version", "21", "toolchain"),
            ("device", "abi", "mips", "ABI"),
            ("device", "form_factor", "car", "form factor"),
            ("device", "locale", "English", "locale"),
            ("device", "report_glob", "../*.xml", "glob"),
            ("resources", "memory_mib", 1, "outside"),
        ]
        policy = self.project / "quality/android-jvm.json"
        for section, key, replacement, message in cases:
            tested = json.loads(json.dumps(value))
            tested[section][key] = replacement
            policy.write_bytes(canonical(tested))
            with self.subTest(key=key), self.assertRaisesRegex(helper.AndroidJvmError, message):
                helper._configuration(self.project)
        tested = json.loads(json.dumps(value))
        del tested["tasks"]["abi"]
        policy.write_bytes(canonical(tested))
        with self.assertRaisesRegex(helper.AndroidJvmError, "task map"):
            helper._configuration(self.project)
        tested = json.loads(json.dumps(value))
        tested["schema_version"] = 2
        policy.write_bytes(canonical(tested))
        with self.assertRaisesRegex(helper.AndroidJvmError, "schema version"):
            helper._configuration(self.project)
        policy.write_bytes(canonical(value))

    def test_project_configuration_mutations_fail_closed(self) -> None:
        config, _ = helper._configuration(self.project)
        wrapper = self.project / "gradle/wrapper/gradle-wrapper.properties"
        original = wrapper.read_text()
        wrapper.write_text(original + "unknown=true\n")
        with self.assertRaisesRegex(helper.AndroidJvmError, "wrapper properties"):
            helper._wrapper_properties(self.project, config["toolchain"])
        wrapper.write_text("# comment\n" + original)
        helper._wrapper_properties(self.project, config["toolchain"])
        catalogue = self.project / "gradle/libs.versions.toml"
        catalogue.write_text('kotlin = "latest"\n')
        with self.assertRaisesRegex(helper.AndroidJvmError, "version catalogue"):
            helper._versions(self.project, config["toolchain"])
        self._write_project_reset()

    def test_verification_metadata_rejects_each_weak_shape(self) -> None:
        path = self.project / "gradle/verification-metadata.xml"
        namespace = "https://schema.gradle.org/dependency-verification"
        cases = [
            ("<x/>", "wrong namespace"),
            (f'<verification-metadata xmlns="{namespace}"/>', "configuration"),
            (
                f'<verification-metadata xmlns="{namespace}"><configuration>'
                "<verify-metadata>false</verify-metadata></configuration></verification-metadata>",
                "settings",
            ),
            (
                f'<verification-metadata xmlns="{namespace}"><configuration>'
                "<verify-metadata>true</verify-metadata><verify-signatures>false</verify-signatures>"
                "</configuration></verification-metadata>",
                "no artifacts",
            ),
            (
                f'<verification-metadata xmlns="{namespace}"><configuration>'
                "<verify-metadata>true</verify-metadata><verify-signatures>false</verify-signatures>"
                '</configuration><artifact><sha512 value="x"/></artifact></verification-metadata>',
                "only valid SHA-256",
            ),
            ("<broken", "malformed"),
            ("<!DOCTYPE x><x/>", "document type"),
        ]
        for text, message in cases:
            path.write_text(text)
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(helper.AndroidJvmError, message),
            ):
                helper._verification_metadata(self.project)

    def test_git_tracking_and_copy_bounds_fail_closed(self) -> None:
        config, _ = helper._configuration(self.project)
        with (
            mock.patch.object(
                subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 1, b"", b""),
            ),
            self.assertRaisesRegex(helper.AndroidJvmError, "Git repository"),
        ):
            helper._git(self.project, "status")
        with (
            mock.patch.object(helper, "_git", return_value=b"\xff\0"),
            self.assertRaisesRegex(helper.AndroidJvmError, "UTF-8"),
        ):
            helper._tracked(self.project, config)
        with (
            mock.patch.object(helper, "_git", return_value=b""),
            self.assertRaisesRegex(helper.AndroidJvmError, "file count"),
        ):
            helper._tracked(self.project, config)
        with (
            mock.patch.object(helper, "_git", return_value=b"b\0a\0"),
            self.assertRaisesRegex(helper.AndroidJvmError, "canonical"),
        ):
            helper._tracked(self.project, config)
        limited = json.loads(json.dumps(config))
        limited["resources"]["tracked_mib"] = 1
        large = self.project / "large.bin"
        large.write_bytes(b"x" * (1024 * 1024 + 1))
        subprocess.run(["git", "-C", str(self.project), "add", "large.bin"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.project),
                "-c",
                "user.name=T",
                "-c",
                "user.email=t@x",
                "commit",
                "-qm",
                "large",
            ],
            check=True,
        )
        destination = self.root / "copy"
        destination.mkdir()
        with self.assertRaisesRegex(helper.AndroidJvmError, "byte bound"):
            helper._copy_tree(self.project, destination, limited)

    def test_tools_process_limits_and_failures(self) -> None:
        config, _ = helper._configuration(self.project)
        missing = self.prefix / "gradle/bin/gradle"
        missing.chmod(0o644)
        with (
            mock.patch.object(helper, "_prefix", return_value=self.prefix),
            self.assertRaisesRegex(helper.AndroidJvmError, "tool is unavailable"),
        ):
            helper._tool("gradle")
        missing.chmod(0o755)
        runtime = self.prefix / "runtime-gradle"
        runtime.rmdir()
        with (
            mock.patch.object(helper, "_prefix", return_value=self.prefix),
            self.assertRaisesRegex(helper.AndroidJvmError, "cache is unavailable"),
        ):
            helper._runtime_gradle()
        runtime.mkdir()
        apply = helper._limits(config)
        with mock.patch.object(resource, "setrlimit") as setlimit:
            apply()
        self.assertEqual(4, setlimit.call_count)
        process = mock.Mock(pid=12345)
        process.wait.side_effect = [subprocess.TimeoutExpired(["tool"], 1), 0]
        with (
            mock.patch("awq.android_jvm_helper.subprocess.Popen", return_value=process),
            mock.patch("awq.android_jvm_helper.os.killpg") as killpg,
            self.assertRaisesRegex(helper.AndroidJvmError, "time bound"),
        ):
            helper._run_process(
                ["/absolute/tool"],
                cwd=self.root,
                environment={"PATH": "/usr/bin:/bin"},
                timeout=1,
            )
        killpg.assert_called_once()
        with (
            mock.patch.object(helper, "MAX_CONFIG_BYTES", 2),
            self.assertRaisesRegex(helper.AndroidJvmError, "output exceeds"),
        ):
            helper._run_process(
                ["/usr/bin/printf", "long"],
                cwd=self.root,
                environment={"PATH": "/usr/bin:/bin"},
                timeout=5,
                capture=True,
            )
        scratch = self.root / "scratch"
        scratch.mkdir()
        with (
            mock.patch.object(helper, "_prefix", return_value=self.prefix),
            mock.patch.object(helper, "_run_process", return_value=(1, b"")),
            self.assertRaisesRegex(helper.AndroidJvmError, "non-zero"),
        ):
            helper._run_gradle(self.project, "test", config, scratch)

    def test_report_and_observation_hostile_shapes_fail(self) -> None:
        report = self.root / "report.xml"
        cases = [
            (b"\xff", "not UTF-8"),
            (b"<!ENTITY x><testsuite/>", "forbidden"),
            (b"<broken", "malformed"),
            (b"<x/>", "root is unsupported"),
            (b'<testsuite name="x" tests="x"/>', "empty suite"),
            (
                b'<testsuite name="x" tests="1" failures="0" errors="0" skipped="2">'
                b'<testcase name="x"><skipped/></testcase></testsuite>',
                "inconsistent",
            ),
        ]
        for content, message in cases:
            report.write_bytes(content)
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(helper.AndroidJvmError, message),
            ):
                helper._suite_counts(report)
        with mock.patch.object(helper, "MAX_REPORT_BYTES", 1):
            report.write_bytes(b"xx")
            with self.assertRaisesRegex(helper.AndroidJvmError, "oversized"):
                helper._suite_counts(report)
        outside = self.root / "outside.xml"
        outside.write_text('<testsuite tests="1"/>')
        with self.assertRaisesRegex(helper.AndroidJvmError, "outside"):
            helper._report_module(self.project, outside)

    def test_connected_floors_missing_reports_and_invalid_observation_time(self) -> None:
        config, digest = helper._configuration(self.project)
        with self.assertRaisesRegex(helper.AndroidJvmError, "report count"):
            helper._connected(self.project, config, digest)
        observation = self.project / "build/awq/device-observation.json"
        observation.parent.mkdir(parents=True)
        value = {
            "abi": "x86_64",
            "accessibility_assertions": True,
            "api_level": 36,
            "form_factor": "phone",
            "image_sha256": "2" * 64,
            "locale": "en-US",
            "observed_at": "invalid",
            "report_sha256": "0" * 64,
            "schema_version": 1,
            "source_revision": "0" * 40,
            "task_status": "success",
            "ui_assertions": True,
        }
        observation.write_bytes(canonical(value))
        with self.assertRaisesRegex(helper.AndroidJvmError, "time is invalid"):
            helper._observation(self.project, config["device"], "0" * 64)
        value["observed_at"] = "invalidZ"
        observation.write_bytes(canonical(value))
        with self.assertRaisesRegex(helper.AndroidJvmError, "time is invalid"):
            helper._observation(self.project, config["device"], "0" * 64)
        with (
            mock.patch.object(helper, "_git", return_value=b"not-a-revision\n"),
            self.assertRaisesRegex(helper.AndroidJvmError, "revision is invalid"),
        ):
            helper._source_revision(self.project)

    def test_execute_rejects_unsupported_temp_and_original_lock_mutation(self) -> None:
        config, digest = helper._configuration(self.project)
        with self.assertRaisesRegex(helper.AndroidJvmError, "unsupported"):
            helper._execute(self.project, "unknown", config, digest)
        with (
            mock.patch.dict("os.environ", {"TMPDIR": "relative"}, clear=False),
            self.assertRaisesRegex(helper.AndroidJvmError, "temporary parent"),
        ):
            helper._execute(self.project, "test", config, digest)
        lock = self.project / "app/gradle.lockfile"

        def mutate(*_args: object) -> None:
            lock.write_text("mutated\n")

        with (
            mock.patch.object(helper, "_run_gradle", side_effect=mutate),
            self.assertRaisesRegex(helper.AndroidJvmError, "lockfile changed"),
        ):
            helper._execute(self.project, "test", config, digest)

    def test_emit_version_invalid_argv_and_probe_skew(self) -> None:
        with (
            mock.patch.object(helper, "MAX_BINDING_BYTES", 1),
            self.assertRaisesRegex(helper.AndroidJvmError, "exceeds"),
        ):
            helper._emit([{"id": "x", "kind": "gradle-project", "sha256": "0" * 64}])
        with mock.patch.object(helper, "_verify_installation"):
            self.assertEqual(0, helper.main(["--version"]))
            self.assertEqual(1, helper.main([]))
        with (
            mock.patch.object(helper, "_prefix", return_value=self.prefix),
            mock.patch.object(helper, "_run_process", return_value=(0, b"skew")),
            self.assertRaisesRegex(helper.AndroidJvmError, "version probes"),
        ):
            helper._verify_installation()
        java = b"java.version = 17.0.20.1\njava.vendor = Eclipse Adoptium\n"
        wrong_gradle = b"Gradle 9.1.0\nLauncher JVM:  17.0.20.10\n"
        with (
            mock.patch.object(helper, "_prefix", return_value=self.prefix),
            mock.patch.object(helper, "_run_process", side_effect=[(0, java), (0, wrong_gradle)]),
            self.assertRaisesRegex(helper.AndroidJvmError, "version probes"),
        ):
            helper._verify_installation()


if __name__ == "__main__":
    unittest.main()
