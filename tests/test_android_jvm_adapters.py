# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Native-equivalence tests for the Android/JVM adapter family."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from awq import adapters
from awq import android_jvm_helper as helper
from scripts.validate_contracts import validate
from tests.support import Repository

TASK_IDS = [
    "ADAPTER-ANDROID-JVM-ABI",
    "ADAPTER-ANDROID-JVM-ANDROID-BUILD",
    "ADAPTER-ANDROID-JVM-ANDROID-LINT",
    "ADAPTER-ANDROID-JVM-COVERAGE",
    "ADAPTER-ANDROID-JVM-DEPENDENCY",
    "ADAPTER-ANDROID-JVM-FORMAT",
    "ADAPTER-ANDROID-JVM-STATIC",
    "ADAPTER-ANDROID-JVM-TEST",
]
EXPECTED_IDS = [
    "ADAPTER-ANDROID-JVM-ABI",
    "ADAPTER-ANDROID-JVM-ANDROID-BUILD",
    "ADAPTER-ANDROID-JVM-ANDROID-LINT",
    "ADAPTER-ANDROID-JVM-CONNECTED-TESTS",
    "ADAPTER-ANDROID-JVM-COVERAGE",
    "ADAPTER-ANDROID-JVM-DEPENDENCY",
    "ADAPTER-ANDROID-JVM-DEVICE-PLAN",
    "ADAPTER-ANDROID-JVM-FORMAT",
    "ADAPTER-ANDROID-JVM-INTEGRITY",
    "ADAPTER-ANDROID-JVM-STATIC",
    "ADAPTER-ANDROID-JVM-TEST",
]


class AndroidJvmAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        families, _ = adapters.load_adapter_catalog()
        self.family = families["android-jvm"]
        self.contracts = {item["id"]: item for item in self.family["contracts"]}
        self.repositories: list[Repository] = []

    def tearDown(self) -> None:
        for repository in self.repositories:
            repository.close()

    def fixture(self, *, failing: bool = False) -> Repository:
        repository = Repository()
        self.repositories.append(repository)
        repository.write(
            "settings.gradle.kts",
            "pluginManagement { repositories { gradlePluginPortal(); google(); mavenCentral() } }\n"
            "dependencyResolutionManagement {\n"
            " repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)\n"
            ' repositories { google(); mavenCentral() }\n}\nrootProject.name = "fixture"\n',
        )
        repository.write(
            "build.gradle.kts",
            'tasks.register("awqPass") { doLast { println("pass") } }\n'
            + (
                'tasks.register("awqFail") { doLast { error("reviewed failure") } }\n'
                if failing
                else ""
            ),
        )
        repository.write(
            "gradle/libs.versions.toml",
            'androidGradlePlugin = "9.0.1"\nkotlin = "2.3.20"\n',
        )
        repository.write(
            "gradle/verification-metadata.xml",
            '<verification-metadata xmlns="https://schema.gradle.org/dependency-verification">'
            "<configuration><verify-metadata>true</verify-metadata>"
            "<verify-signatures>false</verify-signatures></configuration>"
            '<components><component group="g" name="n" version="1"><artifact name="a">'
            f'<sha256 value="{"1" * 64}"/></artifact></component></components>'
            "</verification-metadata>",
        )
        repository.write("gradle/wrapper/gradle-wrapper.jar", b"jar")
        repository.write(
            "gradle/wrapper/gradle-wrapper.properties",
            "distributionBase=GRADLE_USER_HOME\n"
            "distributionPath=wrapper/dists\n"
            f"distributionSha256Sum={helper.GRADLE_ARCHIVE_SHA256}\n"
            "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.1.0-bin.zip\n"
            "networkTimeout=10000\n"
            "validateDistributionUrl=true\n"
            "zipStoreBase=GRADLE_USER_HOME\n"
            "zipStorePath=wrapper/dists\n",
        )
        repository.write("gradle.lockfile", "empty=\n")
        repository.commit()
        records = [
            {
                "path": relative,
                "sha256": hashlib.sha256((repository.root / relative).read_bytes()).hexdigest(),
            }
            for relative in (
                "gradle/libs.versions.toml",
                "gradle/verification-metadata.xml",
                "gradle/wrapper/gradle-wrapper.jar",
                "gradle/wrapper/gradle-wrapper.properties",
                "settings.gradle.kts",
            )
        ]
        task = "awqFail" if failing else "awqPass"
        policy: dict[str, Any] = {
            "device": {
                "abi": "x86_64",
                "api_level": 36,
                "form_factor": "phone",
                "image_sha256": "2" * 64,
                "locale": "en-US",
                "max_age_hours": 24,
                "minimum_executed": 1,
                "minimum_tests": 1,
                "observation_path": "build/awq/device-observation.json",
                "report_glob": "*/build/outputs/androidTest-results/**/*.xml",
                "required_modules": ["app"],
            },
            "integrity": {
                "allowed_repositories": ["google", "gradlePluginPortal", "mavenCentral"],
                "files": records,
                "locks": [
                    {
                        "path": "gradle.lockfile",
                        "sha256": hashlib.sha256(
                            (repository.root / "gradle.lockfile").read_bytes()
                        ).hexdigest(),
                    }
                ],
            },
            "resources": {
                "cpu_seconds": 120,
                "file_size_mib": 100,
                "memory_mib": 2048,
                "open_files": 256,
                "outer_timeout_seconds": 120,
                "tracked_file_limit": 100,
                "tracked_mib": 10,
            },
            "schema_version": 1,
            "tasks": {mode: [task] for mode in sorted(helper.TASK_MODES)},
            "toolchain": {
                "agp_version": helper.AGP_VERSION,
                "gradle_distribution_sha256": helper.GRADLE_ARCHIVE_SHA256,
                "gradle_version": helper.GRADLE_VERSION,
                "host": helper.HOST,
                "java_version": helper.JAVA_VERSION,
                "kotlin_version": helper.KOTLIN_VERSION,
                "wrapper_jar_sha256": records[2]["sha256"],
            },
        }
        repository.json("quality/android-jvm.json", policy)
        return repository

    def native(self, root: Path, task: str) -> bool:
        wrapper = shutil.which("awq-android-jvm-check")
        if wrapper is None:
            raise RuntimeError("pinned Android/JVM wrapper is unavailable")
        prefix = Path(wrapper).resolve().parent.parent
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as name:
            completed = subprocess.run(
                [
                    str(prefix / "gradle/bin/gradle"),
                    "--offline",
                    "--no-daemon",
                    "--no-scan",
                    "--console=plain",
                    "--project-cache-dir",
                    str(Path(name) / "cache"),
                    task,
                ],
                cwd=root,
                env={
                    "ANDROID_HOME": str(prefix / "android-sdk"),
                    "ANDROID_SDK_ROOT": str(prefix / "android-sdk"),
                    "GRADLE_USER_HOME": str(prefix / "runtime-gradle"),
                    "HOME": str(Path(name) / "home"),
                    "JAVA_HOME": str(prefix / "jdk"),
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "NO_COLOR": "1",
                    "PATH": f"{prefix / 'jdk/bin'}:/usr/bin:/bin",
                    "TMPDIR": name,
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=120,
                check=False,
            )
        return completed.returncode == 0

    def test_catalog_is_exact_and_schema_valid(self) -> None:
        validate({"schema_version": 1, "families": [self.family]}, "adapter-catalog.schema.json")
        self.assertEqual(EXPECTED_IDS, list(self.contracts))
        for contract in self.contracts.values():
            self.assertEqual("awq-android-jvm-check", contract["tool"])
            self.assertEqual("awq-bindings-v1", contract["result_protocol"])
            self.assertEqual(["quality/android-jvm.json"], contract["config_paths"])

    def test_task_contracts_match_native_success_and_failure(self) -> None:
        for failing in (False, True):
            repository = self.fixture(failing=failing)
            task = "awqFail" if failing else "awqPass"
            native = self.native(repository.root, task)
            for identifier in TASK_IDS:
                with self.subTest(failing=failing, identifier=identifier):
                    result = adapters.run_adapter(repository.root, self.contracts[identifier])
                    self.assertEqual(native, result["status"] == "pass")
                    self.assertNotIn("reviewed failure", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
