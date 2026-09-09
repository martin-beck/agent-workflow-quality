# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Bounded offline Android and JVM adapter implementation."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ElementTree
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = 1
HELPER_VERSION = "1.0.0"
JAVA_VERSION = "17.0.20.1"
GRADLE_VERSION = "9.1.0"
AGP_VERSION = "9.0.1"
KOTLIN_VERSION = "2.3.20"
HOST = "x86_64-unknown-linux-gnu"
JAVA_ARCHIVE_SHA256 = "3808d1d15e3ec6bd5b84057fb5d84c33d8a1536a258146bcea2e603fc726e08e"
GRADLE_ARCHIVE_SHA256 = "a17ddd85a26b6a7f5ddb71ff8b05fc5104c0202c6e64782429790c933686c806"
VERSION_OUTPUT = (
    "awq-android-jvm-check 1.0.0 "
    "(Temurin 17.0.20.1+1; Gradle 9.1.0; AGP 9.0.1; Kotlin 2.3.20; Linux x86-64)"
)
MODES = {
    "abi",
    "android-build",
    "android-lint",
    "connected-tests",
    "coverage",
    "dependency",
    "device-plan",
    "format",
    "integrity",
    "static",
    "test",
}
TASK_MODES = MODES - {"connected-tests", "device-plan", "integrity"}
TOP_KEYS = {"device", "integrity", "resources", "schema_version", "tasks", "toolchain"}
TOOLCHAIN_KEYS = {
    "agp_version",
    "gradle_distribution_sha256",
    "gradle_version",
    "host",
    "java_version",
    "kotlin_version",
    "wrapper_jar_sha256",
}
INTEGRITY_KEYS = {"allowed_repositories", "files", "locks"}
FILE_KEYS = {"path", "sha256"}
DEVICE_KEYS = {
    "abi",
    "api_level",
    "form_factor",
    "image_sha256",
    "locale",
    "max_age_hours",
    "minimum_executed",
    "minimum_tests",
    "observation_path",
    "report_glob",
    "required_modules",
}
RESOURCE_KEYS = {
    "cpu_seconds",
    "file_size_mib",
    "memory_mib",
    "open_files",
    "outer_timeout_seconds",
    "tracked_file_limit",
    "tracked_mib",
}
TASK = re.compile(r"^(?::[A-Za-z0-9_.-]+)*:[A-Za-z][A-Za-z0-9]*$|^[A-Za-z][A-Za-z0-9]*$")
MODULE = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY = re.compile(r"^(google|mavenCentral|gradlePluginPortal)$")
LOCALE = re.compile(r"^[a-z]{2}(?:-[A-Z]{2})?$")
MAX_CONFIG_BYTES = 1_000_000
MAX_REPORT_BYTES = 5_000_000
MAX_REPORTS = 1_000
MAX_BINDING_BYTES = 4096


class AndroidJvmError(RuntimeError):
    """The reviewed Android/JVM contract is malformed or failed."""


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AndroidJvmError("duplicate JSON key")
        result[key] = value
    return result


def _load_json(path: Path, maximum: int = MAX_CONFIG_BYTES) -> Any:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise AndroidJvmError("required JSON input is unavailable")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AndroidJvmError("required JSON input is invalid") from error
    if raw != _canonical_bytes(value):
        raise AndroidJvmError("required JSON input is not canonical")
    return value


def _relative(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise AndroidJvmError("path must be a repository-relative POSIX path")
    path = PurePosixPath(value)
    if value != path.as_posix() or path.is_absolute() or ".." in path.parts:
        raise AndroidJvmError("path escapes the repository")
    return value


def _exact_object(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise AndroidJvmError(f"{label} has unknown or missing fields")
    return value


def _integer(value: object, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise AndroidJvmError(f"{label} is outside its bound")
    return value


def _strings(
    value: object,
    *,
    pattern: re.Pattern[str] | None = None,
    minimum: int = 1,
    maximum: int = 100,
) -> list[str]:
    if (
        not isinstance(value, list)
        or not minimum <= len(value) <= maximum
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        raise AndroidJvmError("string list is invalid")
    result = list(value)
    if result != sorted(result) or (
        pattern is not None and any(not pattern.fullmatch(x) for x in result)
    ):
        raise AndroidJvmError("string list is not sorted or contains an invalid value")
    return result


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise AndroidJvmError(f"{label} must be SHA-256")
    return value


def _toolchain(value: object) -> dict[str, Any]:
    item = _exact_object(value, TOOLCHAIN_KEYS, "toolchain")
    expected = {
        "agp_version": AGP_VERSION,
        "gradle_version": GRADLE_VERSION,
        "host": HOST,
        "java_version": JAVA_VERSION,
        "kotlin_version": KOTLIN_VERSION,
    }
    if any(item[name] != expected_value for name, expected_value in expected.items()):
        raise AndroidJvmError("toolchain does not match the reviewed version set")
    _digest(item["gradle_distribution_sha256"], "Gradle distribution")
    _digest(item["wrapper_jar_sha256"], "Gradle wrapper JAR")
    return item


def _file_records(value: object, label: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value or len(value) > 1_000:
        raise AndroidJvmError(f"{label} records are invalid")
    records: list[dict[str, str]] = []
    for raw in value:
        item = _exact_object(raw, FILE_KEYS, label)
        records.append({"path": _relative(item["path"]), "sha256": _digest(item["sha256"], label)})
    if records != sorted(records, key=lambda item: item["path"]):
        raise AndroidJvmError(f"{label} records are not sorted")
    if len({item["path"] for item in records}) != len(records):
        raise AndroidJvmError(f"{label} records are duplicated")
    return records


def _integrity(value: object) -> dict[str, Any]:
    item = _exact_object(value, INTEGRITY_KEYS, "integrity")
    files = _file_records(item["files"], "integrity file")
    locks = _file_records(item["locks"], "lock file")
    paths = {entry["path"] for entry in files}
    required = {
        "gradle/libs.versions.toml",
        "gradle/verification-metadata.xml",
        "gradle/wrapper/gradle-wrapper.jar",
        "gradle/wrapper/gradle-wrapper.properties",
        "settings.gradle.kts",
    }
    if not required <= paths or paths & {entry["path"] for entry in locks}:
        raise AndroidJvmError("integrity records do not cover the required distinct inputs")
    repositories = _strings(item["allowed_repositories"], pattern=REPOSITORY)
    return {"allowed_repositories": repositories, "files": files, "locks": locks}


def _tasks(value: object) -> dict[str, list[str]]:
    if not isinstance(value, dict) or set(value) != TASK_MODES:
        raise AndroidJvmError("task map has unknown or missing modes")
    result: dict[str, list[str]] = {}
    for mode in sorted(TASK_MODES):
        result[mode] = _strings(value[mode], pattern=TASK, maximum=50)
    return result


def _device(value: object) -> dict[str, Any]:
    item = _exact_object(value, DEVICE_KEYS, "device")
    if item["abi"] not in {"x86_64", "arm64-v8a"}:
        raise AndroidJvmError("device ABI is unsupported")
    _integer(item["api_level"], 28, 100, "device API")
    if item["form_factor"] not in {"phone", "tablet", "wear"}:
        raise AndroidJvmError("device form factor is unsupported")
    _digest(item["image_sha256"], "device image")
    if not isinstance(item["locale"], str) or LOCALE.fullmatch(item["locale"]) is None:
        raise AndroidJvmError("device locale is invalid")
    _integer(item["max_age_hours"], 1, 168, "device evidence age")
    _integer(item["minimum_tests"], 1, 1_000_000, "minimum tests")
    _integer(item["minimum_executed"], 1, item["minimum_tests"], "minimum executed tests")
    _relative(item["observation_path"])
    report_glob = item["report_glob"]
    if (
        not isinstance(report_glob, str)
        or not report_glob
        or report_glob.startswith("/")
        or ".." in PurePosixPath(report_glob).parts
        or "\\" in report_glob
    ):
        raise AndroidJvmError("connected-test report glob is unsafe")
    _strings(item["required_modules"], pattern=MODULE)
    return item


def _resources(value: object) -> dict[str, int]:
    item = _exact_object(value, RESOURCE_KEYS, "resources")
    bounds = {
        "cpu_seconds": (1, 3_600),
        "file_size_mib": (1, 4_096),
        "memory_mib": (256, 16_384),
        "open_files": (64, 4_096),
        "outer_timeout_seconds": (1, 3_600),
        "tracked_file_limit": (1, 100_000),
        "tracked_mib": (1, 4_096),
    }
    return {name: _integer(item[name], low, high, name) for name, (low, high) in bounds.items()}


def _configuration(root: Path) -> tuple[dict[str, Any], str]:
    path = root / "quality/android-jvm.json"
    config = _exact_object(_load_json(path), TOP_KEYS, "Android/JVM policy")
    if type(config["schema_version"]) is not int or config["schema_version"] != SCHEMA_VERSION:
        raise AndroidJvmError("Android/JVM policy schema version is unsupported")
    normalized = {
        "device": _device(config["device"]),
        "integrity": _integrity(config["integrity"]),
        "resources": _resources(config["resources"]),
        "schema_version": SCHEMA_VERSION,
        "tasks": _tasks(config["tasks"]),
        "toolchain": _toolchain(config["toolchain"]),
    }
    if config != normalized:
        raise AndroidJvmError("Android/JVM policy is not normalized")
    return normalized, hashlib.sha256(_canonical_bytes(normalized)).hexdigest()


def _confined(root: Path, relative: str) -> Path:
    path = root.joinpath(*PurePosixPath(relative).parts)
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise AndroidJvmError("declared input parent is unavailable") from error
    if root not in (parent, *parent.parents):
        raise AndroidJvmError("declared input escapes the repository")
    return path


def _regular_file(root: Path, relative: str, maximum: int = MAX_CONFIG_BYTES) -> Path:
    path = _confined(root, relative)
    if path.is_symlink() or not path.is_file():
        raise AndroidJvmError("declared input is not a regular file")
    if path.stat().st_size > maximum:
        raise AndroidJvmError("declared input exceeds its size bound")
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_records(root: Path, records: list[dict[str, str]]) -> None:
    for item in records:
        if _sha256(_regular_file(root, item["path"], MAX_REPORT_BYTES)) != item["sha256"]:
            raise AndroidJvmError("repository integrity digest mismatch")


def _wrapper_properties(root: Path, toolchain: dict[str, Any]) -> None:
    path = _regular_file(root, "gradle/wrapper/gradle-wrapper.properties")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        if not separator or name in values:
            raise AndroidJvmError("Gradle wrapper properties are invalid")
        values[name] = value
    expected_url = (
        f"https\\://services.gradle.org/distributions/gradle-{toolchain['gradle_version']}-bin.zip"
    )
    required = {
        "distributionBase": "GRADLE_USER_HOME",
        "distributionPath": "wrapper/dists",
        "distributionSha256Sum": toolchain["gradle_distribution_sha256"],
        "distributionUrl": expected_url,
        "networkTimeout": "10000",
        "validateDistributionUrl": "true",
        "zipStoreBase": "GRADLE_USER_HOME",
        "zipStorePath": "wrapper/dists",
    }
    if values != required:
        raise AndroidJvmError("Gradle wrapper properties differ from the reviewed contract")


def _versions(root: Path, toolchain: dict[str, Any]) -> None:
    text = _regular_file(root, "gradle/libs.versions.toml").read_text(encoding="utf-8")
    expected = {
        "androidGradlePlugin": toolchain["agp_version"],
        "kotlin": toolchain["kotlin_version"],
    }
    for name, version in expected.items():
        pattern = re.compile(rf'(?m)^{re.escape(name)}\s*=\s*"{re.escape(version)}"\s*$')
        if pattern.search(text) is None:
            raise AndroidJvmError("version catalogue differs from the reviewed toolchain")


def _repositories(root: Path, repositories: list[str]) -> None:
    text = _regular_file(root, "settings.gradle.kts").read_text(encoding="utf-8")
    without_comments = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    without_comments = re.sub(r"(?m)//.*$", "", without_comments)
    if "RepositoriesMode.FAIL_ON_PROJECT_REPOS" not in without_comments:
        raise AndroidJvmError("project repositories are not centrally denied")
    tokens = {
        "google": r"\bgoogle\s*\(",
        "mavenCentral": r"\bmavenCentral\s*\(",
        "gradlePluginPortal": r"\bgradlePluginPortal\s*\(",
    }
    for name in repositories:
        if re.search(tokens[name], without_comments) is None:
            raise AndroidJvmError("reviewed repository declaration is missing")
    declared = {
        name for name, token in tokens.items() if re.search(token, without_comments) is not None
    }
    if declared != set(repositories):
        raise AndroidJvmError("repository declarations differ from the reviewed allowlist")
    forbidden = (
        r"\b(?:maven|ivy)\s*\{|"
        r"\b(?:url|setUrl)\s*(?:=|\()|"
        r"\bexclusiveContent\s*\{"
    )
    if re.search(forbidden, without_comments):
        raise AndroidJvmError("custom repository syntax is not allowed")


def _verification_metadata(root: Path) -> None:
    path = _regular_file(root, "gradle/verification-metadata.xml", MAX_REPORT_BYTES)
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise AndroidJvmError("Gradle verification metadata is not UTF-8") from error
    upper = text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise AndroidJvmError("Gradle verification metadata contains a document type")
    try:
        document = ElementTree.fromstring(text)  # noqa: S314 - forbidden markup rejected.
    except ElementTree.ParseError as error:
        raise AndroidJvmError("Gradle verification metadata is malformed") from error
    namespace = "{https://schema.gradle.org/dependency-verification}"
    if document.tag != namespace + "verification-metadata":
        raise AndroidJvmError("Gradle verification metadata has the wrong namespace")
    configuration = document.find(namespace + "configuration")
    if configuration is None:
        raise AndroidJvmError("Gradle verification configuration is missing")
    settings = {child.tag.removeprefix(namespace): (child.text or "") for child in configuration}
    if settings != {"verify-metadata": "true", "verify-signatures": "false"}:
        raise AndroidJvmError("Gradle verification settings differ from the reviewed contract")
    artifacts = document.findall(f".//{namespace}artifact")
    if not artifacts:
        raise AndroidJvmError("Gradle verification metadata has no artifacts")
    for artifact in artifacts:
        children = list(artifact)
        if not children or any(
            child.tag != namespace + "sha256"
            or SHA256.fullmatch(child.attrib.get("value", "")) is None
            for child in children
        ):
            raise AndroidJvmError("every Gradle artifact must have only valid SHA-256 records")


def _verify_project(root: Path, config: dict[str, Any]) -> None:
    integrity = config["integrity"]
    _verify_records(root, integrity["files"])
    _verify_records(root, integrity["locks"])
    _wrapper_properties(root, config["toolchain"])
    _versions(root, config["toolchain"])
    _repositories(root, integrity["allowed_repositories"])
    _verification_metadata(root)


def _git(root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(  # noqa: S603 - absolute Git with fixed internal argv.
        ["/usr/bin/git", "-C", str(root), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    if completed.returncode:
        raise AndroidJvmError("Git repository state is unavailable")
    return completed.stdout


def _require_clean(root: Path) -> None:
    if _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=no"):
        raise AndroidJvmError("Android/JVM checks require a clean tracked repository")


def _tracked(root: Path, config: dict[str, Any]) -> list[str]:
    raw = _git(root, "ls-files", "-z")
    try:
        paths = raw.decode("utf-8").split("\0")
    except UnicodeError as error:
        raise AndroidJvmError("tracked path is not UTF-8") from error
    if paths[-1:] == [""]:
        paths.pop()
    resources = config["resources"]
    if not paths or len(paths) > resources["tracked_file_limit"]:
        raise AndroidJvmError("tracked file count exceeds the reviewed bound")
    normalized = sorted(_relative(path) for path in paths)
    if paths != normalized or len(set(paths)) != len(paths):
        raise AndroidJvmError("tracked paths are not canonical and sorted")
    return paths


def _copy_tree(root: Path, destination: Path, config: dict[str, Any]) -> None:
    total = 0
    maximum = config["resources"]["tracked_mib"] * 1024 * 1024
    for relative in _tracked(root, config):
        source = _confined(root, relative)
        metadata = source.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise AndroidJvmError("tracked Android/JVM input is not a regular file")
        total += metadata.st_size
        if total > maximum:
            raise AndroidJvmError("tracked Android/JVM inputs exceed the byte bound")
        target = destination.joinpath(*PurePosixPath(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(metadata.st_mode & 0o777)


def _prefix() -> Path:
    return Path(__file__).resolve().parent.parent


def _tool(name: str) -> Path:
    prefix = _prefix()
    paths = {
        "gradle": prefix / "gradle/bin/gradle",
        "java": prefix / "jdk/bin/java",
    }
    path = paths[name]
    if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
        raise AndroidJvmError("installed Android/JVM tool is unavailable")
    return path


def _runtime_gradle() -> Path:
    path = _prefix() / "runtime-gradle"
    if path.is_symlink() or not path.is_dir():
        raise AndroidJvmError("runtime Gradle cache is unavailable")
    forbidden = [
        path / "gradle.properties",
        path / "init.gradle",
        path / "init.gradle.kts",
        path / "init.d",
        path / "credentials",
    ]
    if any(item.exists() or item.is_symlink() for item in forbidden):
        raise AndroidJvmError("runtime Gradle cache contains global policy or credentials")
    return path


def _limits(config: dict[str, Any]) -> Any:
    resources = config["resources"]

    def apply() -> None:
        resource.setrlimit(
            resource.RLIMIT_CPU, (resources["cpu_seconds"], resources["cpu_seconds"])
        )
        resource.setrlimit(
            resource.RLIMIT_FSIZE,
            (resources["file_size_mib"] * 1024 * 1024,) * 2,
        )
        resource.setrlimit(
            resource.RLIMIT_NOFILE,
            (resources["open_files"], resources["open_files"]),
        )
        resource.setrlimit(
            resource.RLIMIT_AS,
            (resources["memory_mib"] * 1024 * 1024,) * 2,
        )

    return apply


def _environment(scratch: Path) -> dict[str, str]:
    home = scratch / "home"
    temporary = scratch / "tmp"
    project_cache = scratch / "project-cache"
    home.mkdir()
    temporary.mkdir()
    project_cache.mkdir()
    prefix = _prefix()
    return {
        "ANDROID_HOME": str(prefix / "android-sdk"),
        "ANDROID_SDK_ROOT": str(prefix / "android-sdk"),
        "GRADLE_USER_HOME": str(_runtime_gradle()),
        "HOME": str(home),
        "JAVA_HOME": str(prefix / "jdk"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "PATH": f"{prefix / 'jdk/bin'}:/usr/bin:/bin",
        "TMPDIR": str(temporary),
    }


def _run_process(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: int,
    preexec_fn: Any = None,
    capture: bool = False,
) -> tuple[int, bytes]:
    with tempfile.TemporaryFile() as output:
        destination: Any = output if capture else subprocess.DEVNULL
        process = subprocess.Popen(  # noqa: S603 - exact executable and validated argv.
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=destination,
            stderr=destination,
            start_new_session=True,
            preexec_fn=preexec_fn,
        )
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=30)
            raise AndroidJvmError("Android/JVM subprocess exceeded its time bound") from error
        if not capture:
            return returncode, b""
        output.seek(0, os.SEEK_END)
        if output.tell() > MAX_CONFIG_BYTES:
            raise AndroidJvmError("Android/JVM subprocess output exceeds its bound")
        output.seek(0)
        return returncode, output.read()


def _run_gradle(project: Path, mode: str, config: dict[str, Any], scratch: Path) -> None:
    command = [
        str(_tool("gradle")),
        "--offline",
        "--no-daemon",
        "--no-scan",
        "--console=plain",
        "--project-cache-dir",
        str(scratch / "project-cache"),
        *config["tasks"][mode],
    ]
    returncode, _ = _run_process(
        command,
        cwd=project,
        environment=_environment(scratch),
        timeout=config["resources"]["outer_timeout_seconds"],
        preexec_fn=_limits(config),
    )
    if returncode:
        raise AndroidJvmError("reviewed Gradle task returned a non-zero status")


def _source_revision(root: Path) -> str:
    try:
        revision = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    except UnicodeError as error:
        raise AndroidJvmError("source revision is unavailable") from error
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise AndroidJvmError("source revision is invalid")
    return revision


def _observation(
    root: Path,
    device: dict[str, Any],
    report_digest: str,
) -> tuple[dict[str, Any], str]:
    path = _regular_file(root, device["observation_path"], MAX_REPORT_BYTES)
    value = _exact_object(
        _load_json(path, MAX_REPORT_BYTES),
        {
            "abi",
            "accessibility_assertions",
            "api_level",
            "form_factor",
            "image_sha256",
            "locale",
            "observed_at",
            "report_sha256",
            "schema_version",
            "source_revision",
            "task_status",
            "ui_assertions",
        },
        "device observation",
    )
    observed_at = value["observed_at"]
    if not isinstance(observed_at, str) or not observed_at.endswith("Z"):
        raise AndroidJvmError("device observation time is invalid")
    try:
        timestamp = datetime.datetime.fromisoformat(observed_at[:-1] + "+00:00")
    except ValueError as error:
        raise AndroidJvmError("device observation time is invalid") from error
    age = datetime.datetime.now(datetime.UTC) - timestamp
    if age < datetime.timedelta(0) or age > datetime.timedelta(hours=device["max_age_hours"]):
        raise AndroidJvmError("device observation is stale or from the future")
    expected = {
        "abi": device["abi"],
        "accessibility_assertions": True,
        "api_level": device["api_level"],
        "form_factor": device["form_factor"],
        "image_sha256": device["image_sha256"],
        "locale": device["locale"],
        "observed_at": observed_at,
        "report_sha256": report_digest,
        "schema_version": 1,
        "source_revision": _source_revision(root),
        "task_status": "success",
        "ui_assertions": True,
    }
    if value != expected:
        raise AndroidJvmError("device observation does not prove the reviewed plan")
    return value, hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _suite_counts(path: Path) -> tuple[int, int, int, int]:
    raw = path.read_bytes()
    if len(raw) > MAX_REPORT_BYTES:
        raise AndroidJvmError("connected-test report is oversized")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise AndroidJvmError("connected-test report is not UTF-8") from error
    upper = text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise AndroidJvmError("connected-test report contains forbidden markup")
    try:
        document = ElementTree.fromstring(text)  # noqa: S314 - forbidden markup rejected.
    except ElementTree.ParseError as error:
        raise AndroidJvmError("connected-test report is malformed") from error
    suites = [document] if document.tag == "testsuite" else list(document.findall("./testsuite"))
    if document.tag not in {"testsuite", "testsuites"} or not suites:
        raise AndroidJvmError("connected-test report contains no suites")
    totals = [0, 0, 0, 0]
    for suite in suites:
        values: list[int] = []
        for name in ("tests", "failures", "errors", "skipped"):
            raw_value = suite.attrib.get(name, "0")
            if not re.fullmatch(r"[0-9]+", raw_value):
                raise AndroidJvmError("connected-test report contains an invalid count")
            values.append(int(raw_value))
        if values[3] > values[0]:
            raise AndroidJvmError("connected-test skipped count exceeds total tests")
        totals = [left + right for left, right in zip(totals, values, strict=True)]
    return tuple(totals)  # type: ignore[return-value]


def _report_module(root: Path, report: Path) -> str:
    try:
        relative = report.resolve(strict=True).relative_to(root)
        build = relative.parts.index("build")
    except (OSError, ValueError) as error:
        raise AndroidJvmError(
            "connected-test report is outside a module build directory"
        ) from error
    module = "/".join(relative.parts[:build])
    if not module or MODULE.fullmatch(module) is None:
        raise AndroidJvmError("connected-test report module is invalid")
    return module


def _connected(root: Path, config: dict[str, Any], digest: str) -> list[dict[str, str]]:
    device = config["device"]
    reports = sorted(root.glob(device["report_glob"]))
    if not reports or len(reports) > MAX_REPORTS:
        raise AndroidJvmError("connected-test report count is outside its bound")
    modules: set[str] = set()
    report_records: list[dict[str, str]] = []
    tests = failures = errors = skipped = 0
    for report in reports:
        if report.is_symlink() or not report.is_file():
            raise AndroidJvmError("connected-test report is not a regular file")
        try:
            relative = report.resolve(strict=True).relative_to(root).as_posix()
        except (OSError, ValueError) as error:
            raise AndroidJvmError("connected-test report escapes the repository") from error
        report_records.append({"path": relative, "sha256": _sha256(report)})
        modules.add(_report_module(root, report))
        counts = _suite_counts(report)
        tests += counts[0]
        failures += counts[1]
        errors += counts[2]
        skipped += counts[3]
    report_digest = hashlib.sha256(_canonical_bytes(report_records)).hexdigest()
    _, observation_digest = _observation(root, device, report_digest)
    if not set(device["required_modules"]) <= modules:
        raise AndroidJvmError("required connected-test module evidence is missing")
    executed = tests - skipped
    if (
        tests < device["minimum_tests"]
        or executed < device["minimum_executed"]
        or failures
        or errors
    ):
        raise AndroidJvmError("connected-test evidence does not meet the reviewed floor")
    return [
        {
            "id": (
                f"api-{device['api_level']}:{device['abi']}:"
                f"{device['form_factor']}:{device['locale']}"
            ),
            "kind": "android-device-plan",
            "sha256": digest,
        },
        {
            "id": f"tests-{tests}:executed-{executed}:modules-{len(modules)}",
            "kind": "connected-test-summary",
            "sha256": observation_digest,
        },
    ]


def _plan(config: dict[str, Any], digest: str) -> list[dict[str, str]]:
    device = config["device"]
    return [
        {
            "id": (
                f"api-{device['api_level']}:{device['abi']}:"
                f"{device['form_factor']}:{device['locale']}"
            ),
            "kind": "android-device-plan",
            "sha256": digest,
        }
    ]


def _integrity_bindings(config: dict[str, Any], digest: str) -> list[dict[str, str]]:
    integrity = config["integrity"]
    return [
        {
            "id": (
                f"files-{len(integrity['files'])}:locks-{len(integrity['locks'])}:"
                f"repositories-{len(integrity['allowed_repositories'])}"
            ),
            "kind": "gradle-project",
            "sha256": digest,
        }
    ]


def _execute(root: Path, mode: str, config: dict[str, Any], digest: str) -> list[dict[str, str]]:
    _require_clean(root)
    _verify_project(root, config)
    lock_before = {
        item["path"]: _sha256(_regular_file(root, item["path"]))
        for item in config["integrity"]["locks"]
    }
    try:
        if mode == "integrity":
            return _integrity_bindings(config, digest)
        if mode == "device-plan":
            return _plan(config, digest)
        if mode == "connected-tests":
            return _connected(root, config, digest)
        if mode not in TASK_MODES:
            raise AndroidJvmError("unsupported Android/JVM mode")
        temporary_parent = os.environ.get("TMPDIR")
        if temporary_parent is not None:
            candidate = Path(temporary_parent)
            if not candidate.is_absolute() or candidate.is_symlink() or not candidate.is_dir():
                raise AndroidJvmError("temporary parent is unsafe")
        with tempfile.TemporaryDirectory(
            prefix="awq-android-jvm-",
            dir=temporary_parent,
        ) as name:
            scratch = Path(name)
            project = scratch / "project"
            project.mkdir()
            _copy_tree(root, project, config)
            _run_gradle(project, mode, config, scratch)
            _verify_records(project, config["integrity"]["locks"])
        tasks = config["tasks"][mode]
        return [
            {
                "id": f"{mode}:tasks-{len(tasks)}",
                "kind": "gradle-task-plan",
                "sha256": digest,
            }
        ]
    finally:
        for relative, expected in lock_before.items():
            if _sha256(_regular_file(root, relative)) != expected:
                raise AndroidJvmError("Gradle lockfile changed during Android/JVM execution")
        _require_clean(root)


def _verify_installation() -> None:
    prefix = _prefix()
    java = _tool("java")
    gradle = _tool("gradle")
    if not java.resolve().is_relative_to(prefix) or not gradle.resolve().is_relative_to(prefix):
        raise AndroidJvmError("installed Android/JVM tool escapes its prefix")
    _runtime_gradle()
    manifest = _exact_object(
        _load_json(prefix / "manifest.json"),
        {
            "gradle_archive_sha256",
            "gradle_version",
            "helper_sha256",
            "host",
            "java_archive_sha256",
            "java_version",
            "schema_version",
        },
        "installation manifest",
    )
    expected = {
        "gradle_archive_sha256": GRADLE_ARCHIVE_SHA256,
        "gradle_version": GRADLE_VERSION,
        "helper_sha256": _sha256(Path(__file__).resolve()),
        "host": HOST,
        "java_archive_sha256": JAVA_ARCHIVE_SHA256,
        "java_version": JAVA_VERSION,
        "schema_version": 1,
    }
    if manifest != expected:
        raise AndroidJvmError("installation manifest differs from the reviewed toolchain")
    environment = {
        "GRADLE_USER_HOME": str(prefix / "runtime-gradle"),
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "PATH": f"{prefix / 'jdk/bin'}:/usr/bin:/bin",
    }
    java_status, java_output = _run_process(
        [str(java), "-XshowSettings:properties", "-version"],
        cwd=prefix,
        environment=environment,
        timeout=30,
        capture=True,
    )
    gradle_status, gradle_output = _run_process(
        [str(gradle), "--offline", "--no-daemon", "--version"],
        cwd=prefix,
        environment={**environment, "JAVA_HOME": str(prefix / "jdk")},
        timeout=30,
        capture=True,
    )
    if (
        java_status
        or b"java.version = 17.0.20.1" not in java_output
        or b"java.vendor = Eclipse Adoptium" not in java_output
        or gradle_status
        or b"Gradle 9.1.0" not in gradle_output
        or re.search(rb"(?m)^Launcher JVM:[ \t]+17\.0\.20\.1(?:[ \t]|$)", gradle_output) is None
    ):
        raise AndroidJvmError("installed Android/JVM tools fail their exact version probes")


def _emit(bindings: list[dict[str, str]]) -> None:
    ordered = sorted(bindings, key=lambda item: (item["kind"], item["id"]))
    document = {"bindings": ordered, "schema_version": 1, "status": "pass"}
    raw = _canonical_bytes(document)
    if len(raw) > MAX_BINDING_BYTES:
        raise AndroidJvmError("Android/JVM binding result exceeds its bound")
    sys.stdout.buffer.write(raw)


def main(argv: list[str] | None = None) -> int:
    """Run one exact Android/JVM mode without exposing native output."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        _verify_installation()
        if arguments == ["--version"]:
            print(VERSION_OUTPUT)
            return 0
        if len(arguments) != 1 or arguments[0] not in MODES:
            raise AndroidJvmError("invalid Android/JVM invocation")
        root = Path.cwd().resolve()
        config, digest = _configuration(root)
        _emit(_execute(root, arguments[0], config, digest))
    except (
        AndroidJvmError,
        OSError,
        TypeError,
        UnicodeError,
        ValueError,
        RecursionError,
        subprocess.SubprocessError,
    ):
        print("awq-android-jvm-check: validation failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
