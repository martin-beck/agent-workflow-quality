# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Install checksum-pinned Temurin and Gradle tools into a new isolated prefix."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import awq.android_jvm_helper as helper

MAX_ARCHIVE_BYTES = 250_000_000
MAX_MEMBER_BYTES = 150_000_000
MAX_MEMBERS = 100_000
SOURCE_HOSTS = frozenset({"github.com"})
REDIRECT_HOSTS = frozenset({"github.com", "release-assets.githubusercontent.com"})
WRAPPER = b"""#!/usr/bin/env python3
from pathlib import Path
import sys

prefix = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(prefix / "lib"))
from awq_android_jvm_helper import main

raise SystemExit(main())
"""


class ByteReader(Protocol):
    """A bounded archive or HTTP response stream."""

    def read(self, size: int = -1) -> bytes:
        """Read at most size bytes."""
        ...


class AndroidJvmInstallError(RuntimeError):
    """The Android/JVM tool installation failed closed."""


@dataclass(frozen=True)
class Artifact:
    """One immutable reviewed distribution archive."""

    name: str
    url: str
    sha256: str
    maximum: int
    kind: str


ARTIFACTS = (
    Artifact(
        "temurin-jdk.tar.gz",
        "https://github.com/adoptium/temurin17-binaries/releases/download/"
        "jdk-17.0.20.1%2B1/OpenJDK17U-jdk_x64_linux_hotspot_17.0.20.1_1.tar.gz",
        helper.JAVA_ARCHIVE_SHA256,
        MAX_ARCHIVE_BYTES,
        "tar",
    ),
    Artifact(
        "gradle-bin.zip",
        "https://github.com/gradle/gradle-distributions/releases/download/"
        "v9.1.0/gradle-9.1.0-bin.zip",
        helper.GRADLE_ARCHIVE_SHA256,
        MAX_ARCHIVE_BYTES,
        "zip",
    ),
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _copy(stream: ByteReader, destination: Path, maximum: int) -> None:
    total = 0
    with destination.open("xb") as output:
        while chunk := stream.read(64 * 1024):
            total += len(chunk)
            if total > maximum:
                raise AndroidJvmInstallError("Android/JVM content exceeds its size bound")
            output.write(chunk)


def download(artifact: Artifact, destination: Path) -> None:
    source = urlsplit(artifact.url)
    if source.scheme != "https" or source.hostname not in SOURCE_HOSTS:
        raise AndroidJvmInstallError("Android/JVM download uses an unreviewed source")
    partial = destination.with_suffix(destination.suffix + ".part")
    request = Request(artifact.url, headers={"User-Agent": "agent-workflow-quality"})  # noqa: S310
    try:
        with urlopen(request, timeout=30) as response:  # noqa: S310
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname not in REDIRECT_HOSTS:
                raise AndroidJvmInstallError(
                    "Android/JVM download redirected to an unreviewed host"
                )
            _copy(response, partial, artifact.maximum)
        if _sha256(partial) != artifact.sha256:
            raise AndroidJvmInstallError(f"{artifact.name}: SHA-256 mismatch")
        partial.replace(destination)
    except Exception:
        with contextlib.suppress(OSError):
            partial.unlink()
        raise


def _member_path(name: str, top: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or path.is_absolute()
        or path.as_posix() != name.rstrip("/")
        or ".." in path.parts
        or not path.parts
        or path.parts[0] != top
    ):
        raise AndroidJvmInstallError("Android/JVM archive path is unsafe")
    relative = PurePosixPath(*path.parts[1:])
    if not relative.parts:
        raise AndroidJvmInstallError("Android/JVM archive member has no relative path")
    return relative


def _extract_tar_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    destination: Path,
    top: str,
    links: list[tuple[Path, str]],
    remaining: int,
) -> int:
    if member.isdir() and member.name.rstrip("/") == top:
        return 0
    relative = _member_path(member.name, top)
    target = destination.joinpath(*relative.parts)
    if member.isdir():
        target.mkdir(parents=True, exist_ok=True)
        return 0
    if member.issym():
        link = PurePosixPath(member.linkname)
        resolved = PurePosixPath(os.path.normpath(str(relative.parent / link)))
        if link.is_absolute() or ".." in resolved.parts:
            raise AndroidJvmInstallError("JDK archive link escapes its destination")
        links.append((target, member.linkname))
        return 0
    if not member.isfile() or member.islnk() or member.size < 0 or member.size > MAX_MEMBER_BYTES:
        raise AndroidJvmInstallError("JDK archive member is unsafe")
    if member.size > remaining:
        raise AndroidJvmInstallError("JDK extracted content exceeds its bound")
    source = archive.extractfile(member)
    if source is None:
        raise AndroidJvmInstallError("JDK archive member is unavailable")
    target.parent.mkdir(parents=True, exist_ok=True)
    _copy(source, target, MAX_MEMBER_BYTES)
    target.chmod(member.mode & 0o777)
    return member.size


def _extract_tar(archive_path: Path, destination: Path, top: str) -> None:
    with tarfile.open(archive_path, mode="r:gz") as archive:
        members = archive.getmembers()
        if not members or len(members) > MAX_MEMBERS:
            raise AndroidJvmInstallError("JDK archive member count is invalid")
        total = 0
        links: list[tuple[Path, str]] = []
        for member in members:
            total += _extract_tar_member(
                archive, member, destination, top, links, MAX_ARCHIVE_BYTES * 3 - total
            )
        for target, linkname in links:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(linkname)


def _extract_zip(archive_path: Path, destination: Path, top: str) -> None:
    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()
        if not members or len(members) > MAX_MEMBERS:
            raise AndroidJvmInstallError("Gradle archive member count is invalid")
        total = 0
        for member in members:
            if member.is_dir() and member.filename.rstrip("/") == top:
                continue
            relative = _member_path(member.filename, top)
            target = destination.joinpath(*relative.parts)
            mode = member.external_attr >> 16
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if stat.S_ISLNK(mode) or member.file_size > MAX_MEMBER_BYTES:
                raise AndroidJvmInstallError("Gradle archive member is unsafe")
            total += member.file_size
            if total > MAX_ARCHIVE_BYTES * 3:
                raise AndroidJvmInstallError("Gradle extracted content exceeds its bound")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source:
                _copy(source, target, MAX_MEMBER_BYTES)
            target.chmod((mode & 0o777) or 0o644)


def _install_wrapper(staging: Path) -> None:
    source_root = Path(__file__).resolve().parents[1] / "src/awq"
    helper_content = (source_root / "android_jvm_helper.py").read_bytes()
    report_content = (source_root / "test_reports.py").read_bytes()
    if max(len(helper_content), len(report_content)) > helper.MAX_CONFIG_BYTES:
        raise AndroidJvmInstallError("Android/JVM helper exceeds its size bound")
    library = staging / "lib/awq_android_jvm_helper.py"
    report_library = staging / "lib/awq_test_reports.py"
    wrapper = staging / "bin/awq-android-jvm-check"
    library.parent.mkdir(parents=True)
    wrapper.parent.mkdir(parents=True)
    library.write_bytes(helper_content)
    report_library.write_bytes(report_content)
    wrapper.write_bytes(WRAPPER)
    wrapper.chmod(0o755)


def _write_manifest(staging: Path) -> None:
    document = {
        "gradle_archive_sha256": helper.GRADLE_ARCHIVE_SHA256,
        "gradle_version": helper.GRADLE_VERSION,
        "helper_sha256": _sha256(staging / "lib/awq_android_jvm_helper.py"),
        "host": helper.HOST,
        "java_archive_sha256": helper.JAVA_ARCHIVE_SHA256,
        "java_version": helper.JAVA_VERSION,
        "schema_version": 1,
        "test_reports_sha256": _sha256(staging / "lib/awq_test_reports.py"),
    }
    (staging / "manifest.json").write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def verify_versions(prefix: Path) -> None:
    completed = subprocess.run(  # noqa: S603 - exact installed wrapper.
        [str(prefix / "bin/awq-android-jvm-check"), "--version"],
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    if (
        completed.returncode
        or (completed.stdout + completed.stderr).strip() != helper.VERSION_OUTPUT
    ):
        raise AndroidJvmInstallError("Android/JVM version probe mismatch")


def install(prefix: Path) -> None:
    if prefix.is_symlink() or prefix.exists() or not prefix.parent.is_dir():
        raise AndroidJvmInstallError("installation prefix must be new below an existing parent")
    with tempfile.TemporaryDirectory(prefix="awq-android-jvm-", dir=prefix.parent) as directory:
        temporary = Path(directory)
        downloads = temporary / "downloads"
        staging = temporary / "installed"
        downloads.mkdir()
        staging.mkdir(mode=0o755)
        for artifact in ARTIFACTS:
            archive = downloads / artifact.name
            download(artifact, archive)
            destination = staging / ("jdk" if artifact.kind == "tar" else "gradle")
            destination.mkdir()
            if artifact.kind == "tar":
                _extract_tar(archive, destination, "jdk-17.0.20.1+1")
            else:
                _extract_zip(archive, destination, "gradle-9.1.0")
        (staging / "runtime-gradle").mkdir(mode=0o700)
        (staging / "android-sdk").mkdir(mode=0o700)
        _install_wrapper(staging)
        _write_manifest(staging)
        verify_versions(staging)
        staging.rename(prefix)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        install(arguments.prefix.parent.resolve() / arguments.prefix.name)
    except (OSError, AndroidJvmInstallError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"Android/JVM installation failed: {error}")
        return 1
    print("Installed checksum-pinned AWQ Android/JVM tools.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
