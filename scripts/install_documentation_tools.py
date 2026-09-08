# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Install exact reviewed documentation quality tools into an isolated prefix."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

MAX_DOWNLOAD_BYTES = 15_000_000
MAX_ARCHIVE_MEMBERS = 500
MAX_MEMBER_BYTES = 60_000_000
MAX_ARCHIVE_BYTES = 100_000_000
ALLOWED_DOWNLOAD_HOSTS = {
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}


class DocumentationToolInstallError(RuntimeError):
    """A pinned documentation tool failed integrity or installation checks."""


@dataclass(frozen=True)
class Artifact:
    """One immutable archive and its reviewed executable member."""

    name: str
    url: str
    sha256: str
    member: str
    executable: str


RUMDL = Artifact(
    "rumdl.tar.gz",
    "https://github.com/rvben/rumdl/releases/download/v0.2.68/"
    "rumdl-v0.2.68-x86_64-unknown-linux-gnu.tar.gz",
    "a5fbbc1ab31400b16896f3e00192f931f766e3374ec5e31aadcd2114533f4f8b",
    "rumdl",
    "rumdl",
)
VALE = Artifact(
    "vale.tar.gz",
    "https://github.com/vale-cli/vale/releases/download/v3.20.0/vale_3.20.0_Linux_64-bit.tar.gz",
    "f59e7030c5d4ace6cf915497d0d076a1699d61e876142765963237e6867c9712",
    "vale",
    "vale",
)
ARTIFACTS = (RUMDL, VALE)
EXPECTED_VERSIONS = {
    "rumdl": "rumdl 0.2.68",
    "vale": "vale version 3.20.0",
}


def verify_digest(path: Path, expected: str) -> None:
    """Require the complete file to match one lowercase SHA-256 digest."""
    observed = hashlib.sha256(path.read_bytes()).hexdigest()
    if observed != expected:
        raise DocumentationToolInstallError(f"{path.name}: SHA-256 mismatch")


def _copy_response(stream: BinaryIO, destination: Path) -> None:
    total = 0
    with destination.open("xb") as output:
        while chunk := stream.read(64 * 1024):
            total += len(chunk)
            if total > MAX_DOWNLOAD_BYTES:
                raise DocumentationToolInstallError("tool download exceeds the size bound")
            output.write(chunk)


def download(artifact: Artifact, destination: Path) -> None:
    """Download one fixed HTTPS archive with bounded bytes and redirect hosts."""
    request = Request(artifact.url, headers={"User-Agent": "agent-workflow-quality"})  # noqa: S310
    partial = destination.with_suffix(destination.suffix + ".part")
    try:
        with urlopen(request, timeout=30) as response:  # noqa: S310
            host = urlsplit(response.geturl()).hostname
            if host not in ALLOWED_DOWNLOAD_HOSTS:
                raise DocumentationToolInstallError(
                    "tool download redirected to an unreviewed host"
                )
            _copy_response(response, partial)
        verify_digest(partial, artifact.sha256)
        partial.replace(destination)
    except Exception:
        with contextlib.suppress(OSError):
            partial.unlink()
        raise


def _checked_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = archive.getmembers()
    if not members or len(members) > MAX_ARCHIVE_MEMBERS:
        raise DocumentationToolInstallError("tool archive member count is outside the bound")
    names: set[str] = set()
    total = 0
    for member in members:
        path = PurePosixPath(member.name)
        total += member.size
        if (
            not member.name
            or path.is_absolute()
            or ".." in path.parts
            or member.name != path.as_posix()
            or member.name in names
            or member.size > MAX_MEMBER_BYTES
            or total > MAX_ARCHIVE_BYTES
        ):
            raise DocumentationToolInstallError("tool archive contains an unsafe member")
        names.add(member.name)
        if not (member.isfile() or member.isdir()):
            raise DocumentationToolInstallError("tool archive contains an unsupported member type")
    return members


def _member_bytes(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    if not member.isfile():
        raise DocumentationToolInstallError("required tool payload is not a regular file")
    stream = archive.extractfile(member)
    if stream is None:
        raise DocumentationToolInstallError("required tool payload is unreadable")
    with stream:
        value = stream.read(MAX_MEMBER_BYTES + 1)
    if len(value) > MAX_MEMBER_BYTES:
        raise DocumentationToolInstallError("required tool payload exceeds the size bound")
    return value


def _install_archive(artifact: Artifact, archive_path: Path, staging: Path) -> None:
    with tarfile.open(archive_path, mode="r:gz") as archive:
        _checked_members(archive)
        try:
            member = archive.getmember(artifact.member)
        except KeyError as error:
            raise DocumentationToolInstallError(
                f"{artifact.executable}: archive lacks the reviewed executable"
            ) from error
        destination = staging / "bin" / artifact.executable
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(_member_bytes(archive, member))
        destination.chmod(0o755)


def verify_versions(prefix: Path) -> None:
    """Execute exact probes after installation in a minimal environment."""
    environment = {
        "PATH": f"{prefix / 'bin'}:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
    }
    for name, expected in EXPECTED_VERSIONS.items():
        completed = subprocess.run(  # noqa: S603 - exact executable below new prefix.
            [str(prefix / "bin" / name), "--version"],
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        observed = (completed.stdout + completed.stderr).strip()
        if completed.returncode or observed != expected:
            raise DocumentationToolInstallError(f"{name}: installed version probe mismatch")


def install(prefix: Path) -> None:
    """Download, verify, stage, probe, and atomically publish all reviewed tools."""
    if prefix.exists() or not prefix.parent.is_dir():
        raise DocumentationToolInstallError(
            "installation prefix must be a new path below an existing parent"
        )
    with tempfile.TemporaryDirectory(prefix="awq-doc-tools-", dir=prefix.parent) as directory:
        temporary = Path(directory)
        downloads = temporary / "downloads"
        staging = temporary / "installed"
        downloads.mkdir()
        staging.mkdir(mode=0o755)
        for artifact in ARTIFACTS:
            archive_path = downloads / artifact.name
            download(artifact, archive_path)
            _install_archive(artifact, archive_path, staging)
        verify_versions(staging)
        staging.rename(prefix)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        install(args.prefix.resolve())
    except (OSError, tarfile.TarError, DocumentationToolInstallError) as error:
        print(f"documentation tool installation failed: {error}")
        return 1
    print("Installed checksum-pinned rumdl and Vale.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
