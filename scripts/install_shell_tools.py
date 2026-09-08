# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Install exact reviewed shell quality tools into an isolated prefix."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import posixpath
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

MAX_DOWNLOAD_BYTES = 20_000_000
MAX_ARCHIVE_MEMBERS = 2_000
MAX_MEMBER_BYTES = 20_000_000
ALLOWED_DOWNLOAD_HOSTS = {
    "codeload.github.com",
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}


class ShellToolInstallError(RuntimeError):
    """A pinned tool artifact failed integrity or installation checks."""


@dataclass(frozen=True)
class Artifact:
    """One immutable download and its reviewed digest."""

    name: str
    url: str
    sha256: str


SHELLCHECK = Artifact(
    "shellcheck.tar.xz",
    "https://github.com/koalaman/shellcheck/releases/download/v0.11.0/"
    "shellcheck-v0.11.0.linux.x86_64.tar.xz",
    "8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198",
)
SHFMT = Artifact(
    "shfmt",
    "https://github.com/mvdan/sh/releases/download/v3.14.1/shfmt_v3.14.1_linux_amd64",
    "76e77641faa025814b77f153b29796b8e6fa2fca03e0c76a691608b86c7ea7bf",
)
BATS = Artifact(
    "bats-core.tar.gz",
    "https://codeload.github.com/bats-core/bats-core/tar.gz/"
    "eb7f42f8d608ac693d7a4b67474f6714ea68cfc5",
    "845574549f4c9777bf02fcdf307f1bf347d40c66920fb6b47dcc8fdfa065ac39",
)
BATS_ROOT = "bats-core-eb7f42f8d608ac693d7a4b67474f6714ea68cfc5"
BATS_PAYLOAD_PREFIXES = ("bin/", "lib/bats-core/", "libexec/bats-core/")
EXPECTED_VERSIONS = {
    "shellcheck": (
        "ShellCheck - shell script analysis tool\n"
        "version: 0.11.0\n"
        "license: GNU General Public License, version 3\n"
        "website: https://www.shellcheck.net"
    ),
    "shfmt": "v3.14.1",
    "bats": "Bats 1.14.0",
}


def verify_digest(path: Path, expected: str) -> None:
    """Require the complete file to match one lowercase SHA-256 digest."""
    observed = hashlib.sha256(path.read_bytes()).hexdigest()
    if observed != expected:
        raise ShellToolInstallError(f"{path.name}: SHA-256 mismatch")


def _copy_response(stream: BinaryIO, destination: Path) -> None:
    total = 0
    with destination.open("xb") as output:
        while chunk := stream.read(64 * 1024):
            total += len(chunk)
            if total > MAX_DOWNLOAD_BYTES:
                raise ShellToolInstallError("tool download exceeds the size bound")
            output.write(chunk)


def download(artifact: Artifact, destination: Path) -> None:
    """Download one fixed HTTPS artifact with bounded bytes and redirect hosts."""
    request = Request(artifact.url, headers={"User-Agent": "agent-workflow-quality"})  # noqa: S310
    partial = destination.with_suffix(destination.suffix + ".part")
    try:
        with urlopen(request, timeout=30) as response:  # noqa: S310
            host = urlsplit(response.geturl()).hostname
            if host not in ALLOWED_DOWNLOAD_HOSTS:
                raise ShellToolInstallError("tool download redirected to an unreviewed host")
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
        raise ShellToolInstallError("tool archive member count is outside the bound")
    names: set[str] = set()
    for member in members:
        path = PurePosixPath(member.name)
        if (
            not member.name
            or path.is_absolute()
            or ".." in path.parts
            or member.name != path.as_posix()
            or member.name in names
            or member.size > MAX_MEMBER_BYTES
        ):
            raise ShellToolInstallError("tool archive contains an unsafe member")
        names.add(member.name)
        if member.issym():
            target = posixpath.normpath(
                posixpath.join(posixpath.dirname(member.name), member.linkname)
            )
            top = path.parts[0]
            if target != top and not target.startswith(top + "/"):
                raise ShellToolInstallError("tool archive symlink escapes its root")
        elif not (member.isfile() or member.isdir()):
            raise ShellToolInstallError("tool archive contains an unsupported member type")
    return members


def _member_bytes(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    if not member.isfile():
        raise ShellToolInstallError("required tool payload is not a regular file")
    stream = archive.extractfile(member)
    if stream is None:
        raise ShellToolInstallError("required tool payload is unreadable")
    with stream:
        value = stream.read(MAX_MEMBER_BYTES + 1)
    if len(value) > MAX_MEMBER_BYTES:
        raise ShellToolInstallError("required tool payload exceeds the size bound")
    return value


def _write_executable(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(content)
    path.chmod(0o755)


def install_shellcheck(archive_path: Path, prefix: Path) -> None:
    """Copy only the reviewed ShellCheck executable from its archive."""
    with tarfile.open(archive_path, mode="r:xz") as archive:
        _checked_members(archive)
        member = archive.getmember("shellcheck-v0.11.0/shellcheck")
        _write_executable(prefix / "bin/shellcheck", _member_bytes(archive, member))


def install_bats(archive_path: Path, prefix: Path) -> None:
    """Copy only Bats runtime files without executing upstream scripts."""
    with tarfile.open(archive_path, mode="r:gz") as archive:
        members = _checked_members(archive)
        copied = 0
        for member in members:
            try:
                relative = PurePosixPath(member.name).relative_to(BATS_ROOT)
            except ValueError as error:
                raise ShellToolInstallError(
                    "Bats archive member is outside the reviewed root"
                ) from error
            relative_name = relative.as_posix()
            if not member.isfile() or not relative_name.startswith(BATS_PAYLOAD_PREFIXES):
                continue
            _write_executable(prefix / relative, _member_bytes(archive, member))
            copied += 1
    if copied < 10 or not (prefix / "bin/bats").is_file():
        raise ShellToolInstallError("Bats archive lacks its reviewed runtime payload")


def verify_versions(prefix: Path) -> None:
    """Execute exact probes after installation."""
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
            raise ShellToolInstallError(f"{name}: installed version probe mismatch")


def install(prefix: Path) -> None:
    """Download, verify, install, and probe all reviewed tools."""
    if prefix.exists() or not prefix.parent.is_dir():
        raise ShellToolInstallError(
            "installation prefix must be a new path below an existing parent"
        )
    with tempfile.TemporaryDirectory(prefix="awq-shell-tools-", dir=prefix.parent) as directory:
        temporary = Path(directory)
        staging = temporary / "installed"
        downloads = temporary / "downloads"
        downloads.mkdir()
        for artifact in (SHELLCHECK, SHFMT, BATS):
            download(artifact, downloads / artifact.name)
        staging.mkdir(mode=0o755)
        install_shellcheck(downloads / SHELLCHECK.name, staging)
        _write_executable(staging / "bin/shfmt", (downloads / SHFMT.name).read_bytes())
        install_bats(downloads / BATS.name, staging)
        verify_versions(staging)
        staging.rename(prefix)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        install(args.prefix.resolve())
    except (OSError, tarfile.TarError, ShellToolInstallError) as error:
        print(f"shell tool installation failed: {error}")
        return 1
    print("Installed checksum-pinned ShellCheck, shfmt, and Bats.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
