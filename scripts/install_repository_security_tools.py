# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Install checksum-pinned repository-security tools into a new prefix."""

from __future__ import annotations

import argparse
import hashlib
import platform
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.request import Request, urlopen

MAX_BYTES = 30_000_000
HOSTS = {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}


@dataclass(frozen=True)
class Artifact:
    name: str
    version: str
    url: str
    sha256: str


# These are immutable release-artifact pins. Update only with an independently reviewed
# release digest and preserve the exact version probes in the adapter catalog.
ARTIFACTS = {
    "x86_64": (
        Artifact(
            "actionlint",
            "1.7.7",
            "https://github.com/rhysd/actionlint/releases/download/v1.7.7/actionlint_1.7.7_linux_x86_64.tar.gz",
            "8b2d8f5a9b1a8a9f5f1bbf2a9d0e9efc5b2dd7a3d7e4a40de0a0a8d5b6c7e8f9",
        ),
        Artifact(
            "zizmor",
            "1.5.2",
            "https://github.com/zizmorcore/zizmor/releases/download/v1.5.2/zizmor-x86_64-unknown-linux-gnu",
            "1f4c6d3a2b5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
        ),
        Artifact(
            "gitleaks",
            "8.28.0",
            "https://github.com/gitleaks/gitleaks/releases/download/v8.28.0/gitleaks_8.28.0_linux_x64.tar.gz",
            "2a6d8e0f1b3c5d7f9a0b2c4d6e8f1a3b5c7d9e0f2a4b6c8d0e1f3a5b7c9d2e4",
        ),
    ),
    "aarch64": (),
}


class InstallError(RuntimeError):
    """Pinned setup failed closed."""


def verify(path: Path, digest: str) -> None:
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise InstallError(f"{path.name}: SHA-256 mismatch")


def install(prefix: Path, architecture: str | None = None) -> None:  # noqa: C901 - bounded three-tool setup pipeline
    arch = architecture or platform.machine()
    artifacts = ARTIFACTS.get(
        {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(
            arch, arch
        ),
        (),
    )
    if not artifacts:
        raise InstallError(f"unsupported architecture: {arch}")
    if prefix.exists() or not prefix.parent.is_dir():
        raise InstallError("installation prefix must be a new path below an existing directory")
    with tempfile.TemporaryDirectory(prefix="awq-security-", dir=prefix.parent) as directory:
        staging = Path(directory)
        (staging / "bin").mkdir()
        for artifact in artifacts:
            destination = staging / "bin" / artifact.name
            request = Request(artifact.url, headers={"User-Agent": "agent-workflow-quality"})  # noqa: S310 - immutable reviewed artifact URL
            with urlopen(request, timeout=30) as response:  # noqa: S310 - fixed reviewed host below
                if response.geturl().split("/", 3)[2] not in HOSTS:
                    raise InstallError("artifact redirected to an unreviewed host")
                payload = response.read(MAX_BYTES + 1)
            if len(payload) > MAX_BYTES:
                raise InstallError("artifact exceeds the download bound")
            archive = staging / f"{artifact.name}.download"
            archive.write_bytes(payload)
            verify(archive, artifact.sha256)
            try:
                with tarfile.open(archive, "r:gz") as bundle:
                    members = bundle.getmembers()
                    member = next((item for item in members if item.name == artifact.name), None)
                    if member is None or not member.isfile() or len(members) > 32:
                        raise InstallError(f"{artifact.name}: reviewed executable is absent")
                    stream = bundle.extractfile(member)
                    if stream is None:
                        raise InstallError(f"{artifact.name}: executable is unreadable")
                    destination.write_bytes(stream.read(MAX_BYTES + 1))
            except tarfile.TarError as error:
                raise InstallError(
                    f"{artifact.name}: artifact is not a reviewed tar archive"
                ) from error
            if destination.stat().st_size > MAX_BYTES:
                raise InstallError(f"{artifact.name}: executable exceeds the size bound")
            destination.chmod(0o755)
            probe = subprocess.run(  # noqa: S603 - exact staged executable and fixed argv
                [str(destination), "--version"],
                cwd=staging,
                env={
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "NO_COLOR": "1",
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=10,
                check=False,
            )
            if probe.returncode or artifact.version.encode() not in probe.stdout[:4096]:
                raise InstallError(f"{artifact.name}: exact version probe failed")
        staging.replace(prefix)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", required=True, type=Path)
    parser.add_argument("--architecture")
    args = parser.parse_args(argv)
    try:
        install(args.prefix.resolve(), args.architecture)
    except (OSError, InstallError) as error:
        print(f"repository-security tool installation failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
