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
# release digest and preserve the exact version probes in the adapter catalog. The actionlint
# and gitleaks values below match the vendors' published checksum manifests; zizmor publishes
# no checksum manifest, so its GitHub release asset bytes were downloaded and hashed independently
# on 2026-09-14. Release provenance is retained in the AR-0039 coordination record.
ARTIFACTS = {
    "x86_64": (
        Artifact(
            "actionlint",
            "1.7.7",
            "https://github.com/rhysd/actionlint/releases/download/v1.7.7/actionlint_1.7.7_linux_amd64.tar.gz",
            "023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757",
        ),
        Artifact(
            "zizmor",
            "1.30.1",
            "https://github.com/zizmorcore/zizmor/releases/download/v1.30.1/zizmor-x86_64-unknown-linux-gnu.tar.gz",
            "e65324f4430c2717591937edcec90ccbefaf14c174f8ec9415e03ca875b46e1a",
        ),
        Artifact(
            "gitleaks",
            "8.28.0",
            "https://github.com/gitleaks/gitleaks/releases/download/v8.28.0/gitleaks_8.28.0_linux_x64.tar.gz",
            "a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb",
        ),
    ),
    "aarch64": (
        Artifact(
            "actionlint",
            "1.7.7",
            "https://github.com/rhysd/actionlint/releases/download/v1.7.7/actionlint_1.7.7_linux_arm64.tar.gz",
            "401942f9c24ed71e4fe71b76c7d638f66d8633575c4016efd2977ce7c28317d0",
        ),
        Artifact(
            "zizmor",
            "1.30.1",
            "https://github.com/zizmorcore/zizmor/releases/download/v1.30.1/zizmor-aarch64-unknown-linux-gnu.tar.gz",
            "7ff1dce33bdd18fd2a4affe63bdd47efcccca97b2cec1c1863ec26e9e2647540",
        ),
        Artifact(
            "gitleaks",
            "8.28.0",
            "https://github.com/gitleaks/gitleaks/releases/download/v8.28.0/gitleaks_8.28.0_linux_arm64.tar.gz",
            "eff65261156100e5d94a6b3dec313d532fddfe19ae1590bf7a2b4f2699128356",
        ),
    ),
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
