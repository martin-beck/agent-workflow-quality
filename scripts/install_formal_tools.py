# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Install the checksum-pinned TLA+ Tools launcher into an isolated prefix."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

MAX_DOWNLOAD_BYTES = 10_000_000
ALLOWED_DOWNLOAD_HOSTS = {
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}


class FormalToolInstallError(RuntimeError):
    """The pinned formal tool failed integrity or installation checks."""


@dataclass(frozen=True)
class Artifact:
    """One immutable tool artifact."""

    name: str
    url: str
    sha256: str


TLA_TOOLS = Artifact(
    "tla2tools.jar",
    "https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar",
    "8836549e83db7f0b3f9fdde679ab56270d18e06198366d217d960738c02b9dbe",
)
GENERATED_HEADER = (
    "# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.\n"
    "# SPDX-License-Identifier: MIT\n"
)


def _wrapper(digest: str) -> bytes:
    return f"""#!/usr/bin/env python3
{GENERATED_HEADER}\
import hashlib
import os
from pathlib import Path
import shutil
import sys

jar = Path(__file__).resolve().parent.parent / "lib/tla2tools.jar"
try:
    digest = hashlib.sha256(jar.read_bytes()).hexdigest()
except OSError:
    raise SystemExit(126)
if digest != "{digest}":
    raise SystemExit(126)
if sys.argv[1:] == ["--version"]:
    print("TLC 1.8.0")
    raise SystemExit(0)
java = shutil.which("java", path=os.environ.get("PATH"))
if java is None:
    raise SystemExit(127)
os.execv(java, [java, "-XX:+UseParallelGC", "-cp", str(jar), "tlc2.TLC", *sys.argv[1:]])
""".encode()


def verify_digest(path: Path, expected: str) -> None:
    """Require the complete artifact to match its lowercase SHA-256."""
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise FormalToolInstallError(f"{path.name}: SHA-256 mismatch")


def _copy_response(stream: BinaryIO, destination: Path) -> None:
    total = 0
    with destination.open("xb") as output:
        while chunk := stream.read(64 * 1024):
            total += len(chunk)
            if total > MAX_DOWNLOAD_BYTES:
                raise FormalToolInstallError("tool download exceeds the size bound")
            output.write(chunk)


def download(artifact: Artifact, destination: Path) -> None:
    """Download one fixed HTTPS artifact with bounded bytes and redirect hosts."""
    source = urlsplit(artifact.url)
    if source.scheme != "https" or source.hostname not in ALLOWED_DOWNLOAD_HOSTS:
        raise FormalToolInstallError("tool download uses an unreviewed source")
    request = Request(artifact.url, headers={"User-Agent": "agent-workflow-quality"})  # noqa: S310
    partial = destination.with_suffix(destination.suffix + ".part")
    try:
        with urlopen(request, timeout=30) as response:  # noqa: S310
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname not in ALLOWED_DOWNLOAD_HOSTS:
                raise FormalToolInstallError("tool download redirected to an unreviewed host")
            _copy_response(response, partial)
        verify_digest(partial, artifact.sha256)
        partial.replace(destination)
    except Exception:
        with contextlib.suppress(OSError):
            partial.unlink()
        raise


def _write(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(content)
    path.chmod(mode)


def verify_version(prefix: Path) -> None:
    """Probe the installed launcher with a fixed minimal environment."""
    completed = subprocess.run(  # noqa: S603 - exact new-prefix executable.
        [str(prefix / "bin/tlc"), "--version"],
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "NO_COLOR": "1"},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if completed.returncode or completed.stdout.strip() != "TLC 1.8.0" or completed.stderr:
        raise FormalToolInstallError("installed TLC version probe mismatch")


def install(prefix: Path) -> None:
    """Download, verify, stage, probe, and atomically publish the reviewed tool."""
    if prefix.exists() or not prefix.parent.is_dir():
        raise FormalToolInstallError(
            "installation prefix must be a new path below an existing parent"
        )
    with tempfile.TemporaryDirectory(prefix="awq-formal-tools-", dir=prefix.parent) as directory:
        temporary = Path(directory)
        artifact = temporary / TLA_TOOLS.name
        staging = temporary / "installed"
        staging.mkdir(mode=0o755)
        download(TLA_TOOLS, artifact)
        _write(staging / "lib/tla2tools.jar", artifact.read_bytes(), 0o644)
        _write(staging / "bin/tlc", _wrapper(TLA_TOOLS.sha256), 0o755)
        verify_version(staging)
        staging.rename(prefix)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        install(args.prefix.resolve())
    except (OSError, FormalToolInstallError) as error:
        print(f"formal tool installation failed: {error}")
        return 1
    print("Installed checksum-pinned AWQ formal tool bundle.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
