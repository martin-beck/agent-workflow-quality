# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Install the exact reviewed schema-check tool bundle into an isolated prefix."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import stat
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

MAX_DOWNLOAD_BYTES = 20_000_000
MAX_ARCHIVE_MEMBERS = 2_000
MAX_MEMBER_BYTES = 20_000_000
MAX_ARCHIVE_BYTES = 80_000_000
ALLOWED_DOWNLOAD_HOSTS = {
    "files.pythonhosted.org",
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}


class SchemaToolInstallError(RuntimeError):
    """A pinned schema tool failed integrity or installation checks."""


@dataclass(frozen=True)
class Artifact:
    """One immutable ZIP-format artifact."""

    name: str
    url: str
    sha256: str


JSONSCHEMA = Artifact(
    "jsonschema.zip",
    "https://github.com/sourcemeta/jsonschema/releases/download/v16.3.0/"
    "jsonschema-16.3.0-linux-x86_64.zip",
    "d348714cfceeedf521cffecb13c199ba4b08fd865dc23c985f2de44fda39a9c4",
)
STRICTYAML = Artifact(
    "strictyaml.whl",
    "https://files.pythonhosted.org/packages/96/7c/"
    "a81ef5ef10978dd073a854e0fa93b5d8021d0594b639cc8f6453c3c78a1d/"
    "strictyaml-1.7.3-py3-none-any.whl",
    "fb5c8a4edb43bebb765959e420f9b3978d7f1af88c80606c03fb420888f5d1c7",
)
DATEUTIL = Artifact(
    "python-dateutil.whl",
    "https://files.pythonhosted.org/packages/ec/57/"
    "56b9bcc3c9c6a792fcbaf139543cee77261f3651ca9da0c93f5c1221264b/"
    "python_dateutil-2.9.0.post0-py2.py3-none-any.whl",
    "a8b2bc7bffae282281c8140a97d3aa9c14da0b136dfe83f850eea9a5f7470427",
)
SIX = Artifact(
    "six.whl",
    "https://files.pythonhosted.org/packages/b7/ce/"
    "149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/"
    "six-1.17.0-py2.py3-none-any.whl",
    "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274",
)
ARTIFACTS = (JSONSCHEMA, STRICTYAML, DATEUTIL, SIX)
JSONSCHEMA_MEMBER = "jsonschema-16.3.0-linux-x86_64/bin/jsonschema"
WRAPPER = b"""#!/usr/bin/env python3
from pathlib import Path
import sys

prefix = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(prefix / "lib"))
from awq_schema_helper import main

raise SystemExit(main())
"""


def verify_digest(path: Path, expected: str) -> None:
    """Require the complete file to match one lowercase SHA-256 digest."""
    observed = hashlib.sha256(path.read_bytes()).hexdigest()
    if observed != expected:
        raise SchemaToolInstallError(f"{path.name}: SHA-256 mismatch")


def _copy_response(stream: BinaryIO, destination: Path) -> None:
    total = 0
    with destination.open("xb") as output:
        while chunk := stream.read(64 * 1024):
            total += len(chunk)
            if total > MAX_DOWNLOAD_BYTES:
                raise SchemaToolInstallError("tool download exceeds the size bound")
            output.write(chunk)


def download(artifact: Artifact, destination: Path) -> None:
    """Download one fixed HTTPS artifact with bounded bytes and redirect hosts."""
    source = urlsplit(artifact.url)
    if source.scheme != "https" or source.hostname not in ALLOWED_DOWNLOAD_HOSTS:
        raise SchemaToolInstallError("tool download uses an unreviewed source")
    request = Request(artifact.url, headers={"User-Agent": "agent-workflow-quality"})  # noqa: S310
    partial = destination.with_suffix(destination.suffix + ".part")
    try:
        with urlopen(request, timeout=30) as response:  # noqa: S310
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname not in ALLOWED_DOWNLOAD_HOSTS:
                raise SchemaToolInstallError("tool download redirected to an unreviewed host")
            _copy_response(response, partial)
        verify_digest(partial, artifact.sha256)
        partial.replace(destination)
    except Exception:
        with contextlib.suppress(OSError):
            partial.unlink()
        raise


def _checked_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = archive.infolist()
    if not members or len(members) > MAX_ARCHIVE_MEMBERS:
        raise SchemaToolInstallError("tool archive member count is outside the bound")
    names: set[str] = set()
    total = 0
    for member in members:
        path = PurePosixPath(member.filename)
        mode = (member.external_attr >> 16) & 0o170000
        total += member.file_size
        if (
            not member.filename
            or path.is_absolute()
            or ".." in path.parts
            or member.filename != path.as_posix() + ("/" if member.is_dir() else "")
            or member.filename in names
            or member.file_size > MAX_MEMBER_BYTES
            or total > MAX_ARCHIVE_BYTES
            or mode not in {0, stat.S_IFREG, stat.S_IFDIR}
        ):
            raise SchemaToolInstallError("tool archive contains an unsafe member")
        names.add(member.filename)
    return members


def _member_bytes(archive: zipfile.ZipFile, member: zipfile.ZipInfo) -> bytes:
    if member.is_dir():
        raise SchemaToolInstallError("required tool payload is not a regular file")
    with archive.open(member, mode="r") as stream:
        value = stream.read(MAX_MEMBER_BYTES + 1)
    if len(value) > MAX_MEMBER_BYTES:
        raise SchemaToolInstallError("required tool payload exceeds the size bound")
    return value


def _write(path: Path, content: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(content)
    path.chmod(mode)


def _install_jsonschema(archive_path: Path, staging: Path) -> None:
    with zipfile.ZipFile(archive_path) as archive:
        _checked_members(archive)
        try:
            member = archive.getinfo(JSONSCHEMA_MEMBER)
        except KeyError as error:
            raise SchemaToolInstallError("archive lacks the reviewed JSON Schema CLI") from error
        _write(staging / "bin/jsonschema", _member_bytes(archive, member), 0o755)


def _selected_python_member(artifact: Artifact, name: str) -> bool:
    if artifact == STRICTYAML:
        return name.startswith("strictyaml/") and name.endswith(".py")
    if artifact == DATEUTIL:
        return name.startswith("dateutil/") and name.endswith((".py", ".txt"))
    return artifact == SIX and name == "six.py"


def _install_python_artifact(artifact: Artifact, archive_path: Path, staging: Path) -> None:
    copied = 0
    with zipfile.ZipFile(archive_path) as archive:
        for member in _checked_members(archive):
            if member.is_dir() or not _selected_python_member(artifact, member.filename):
                continue
            _write(staging / "lib" / member.filename, _member_bytes(archive, member))
            copied += 1
    if not copied:
        raise SchemaToolInstallError(f"{artifact.name}: archive lacks reviewed Python payload")


def _install_wrapper(staging: Path) -> None:
    helper = Path(__file__).resolve().parents[1] / "src/awq/schema_helper.py"
    content = helper.read_bytes()
    if len(content) > MAX_MEMBER_BYTES:
        raise SchemaToolInstallError("schema helper source exceeds the size bound")
    _write(staging / "lib/awq_schema_helper.py", content)
    _write(staging / "bin/awq-schema-check", WRAPPER, 0o755)


def verify_versions(prefix: Path) -> None:
    """Execute exact probes after installation in a minimal environment."""
    environment = {
        "PATH": f"{prefix / 'bin'}:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
    }
    expected = {
        "jsonschema": "16.3.0",
        "awq-schema-check": ("awq-schema-check 1.0.0 (StrictYAML 1.7.3; JSON Schema CLI 16.3.0)"),
    }
    for name, output in expected.items():
        completed = subprocess.run(  # noqa: S603 - exact executable below the new prefix.
            [str(prefix / "bin" / name), "--version"],
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        observed = (completed.stdout + completed.stderr).strip()
        if completed.returncode or observed != output:
            raise SchemaToolInstallError(f"{name}: installed version probe mismatch")


def install(prefix: Path) -> None:
    """Download, verify, stage, probe, and atomically publish the reviewed bundle."""
    if prefix.exists() or not prefix.parent.is_dir():
        raise SchemaToolInstallError(
            "installation prefix must be a new path below an existing parent"
        )
    with tempfile.TemporaryDirectory(prefix="awq-schema-tools-", dir=prefix.parent) as directory:
        temporary = Path(directory)
        downloads = temporary / "downloads"
        staging = temporary / "installed"
        downloads.mkdir()
        staging.mkdir(mode=0o755)
        for artifact in ARTIFACTS:
            target = downloads / artifact.name
            download(artifact, target)
            if artifact == JSONSCHEMA:
                _install_jsonschema(target, staging)
            else:
                _install_python_artifact(artifact, target, staging)
        _install_wrapper(staging)
        verify_versions(staging)
        staging.rename(prefix)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        install(args.prefix.resolve())
    except (OSError, zipfile.BadZipFile, SchemaToolInstallError) as error:
        print(f"schema tool installation failed: {error}")
        return 1
    print("Installed checksum-pinned AWQ schema check bundle.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
