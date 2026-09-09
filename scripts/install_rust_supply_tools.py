# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Install exact Rust supply-chain tools and advisory data into a new prefix."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import awq.rust_supply_helper as helper

MAX_ARCHIVE_BYTES = 12_000_000
MAX_BINARY_BYTES = 30_000_000
ALLOWED_SOURCE_HOST = "github.com"
ASSET_HOSTS = frozenset({"release-assets.githubusercontent.com"})
ARCHIVE_HOSTS = frozenset({"codeload.github.com"})
DATABASE_ROOT = f"advisory-db-{helper.ADVISORY_COMMIT}"
WRAPPER = b"""#!/usr/bin/env python3
from pathlib import Path
import sys

prefix = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(prefix / "lib"))
from awq_rust_supply_helper import main

raise SystemExit(main())
"""


class RustSupplyInstallError(RuntimeError):
    """Pinned Rust supply tooling failed integrity or installation checks."""


@dataclass(frozen=True)
class Artifact:
    """One immutable release archive."""

    name: str
    url: str
    sha256: str
    maximum: int
    final_hosts: frozenset[str]


@dataclass(frozen=True)
class BinaryArtifact:
    """One archive containing an exact executable member."""

    artifact: Artifact
    executable: str
    member: str


CARGO_DENY = BinaryArtifact(
    Artifact(
        "cargo-deny.tar.gz",
        "https://github.com/EmbarkStudios/cargo-deny/releases/download/0.20.2/"
        "cargo-deny-0.20.2-x86_64-unknown-linux-musl.tar.gz",
        "9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f",
        MAX_ARCHIVE_BYTES,
        ASSET_HOSTS,
    ),
    "cargo-deny",
    "cargo-deny-0.20.2-x86_64-unknown-linux-musl/cargo-deny",
)
CARGO_AUDIT = BinaryArtifact(
    Artifact(
        "cargo-audit.tgz",
        "https://github.com/rustsec/rustsec/releases/download/cargo-audit/v0.22.2/"
        "cargo-audit-x86_64-unknown-linux-gnu-v0.22.2.tgz",
        "ab28a1bdb54db4d5d8ad5981cf1f959410370b3d28250dbd35f6a44248620e39",
        MAX_ARCHIVE_BYTES,
        ASSET_HOSTS,
    ),
    "cargo-audit",
    "cargo-audit-x86_64-unknown-linux-gnu-v0.22.2/cargo-audit",
)
CARGO_SEMVER_CHECKS = BinaryArtifact(
    Artifact(
        "cargo-semver-checks.tar.gz",
        "https://github.com/obi1kenobi/cargo-semver-checks/releases/download/v0.50.0/"
        "cargo-semver-checks-x86_64-unknown-linux-gnu.tar.gz",
        "52a65dc88dc53fa8b57d6087954eb52cda149ca03bcfca78ce3fdecd23f893c4",
        MAX_ARCHIVE_BYTES,
        ASSET_HOSTS,
    ),
    "cargo-semver-checks",
    "cargo-semver-checks",
)
ADVISORY_DATABASE = Artifact(
    "advisory-db.tar.gz",
    f"https://github.com/RustSec/advisory-db/archive/{helper.ADVISORY_COMMIT}.tar.gz",
    "ff54ebd7becdaa59efe2d54e516d8c1e10e7c2fb20c8d3241a20889c5000f3eb",
    1_000_000,
    ARCHIVE_HOSTS,
)
BINARIES = (CARGO_DENY, CARGO_AUDIT, CARGO_SEMVER_CHECKS)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def verify_digest(path: Path, expected: str) -> None:
    if _sha256(path) != expected:
        raise RustSupplyInstallError(f"{path.name}: SHA-256 mismatch")


def _copy_response(stream: BinaryIO, destination: Path, maximum: int) -> None:
    total = 0
    with destination.open("xb") as output:
        while chunk := stream.read(64 * 1024):
            total += len(chunk)
            if total > maximum:
                raise RustSupplyInstallError("Rust supply download exceeds the size bound")
            output.write(chunk)


def download(artifact: Artifact, destination: Path) -> None:
    source = urlsplit(artifact.url)
    if source.scheme != "https" or source.hostname != ALLOWED_SOURCE_HOST:
        raise RustSupplyInstallError("Rust supply download uses an unreviewed source")
    request = Request(artifact.url, headers={"User-Agent": "agent-workflow-quality"})  # noqa: S310
    partial = destination.with_suffix(destination.suffix + ".part")
    try:
        with urlopen(request, timeout=30) as response:  # noqa: S310
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname not in artifact.final_hosts:
                raise RustSupplyInstallError(
                    "Rust supply download redirected to an unreviewed host"
                )
            _copy_response(response, partial, artifact.maximum)
        verify_digest(partial, artifact.sha256)
        partial.replace(destination)
    except Exception:
        with contextlib.suppress(OSError):
            partial.unlink()
        raise


def _safe_member(member: tarfile.TarInfo) -> PurePosixPath:
    name = member.name
    path = PurePosixPath(name)
    if (
        not name
        or name.startswith("/")
        or "\\" in name
        or ".." in path.parts
        or name != path.as_posix()
    ):
        raise RustSupplyInstallError("Rust supply archive contains an unsafe path")
    if member.issym() or member.islnk() or member.isdev() or member.isfifo():
        raise RustSupplyInstallError("Rust supply archive contains an unsafe member")
    return path


def _copy_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    destination: Path,
    maximum: int,
) -> None:
    if not member.isfile() or member.size < 0 or member.size > maximum:
        raise RustSupplyInstallError("Rust supply archive member exceeds its safety bound")
    stream = archive.extractfile(member)
    if stream is None:
        raise RustSupplyInstallError("Rust supply archive member is unavailable")
    total = 0
    with stream, destination.open("xb") as output:
        while chunk := stream.read(64 * 1024):
            total += len(chunk)
            if total > maximum or total > member.size:
                raise RustSupplyInstallError("Rust supply archive member exceeds its safety bound")
            output.write(chunk)
    if total != member.size:
        raise RustSupplyInstallError("Rust supply archive member is truncated")


def extract_binary(bundle: BinaryArtifact, archive_path: Path, staging: Path) -> None:
    destination = staging / "bin" / bundle.executable
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 100:
            raise RustSupplyInstallError("Rust supply binary archive has too many members")
        selected: tarfile.TarInfo | None = None
        for member in members:
            path = _safe_member(member)
            if path.as_posix() == bundle.member:
                if selected is not None:
                    raise RustSupplyInstallError("Rust supply archive repeats its executable")
                selected = member
        if selected is None:
            raise RustSupplyInstallError("Rust supply archive lacks its reviewed executable")
        _copy_member(archive, selected, destination, MAX_BINARY_BYTES)
    expected = helper.TOOL_METADATA[bundle.executable]["binary_sha256"]
    verify_digest(destination, str(expected))
    destination.chmod(0o755)


def extract_advisory_database(archive_path: Path, staging: Path) -> None:
    destination = staging / "advisory-db"
    destination.mkdir()
    file_count = 0
    entry_count = 0
    total = 0
    with tarfile.open(archive_path, mode="r:gz") as archive:
        for member in archive:
            path = _safe_member(member)
            entry_count += 1
            if entry_count > helper.MAX_TREE_ENTRIES:
                raise RustSupplyInstallError("advisory archive has too many entries")
            if not path.parts or path.parts[0] != DATABASE_ROOT:
                raise RustSupplyInstallError("advisory archive has an unreviewed root")
            relative = PurePosixPath(*path.parts[1:])
            if not relative.parts:
                if not member.isdir():
                    raise RustSupplyInstallError("advisory archive root is invalid")
                continue
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise RustSupplyInstallError("advisory archive contains an unsafe member")
            file_count += 1
            total += member.size
            if (
                file_count > helper.MAX_TREE_FILES
                or member.size > helper.MAX_DOCUMENT_BYTES
                or total > helper.MAX_TREE_BYTES
            ):
                raise RustSupplyInstallError("advisory archive exceeds its safety bound")
            target.parent.mkdir(parents=True, exist_ok=True)
            _copy_member(archive, member, target, helper.MAX_DOCUMENT_BYTES)
    if helper._tree_sha256(destination) != helper.ADVISORY_TREE_SHA256:
        raise RustSupplyInstallError("advisory database tree integrity mismatch")


def _verify_rust_prefix(rust_prefix: Path) -> Path:
    path = rust_prefix.resolve()
    if (
        rust_prefix.is_symlink()
        or not rust_prefix.is_absolute()
        or not rust_prefix.is_dir()
        or path != rust_prefix
    ):
        raise RustSupplyInstallError("Rust tool prefix is unavailable")
    wrapper = rust_prefix / "bin/awq-rust-check"
    if (
        wrapper.is_symlink()
        or not wrapper.is_file()
        or wrapper.resolve(strict=True) != wrapper
        or not os.access(wrapper, os.X_OK)
    ):
        raise RustSupplyInstallError("Rust tool prefix lacks the reviewed wrapper")
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    completed = subprocess.run(  # noqa: S603 - exact absolute existing wrapper.
        [str(wrapper), "--version"],
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if (
        completed.returncode
        or (completed.stdout + completed.stderr).strip() != helper.RUST_WRAPPER_VERSION
    ):
        raise RustSupplyInstallError("Rust tool prefix version probe mismatch")
    return rust_prefix


def _install_wrapper(staging: Path) -> None:
    source = Path(__file__).resolve().parents[1] / "src/awq/rust_supply_helper.py"
    content = source.read_bytes()
    if len(content) > helper.MAX_DOCUMENT_BYTES:
        raise RustSupplyInstallError("Rust supply helper exceeds the size bound")
    library = staging / "lib/awq_rust_supply_helper.py"
    wrapper = staging / "bin/awq-rust-supply-check"
    library.parent.mkdir(parents=True)
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    library.write_bytes(content)
    wrapper.write_bytes(WRAPPER)
    wrapper.chmod(0o755)


def _write_manifest(staging: Path, rust_prefix: Path) -> None:
    document = {
        "advisory_db": {
            "archive_sha256": ADVISORY_DATABASE.sha256,
            "commit": helper.ADVISORY_COMMIT,
            "expires_at": helper.ADVISORY_EXPIRES_AT,
            "snapshot_at": "2026-09-08T09:58:15Z",
            "tree_sha256": helper.ADVISORY_TREE_SHA256,
        },
        "rust_tools_prefix": str(rust_prefix),
        "schema_version": 1,
        "tools": helper.TOOL_METADATA,
    }
    (staging / "manifest.json").write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def verify_versions(prefix: Path) -> None:
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    completed = subprocess.run(  # noqa: S603 - exact installed wrapper.
        [str(prefix / "bin/awq-rust-supply-check"), "--version"],
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if (
        completed.returncode
        or (completed.stdout + completed.stderr).strip() != helper.VERSION_OUTPUT
    ):
        raise RustSupplyInstallError("installed Rust supply version probe mismatch")


def install(prefix: Path, rust_tools_prefix: Path) -> None:
    if prefix.is_symlink() or prefix.exists() or not prefix.parent.is_dir():
        raise RustSupplyInstallError(
            "installation prefix must be a new path below an existing parent"
        )
    rust_prefix = _verify_rust_prefix(rust_tools_prefix)
    with tempfile.TemporaryDirectory(prefix="awq-rust-supply-", dir=prefix.parent) as directory:
        temporary = Path(directory)
        downloads = temporary / "downloads"
        staging = temporary / "installed"
        downloads.mkdir()
        staging.mkdir(mode=0o755)
        for bundle in BINARIES:
            archive_path = downloads / bundle.artifact.name
            download(bundle.artifact, archive_path)
            extract_binary(bundle, archive_path, staging)
        database_archive = downloads / ADVISORY_DATABASE.name
        download(ADVISORY_DATABASE, database_archive)
        extract_advisory_database(database_archive, staging)
        _install_wrapper(staging)
        _write_manifest(staging, rust_prefix)
        verify_versions(staging)
        staging.rename(prefix)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", required=True, type=Path)
    parser.add_argument("--rust-tools-prefix", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        install(
            args.prefix.parent.resolve() / args.prefix.name,
            args.rust_tools_prefix.parent.resolve() / args.rust_tools_prefix.name,
        )
    except (
        OSError,
        tarfile.TarError,
        subprocess.SubprocessError,
        RustSupplyInstallError,
    ) as error:
        print(f"Rust supply tool installation failed: {error}")
        return 1
    print("Installed checksum-pinned AWQ Rust supply tooling.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
