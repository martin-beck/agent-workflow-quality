# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Install checksum-pinned advanced Rust tools into a new isolated prefix."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import awq.rust_advanced_helper as helper

MAX_ARCHIVE_BYTES = 15_000_000
MAX_BINARY_BYTES = 30_000_000
MAX_MANIFEST_BYTES = 1_100_000
SOURCE_HOSTS = frozenset({"github.com", "static.rust-lang.org"})
REDIRECT_HOSTS = frozenset({"release-assets.githubusercontent.com", "static.rust-lang.org"})
WRAPPER = b"""#!/usr/bin/env python3
from pathlib import Path
import sys

prefix = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(prefix / "lib"))
from awq_rust_advanced_helper import main

raise SystemExit(main())
"""


class ByteReader(Protocol):
    """A bounded binary stream used by HTTP and tar readers."""

    def read(self, size: int = -1) -> bytes:
        """Read at most size bytes."""
        ...


class RustAdvancedInstallError(RuntimeError):
    """Advanced Rust installation failed its integrity contract."""


@dataclass(frozen=True)
class Artifact:
    """One immutable reviewed download."""

    name: str
    url: str
    sha256: str
    maximum: int
    executable: str = ""


ARTIFACTS = (
    Artifact(
        "cargo-fuzz.tar.gz",
        "https://github.com/rust-fuzz/cargo-fuzz/releases/download/0.13.2/"
        "cargo-fuzz-0.13.2-x86_64-unknown-linux-musl.tar.gz",
        str(helper.TOOL_METADATA["cargo-fuzz"]["archive_sha256"]),
        MAX_ARCHIVE_BYTES,
        "cargo-fuzz",
    ),
    Artifact(
        "cargo-llvm-cov.tar.gz",
        "https://github.com/taiki-e/cargo-llvm-cov/releases/download/v0.9.1/"
        "cargo-llvm-cov-x86_64-unknown-linux-musl.tar.gz",
        str(helper.TOOL_METADATA["cargo-llvm-cov"]["archive_sha256"]),
        MAX_ARCHIVE_BYTES,
        "cargo-llvm-cov",
    ),
    Artifact(
        "cargo-mutants.tar.gz",
        "https://github.com/sourcefrog/cargo-mutants/releases/download/v27.1.0/"
        "cargo-mutants-x86_64-unknown-linux-gnu.tar.gz",
        str(helper.TOOL_METADATA["cargo-mutants"]["archive_sha256"]),
        MAX_ARCHIVE_BYTES,
        "cargo-mutants",
    ),
)
NIGHTLY_MANIFEST = Artifact(
    "channel-rust-nightly-2026-09-01.toml",
    "https://static.rust-lang.org/dist/2026-09-01/channel-rust-nightly.toml",
    str(helper.TOOLCHAIN_METADATA["nightly"]["manifest_sha256"]),
    MAX_MANIFEST_BYTES,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _copy_response(stream: ByteReader, destination: Path, maximum: int) -> None:
    total = 0
    with destination.open("xb") as output:
        while chunk := stream.read(64 * 1024):
            total += len(chunk)
            if total > maximum:
                raise RustAdvancedInstallError("advanced Rust download exceeds its size bound")
            output.write(chunk)


def download(artifact: Artifact, destination: Path) -> None:
    source = urlsplit(artifact.url)
    if source.scheme != "https" or source.hostname not in SOURCE_HOSTS:
        raise RustAdvancedInstallError("advanced Rust download uses an unreviewed source")
    partial = destination.with_suffix(destination.suffix + ".part")
    request = Request(artifact.url, headers={"User-Agent": "agent-workflow-quality"})  # noqa: S310
    try:
        with urlopen(request, timeout=30) as response:  # noqa: S310
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname not in REDIRECT_HOSTS:
                raise RustAdvancedInstallError(
                    "advanced Rust download redirected to an unreviewed host"
                )
            _copy_response(response, partial, artifact.maximum)
        if _sha256(partial) != artifact.sha256:
            raise RustAdvancedInstallError(f"{artifact.name}: SHA-256 mismatch")
        partial.replace(destination)
    except Exception:
        with contextlib.suppress(OSError):
            partial.unlink()
        raise


def _extract_binary(artifact: Artifact, archive_path: Path, staging: Path) -> None:
    destination = staging / "bin" / artifact.executable
    with tarfile.open(archive_path, mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) != 1:
            raise RustAdvancedInstallError("advanced Rust archive shape is invalid")
        member = members[0]
        path = PurePosixPath(member.name)
        if (
            not member.isfile()
            or member.issym()
            or member.islnk()
            or member.name != artifact.executable
            or path.as_posix() != member.name
            or member.size < 1
            or member.size > MAX_BINARY_BYTES
        ):
            raise RustAdvancedInstallError("advanced Rust archive member is unsafe")
        source = archive.extractfile(member)
        if source is None:
            raise RustAdvancedInstallError("advanced Rust archive member is unavailable")
        _copy_response(source, destination, MAX_BINARY_BYTES)
    expected = str(helper.TOOL_METADATA[artifact.executable]["binary_sha256"])
    if _sha256(destination) != expected:
        raise RustAdvancedInstallError("advanced Rust executable integrity mismatch")
    destination.chmod(0o755)


def _rustup_environment(staging: Path, temporary: Path) -> dict[str, str]:
    return {
        "PATH": f"{staging / 'cargo/bin'}:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "CARGO_HOME": str(staging / "cargo"),
        "RUSTUP_HOME": str(staging / "rustup"),
        "RUSTUP_AUTO_INSTALL": "0",
        "RUSTUP_DIST_SERVER": "https://static.rust-lang.org",
        "RUSTUP_NO_UPDATE_CHECK": "1",
        "RUSTUP_UPDATE_ROOT": "https://static.rust-lang.org/rustup",
        "TMPDIR": str(temporary),
    }


def _bounded_process(
    argv: list[str], env: dict[str, str], timeout: int, *, capture_output: bool = False
) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(  # noqa: S603 - exact reviewed executables and argv.
        argv,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
        stderr=subprocess.PIPE if capture_output else subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise RustAdvancedInstallError(
            "advanced Rust installation command exceeded its deadline"
        ) from error
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


def _rustup(staging: Path, temporary: Path, arguments: list[str], timeout: int = 900) -> None:
    rustup = staging / "cargo/bin/rustup"
    completed = _bounded_process(
        [str(rustup), *arguments],
        _rustup_environment(staging, temporary),
        timeout,
    )
    if completed.returncode:
        raise RustAdvancedInstallError("rustup failed to install reviewed components")


def _install_stable(staging: Path) -> None:
    script = Path(__file__).resolve().with_name("install_rust_tools.py")
    completed = _bounded_process(
        [sys.executable, "-B", str(script), "--prefix", str(staging)],
        {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        1200,
    )
    if completed.returncode:
        raise RustAdvancedInstallError("stable Rust installer rejected the reviewed prefix")


def _install_toolchains(staging: Path, temporary: Path) -> None:
    _rustup(staging, temporary, ["set", "auto-self-update", "disable"], 60)
    _rustup(
        staging,
        temporary,
        ["component", "add", "llvm-tools-preview", "--toolchain", helper.STABLE_TOOLCHAIN],
    )
    _rustup(
        staging,
        temporary,
        [
            "toolchain",
            "install",
            helper.NIGHTLY_TOOLCHAIN,
            "--profile",
            "minimal",
            "--component",
            "rust-src",
        ],
    )
    for key, channel in (
        ("stable", helper.STABLE_TOOLCHAIN),
        ("nightly", helper.NIGHTLY_TOOLCHAIN),
    ):
        path = staging / "rustup/update-hashes" / f"{channel}-{helper.HOST_TARGET}"
        expected = str(helper.TOOLCHAIN_METADATA[key]["manifest_sha256"])[:20]
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size > 128
            or path.read_text(encoding="ascii") != expected
        ):
            raise RustAdvancedInstallError("rustup used an unreviewed channel manifest")


def _install_wrapper(staging: Path) -> None:
    source = Path(__file__).resolve().parents[1] / "src/awq/rust_advanced_helper.py"
    content = source.read_bytes()
    if len(content) > MAX_MANIFEST_BYTES:
        raise RustAdvancedInstallError("advanced Rust helper exceeds its size bound")
    library = staging / "lib/awq_rust_advanced_helper.py"
    wrapper = staging / "bin/awq-rust-advanced-check"
    library.parent.mkdir(parents=True, exist_ok=True)
    library.write_bytes(content)
    wrapper.write_bytes(WRAPPER)
    wrapper.chmod(0o755)


def _write_manifest(staging: Path) -> None:
    document = {
        "schema_version": 1,
        "toolchains": helper.TOOLCHAIN_METADATA,
        "tools": helper.TOOL_METADATA,
    }
    (staging / "manifest.json").write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def verify_versions(prefix: Path) -> None:
    completed = _bounded_process(
        [str(prefix / "bin/awq-rust-advanced-check"), "--version"],
        {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        60,
        capture_output=True,
    )
    if (
        completed.returncode
        or (completed.stdout + completed.stderr).strip() != helper.VERSION_OUTPUT
    ):
        raise RustAdvancedInstallError("advanced Rust version probe mismatch")


def install(prefix: Path) -> None:
    if prefix.is_symlink() or prefix.exists() or not prefix.parent.is_dir():
        raise RustAdvancedInstallError(
            "installation prefix must be a new path below an existing parent"
        )
    with tempfile.TemporaryDirectory(
        prefix="awq-rust-advanced-tools-", dir=prefix.parent
    ) as directory:
        temporary = Path(directory)
        staging = temporary / "installed"
        downloads = temporary / "downloads"
        process_temporary = temporary / "tmp"
        downloads.mkdir()
        process_temporary.mkdir(mode=0o700)
        _install_stable(staging)
        download(NIGHTLY_MANIFEST, downloads / NIGHTLY_MANIFEST.name)
        for artifact in ARTIFACTS:
            target = downloads / artifact.name
            download(artifact, target)
            _extract_binary(artifact, target, staging)
        _install_toolchains(staging, process_temporary)
        shutil.rmtree(staging / "cargo")
        _install_wrapper(staging)
        _write_manifest(staging)
        verify_versions(staging)
        staging.rename(prefix)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        install(args.prefix.parent.resolve() / args.prefix.name)
    except (OSError, subprocess.SubprocessError, RustAdvancedInstallError) as error:
        print(f"Advanced Rust tool installation failed: {error}")
        return 1
    print("Installed checksum-pinned AWQ advanced Rust tools.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
