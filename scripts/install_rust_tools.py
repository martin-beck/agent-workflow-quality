# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Install the exact reviewed Rust stable toolchain into an isolated prefix."""

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

MAX_BINARY_BYTES = 30_000_000
MAX_MANIFEST_BYTES = 1_000_000
ALLOWED_HOST = "static.rust-lang.org"
RUSTUP_VERSION = "1.29.0"
TOOLCHAIN = "1.93.0"
HOST_TARGET = "x86_64-unknown-linux-gnu"


class RustToolInstallError(RuntimeError):
    """The pinned Rust toolchain failed integrity or installation checks."""


@dataclass(frozen=True)
class Artifact:
    """One immutable Rust distribution artifact."""

    name: str
    url: str
    sha256: str
    maximum: int


RUSTUP_INIT = Artifact(
    "rustup-init",
    "https://static.rust-lang.org/rustup/archive/1.29.0/x86_64-unknown-linux-gnu/rustup-init",
    "4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10",
    MAX_BINARY_BYTES,
)
TOOLCHAIN_MANIFEST = Artifact(
    "channel-rust-1.93.0.toml",
    "https://static.rust-lang.org/dist/channel-rust-1.93.0.toml",
    "beb6ba4e41c84e9c11c80e6804a007497d0c8ba0810cd403fabc8f4a9c45b1f8",
    MAX_MANIFEST_BYTES,
)
WRAPPER = b"""#!/usr/bin/env python3
from pathlib import Path
import sys

prefix = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(prefix / "lib"))
from awq_rust_helper import main

raise SystemExit(main())
"""


def verify_digest(path: Path, expected: str) -> None:
    observed = hashlib.sha256(path.read_bytes()).hexdigest()
    if observed != expected:
        raise RustToolInstallError(f"{path.name}: SHA-256 mismatch")


def _copy_response(stream: BinaryIO, destination: Path, maximum: int) -> None:
    total = 0
    with destination.open("xb") as output:
        while chunk := stream.read(64 * 1024):
            total += len(chunk)
            if total > maximum:
                raise RustToolInstallError("Rust tool download exceeds the size bound")
            output.write(chunk)


def download(artifact: Artifact, destination: Path) -> None:
    source = urlsplit(artifact.url)
    if source.scheme != "https" or source.hostname != ALLOWED_HOST:
        raise RustToolInstallError("Rust tool download uses an unreviewed source")
    request = Request(artifact.url, headers={"User-Agent": "agent-workflow-quality"})  # noqa: S310
    partial = destination.with_suffix(destination.suffix + ".part")
    try:
        with urlopen(request, timeout=30) as response:  # noqa: S310
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname != ALLOWED_HOST:
                raise RustToolInstallError("Rust tool download redirected to an unreviewed host")
            _copy_response(response, partial, artifact.maximum)
        verify_digest(partial, artifact.sha256)
        partial.replace(destination)
    except Exception:
        with contextlib.suppress(OSError):
            partial.unlink()
        raise


def _environment(staging: Path, temporary: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "RUSTUP_HOME": str(staging / "rustup"),
        "CARGO_HOME": str(staging / "cargo"),
        "RUSTUP_DIST_SERVER": "https://static.rust-lang.org",
        "RUSTUP_UPDATE_ROOT": "https://static.rust-lang.org/rustup",
        "RUSTUP_AUTO_INSTALL": "0",
        "TMPDIR": str(temporary),
    }


def _install_toolchain(rustup_init: Path, staging: Path, temporary: Path) -> None:
    rustup_init.chmod(0o755)
    completed = subprocess.run(  # noqa: S603 - exact digest-verified absolute binary.
        [
            str(rustup_init),
            "-y",
            "--no-modify-path",
            "--profile",
            "minimal",
            "--default-toolchain",
            TOOLCHAIN,
            "--component",
            "rustfmt",
            "--component",
            "clippy",
        ],
        env=_environment(staging, temporary),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=900,
        check=False,
    )
    if completed.returncode:
        raise RustToolInstallError("rustup-init failed to install the reviewed toolchain")


def _verify_manifest_use(staging: Path) -> None:
    update_hash = staging / "rustup/update-hashes" / f"{TOOLCHAIN}-{HOST_TARGET}"
    if update_hash.is_symlink() or not update_hash.is_file():
        raise RustToolInstallError("rustup did not record the reviewed toolchain manifest")
    if update_hash.stat().st_size > 128:
        raise RustToolInstallError("rustup recorded an invalid toolchain manifest hash")
    if update_hash.read_text(encoding="ascii") != TOOLCHAIN_MANIFEST.sha256[:20]:
        raise RustToolInstallError("rustup used an unreviewed toolchain manifest")


def _install_wrapper(staging: Path) -> None:
    helper = Path(__file__).resolve().parents[1] / "src/awq/rust_helper.py"
    content = helper.read_bytes()
    if len(content) > MAX_MANIFEST_BYTES:
        raise RustToolInstallError("Rust helper source exceeds the size bound")
    library = staging / "lib/awq_rust_helper.py"
    wrapper = staging / "bin/awq-rust-check"
    library.parent.mkdir(parents=True)
    wrapper.parent.mkdir(parents=True)
    library.write_bytes(content)
    wrapper.write_bytes(WRAPPER)
    wrapper.chmod(0o755)


def verify_versions(prefix: Path) -> None:
    environment = {
        "PATH": f"{prefix / 'bin'}:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    completed = subprocess.run(  # noqa: S603 - exact installed wrapper.
        [str(prefix / "bin/awq-rust-check"), "--version"],
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    expected = (
        "awq-rust-check 1.0.0 (Rust 1.93.0; Cargo 1.93.0; rustfmt 1.8.0-stable; Clippy 0.1.93)"
    )
    if completed.returncode or (completed.stdout + completed.stderr).strip() != expected:
        raise RustToolInstallError("installed Rust tool version probe mismatch")


def install(prefix: Path) -> None:
    if prefix.is_symlink() or prefix.exists() or not prefix.parent.is_dir():
        raise RustToolInstallError(
            "installation prefix must be a new path below an existing parent"
        )
    with tempfile.TemporaryDirectory(prefix="awq-rust-tools-", dir=prefix.parent) as directory:
        temporary = Path(directory)
        downloads = temporary / "downloads"
        staging = temporary / "installed"
        process_temporary = temporary / "tmp"
        downloads.mkdir()
        staging.mkdir(mode=0o755)
        process_temporary.mkdir(mode=0o700)
        rustup_init = downloads / RUSTUP_INIT.name
        download(RUSTUP_INIT, rustup_init)
        download(TOOLCHAIN_MANIFEST, downloads / TOOLCHAIN_MANIFEST.name)
        _install_toolchain(rustup_init, staging, process_temporary)
        _verify_manifest_use(staging)
        (staging / "runtime-cargo").mkdir(mode=0o700)
        _install_wrapper(staging)
        verify_versions(staging)
        staging.rename(prefix)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        install(args.prefix.parent.resolve() / args.prefix.name)
    except (OSError, subprocess.SubprocessError, RustToolInstallError) as error:
        print(f"Rust tool installation failed: {error}")
        return 1
    print("Installed checksum-pinned AWQ Rust stable toolchain.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
