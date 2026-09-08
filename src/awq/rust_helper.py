# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Pinned, offline Rust stable-toolchain checks with content-minimized failures."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Final

HELPER_VERSION: Final = "1.0.0"
TOOLCHAIN: Final = "1.93.0"
VERSION_OUTPUT: Final = (
    "awq-rust-check 1.0.0 (Rust 1.93.0; Cargo 1.93.0; rustfmt 1.8.0-stable; Clippy 0.1.93)"
)
MAX_CONFIG_BYTES: Final = 1_000_000
COMMAND_TIMEOUT_SECONDS: Final = 840
EXPECTED_PROBES: Final = {
    "rustc": "rustc 1.93.0 (254b59607 2026-01-19)",
    "cargo": "cargo 1.93.0 (083ac5135 2025-12-15)",
    "rustfmt": "rustfmt 1.8.0-stable (254b59607d 2026-01-19)",
    "clippy": "clippy 0.1.93 (254b59607d 2026-01-19)",
}
HOST_TARGET: Final = "x86_64-unknown-linux-gnu"
TOOL_NAMES: Final = frozenset(
    {
        "cargo",
        "cargo-clippy",
        "cargo-fmt",
        "clippy-driver",
        "rustc",
        "rustdoc",
        "rustfmt",
    }
)


class RustCheckError(ValueError):
    """A Rust check violated the pinned execution contract."""


def _prefix() -> Path:
    return Path(__file__).resolve().parent.parent


def _tool_bin() -> Path:
    directory = _prefix() / "rustup/toolchains" / f"{TOOLCHAIN}-{HOST_TARGET}" / "bin"
    if not directory.is_dir() or directory.resolve(strict=True) != directory:
        raise RustCheckError("Rust tool directory is unavailable")
    return directory


def _tool(name: str) -> Path:
    if name not in TOOL_NAMES:
        raise RustCheckError("Rust tool is unavailable")
    path = _tool_bin() / name
    if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
        raise RustCheckError("Rust tool is unavailable")
    return path


def _runtime_cargo() -> Path:
    directory = _prefix() / "runtime-cargo"
    if (
        directory.is_symlink()
        or not directory.is_dir()
        or directory.resolve(strict=True) != directory
    ):
        raise RustCheckError("Rust runtime Cargo home is unavailable")
    for name in ("bin", "config", "config.toml", "credentials", "credentials.toml"):
        path = directory / name
        if path.exists() or path.is_symlink():
            raise RustCheckError("Rust runtime Cargo home is unsafe")
    return directory


def _base_environment() -> dict[str, str]:
    tool_bin = _tool_bin()
    return {
        "PATH": f"{tool_bin}:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "CARGO": str(_tool("cargo")),
        "CARGO_HOME": str(_runtime_cargo()),
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TERM_COLOR": "never",
        "RUSTC": str(_tool("rustc")),
        "RUSTDOC": str(_tool("rustdoc")),
    }


def _run_probe(name: str, argv: list[str]) -> None:
    completed = subprocess.run(  # noqa: S603 - exact tool under the pinned prefix.
        argv,
        env=_base_environment(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    observed = (completed.stdout + completed.stderr).strip()
    if completed.returncode or observed != EXPECTED_PROBES[name]:
        raise RustCheckError("Rust tool version mismatch")


def _verify_toolset() -> None:
    cargo = str(_tool("cargo"))
    _run_probe("rustc", [str(_tool("rustc")), "--version"])
    _run_probe("cargo", [cargo, "--version"])
    _run_probe("rustfmt", [str(_tool("rustfmt")), "--version"])
    _run_probe(
        "clippy",
        [str(_tool("cargo-clippy")), "clippy", "--version"],
    )
    for name in ("cargo-clippy", "cargo-fmt", "clippy-driver", "rustdoc"):
        _tool(name)


def _confined_file(root: Path, relative: str) -> Path:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise RustCheckError("required Rust configuration is unavailable")
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise RustCheckError("required Rust configuration is unavailable")
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise RustCheckError("required Rust configuration exceeds the size bound")
    return path


def _verify_project(root: Path) -> None:
    document = tomllib.loads(_confined_file(root, "rust-toolchain.toml").read_text("utf-8"))
    expected = {
        "toolchain": {
            "channel": TOOLCHAIN,
            "profile": "minimal",
            "components": ["clippy", "rustfmt"],
        }
    }
    if document != expected:
        raise RustCheckError("rust-toolchain.toml does not match the reviewed contract")
    _confined_file(root, "Cargo.toml")
    _confined_file(root, "Cargo.lock")
    _confined_file(root, ".cargo/config.toml")


def _arguments(mode: str) -> tuple[list[str], dict[str, str]]:
    cargo = str(_tool("cargo"))
    environment = _base_environment()
    if mode == "fmt":
        return [
            str(_tool("cargo-fmt")),
            "fmt",
            "--all",
            "--",
            "--check",
        ], environment
    if mode == "clippy":
        return [
            str(_tool("cargo-clippy")),
            "clippy",
            "--locked",
            "--offline",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ], environment
    if mode == "test":
        return [cargo, "test", "--locked", "--offline", "--workspace"], environment
    if mode == "doc":
        environment["RUSTDOCFLAGS"] = "-D warnings"
        return [
            cargo,
            "doc",
            "--locked",
            "--offline",
            "--workspace",
            "--no-deps",
        ], environment
    if mode == "build":
        return [
            cargo,
            "build",
            "--locked",
            "--offline",
            "--workspace",
            "--release",
        ], environment
    raise RustCheckError("unsupported Rust check mode")


def _temporary_parent() -> Path | None:
    value = os.environ.get("TMPDIR")
    if value is None:
        return None
    parent = Path(value)
    if (
        not parent.is_absolute()
        or parent.is_symlink()
        or not parent.is_dir()
        or parent.resolve(strict=True) != parent
    ):
        raise RustCheckError("temporary directory is unavailable")
    return parent


def _invoke(root: Path, mode: str) -> None:
    argv, environment = _arguments(mode)
    with tempfile.TemporaryDirectory(prefix="awq-rust-", dir=_temporary_parent()) as scratch_name:
        scratch = Path(scratch_name)
        target = scratch / "target"
        temporary = scratch / "tmp"
        target.mkdir()
        temporary.mkdir()
        environment["CARGO_TARGET_DIR"] = str(target)
        environment["TMPDIR"] = str(temporary)
        completed = subprocess.run(  # noqa: S603 - exact tool and fixed argv.
            argv,
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    if completed.returncode:
        raise RustCheckError("Rust command rejected the project")


def main(argv: list[str] | None = None) -> int:
    """Run one exact mode without returning project or compiler content."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        _verify_toolset()
        if arguments == ["--version"]:
            print(VERSION_OUTPUT)
            return 0
        if len(arguments) != 1:
            raise RustCheckError("invalid Rust check invocation")
        root = Path.cwd().resolve()
        _verify_project(root)
        _invoke(root, arguments[0])
    except (
        OSError,
        UnicodeError,
        ValueError,
        RecursionError,
        subprocess.SubprocessError,
    ):
        print("awq-rust-check: validation failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
