# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Bounded offline Rust coverage, fuzz-regression, and mutation evidence."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import resource
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any, Final

HELPER_VERSION: Final = "1.0.0"
STABLE_TOOLCHAIN: Final = "1.93.0"
NIGHTLY_TOOLCHAIN: Final = "nightly-2026-09-01"
HOST_TARGET: Final = "x86_64-unknown-linux-gnu"
COMMAND_TIMEOUT_MAX: Final = 840
MAX_DOCUMENT_BYTES: Final = 2_000_000
MAX_RESULT_BYTES: Final = 2_000_000
MAX_SEED_BYTES: Final = 65_536
MAX_CORPUS_BYTES: Final = 1_000_000
MAX_TARGETS: Final = 3
SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
PACKAGE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$")
GENRES: Final = frozenset(
    {"BinaryOperator", "FnValue", "LogicalAndOr", "MatchArm", "Range", "UnaryOperator"}
)
VERSION_OUTPUT: Final = (
    "awq-rust-advanced-check 1.0.0 (cargo-llvm-cov 0.9.1; cargo-fuzz 0.13.2; "
    "cargo-mutants 27.1.0; Rust 1.93.0; nightly-2026-09-01)"
)
TOOL_METADATA: Final = {
    "cargo-fuzz": {
        "archive_sha256": "b5b704018b63e0f151c17a057ac53b5111e1db545d1b9f72fee79f08a545931c",
        "binary_sha256": "f87d63fc80e4f897a32ead5df85bd67665afb6a63ed92bb0d2b0473e15295eba",
        "probe": ["fuzz", "--version"],
        "version": "0.13.2",
        "version_output": "cargo-fuzz 0.13.2",
    },
    "cargo-llvm-cov": {
        "archive_sha256": "3fca950394a3c49457657c158b1619cec8dfd2647ae5b48746734c0ab969a522",
        "binary_sha256": "7ce3cb54a77786151ccc3d2df2a425a2330442c123e28135d5c5cf27145c5c6d",
        "probe": ["llvm-cov", "--version"],
        "version": "0.9.1",
        "version_output": "cargo-llvm-cov 0.9.1",
    },
    "cargo-mutants": {
        "archive_sha256": "dfe6dc37d0342c891d2829b5a695aa57c2d0edecef7e7d0399a30cc6e206411e",
        "binary_sha256": "f985f265ee3ea3e453aa98b04c52134953911f692f8ce8abf137f3873202a2d0",
        "probe": ["mutants", "--version"],
        "version": "27.1.0",
        "version_output": "cargo-mutants 27.1.0",
    },
}
TOOLCHAIN_METADATA: Final = {
    "nightly": {
        "channel": NIGHTLY_TOOLCHAIN,
        "components": ["rust-src"],
        "manifest_sha256": "c0108d53937d7ed5ca4cccef516df1a2521798ae59ffddd2740c4ad6c3110f14",
        "rustc": "rustc 1.100.0-nightly (0dfb098f3 2026-08-31)",
        "cargo": "cargo 1.100.0-nightly (e8cb624d5 2026-08-22)",
    },
    "stable": {
        "channel": STABLE_TOOLCHAIN,
        "components": ["llvm-tools-preview"],
        "manifest_sha256": "beb6ba4e41c84e9c11c80e6804a007497d0c8ba0810cd403fabc8f4a9c45b1f8",
        "rustc": "rustc 1.93.0 (254b59607 2026-01-19)",
        "cargo": "cargo 1.93.0 (083ac5135 2025-12-15)",
    },
}


class RustAdvancedError(ValueError):
    """An advanced Rust check violated its reviewed execution contract."""


def _prefix() -> Path:
    return Path(__file__).resolve().parent.parent


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RustAdvancedError("JSON document contains duplicate keys")
        result[key] = value
    return result


def _safe_relative(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not value.startswith("/")
        and value == path.as_posix()
        and ".." not in path.parts
        and value not in {".", ".."}
    )


def _confined_file(root: Path, relative: str, maximum: int = MAX_DOCUMENT_BYTES) -> Path:
    if not _safe_relative(relative):
        raise RustAdvancedError("advanced Rust path is unsafe")
    path = root / relative
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise RustAdvancedError("advanced Rust input is unavailable")
    if path.stat().st_size > maximum:
        raise RustAdvancedError("advanced Rust input exceeds its size bound")
    return path


def _read_json(root: Path, relative: str) -> tuple[dict[str, Any], str]:
    path = _confined_file(root, relative)
    content = path.read_bytes()
    try:
        value = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda item: (_ for _ in ()).throw(
                RustAdvancedError(f"invalid JSON constant: {item}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RustAdvancedError("advanced Rust JSON is invalid") from error
    if not isinstance(value, dict) or content != _canonical_bytes(value):
        raise RustAdvancedError("advanced Rust JSON is not canonical")
    return value, hashlib.sha256(content).hexdigest()


def _manifest() -> None:
    document, _ = _read_json(_prefix(), "manifest.json")
    expected = {
        "schema_version": 1,
        "toolchains": TOOLCHAIN_METADATA,
        "tools": TOOL_METADATA,
    }
    if (
        type(document.get("schema_version")) is not int
        or document["schema_version"] != 1
        or document != expected
    ):
        raise RustAdvancedError("installed advanced Rust manifest is unreviewed")


def _tool(name: str) -> Path:
    if name not in TOOL_METADATA:
        raise RustAdvancedError("advanced Rust tool is unavailable")
    path = _prefix() / "bin" / name
    if (
        path.is_symlink()
        or not path.is_file()
        or path.resolve(strict=True) != path
        or not os.access(path, os.X_OK)
        or _sha256(path) != TOOL_METADATA[name]["binary_sha256"]
    ):
        raise RustAdvancedError("advanced Rust tool integrity mismatch")
    return path


def _toolchain_bin(channel: str) -> Path:
    if channel not in {STABLE_TOOLCHAIN, NIGHTLY_TOOLCHAIN}:
        raise RustAdvancedError("advanced Rust toolchain is unavailable")
    path = _prefix() / "rustup/toolchains" / f"{channel}-{HOST_TARGET}" / "bin"
    if path.is_symlink() or not path.is_dir() or path.resolve(strict=True) != path:
        raise RustAdvancedError("advanced Rust toolchain is unavailable")
    return path


def _rust_tool(channel: str, name: str) -> Path:
    if name not in {"cargo", "rustc", "rustdoc"}:
        raise RustAdvancedError("Rust executable is unavailable")
    path = _toolchain_bin(channel) / name
    if (
        path.is_symlink()
        or not path.is_file()
        or path.resolve(strict=True) != path
        or not os.access(path, os.X_OK)
    ):
        raise RustAdvancedError("Rust executable is unavailable")
    return path


def _runtime_cargo() -> Path:
    path = _prefix() / "runtime-cargo"
    if path.is_symlink() or not path.is_dir() or path.resolve(strict=True) != path:
        raise RustAdvancedError("advanced Rust Cargo home is unavailable")
    for name in ("bin", "config", "config.toml", "credentials", "credentials.toml"):
        if (path / name).exists() or (path / name).is_symlink():
            raise RustAdvancedError("advanced Rust Cargo home is unsafe")
    return path


def _probe(argv: list[str], expected: str) -> None:
    completed = subprocess.run(  # noqa: S603 - exact integrity-checked executable.
        argv,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if completed.returncode or (completed.stdout + completed.stderr).strip() != expected:
        raise RustAdvancedError("advanced Rust tool version mismatch")


def _verify_installation() -> None:
    _manifest()
    for name, metadata in TOOL_METADATA.items():
        _probe([str(_tool(name)), *metadata["probe"]], str(metadata["version_output"]))
    for key, channel in (("stable", STABLE_TOOLCHAIN), ("nightly", NIGHTLY_TOOLCHAIN)):
        metadata = TOOLCHAIN_METADATA[key]
        _probe([str(_rust_tool(channel, "rustc")), "--version"], str(metadata["rustc"]))
        _probe([str(_rust_tool(channel, "cargo")), "--version"], str(metadata["cargo"]))
        _rust_tool(channel, "rustdoc")
        update_hash = _prefix() / "rustup/update-hashes" / f"{channel}-{HOST_TARGET}"
        if (
            update_hash.is_symlink()
            or not update_hash.is_file()
            or update_hash.stat().st_size > 128
            or update_hash.read_text(encoding="ascii") != str(metadata["manifest_sha256"])[:20]
        ):
            raise RustAdvancedError("advanced Rust toolchain manifest mismatch")
    _runtime_cargo()


def _integer(value: object, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise RustAdvancedError(f"{label} is outside its reviewed bound")
    return value


def _strings(
    value: object,
    pattern: re.Pattern[str],
    *,
    maximum: int,
    label: str,
) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > maximum
        or not all(isinstance(item, str) and pattern.fullmatch(item) for item in value)
        or value != sorted(set(value))
    ):
        raise RustAdvancedError(f"{label} is invalid")
    return value


def _resources(value: object) -> dict[str, int]:
    keys = {
        "memory_mib",
        "cpu_seconds",
        "file_size_mib",
        "open_files",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise RustAdvancedError("advanced Rust resource policy is invalid")
    return {
        "memory_mib": _integer(value["memory_mib"], 1024, 16384, "memory"),
        "cpu_seconds": _integer(value["cpu_seconds"], 10, 1800, "CPU time"),
        "file_size_mib": _integer(value["file_size_mib"], 1, 1024, "file size"),
        "open_files": _integer(value["open_files"], 64, 4096, "open files"),
    }


def _coverage(value: object) -> dict[str, Any]:
    keys = {"all_targets", "feature_policy", "line_floor", "outer_timeout_seconds", "packages"}
    if not isinstance(value, dict) or set(value) != keys:
        raise RustAdvancedError("coverage policy is invalid")
    packages = _strings(value["packages"], PACKAGE, maximum=5, label="coverage packages")
    if value["all_targets"] is not True or value["feature_policy"] != "default-features":
        raise RustAdvancedError("coverage command is unreviewed")
    return {
        **value,
        "line_floor": _integer(value["line_floor"], 1, 100, "coverage floor"),
        "outer_timeout_seconds": _integer(
            value["outer_timeout_seconds"], 10, COMMAND_TIMEOUT_MAX, "coverage timeout"
        ),
        "packages": packages,
    }


def _fuzz_targets(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > MAX_TARGETS:
        raise RustAdvancedError("fuzz target list is invalid")
    names: list[str] = []
    validated: list[dict[str, Any]] = []
    for target in value:
        if not isinstance(target, dict) or set(target) != {"name", "seeds"}:
            raise RustAdvancedError("fuzz target is invalid")
        name = target["name"]
        if not isinstance(name, str) or not IDENTIFIER.fullmatch(name) or name in names:
            raise RustAdvancedError("fuzz target identity is invalid")
        seeds = target["seeds"]
        if not isinstance(seeds, list) or not seeds or len(seeds) > 64:
            raise RustAdvancedError("fuzz seed list is invalid")
        paths: list[str] = []
        for seed in seeds:
            if (
                not isinstance(seed, dict)
                or set(seed) != {"path", "sha256"}
                or not _safe_relative(seed["path"])
                or not str(seed["path"]).startswith(f"fuzz/corpus/{name}/")
                or not isinstance(seed["sha256"], str)
                or not SHA256.fullmatch(seed["sha256"])
                or seed["path"] in paths
            ):
                raise RustAdvancedError("fuzz seed is invalid")
            paths.append(seed["path"])
        if paths != sorted(paths):
            raise RustAdvancedError("fuzz seeds are not ordered")
        names.append(name)
        validated.append({"name": name, "seeds": seeds})
    if names != sorted(names):
        raise RustAdvancedError("fuzz targets are not ordered")
    return validated


def _fuzz(value: object) -> dict[str, Any]:
    keys = {
        "fuzz_dir",
        "input_timeout_seconds",
        "max_length",
        "max_total_time_seconds",
        "outer_timeout_seconds",
        "random_seed",
        "runs",
        "sanitizer",
        "target",
        "targets",
        "toolchain",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise RustAdvancedError("fuzz policy is invalid")
    if (
        value["fuzz_dir"] != "fuzz"
        or value["sanitizer"] != "address"
        or value["target"] != HOST_TARGET
        or value["toolchain"] != NIGHTLY_TOOLCHAIN
    ):
        raise RustAdvancedError("fuzz command is unreviewed")
    validated = _fuzz_targets(value["targets"])
    return {
        **value,
        "input_timeout_seconds": _integer(
            value["input_timeout_seconds"], 1, 10, "fuzz input timeout"
        ),
        "max_length": _integer(value["max_length"], 1, 65_536, "fuzz maximum length"),
        "max_total_time_seconds": _integer(
            value["max_total_time_seconds"], 1, 120, "fuzz run time"
        ),
        "outer_timeout_seconds": _integer(
            value["outer_timeout_seconds"], 10, COMMAND_TIMEOUT_MAX, "fuzz timeout"
        ),
        "random_seed": _integer(value["random_seed"], 1, 4_294_967_295, "fuzz random seed"),
        "runs": _integer(value["runs"], 1, 100_000, "fuzz runs"),
        "targets": validated,
    }


def _mutation(value: object) -> dict[str, Any]:
    keys = {
        "build_timeout_seconds",
        "exclude_re",
        "expected_caught",
        "files",
        "genres",
        "include_re",
        "max_mutants",
        "outer_timeout_seconds",
        "packages",
        "test_timeout_seconds",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise RustAdvancedError("mutation policy is invalid")
    files = value["files"]
    if (
        not isinstance(files, list)
        or not files
        or len(files) > 20
        or not all(_safe_relative(item) and str(item).endswith(".rs") for item in files)
        or files != sorted(set(files))
    ):
        raise RustAdvancedError("mutation target files are invalid")
    packages = _strings(value["packages"], PACKAGE, maximum=5, label="mutation packages")
    genres = value["genres"]
    if (
        not isinstance(genres, list)
        or not all(isinstance(item, str) and item in GENRES for item in genres)
        or not genres
        or genres != sorted(set(genres))
    ):
        raise RustAdvancedError("mutation operator genres are invalid")
    include = value["include_re"]
    excludes = value["exclude_re"]
    if (
        not isinstance(include, str)
        or not 1 <= len(include) <= 500
        or not isinstance(excludes, list)
        or len(excludes) > 20
        or not all(isinstance(item, str) and 1 <= len(item) <= 500 for item in excludes)
        or excludes != sorted(set(excludes))
    ):
        raise RustAdvancedError("mutation filters are invalid")
    filters = [include, *excludes]
    if any(
        item[:1] != "^" or item[-1:] != "$" or any(token in item for token in "()*+?{|}\\")
        for item in filters
    ):
        raise RustAdvancedError("mutation filter uses an unsafe expression")
    try:
        re.compile(include)
        for item in excludes:
            re.compile(item)
    except re.error as error:
        raise RustAdvancedError("mutation filter is invalid") from error
    maximum = _integer(value["max_mutants"], 1, 32, "mutation count")
    expected = _integer(value["expected_caught"], 1, maximum, "expected caught mutants")
    return {
        **value,
        "build_timeout_seconds": _integer(
            value["build_timeout_seconds"], 1, 300, "mutation build timeout"
        ),
        "expected_caught": expected,
        "files": files,
        "genres": genres,
        "max_mutants": maximum,
        "outer_timeout_seconds": _integer(
            value["outer_timeout_seconds"], 10, COMMAND_TIMEOUT_MAX, "mutation timeout"
        ),
        "packages": packages,
        "test_timeout_seconds": _integer(
            value["test_timeout_seconds"], 1, 120, "mutation test timeout"
        ),
    }


def _configuration(root: Path) -> tuple[dict[str, Any], str]:
    value, digest = _read_json(root, "quality/rust-advanced.json")
    keys = {"coverage", "fuzz", "mutation", "resources", "schema_version"}
    if (
        set(value) != keys
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        raise RustAdvancedError("advanced Rust policy is invalid")
    return {
        "coverage": _coverage(value["coverage"]),
        "fuzz": _fuzz(value["fuzz"]),
        "mutation": _mutation(value["mutation"]),
        "resources": _resources(value["resources"]),
        "schema_version": 1,
    }, digest


def _verify_project(root: Path, mode: str, config: dict[str, Any]) -> None:
    toolchain = tomllib.loads(_confined_file(root, "rust-toolchain.toml").read_text("utf-8"))
    if toolchain != {
        "toolchain": {
            "channel": STABLE_TOOLCHAIN,
            "profile": "minimal",
            "components": ["clippy", "rustfmt"],
        }
    }:
        raise RustAdvancedError("rust-toolchain.toml does not match the stable contract")
    for relative in ("Cargo.toml", "Cargo.lock", ".cargo/config.toml"):
        _confined_file(root, relative)
    if mode == "fuzz":
        nightly = tomllib.loads(_confined_file(root, "fuzz/rust-toolchain.toml").read_text("utf-8"))
        if nightly != {
            "toolchain": {
                "channel": NIGHTLY_TOOLCHAIN,
                "profile": "minimal",
                "components": ["rust-src"],
            }
        }:
            raise RustAdvancedError("fuzz toolchain declaration is unreviewed")
        for relative in ("fuzz/Cargo.toml", "fuzz/Cargo.lock"):
            _confined_file(root, relative)
        for target in config["fuzz"]["targets"]:
            _confined_file(root, f"fuzz/fuzz_targets/{target['name']}.rs")


def _git(root: Path, *arguments: str) -> int:
    completed = subprocess.run(  # noqa: S603 - exact /usr/bin/git and fixed arguments.
        ["/usr/bin/git", "-c", "core.fsmonitor=false", *arguments],
        cwd=root,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
    )
    return completed.returncode


def _require_clean(root: Path) -> None:
    if _git(root, "diff", "--quiet", "--") or _git(root, "diff", "--cached", "--quiet", "--"):
        raise RustAdvancedError("tracked project state is not clean")


def _require_tracked(root: Path, paths: list[str]) -> None:
    if any(_git(root, "ls-files", "--error-unmatch", "--", path) for path in paths):
        raise RustAdvancedError("advanced Rust input is not tracked")


def _temporary_parent() -> Path | None:
    value = os.environ.get("TMPDIR")
    if value is None:
        return None
    path = Path(value)
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_dir()
        or path.resolve(strict=True) != path
    ):
        raise RustAdvancedError("temporary directory is unavailable")
    return path


def _environment(channel: str, scratch: Path) -> dict[str, str]:
    cargo = _rust_tool(channel, "cargo")
    rustc = _rust_tool(channel, "rustc")
    rustdoc = _rust_tool(channel, "rustdoc")
    tool_bin = _toolchain_bin(channel)
    temporary = scratch / "tmp"
    target = scratch / "target"
    temporary.mkdir()
    target.mkdir()
    return {
        "PATH": f"{tool_bin}:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "CARGO": str(cargo),
        "CARGO_BUILD_JOBS": "1",
        "CARGO_HOME": str(_runtime_cargo()),
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": str(target),
        "CARGO_TERM_COLOR": "never",
        "RUSTC": str(rustc),
        "RUSTDOC": str(rustdoc),
        "RUSTUP_AUTO_INSTALL": "0",
        "RUSTUP_TOOLCHAIN": channel,
        "TMPDIR": str(temporary),
    }


def _limit_process(resources: dict[str, int], *, address_space: bool) -> None:
    mib = 1024 * 1024
    if address_space:
        resource.setrlimit(
            resource.RLIMIT_AS,
            (resources["memory_mib"] * mib, resources["memory_mib"] * mib),
        )
    resource.setrlimit(resource.RLIMIT_CPU, (resources["cpu_seconds"], resources["cpu_seconds"]))
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (resources["file_size_mib"] * mib, resources["file_size_mib"] * mib),
    )
    resource.setrlimit(resource.RLIMIT_NOFILE, (resources["open_files"], resources["open_files"]))


def _descendants(root_pid: int) -> list[int]:
    parents: dict[int, list[int]] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            content = (entry / "stat").read_text(encoding="ascii")
            fields = content[content.rfind(")") + 2 :].split()
            parent = int(fields[1])
            parents.setdefault(parent, []).append(int(entry.name))
        except (OSError, UnicodeError, ValueError, IndexError):
            continue
    result: list[int] = []
    pending = [root_pid]
    while pending:
        children = parents.get(pending.pop(), [])
        result.extend(children)
        pending.extend(children)
    return result


def _terminate_tree(process: subprocess.Popen[bytes]) -> None:
    for pid in reversed(_descendants(process.pid)):
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)
    with contextlib.suppress(ProcessLookupError):
        process.kill()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired as error:
        raise RustAdvancedError("advanced Rust process tree did not terminate") from error


def _run(
    argv: list[str],
    root: Path,
    environment: dict[str, str],
    timeout: float,
    resources: dict[str, int],
    *,
    address_space: bool = True,
) -> int:
    process = subprocess.Popen(  # noqa: S603 - absolute reviewed tools and fixed direct argv.
        argv,
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=lambda: _limit_process(resources, address_space=address_space),
    )
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        _terminate_tree(process)
        raise RustAdvancedError("advanced Rust command exceeded its outer deadline") from error


def _remaining_timeout(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RustAdvancedError("advanced Rust command exceeded its outer deadline")
    return remaining


def _binding(kind: str, identifier: str, digest: str) -> dict[str, str]:
    return {"kind": kind, "id": identifier[:199], "sha256": digest}


def _coverage_result(
    root: Path, config: dict[str, Any], digest: str, scratch: Path
) -> list[dict[str, str]]:
    policy = config["coverage"]
    output = scratch / "coverage.json"
    argv = [
        str(_tool("cargo-llvm-cov")),
        "llvm-cov",
        "--json",
        "--summary-only",
        "--output-path",
        str(output),
        "--fail-under-lines",
        str(policy["line_floor"]),
        "--locked",
        "--offline",
        "--all-targets",
    ]
    for package in policy["packages"]:
        argv.extend(["--package", package])
    code = _run(
        argv,
        root,
        _environment(STABLE_TOOLCHAIN, scratch),
        policy["outer_timeout_seconds"],
        config["resources"],
    )
    if code:
        raise RustAdvancedError("coverage command rejected the project")
    if output.is_symlink() or not output.is_file() or output.stat().st_size > MAX_RESULT_BYTES:
        raise RustAdvancedError("coverage result is unavailable")
    try:
        report = json.loads(output.read_text(encoding="utf-8"))
        data = report["data"]
        lines = data[0]["totals"]["lines"]
        count = lines["count"]
        covered = lines["covered"]
    except (KeyError, IndexError, TypeError, UnicodeError, json.JSONDecodeError) as error:
        raise RustAdvancedError("coverage result is invalid") from error
    if (
        report.get("type") != "llvm.coverage.json.export"
        or not isinstance(report.get("version"), str)
        or not isinstance(data, list)
        or len(data) != 1
        or type(count) is not int
        or type(covered) is not int
        or count <= 0
        or not 0 <= covered <= count
        or covered * 100 < count * policy["line_floor"]
    ):
        raise RustAdvancedError("coverage result does not meet the reviewed floor")
    identifier = (
        f"lines-floor-{policy['line_floor']}:packages-{len(policy['packages'])}:"
        f"covered-{covered}-of-{count}"
    )
    return [_binding("coverage-policy", identifier, digest)]


def _copy_corpus(root: Path, policy: dict[str, Any], scratch: Path) -> tuple[Path, str, int]:
    destination = scratch / "corpus"
    destination.mkdir()
    aggregate = hashlib.sha256()
    total = 0
    count = 0
    tracked: list[str] = []
    for target in policy["targets"]:
        target_dir = destination / target["name"]
        target_dir.mkdir()
        for index, seed in enumerate(target["seeds"]):
            source = _confined_file(root, seed["path"], MAX_SEED_BYTES)
            content = source.read_bytes()
            if len(content) > MAX_SEED_BYTES:
                raise RustAdvancedError("fuzz seed exceeds its size bound")
            tracked.append(seed["path"])
            observed = hashlib.sha256(content).hexdigest()
            if observed != seed["sha256"]:
                raise RustAdvancedError("fuzz seed integrity mismatch")
            total += len(content)
            count += 1
            if total > MAX_CORPUS_BYTES:
                raise RustAdvancedError("fuzz corpus exceeds its size bound")
            aggregate.update(target["name"].encode())
            aggregate.update(index.to_bytes(4, "big"))
            aggregate.update(bytes.fromhex(observed))
            (target_dir / f"seed-{index:04d}").write_bytes(content)
    _require_tracked(root, tracked)
    return destination, aggregate.hexdigest(), count


def _fuzz_result(
    root: Path, config: dict[str, Any], digest: str, scratch: Path
) -> list[dict[str, str]]:
    policy = config["fuzz"]
    corpus, corpus_digest, seed_count = _copy_corpus(root, policy, scratch)
    artifacts = scratch / "artifacts"
    artifacts.mkdir()
    environment = _environment(NIGHTLY_TOOLCHAIN, scratch)
    target_dir = environment["CARGO_TARGET_DIR"]
    deadline = time.monotonic() + policy["outer_timeout_seconds"]
    runs = policy["runs"]
    maximum_length = policy["max_length"]
    maximum_time = policy["max_total_time_seconds"]
    input_timeout = policy["input_timeout_seconds"]
    random_seed = policy["random_seed"]
    memory_mib = config["resources"]["memory_mib"]
    for target in policy["targets"]:
        name = target["name"]
        build_argv = [
            str(_tool("cargo-fuzz")),
            "fuzz",
            "build",
            name,
            "--fuzz-dir",
            str(root / policy["fuzz_dir"]),
            "--sanitizer",
            policy["sanitizer"],
            "--target",
            policy["target"],
            "--target-dir",
            target_dir,
        ]
        code = _run(
            build_argv,
            root,
            environment,
            _remaining_timeout(deadline),
            config["resources"],
        )
        if code:
            raise RustAdvancedError("fuzz target build rejected the project")
        executable = Path(target_dir) / policy["target"] / "release" / name
        if (
            executable.is_symlink()
            or not executable.is_file()
            or executable.resolve(strict=True) != executable
            or not os.access(executable, os.X_OK)
        ):
            raise RustAdvancedError("fuzz target executable is unavailable")
        runtime_environment = dict(environment)
        runtime_environment["ASAN_OPTIONS"] = "detect_odr_violation=0"
        run_argv = [
            str(executable),
            f"-runs={runs}",
            f"-max_len={maximum_length}",
            f"-max_total_time={maximum_time}",
            f"-timeout={input_timeout}",
            f"-seed={random_seed}",
            f"-rss_limit_mb={memory_mib}",
            f"-malloc_limit_mb={memory_mib}",
            f"-artifact_prefix={artifacts}/",
            str(corpus / name),
        ]
        code = _run(
            run_argv,
            root,
            runtime_environment,
            _remaining_timeout(deadline),
            config["resources"],
            address_space=False,
        )
        if code:
            raise RustAdvancedError("fixed-run fuzz regression rejected the project")
    names = "-".join(target["name"] for target in policy["targets"])
    plan_id = (
        f"{NIGHTLY_TOOLCHAIN}:targets-{names}:runs-{runs}:"
        f"seconds-{maximum_time}:maxlen-{maximum_length}:input-timeout-{input_timeout}:"
        f"seed-{random_seed}"
    )
    return sorted(
        [
            _binding("fuzz-corpus", f"seed-set-{seed_count}:{corpus_digest[:16]}", corpus_digest),
            _binding("fuzz-plan", plan_id, digest),
        ],
        key=lambda item: (item["kind"], item["id"]),
    )


def _mutation_report(output: Path, policy: dict[str, Any]) -> tuple[int, int, int, int]:
    path = output / "mutants.out/outcomes.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_RESULT_BYTES:
        raise RustAdvancedError("mutation result is unavailable")
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
        counts = tuple(report[name] for name in ("caught", "missed", "timeout", "unviable"))
        total = report["total_mutants"]
        outcomes = report["outcomes"]
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError) as error:
        raise RustAdvancedError("mutation result is invalid") from error
    if (
        report.get("cargo_mutants_version") != "27.1.0"
        or any(type(item) is not int or item < 0 for item in (*counts, total))
        or total < 1
        or total > policy["max_mutants"]
        or sum(counts) != total
        or not isinstance(outcomes, list)
    ):
        raise RustAdvancedError("mutation result is invalid")
    include = re.compile(policy["include_re"])
    excludes = [re.compile(item) for item in policy["exclude_re"]]
    mutants = 0
    for outcome in outcomes:
        if not isinstance(outcome, dict):
            raise RustAdvancedError("mutation outcome is invalid")
        scenario = outcome.get("scenario")
        if isinstance(scenario, dict) and "Mutant" in scenario:
            mutant = scenario["Mutant"]
            if not isinstance(mutant, dict):
                raise RustAdvancedError("mutation outcome is invalid")
            name = mutant.get("name")
            if (
                not isinstance(name, str)
                or not include.search(name)
                or any(pattern.search(name) for pattern in excludes)
                or mutant.get("file") not in policy["files"]
                or mutant.get("package") not in policy["packages"]
                or mutant.get("genre") not in policy["genres"]
            ):
                raise RustAdvancedError("mutation outcome escaped its reviewed selection")
            mutants += 1
    if mutants != total:
        raise RustAdvancedError("mutation outcome count is invalid")
    return counts


def _mutation_result(
    root: Path, config: dict[str, Any], digest: str, scratch: Path
) -> list[dict[str, str]]:
    policy = config["mutation"]
    output = scratch / "mutation"
    output.mkdir()
    argv = [
        str(_tool("cargo-mutants")),
        "mutants",
        "--baseline",
        "run",
        "--jobs",
        "1",
        "--timeout",
        str(policy["test_timeout_seconds"]),
        "--build-timeout",
        str(policy["build_timeout_seconds"]),
        "--output",
        str(output),
        "--re",
        policy["include_re"],
        "--colors",
        "never",
        "--no-shuffle",
        "--no-times",
        "-C=--offline",
        "-C=--locked",
    ]
    for package in policy["packages"]:
        argv.extend(["--package", package])
    for path in policy["files"]:
        argv.extend(["--file", path])
    for expression in policy["exclude_re"]:
        argv.extend(["--exclude-re", expression])
    code = _run(
        argv,
        root,
        _environment(STABLE_TOOLCHAIN, scratch),
        policy["outer_timeout_seconds"],
        config["resources"],
    )
    caught, missed, timed_out, unviable = _mutation_report(output, policy)
    if code or caught != policy["expected_caught"] or missed or timed_out or unviable:
        raise RustAdvancedError("mutation sentinels were not all caught")
    genres = "-".join(policy["genres"])
    packages = "-".join(policy["packages"])
    plan_id = (
        f"packages-{packages}:genres-{genres}:files-{len(policy['files'])}:"
        f"filter-{hashlib.sha256(policy['include_re'].encode()).hexdigest()[:16]}"
    )
    outcome = {"caught": caught, "survived": missed, "timeout": timed_out, "unviable": unviable}
    outcome_digest = hashlib.sha256(_canonical_bytes(outcome)).hexdigest()
    return sorted(
        [
            _binding("mutation-outcome", f"caught-{caught}:survived-{missed}", outcome_digest),
            _binding("mutation-plan", plan_id, digest),
        ],
        key=lambda item: (item["kind"], item["id"]),
    )


def _execute(root: Path, mode: str, config: dict[str, Any], digest: str) -> list[dict[str, str]]:
    lock_digest = _sha256(_confined_file(root, "Cargo.lock"))
    _require_clean(root)
    declared = [
        ".cargo/config.toml",
        "Cargo.lock",
        "Cargo.toml",
        "quality/rust-advanced.json",
        "rust-toolchain.toml",
    ]
    if mode == "fuzz":
        declared.extend(["fuzz/Cargo.lock", "fuzz/Cargo.toml", "fuzz/rust-toolchain.toml"])
        declared.extend(
            f"fuzz/fuzz_targets/{target['name']}.rs" for target in config["fuzz"]["targets"]
        )
    if mode == "mutation":
        declared.extend(config["mutation"]["files"])
    _require_tracked(root, sorted(set(declared)))
    try:
        with tempfile.TemporaryDirectory(
            prefix="awq-rust-advanced-", dir=_temporary_parent()
        ) as name:
            scratch = Path(name)
            if mode == "coverage":
                return _coverage_result(root, config, digest, scratch)
            if mode == "fuzz":
                return _fuzz_result(root, config, digest, scratch)
            if mode == "mutation":
                return _mutation_result(root, config, digest, scratch)
            raise RustAdvancedError("unsupported advanced Rust check mode")
    finally:
        if _sha256(_confined_file(root, "Cargo.lock")) != lock_digest:
            raise RustAdvancedError("Cargo.lock changed during advanced Rust execution")
        _require_clean(root)


def _emit(bindings: list[dict[str, str]]) -> None:
    document = {"bindings": bindings, "schema_version": 1, "status": "pass"}
    sys.stdout.buffer.write(_canonical_bytes(document))


def main(argv: list[str] | None = None) -> int:
    """Run one exact advanced Rust mode without exposing project or native output."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        _verify_installation()
        if arguments == ["--version"]:
            print(VERSION_OUTPUT)
            return 0
        if len(arguments) != 1:
            raise RustAdvancedError("invalid advanced Rust invocation")
        root = Path.cwd().resolve()
        config, digest = _configuration(root)
        _verify_project(root, arguments[0], config)
        _emit(_execute(root, arguments[0], config, digest))
    except (
        OSError,
        TypeError,
        UnicodeError,
        ValueError,
        RecursionError,
        subprocess.SubprocessError,
    ):
        print("awq-rust-advanced-check: validation failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
