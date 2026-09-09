# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Pinned offline Rust supply-chain and public API compatibility checks."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Final, Never

HELPER_VERSION: Final = "1.0.0"
RUST_VERSION: Final = "1.93.0"
HOST_TARGET: Final = "x86_64-unknown-linux-gnu"
ADVISORY_COMMIT: Final = "bf25f6575a93a35f30796c65c0ed91bee7fa19fd"
ADVISORY_TREE_SHA256: Final = "5cbbfdbbee55950d0fd592e52bc883aba747dad9cb986832b90320d03ce2ac4a"
ADVISORY_EXPIRES_AT: Final = "2026-12-07T09:58:15Z"
MAX_DOCUMENT_BYTES: Final = 2_000_000
MAX_TREE_FILES: Final = 2_000
MAX_TREE_ENTRIES: Final = 4_000
MAX_TREE_BYTES: Final = 5_000_000
COMMAND_TIMEOUT_SECONDS: Final = 840
VERSION_OUTPUT: Final = (
    "awq-rust-supply-check 1.0.0 (cargo-deny 0.20.2; cargo-audit 0.22.2; "
    "cargo-semver-checks 0.50.0; Rust 1.93.0; advisory-db "
    "bf25f6575a93a35f30796c65c0ed91bee7fa19fd)"
)
RUST_WRAPPER_VERSION: Final = (
    "awq-rust-check 1.0.0 (Rust 1.93.0; Cargo 1.93.0; rustfmt 1.8.0-stable; Clippy 0.1.93)"
)
TOOL_METADATA: Final = {
    "cargo-audit": {
        "archive_sha256": "ab28a1bdb54db4d5d8ad5981cf1f959410370b3d28250dbd35f6a44248620e39",
        "binary_sha256": "473b9a71e5cb5bde22f69c32f749c9b83931287d92dc36b91cb04f6705640ef2",
        "version": "0.22.2",
        "version_output": "cargo-audit 0.22.2",
    },
    "cargo-deny": {
        "archive_sha256": "9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f",
        "binary_sha256": "b329e25933d01c36dd7c47d84ea5716694f9b7caf53a5003d45674703a8ed54a",
        "version": "0.20.2",
        "version_output": "cargo-deny 0.20.2",
    },
    "cargo-semver-checks": {
        "archive_sha256": "52a65dc88dc53fa8b57d6087954eb52cda149ca03bcfca78ce3fdecd23f893c4",
        "binary_sha256": "bb749b764d3dde32b37ace1e86d5601f1033e06c8a5579e18ee67323c145ed3a",
        "version": "0.50.0",
        "version_output": "cargo-semver-checks 0.50.0",
    },
}
REGISTRY_SOURCE: Final = "registry+https://github.com/rust-lang/crates.io-index"
ADVISORY_ID: Final = re.compile(r"^RUSTSEC-[0-9]{4}-[0-9]{4}$")
BASELINE_ID: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$")
PACKAGE_NAME: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$")
CRATE_NAME: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,99}$")
SHA256: Final = re.compile(r"^[0-9a-f]{64}$")


class RustSupplyError(ValueError):
    """A Rust supply check violated its pinned execution contract."""


def _prefix() -> Path:
    return Path(__file__).resolve().parent.parent


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RustSupplyError("JSON document contains duplicate keys")
        result[key] = value
    return result


def _confined_file(root: Path, relative: str, maximum: int = MAX_DOCUMENT_BYTES) -> Path:
    candidate = PurePosixPath(relative)
    if (
        not relative
        or relative.startswith("/")
        or "\\" in relative
        or ".." in candidate.parts
        or relative != candidate.as_posix()
    ):
        raise RustSupplyError("required Rust supply file path is unsafe")
    path = root / relative
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise RustSupplyError("required Rust supply file is unavailable")
    if path.stat().st_size > maximum:
        raise RustSupplyError("required Rust supply file exceeds the size bound")
    return path


def _read_json(root: Path, relative: str) -> tuple[dict[str, Any], str]:
    path = _confined_file(root, relative)
    content = path.read_bytes()
    try:
        value = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda item: (_ for _ in ()).throw(
                RustSupplyError(f"invalid JSON constant: {item}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RustSupplyError("required Rust supply JSON is invalid") from error
    if not isinstance(value, dict) or content != _canonical_bytes(value):
        raise RustSupplyError("required Rust supply JSON is not canonical")
    return value, hashlib.sha256(content).hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest() -> dict[str, Any]:
    document, _ = _read_json(_prefix(), "manifest.json")
    if set(document) != {
        "advisory_db",
        "rust_tools_prefix",
        "schema_version",
        "tools",
    }:
        raise RustSupplyError("installed Rust supply manifest is invalid")
    advisory = document["advisory_db"]
    expected_advisory = {
        "archive_sha256": "ff54ebd7becdaa59efe2d54e516d8c1e10e7c2fb20c8d3241a20889c5000f3eb",
        "commit": ADVISORY_COMMIT,
        "expires_at": ADVISORY_EXPIRES_AT,
        "snapshot_at": "2026-09-08T09:58:15Z",
        "tree_sha256": ADVISORY_TREE_SHA256,
    }
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or advisory != expected_advisory
        or document["tools"] != TOOL_METADATA
    ):
        raise RustSupplyError("installed Rust supply manifest is unreviewed")
    return document


def _rust_prefix(manifest: dict[str, Any]) -> Path:
    value = manifest["rust_tools_prefix"]
    if not isinstance(value, str):
        raise RustSupplyError("installed Rust toolchain path is invalid")
    path = Path(value)
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_dir()
        or path.resolve(strict=True) != path
    ):
        raise RustSupplyError("installed Rust toolchain path is unavailable")
    return path


def _tool(name: str) -> Path:
    if name not in TOOL_METADATA:
        raise RustSupplyError("Rust supply tool is unavailable")
    path = _prefix() / "bin" / name
    if (
        path.is_symlink()
        or not path.is_file()
        or path.resolve(strict=True) != path
        or not os.access(path, os.X_OK)
    ):
        raise RustSupplyError("Rust supply tool is unavailable")
    if _sha256(path) != TOOL_METADATA[name]["binary_sha256"]:
        raise RustSupplyError("Rust supply tool integrity mismatch")
    return path


def _rust_tool(rust_prefix: Path, name: str) -> Path:
    if name not in {"cargo", "rustc", "rustdoc"}:
        raise RustSupplyError("Rust tool is unavailable")
    path = rust_prefix / "rustup/toolchains" / f"{RUST_VERSION}-{HOST_TARGET}" / "bin" / name
    if (
        path.is_symlink()
        or not path.is_file()
        or path.resolve(strict=True) != path
        or not os.access(path, os.X_OK)
    ):
        raise RustSupplyError("Rust tool is unavailable")
    return path


def _probe(argv: list[str], expected: str, environment: dict[str, str]) -> None:
    completed = subprocess.run(  # noqa: S603 - absolute integrity-checked executable.
        argv,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if completed.returncode or (completed.stdout + completed.stderr).strip() != expected:
        raise RustSupplyError("Rust supply tool version mismatch")


def _verify_installation(manifest: dict[str, Any], rust_prefix: Path) -> None:
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    for name, metadata in TOOL_METADATA.items():
        _probe([str(_tool(name)), "--version"], str(metadata["version_output"]), environment)
    wrapper = rust_prefix / "bin/awq-rust-check"
    if (
        wrapper.is_symlink()
        or not wrapper.is_file()
        or wrapper.resolve(strict=True) != wrapper
        or not os.access(wrapper, os.X_OK)
    ):
        raise RustSupplyError("pinned Rust wrapper is unavailable")
    _probe([str(wrapper), "--version"], RUST_WRAPPER_VERSION, environment)
    _rust_tool(rust_prefix, "cargo")
    _rust_tool(rust_prefix, "rustc")
    _rust_tool(rust_prefix, "rustdoc")
    if manifest["advisory_db"]["tree_sha256"] != ADVISORY_TREE_SHA256:
        raise RustSupplyError("installed advisory database is unreviewed")


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RustSupplyError("snapshot timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise RustSupplyError("snapshot timestamp is invalid") from error
    if parsed.tzinfo != UTC:
        raise RustSupplyError("snapshot timestamp is invalid")
    return parsed


def _not_expired(value: object) -> None:
    if _timestamp(value) <= datetime.now(UTC):
        raise RustSupplyError("snapshot has expired")


def _walk_error(error: OSError) -> Never:
    raise RustSupplyError("installed advisory database traversal failed") from error


def _bounded_tree_files(root: Path) -> list[Path]:
    paths: list[Path] = []
    entries = 0
    for current, directories, files in os.walk(root, followlinks=False, onerror=_walk_error):
        directories.sort()
        files.sort()
        entries += len(directories) + len(files)
        if entries > MAX_TREE_ENTRIES:
            raise RustSupplyError("installed advisory database exceeds its safety bound")
        parent = Path(current)
        if any((parent / directory).is_symlink() for directory in directories):
            raise RustSupplyError("installed advisory database contains a symlink")
        paths.extend(parent / filename for filename in files)
    if not paths:
        raise RustSupplyError("installed advisory database is empty")
    if len(paths) > MAX_TREE_FILES:
        raise RustSupplyError("installed advisory database exceeds its safety bound")
    return sorted(paths)


def _tree_sha256(root: Path) -> str:
    if root.is_symlink() or not root.is_dir() or root.resolve(strict=True) != root:
        raise RustSupplyError("installed advisory database is unavailable")
    digest = hashlib.sha256()
    total = 0
    for path in _bounded_tree_files(root):
        if path.is_symlink() or path.resolve(strict=True) != path:
            raise RustSupplyError("installed advisory database contains an unsafe entry")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise RustSupplyError("installed advisory database contains an unsafe entry")
            total += metadata.st_size
            if metadata.st_size > MAX_DOCUMENT_BYTES or total > MAX_TREE_BYTES:
                raise RustSupplyError("installed advisory database exceeds its safety bound")
            relative = path.relative_to(root).as_posix().encode()
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            digest.update(metadata.st_size.to_bytes(8, "big"))
            remaining = metadata.st_size
            while remaining:
                chunk = stream.read(min(64 * 1024, remaining))
                if not chunk:
                    raise RustSupplyError("installed advisory database file was truncated")
                digest.update(chunk)
                remaining -= len(chunk)
            if stream.read(1):
                raise RustSupplyError("installed advisory database file grew while hashing")
    return digest.hexdigest()


def _verify_advisory_database(manifest: dict[str, Any]) -> Path:
    _not_expired(manifest["advisory_db"]["expires_at"])
    database = _prefix() / "advisory-db"
    if _tree_sha256(database) != ADVISORY_TREE_SHA256:
        raise RustSupplyError("installed advisory database integrity mismatch")
    return database


def _verify_rust_project(root: Path) -> None:
    expected = {
        "toolchain": {
            "channel": RUST_VERSION,
            "profile": "minimal",
            "components": ["clippy", "rustfmt"],
        }
    }
    document = tomllib.loads(
        _confined_file(root, "rust-toolchain.toml").read_text(encoding="utf-8")
    )
    if document != expected:
        raise RustSupplyError("rust-toolchain.toml does not match the reviewed contract")
    for relative in ("Cargo.toml", "Cargo.lock", ".cargo/config.toml"):
        _confined_file(root, relative)


def _registry_packages_from_content(content: bytes) -> list[dict[str, str]]:
    lock = tomllib.loads(content.decode("utf-8"))
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise RustSupplyError("Cargo.lock packages are invalid")
    result: list[dict[str, str]] = []
    for package in packages:
        if not isinstance(package, dict):
            raise RustSupplyError("Cargo.lock package is invalid")
        source = package.get("source")
        if source is None:
            continue
        if source != REGISTRY_SOURCE:
            continue
        name, version, checksum = (
            package.get("name"),
            package.get("version"),
            package.get("checksum"),
        )
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(version, str)
            or not version
            or not isinstance(checksum, str)
            or not checksum
        ):
            raise RustSupplyError("Cargo.lock registry package is incomplete")
        if not SHA256.fullmatch(checksum):
            raise RustSupplyError("Cargo.lock registry checksum is invalid")
        result.append({"checksum": checksum, "name": name, "source": source, "version": version})
    ordered = sorted(result, key=lambda item: (item["name"], item["version"], item["checksum"]))
    identities = {(item["name"], item["version"]) for item in result}
    if result != ordered or len(identities) != len(result):
        raise RustSupplyError("Cargo.lock registry packages are not canonical")
    return result


def _registry_packages(root: Path) -> list[dict[str, str]]:
    return _registry_packages_from_content(_confined_file(root, "Cargo.lock").read_bytes())


def _registry_snapshot(root: Path) -> tuple[str, str]:
    document, digest = _read_json(root, "quality/rust-registry-snapshot.json")
    if set(document) != {
        "cargo_lock_sha256",
        "expires_at",
        "generated_at",
        "packages",
        "schema_version",
    }:
        raise RustSupplyError("registry snapshot is invalid")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise RustSupplyError("registry snapshot version is invalid")
    generated = _timestamp(document["generated_at"])
    expires = _timestamp(document["expires_at"])
    now = datetime.now(UTC)
    if generated > now or expires <= now or expires <= generated:
        raise RustSupplyError("registry snapshot has expired")
    if expires - generated > timedelta(days=90):
        raise RustSupplyError("registry snapshot validity is too broad")
    lock = _confined_file(root, "Cargo.lock")
    if document["cargo_lock_sha256"] != _sha256(lock):
        raise RustSupplyError("registry snapshot does not match Cargo.lock")
    expected = [{**package, "yanked": False} for package in _registry_packages(root)]
    if document["packages"] != expected:
        raise RustSupplyError("registry snapshot package policy failed")
    return f"cargo-lock:{document['cargo_lock_sha256'][:16]}", digest


def _advisory_policy(root: Path) -> list[str]:
    document, _ = _read_json(root, "quality/rust-advisory-policy.json")
    if set(document) != {"ignored_advisories", "schema_version"}:
        raise RustSupplyError("advisory policy is invalid")
    ignored = document["ignored_advisories"]
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or not isinstance(ignored, list)
        or len(ignored) > 50
        or not all(isinstance(item, str) and ADVISORY_ID.fullmatch(item) for item in ignored)
        or ignored != sorted(set(ignored))
    ):
        raise RustSupplyError("advisory policy is invalid")
    return ignored


def _semver_baseline(root: Path) -> tuple[Path, str, str, str, str, str]:
    document, _ = _read_json(root, "quality/rust-semver-baseline.lock.json")
    if set(document) != {
        "baseline_id",
        "baseline_path",
        "baseline_sha256",
        "cargo_semver_checks",
        "crate_name",
        "feature_policy",
        "package",
        "release_type",
        "rust",
        "schema_version",
        "target",
    }:
        raise RustSupplyError("semver baseline descriptor is invalid")
    identifier = document["baseline_id"]
    digest = document["baseline_sha256"]
    package = document["package"]
    crate_name = document["crate_name"]
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or not isinstance(identifier, str)
        or not BASELINE_ID.fullmatch(identifier)
        or document["baseline_path"] != "quality/rust-semver-baseline.json"
        or not isinstance(digest, str)
        or not SHA256.fullmatch(digest)
        or document["cargo_semver_checks"] != "0.50.0"
        or document["feature_policy"] != "default-features"
        or not isinstance(package, str)
        or not PACKAGE_NAME.fullmatch(package)
        or not isinstance(crate_name, str)
        or not CRATE_NAME.fullmatch(crate_name)
        or not isinstance(document["release_type"], str)
        or document["release_type"] not in {"major", "minor", "patch"}
        or document["rust"] != RUST_VERSION
        or document["target"] != HOST_TARGET
    ):
        raise RustSupplyError("semver baseline descriptor is unreviewed")
    baseline = _confined_file(root, "quality/rust-semver-baseline.json", 20_000_000)
    if _sha256(baseline) != digest:
        raise RustSupplyError("semver baseline integrity mismatch")
    try:
        value = json.loads(baseline.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RustSupplyError("semver baseline is not rustdoc JSON") from error
    if not isinstance(value, dict) or "format_version" not in value or "index" not in value:
        raise RustSupplyError("semver baseline is not rustdoc JSON")
    return (
        baseline,
        identifier,
        digest,
        str(document["release_type"]),
        package,
        crate_name,
    )


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
        raise RustSupplyError("temporary directory is unavailable")
    return path


def _environment(rust_prefix: Path, scratch: Path) -> dict[str, str]:
    tool_bin = rust_prefix / "rustup/toolchains" / f"{RUST_VERSION}-{HOST_TARGET}" / "bin"
    cargo_home = rust_prefix / "runtime-cargo"
    if (
        cargo_home.is_symlink()
        or not cargo_home.is_dir()
        or cargo_home.resolve(strict=True) != cargo_home
    ):
        raise RustSupplyError("Rust runtime Cargo home is unavailable")
    for name in ("bin", "config", "config.toml", "credentials", "credentials.toml"):
        if (cargo_home / name).exists() or (cargo_home / name).is_symlink():
            raise RustSupplyError("Rust runtime Cargo home is unsafe")
    home = scratch / "home"
    cache = scratch / "cache"
    target = scratch / "target"
    temporary = scratch / "tmp"
    for path in (home, cache, target, temporary):
        path.mkdir()
    return {
        "PATH": f"{tool_bin}:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "HOME": str(home),
        "XDG_CACHE_HOME": str(cache),
        "CARGO": str(_rust_tool(rust_prefix, "cargo")),
        "CARGO_HOME": str(cargo_home),
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": str(target),
        "CARGO_TERM_COLOR": "never",
        "RUSTC": str(_rust_tool(rust_prefix, "rustc")),
        "RUSTDOC": str(_rust_tool(rust_prefix, "rustdoc")),
        "RUSTC_BOOTSTRAP": "1",
        "TMPDIR": str(temporary),
    }


def _run_command(root: Path, argv: list[str], environment: dict[str, str]) -> None:
    completed = subprocess.run(  # noqa: S603 - fixed absolute reviewed executable.
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
        raise RustSupplyError("Rust supply command rejected the project")


def _invoke(root: Path, argv: list[str], rust_prefix: Path) -> None:
    with tempfile.TemporaryDirectory(
        prefix="awq-rust-supply-", dir=_temporary_parent()
    ) as scratch_name:
        environment = _environment(rust_prefix, Path(scratch_name))
        _run_command(root, argv, environment)


def _binding(kind: str, identifier: str, digest: str) -> None:
    print(
        _canonical_bytes(
            {
                "bindings": [{"id": identifier, "kind": kind, "sha256": digest}],
                "schema_version": 1,
                "status": "pass",
            }
        ).decode(),
        end="",
    )


def _policy(root: Path, rust_prefix: Path) -> None:
    _confined_file(root, "deny.toml")
    identifier, digest = _registry_snapshot(root)
    _invoke(
        root,
        [
            str(_tool("cargo-deny")),
            "--format",
            "json",
            "--color",
            "never",
            "--manifest-path",
            "Cargo.toml",
            "--config",
            "deny.toml",
            "--workspace",
            "--frozen",
            "check",
            "bans",
            "licenses",
            "sources",
        ],
        rust_prefix,
    )
    _binding("registry-snapshot", identifier, digest)


def _audit(root: Path, manifest: dict[str, Any], rust_prefix: Path) -> None:
    database = _verify_advisory_database(manifest)
    ignored = _advisory_policy(root)
    argv = [
        str(_tool("cargo-audit")),
        "audit",
        "--no-fetch",
        "--no-yanked",
        "--db",
        str(database),
        "--file",
        "Cargo.lock",
        "--deny",
        "warnings",
        "--format",
        "json",
    ]
    for advisory in ignored:
        argv.extend(["--ignore", advisory])
    _invoke(root, argv, rust_prefix)
    _binding("advisory-db", f"rustsec:{ADVISORY_COMMIT}", ADVISORY_TREE_SHA256)


def _semver(root: Path, rust_prefix: Path) -> None:
    baseline, identifier, digest, release_type, package, crate_name = _semver_baseline(root)
    with tempfile.TemporaryDirectory(
        prefix="awq-rust-semver-", dir=_temporary_parent()
    ) as scratch_name:
        scratch = Path(scratch_name)
        environment = _environment(rust_prefix, scratch)
        _run_command(
            root,
            [
                str(_rust_tool(rust_prefix, "cargo")),
                "rustdoc",
                "--locked",
                "--offline",
                "--manifest-path",
                "Cargo.toml",
                "--package",
                package,
                "--lib",
                "--target",
                HOST_TARGET,
                "--",
                "-Z",
                "unstable-options",
                "--output-format=json",
            ],
            environment,
        )
        current_relative = f"target/{HOST_TARGET}/doc/{crate_name}.json"
        current = _confined_file(scratch, current_relative, 20_000_000)
        try:
            value = json.loads(current.read_text(encoding="utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise RustSupplyError("current API is not rustdoc JSON") from error
        if not isinstance(value, dict) or "format_version" not in value or "index" not in value:
            raise RustSupplyError("current API is not rustdoc JSON")
        _run_command(
            root,
            [
                str(_tool("cargo-semver-checks")),
                "check-release",
                "--baseline-rustdoc",
                str(baseline),
                "--current-rustdoc",
                str(current),
                "--release-type",
                release_type,
                "--color",
                "never",
            ],
            environment,
        )
    _binding("semver-baseline", identifier, digest)


def main(argv: list[str] | None = None) -> int:
    """Run one exact mode without returning project or tool content."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        manifest = _manifest()
        rust_prefix = _rust_prefix(manifest)
        _verify_installation(manifest, rust_prefix)
        if arguments == ["--version"]:
            print(VERSION_OUTPUT)
            return 0
        if len(arguments) != 1 or arguments[0] not in {"audit", "policy", "semver"}:
            raise RustSupplyError("invalid Rust supply invocation")
        root = Path.cwd().resolve()
        _verify_rust_project(root)
        if arguments[0] == "policy":
            _policy(root, rust_prefix)
        elif arguments[0] == "audit":
            _audit(root, manifest, rust_prefix)
        else:
            _semver(root, rust_prefix)
    except (
        OSError,
        UnicodeError,
        ValueError,
        RecursionError,
        subprocess.SubprocessError,
    ):
        print("awq-rust-supply-check: validation failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
