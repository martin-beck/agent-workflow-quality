# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Create a time-bounded crates.io yank snapshot for the exact Cargo.lock."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO, TypedDict
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import awq.rust_supply_helper as helper

INDEX_HOST = "index.crates.io"
MAX_INDEX_BYTES = 5_000_000
MAX_PACKAGES = 10_000


class SnapshotPackage(TypedDict):
    checksum: str
    name: str
    source: str
    version: str
    yanked: bool


class RegistrySnapshot(TypedDict):
    cargo_lock_sha256: str
    expires_at: str
    generated_at: str
    packages: list[SnapshotPackage]
    schema_version: int


class RegistrySnapshotError(RuntimeError):
    """Registry snapshot generation violated its bounded acquisition contract."""


def _index_path(name: str) -> str:
    lowered = name.lower()
    if not lowered or any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for character in lowered
    ):
        raise RegistrySnapshotError("Cargo.lock contains an invalid crates.io package name")
    if len(lowered) == 1:
        return f"1/{lowered}"
    if len(lowered) == 2:
        return f"2/{lowered}"
    if len(lowered) == 3:
        return f"3/{lowered[0]}/{lowered}"
    return f"{lowered[:2]}/{lowered[2:4]}/{lowered}"


def _read_bounded(stream: BinaryIO) -> bytes:
    content = bytearray()
    while chunk := stream.read(64 * 1024):
        content.extend(chunk)
        if len(content) > MAX_INDEX_BYTES:
            raise RegistrySnapshotError("crates.io index response exceeds the size bound")
    return bytes(content)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RegistrySnapshotError("crates.io index entry contains duplicate keys")
        result[key] = value
    return result


def _crate_versions(name: str) -> list[dict[str, Any]]:
    url = f"https://{INDEX_HOST}/{_index_path(name)}"
    request = Request(url, headers={"User-Agent": "agent-workflow-quality"})
    with urlopen(request, timeout=30) as response:  # noqa: S310
        final = urlsplit(response.geturl())
        if final.scheme != "https" or final.hostname != INDEX_HOST:
            raise RegistrySnapshotError("crates.io index redirected to an unreviewed host")
        content = _read_bounded(response)
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise RegistrySnapshotError("crates.io index response is not UTF-8") from error
    result: list[dict[str, Any]] = []
    for line in lines:
        try:
            value = json.loads(
                line,
                object_pairs_hook=_unique_object,
                parse_constant=lambda item: (_ for _ in ()).throw(
                    RegistrySnapshotError(f"invalid index constant: {item}")
                ),
            )
        except json.JSONDecodeError as error:
            raise RegistrySnapshotError("crates.io index entry is invalid") from error
        if not isinstance(value, dict):
            raise RegistrySnapshotError("crates.io index entry is not an object")
        result.append(value)
    if not result:
        raise RegistrySnapshotError("crates.io index response is empty")
    return result


def _observe(package: dict[str, str], versions: list[dict[str, Any]]) -> SnapshotPackage:
    matches = [entry for entry in versions if entry.get("vers") == package["version"]]
    if len(matches) != 1:
        raise RegistrySnapshotError("Cargo.lock version is absent or repeated in crates.io")
    entry = matches[0]
    yanked = entry.get("yanked")
    if (
        entry.get("name") != package["name"]
        or entry.get("cksum") != package["checksum"]
        or type(yanked) is not bool
    ):
        raise RegistrySnapshotError("crates.io metadata does not match Cargo.lock")
    return {
        "checksum": package["checksum"],
        "name": package["name"],
        "source": package["source"],
        "version": package["version"],
        "yanked": yanked,
    }


def _validate_output(root: Path, path: Path) -> None:
    if (
        not path.is_absolute()
        or not path.is_relative_to(root)
        or path == root
        or path.is_symlink()
        or not path.parent.is_dir()
        or path.parent.resolve(strict=True) != path.parent
    ):
        raise RegistrySnapshotError("snapshot output directory is unsafe")


def _publish(root: Path, path: Path, content: bytes) -> None:
    _validate_output(root, path)
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=".rust-registry-", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    except Exception:
        if temporary is not None:
            with contextlib.suppress(OSError):
                temporary.unlink()
        raise


def generate(root: Path, output: Path, valid_days: int) -> RegistrySnapshot:
    if not 1 <= valid_days <= 90:
        raise RegistrySnapshotError("snapshot validity must be between 1 and 90 days")
    _validate_output(root, output)
    lock = helper._confined_file(root, "Cargo.lock")
    lock_content = lock.read_bytes()
    packages = helper._registry_packages_from_content(lock_content)
    if len(packages) > MAX_PACKAGES:
        raise RegistrySnapshotError("Cargo.lock contains too many registry packages")
    for name in {package["name"] for package in packages}:
        _index_path(name)
    by_name: dict[str, list[dict[str, Any]]] = {}
    observed: list[SnapshotPackage] = []
    for package in packages:
        name = package["name"]
        if name not in by_name:
            by_name[name] = _crate_versions(name)
        observed.append(_observe(package, by_name[name]))
    now = datetime.now(UTC).replace(microsecond=0)
    if helper._confined_file(root, "Cargo.lock").read_bytes() != lock_content:
        raise RegistrySnapshotError("Cargo.lock changed during registry acquisition")
    document: RegistrySnapshot = {
        "cargo_lock_sha256": hashlib.sha256(lock_content).hexdigest(),
        "expires_at": (now + timedelta(days=valid_days))
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "generated_at": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "packages": observed,
        "schema_version": 1,
    }
    content = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    _publish(root, output, content)
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("quality/rust-registry-snapshot.json"),
    )
    parser.add_argument("--valid-days", type=int, default=30)
    args = parser.parse_args(argv)
    root = Path.cwd().resolve()
    output = root / args.output
    try:
        if args.output.is_absolute() or ".." in args.output.parts:
            raise RegistrySnapshotError("snapshot output path must be project-relative")
        generate(root, output, args.valid_days)
    except (OSError, UnicodeError, ValueError, RegistrySnapshotError) as error:
        print(f"Rust registry snapshot failed: {error}")
        return 1
    print("Created bounded crates.io metadata snapshot.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
