# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Generate a pinned default-feature rustdoc baseline and integrity descriptor."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

import awq.rust_supply_helper as helper

MAX_RUSTDOC_BYTES = 20_000_000


class SemverSnapshotError(RuntimeError):
    """Rustdoc baseline generation violated its pinned execution contract."""


def _verify_wrapper(rust_prefix: Path) -> Path:
    wrapper = rust_prefix / "bin/awq-rust-check"
    if (
        rust_prefix.is_symlink()
        or not rust_prefix.is_dir()
        or rust_prefix.resolve(strict=True) != rust_prefix
        or wrapper.is_symlink()
        or not wrapper.is_file()
        or wrapper.resolve(strict=True) != wrapper
        or not os.access(wrapper, os.X_OK)
    ):
        raise SemverSnapshotError("Rust tool prefix is unavailable")
    completed = subprocess.run(  # noqa: S603 - exact existing absolute wrapper.
        [str(wrapper), "--version"],
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
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
        raise SemverSnapshotError("Rust tool prefix version mismatch")
    return rust_prefix


def _read_rustdoc(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise SemverSnapshotError("generated rustdoc JSON is unavailable")
    if path.stat().st_size > MAX_RUSTDOC_BYTES:
        raise SemverSnapshotError("generated rustdoc JSON exceeds the size bound")
    content = path.read_bytes()
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SemverSnapshotError("generated output is not rustdoc JSON") from error
    if not isinstance(value, dict) or "format_version" not in value or "index" not in value:
        raise SemverSnapshotError("generated output is not rustdoc JSON")
    return content


def _publish(path: Path, content: bytes) -> None:
    if (
        path.is_symlink()
        or not path.parent.is_dir()
        or path.parent.resolve(strict=True) != path.parent
    ):
        raise SemverSnapshotError("rustdoc output directory is unsafe")
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
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


def generate(
    root: Path,
    rust_prefix: Path,
    package: str,
    crate_name: str,
    baseline_id: str,
    release_type: str,
) -> dict[str, object]:
    if not helper.PACKAGE_NAME.fullmatch(package):
        raise SemverSnapshotError("package name is invalid")
    if not helper.CRATE_NAME.fullmatch(crate_name):
        raise SemverSnapshotError("crate name is invalid")
    if not helper.BASELINE_ID.fullmatch(baseline_id):
        raise SemverSnapshotError("baseline identifier is invalid")
    if release_type not in {"major", "minor", "patch"}:
        raise SemverSnapshotError("release type is invalid")
    helper._verify_rust_project(root)
    rust_prefix = _verify_wrapper(rust_prefix)
    with tempfile.TemporaryDirectory(
        prefix="awq-rust-baseline-", dir=helper._temporary_parent()
    ) as scratch_name:
        scratch = Path(scratch_name)
        environment = helper._environment(rust_prefix, scratch)
        helper._run_command(
            root,
            [
                str(helper._rust_tool(rust_prefix, "cargo")),
                "rustdoc",
                "--locked",
                "--offline",
                "--manifest-path",
                "Cargo.toml",
                "--package",
                package,
                "--lib",
                "--target",
                helper.HOST_TARGET,
                "--",
                "-Z",
                "unstable-options",
                "--output-format=json",
            ],
            environment,
        )
        source = scratch / f"target/{helper.HOST_TARGET}/doc/{crate_name}.json"
        content = _read_rustdoc(source)
    baseline = root / "quality/rust-semver-baseline.json"
    descriptor_path = root / "quality/rust-semver-baseline.lock.json"
    digest = hashlib.sha256(content).hexdigest()
    document = {
        "baseline_id": baseline_id,
        "baseline_path": "quality/rust-semver-baseline.json",
        "baseline_sha256": digest,
        "cargo_semver_checks": "0.50.0",
        "crate_name": crate_name,
        "feature_policy": "default-features",
        "package": package,
        "release_type": release_type,
        "rust": helper.RUST_VERSION,
        "schema_version": 1,
        "target": helper.HOST_TARGET,
    }
    _publish(baseline, content)
    _publish(
        descriptor_path,
        (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(),
    )
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-tools-prefix", required=True, type=Path)
    parser.add_argument("--package", required=True)
    parser.add_argument("--crate-name", required=True)
    parser.add_argument("--baseline-id", required=True)
    parser.add_argument(
        "--release-type",
        choices=("major", "minor", "patch"),
        default="minor",
    )
    args = parser.parse_args(argv)
    root = Path.cwd().resolve()
    rust_prefix = args.rust_tools_prefix.parent.resolve() / args.rust_tools_prefix.name
    try:
        generate(
            root,
            rust_prefix,
            args.package,
            args.crate_name,
            args.baseline_id,
            args.release_type,
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        subprocess.SubprocessError,
        SemverSnapshotError,
    ) as error:
        print(f"Rust semver baseline failed: {error}")
        return 1
    print("Created pinned default-feature rustdoc baseline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
