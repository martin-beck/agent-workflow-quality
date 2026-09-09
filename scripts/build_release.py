# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Build two identical AWQ distributions and publish a verified release bundle."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import IO, Any

from awq.release import (
    ARTIFACT_MEDIA,
    BUILD_CONSTRAINTS_PATH,
    ReleaseError,
    build_constraints_digest,
    canonical_bytes,
    inspect_archive,
    make_manifest,
    registry_digests,
    sha256_file,
    source_identity,
    verify_release,
)

UV_VERSION = "0.12.8"
PYTHON_VERSION = "3.13.15"
RECIPE = "awq-release-v1"
BUILD_TIMEOUT_SECONDS = 600
SOURCE_TIMEOUT_SECONDS = 60
MAX_SOURCE_ARCHIVE_BYTES = 100_000_000
MAX_SOURCE_MEMBERS = 10_000
MAX_SOURCE_MEMBER_BYTES = 5_000_000
MAX_SOURCE_TOTAL_BYTES = 50_000_000
UV_OUTPUT = re.compile(r"^uv ([0-9]+\.[0-9]+\.[0-9]+) \([A-Za-z0-9_.-]+\)$")


class BuildError(ValueError):
    """The deterministic release build contract was not satisfied."""


def _run_bounded(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    stdout: int | IO[bytes] = subprocess.DEVNULL,
    timeout: int,
) -> int:
    """Run one silent process group and kill all descendants on timeout."""
    process = subprocess.Popen(  # noqa: S603 - callers provide fixed reviewed argv.
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=stdout,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        raise


def _exact_directory(path: Path, label: str) -> Path:
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_dir()
        or path.resolve(strict=True) != path
    ):
        raise BuildError(f"{label} must be an exact existing directory")
    return path


def _output_path(path: Path, source: Path) -> Path:
    if (
        not path.is_absolute()
        or path.exists()
        or path.is_symlink()
        or not path.parent.is_dir()
        or path.parent.is_symlink()
        or path.parent.resolve(strict=True) != path.parent
        or path.is_relative_to(source)
    ):
        raise BuildError("output must be a new external directory")
    return path


def _project_versions(source: Path) -> tuple[str, str]:
    path = source / "pyproject.toml"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 256_000:
        raise BuildError("project metadata is unavailable")
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        version = document["project"]["version"]
        build_system = document["build-system"]
        requires = build_system["requires"]
        backend = build_system["build-backend"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise BuildError("project metadata is invalid") from error
    if (
        not isinstance(build_system, dict)
        or set(build_system) != {"requires", "build-backend"}
        or not isinstance(version, str)
        or requires != ["hatchling==1.27.0"]
        or backend != "hatchling.build"
    ):
        raise BuildError("project build versions are not exact")
    return version, "1.27.0"


def _uv_executable(path: Path, scratch: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise BuildError("uv executable is unavailable") from error
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise BuildError("uv executable is unavailable")
    with tempfile.TemporaryFile(dir=scratch) as output:
        returncode = _run_bounded(
            [str(resolved), "--version"],
            stdout=output,
            timeout=30,
        )
        size = output.tell()
        if returncode or size > 200:
            raise BuildError("uv version probe failed")
        output.seek(0)
        observed = output.read(201)
    try:
        match = UV_OUTPUT.fullmatch(observed.decode("ascii").strip())
    except UnicodeError as error:
        raise BuildError("uv version probe is invalid") from error
    if match is None or match.group(1) != UV_VERSION:
        raise BuildError("uv version differs from the reviewed recipe")
    return resolved


def _environment(cache: Path, temporary: Path, epoch: int) -> dict[str, str]:
    return {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "SOURCE_DATE_EPOCH": str(epoch),
        "TMPDIR": str(temporary),
        "TZ": "UTC",
        "UV_CACHE_DIR": str(cache),
        "UV_LINK_MODE": "copy",
        "UV_NO_PROGRESS": "1",
        "UV_OFFLINE": "1",
        "UV_PYTHON_DOWNLOADS": "never",
    }


def _build_once(
    uv: Path,
    source: Path,
    output: Path,
    cache: Path,
    temporary: Path,
    epoch: int,
) -> None:
    output.mkdir(mode=0o700)
    returncode = _run_bounded(
        [
            str(uv),
            "build",
            "--offline",
            "--no-build-logs",
            "--no-sources",
            "--no-python-downloads",
            "--no-create-gitignore",
            "--no-config",
            "--require-hashes",
            "--build-constraints",
            str(source / BUILD_CONSTRAINTS_PATH),
            "--python",
            sys.executable,
            "--out-dir",
            str(output),
            str(source),
        ],
        cwd=source,
        env=_environment(cache, temporary, epoch),
        timeout=BUILD_TIMEOUT_SECONDS,
    )
    if returncode:
        raise BuildError("offline distribution build failed")


def _safe_source_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (
        not name
        or "\0" in name
        or "\\" in name
        or path.is_absolute()
        or ".." in path.parts
        or name != path.as_posix()
    ):
        raise BuildError("Git source archive contains an unsafe path")
    return path


def _write_source_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    target: Path,
    epoch: int,
) -> int:
    relative = _safe_source_name(member.name)
    destination = target.joinpath(*relative.parts)
    if member.isdir():
        destination.mkdir(mode=0o755, parents=True, exist_ok=True)
        return 0
    if not member.isfile() or member.size > MAX_SOURCE_MEMBER_BYTES or member.mtime != epoch:
        raise BuildError("Git source snapshot member is unsafe")
    stream = archive.extractfile(member)
    if stream is None:
        raise BuildError("Git source snapshot member is unreadable")
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with stream, destination.open("xb") as output:
        remaining = member.size
        while remaining:
            chunk = stream.read(min(64 * 1024, remaining))
            if not chunk:
                raise BuildError("Git source snapshot member is truncated")
            output.write(chunk)
            remaining -= len(chunk)
        if stream.read(1):
            raise BuildError("Git source snapshot member exceeds its declared size")
    destination.chmod(0o755 if member.mode & 0o111 else 0o644)
    return member.size


def _extract_source_archive(archive_path: Path, target: Path, epoch: int) -> None:
    target.mkdir(mode=0o700)
    total = 0
    with tarfile.open(archive_path, mode="r:") as archive:
        for index, member in enumerate(archive, start=1):
            if index > MAX_SOURCE_MEMBERS:
                raise BuildError("Git source snapshot member count exceeds its bound")
            total += _write_source_member(archive, member, target, epoch)
            if total > MAX_SOURCE_TOTAL_BYTES:
                raise BuildError("Git source snapshot content exceeds its bound")


def _materialize_source(source: Path, target: Path, epoch: int) -> None:
    """Materialize one exact tracked HEAD snapshot without worktree noise."""
    archive_path = target.parent / f".{target.name}.tar"
    if target.exists() or archive_path.exists():
        raise BuildError("source snapshot target already exists")
    try:
        returncode = _run_bounded(
            [
                "/usr/bin/git",
                "-C",
                str(source),
                "archive",
                "--format=tar",
                f"--output={archive_path}",
                "HEAD",
            ],
            timeout=SOURCE_TIMEOUT_SECONDS,
        )
        if (
            returncode
            or not archive_path.is_file()
            or archive_path.is_symlink()
            or archive_path.stat().st_size > MAX_SOURCE_ARCHIVE_BYTES
        ):
            raise BuildError("Git source snapshot failed or exceeds its bound")
        _extract_source_archive(archive_path, target, epoch)
    except (OSError, tarfile.TarError) as error:
        raise BuildError("Git source snapshot is unavailable") from error
    finally:
        archive_path.unlink(missing_ok=True)


def _expected_names(version: str) -> dict[str, str]:
    return {
        "wheel": f"agent_workflow_quality-{version}-py3-none-any.whl",
        "sdist": f"agent_workflow_quality-{version}.tar.gz",
    }


def _distributions(directory: Path, version: str) -> dict[str, Path]:
    expected = _expected_names(version)
    observed = {item.name for item in directory.iterdir()}
    if observed != set(expected.values()):
        raise BuildError("distribution outputs differ from the reviewed recipe")
    result = {kind: directory / name for kind, name in expected.items()}
    for path in result.values():
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 50_000_000:
            raise BuildError("distribution output is unsafe or exceeds its bound")
        if inspect_archive(path):
            raise BuildError("distribution output fails bounded archive verification")
    return result


def _compare(first: dict[str, Path], second: dict[str, Path]) -> None:
    for kind in sorted(first):
        if first[kind].stat().st_size != second[kind].stat().st_size or sha256_file(
            first[kind]
        ) != sha256_file(second[kind]):
            raise BuildError(f"{kind} output is not byte-reproducible")


def _artifact_records(distributions: dict[str, Path]) -> list[dict[str, object]]:
    return [
        {
            "name": path.name,
            "kind": kind,
            "media_type": ARTIFACT_MEDIA[kind],
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for kind, path in distributions.items()
    ]


def _rename_noreplace(source: Path, target: Path) -> None:
    """Atomically publish one directory without replacing a competing target."""
    library = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(library, "renameat2", None)
    if renameat2 is None:
        raise BuildError("atomic no-replace publication is unavailable")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(target),
        1,
    )
    if result:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), target)


def _add_sbom(source: Path, stage: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    from awq.sbom import generate, metadata, source_inputs

    inputs = source_inputs(source)
    document = generate(inputs, manifest)
    path = stage / f"agent_workflow_quality-{manifest['version']}.spdx.json"
    path.write_bytes(canonical_bytes(document))
    path.chmod(0o644)
    result = dict(manifest)
    result["schema_version"] = 2
    result["sbom"] = metadata(inputs)
    result["artifacts"] = sorted(
        [
            *manifest["artifacts"],
            {
                "name": path.name,
                "kind": "sbom",
                "media_type": ARTIFACT_MEDIA["sbom"],
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            },
        ],
        key=lambda item: str(item["name"]),
    )
    return result


def _stage_bundle(
    source: Path,
    output: Path,
    distributions: dict[str, Path],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}-", dir=output.parent))
    published = False
    try:
        for path in distributions.values():
            target = stage / path.name
            shutil.copyfile(path, target)
            target.chmod(0o644)
        if tuple(int(part) for part in manifest["version"].split(".")) >= (0, 14, 0):
            manifest = _add_sbom(source, stage, manifest)
        manifest_path = stage / f"agent_workflow_quality-{manifest['version']}.release.json"
        manifest_path.write_bytes(canonical_bytes(manifest))
        manifest_path.chmod(0o644)
        result = verify_release(manifest_path, source)
        stage.chmod(0o755)
        _rename_noreplace(stage, output)
        published = True
        return result
    finally:
        if not published:
            shutil.rmtree(stage, ignore_errors=True)


def build_release(
    source: Path,
    output: Path,
    scratch: Path,
    cache: Path,
    uv_path: Path,
) -> dict[str, Any]:
    """Build twice, compare bytes, create a manifest and publish atomically."""
    source = _exact_directory(source, "source")
    output = _output_path(output, source)
    scratch = _exact_directory(scratch, "scratch")
    cache = _exact_directory(cache, "uv cache")
    if scratch.is_relative_to(source) or cache.is_relative_to(source):
        raise BuildError("build scratch and cache must be external")
    uv = _uv_executable(uv_path, scratch)
    identity = source_identity(source)
    version, hatchling_version = _project_versions(source)
    constraints_digest = build_constraints_digest(source)
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise BuildError("the reviewed release host is linux-x86_64")
    if platform.python_version() != PYTHON_VERSION:
        raise BuildError("Python version differs from the reviewed recipe")
    builder = {
        "recipe": RECIPE,
        "python_version": PYTHON_VERSION,
        "uv_version": UV_VERSION,
        "hatchling_version": hatchling_version,
        "host": "linux-x86_64",
        "build_constraints_sha256": constraints_digest,
    }
    with tempfile.TemporaryDirectory(prefix="awq-release-", dir=scratch) as temporary_name:
        temporary = Path(temporary_name)
        first_dir = temporary / "first"
        second_dir = temporary / "second"
        first_source = temporary / "source-first"
        second_source = temporary / "source-second"
        first_tmp = temporary / "tmp-first"
        second_tmp = temporary / "tmp-second"
        first_tmp.mkdir(mode=0o700)
        second_tmp.mkdir(mode=0o700)
        epoch_value = identity["source_date_epoch"]
        if type(epoch_value) is not int:
            raise BuildError("source epoch is invalid")
        epoch = epoch_value
        _materialize_source(source, first_source, epoch)
        _materialize_source(source, second_source, epoch)
        if (
            _project_versions(first_source) != (version, hatchling_version)
            or _project_versions(second_source) != (version, hatchling_version)
            or build_constraints_digest(first_source) != constraints_digest
            or build_constraints_digest(second_source) != constraints_digest
        ):
            raise BuildError("materialized source differs from the reviewed recipe")
        _build_once(uv, first_source, first_dir, cache, first_tmp, epoch)
        _build_once(uv, second_source, second_dir, cache, second_tmp, epoch)
        first = _distributions(first_dir, version)
        second = _distributions(second_dir, version)
        _compare(first, second)
        manifest = make_manifest(
            version=version,
            source=identity,
            builder=builder,
            registries=registry_digests(source),
            artifacts=_artifact_records(first),
        )
        return _stage_bundle(source, output, first, manifest)


def main(argv: list[str] | None = None) -> int:
    """Build one deterministic release bundle without exposing subprocess output."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--uv-cache", type=Path, required=True)
    parser.add_argument("--uv", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = build_release(
            args.source,
            args.output,
            args.scratch,
            args.uv_cache,
            args.uv,
        )
    except (
        BuildError,
        ReleaseError,
        OSError,
        subprocess.SubprocessError,
        ValueError,
    ):
        print("release build failed")
        return 1
    print(canonical_bytes(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
