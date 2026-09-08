# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Reject unsafe, private, or incomplete AWQ distribution archives."""

from __future__ import annotations

import argparse
import re
import stat
import tarfile
import zipfile
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

MAX_MEMBERS = 10_000
MAX_MEMBER_BYTES = 5_000_000
MAX_TOTAL_BYTES = 50_000_000
DENIED_PARTS = frozenset({".git", ".venv", "__pycache__"})
REQUIRED_SCHEMAS = frozenset({"adapter-contract.schema.json", "adapter-result.schema.json"})
ArchiveMember = tuple[str, bytes | None]


class DistributionError(ValueError):
    """A distribution archive is malformed or outside the review bounds."""


def _checked_name(name: str) -> tuple[PurePosixPath, list[str]]:
    path = PurePosixPath(name)
    issues: list[str] = []
    if (
        not name
        or "\0" in name
        or "\\" in name
        or path.is_absolute()
        or ".." in path.parts
        or re.match(r"^[A-Za-z]:", name)
        or name != path.as_posix()
    ):
        issues.append(f"{name}: unsafe archive path")
    if DENIED_PARTS.intersection(path.parts) or path.name == ".coverage":
        issues.append(f"{name}: forbidden development artifact")
    return path, issues


def _tar_members(path: Path) -> Iterator[ArchiveMember]:
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > MAX_MEMBERS:
            raise DistributionError("archive member count exceeds the review bound")
        for member in members:
            if member.isdir():
                continue
            if not member.isfile():
                yield member.name, None
                continue
            if member.size > MAX_MEMBER_BYTES:
                raise DistributionError(f"{member.name}: member exceeds the review bound")
            stream = archive.extractfile(member)
            if stream is None:
                raise DistributionError(f"{member.name}: regular member is unreadable")
            with stream:
                content = stream.read(MAX_MEMBER_BYTES + 1)
            if len(content) > MAX_MEMBER_BYTES:
                raise DistributionError(f"{member.name}: member exceeds the review bound")
            yield member.name, content


def _zip_members(path: Path) -> Iterator[ArchiveMember]:
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS:
            raise DistributionError("archive member count exceeds the review bound")
        for member in members:
            if member.is_dir():
                continue
            if member.file_size > MAX_MEMBER_BYTES:
                raise DistributionError(f"{member.filename}: member exceeds the review bound")
            kind = stat.S_IFMT(member.external_attr >> 16)
            if kind not in {0, stat.S_IFREG}:
                yield member.filename, None
                continue
            yield member.filename, archive.read(member)


def inspect_archive(path: Path) -> list[str]:
    """Return bounded archive findings without extracting any member."""
    try:
        if path.name.endswith(".tar.gz"):
            members = _tar_members(path)
        elif path.suffix == ".whl":
            members = _zip_members(path)
        else:
            raise DistributionError(f"{path.name}: unsupported distribution format")
        issues: list[str] = []
        names: list[PurePosixPath] = []
        seen: set[str] = set()
        total = 0
        for name, content in members:
            normalized, path_issues = _checked_name(name)
            names.append(normalized)
            issues.extend(path_issues)
            if name in seen:
                issues.append(f"{name}: duplicate archive path")
            seen.add(name)
            if content is None:
                issues.append(f"{name}: non-regular archive member")
                continue
            total += len(content)
            if total > MAX_TOTAL_BYTES:
                raise DistributionError("archive content exceeds the review bound")
        present = {
            name.name for name in names if len(name.parts) >= 2 and name.parts[-2] == "schemas"
        }
        issues.extend(
            f"{path.name}: required packaged schema is missing: {schema}"
            for schema in sorted(REQUIRED_SCHEMAS - present)
        )
        return issues
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise DistributionError(f"{path.name}: cannot inspect archive") from error


def main(argv: list[str] | None = None) -> int:
    """Inspect named archives and report content-minimized findings."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", nargs="+", type=Path)
    paths = parser.parse_args(argv).archives
    try:
        issues = [
            issue
            for path in sorted(paths, key=lambda item: item.name)
            for issue in inspect_archive(path)
        ]
    except DistributionError as error:
        print(f"distribution verification failed: {error}")
        return 2
    if issues:
        print("\n".join(issues))
        return 1
    print(f"Verified {len(paths)} bounded distribution archives.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
