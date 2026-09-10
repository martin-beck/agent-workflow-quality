# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Offline installer using an independently provisioned and digest-reviewed CPython."""

from __future__ import annotations

import argparse
import ctypes
import os
import tempfile
from pathlib import Path

import awq
from awq import refactor
from awq.project import ProjectError
from awq.registry import canonical_bytes
from awq.trust import read_file


def _publish(source: Path, target: Path) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    rename = getattr(library, "renameat2", None)
    if rename is None:
        raise ProjectError("Python refactoring install requires atomic no-replace publication")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(target), 1):
        raise ProjectError("Python refactoring tool prefix could not be published")


def install(prefix: Path, python: Path, python_sha256: str) -> None:
    """Copy the installed AWQ bundle offline; never download or replace an existing prefix."""
    refactor._platform()
    if (
        not prefix.is_absolute()
        or prefix.exists()
        or prefix.is_symlink()
        or prefix.parent.resolve(strict=True) != prefix.parent
        or not python.is_absolute()
        or python.resolve(strict=True) != python
    ):
        raise ProjectError("Python refactoring install paths are invalid")
    if refactor._hash(read_file(python, 50_000_000)) != refactor._digest(python_sha256):
        raise ProjectError("Python refactoring interpreter digest differs")
    package = Path(awq.__file__).resolve().parent
    files = sorted(path for path in package.rglob("*") if path.suffix in (".py", ".json"))
    if not 1 <= len(files) <= 200:
        raise ProjectError("Python refactoring installed package exceeds file bound")
    with tempfile.TemporaryDirectory(
        prefix=".awq-refactor-install-", dir=prefix.parent
    ) as temporary:
        stage = Path(temporary) / "installed"
        stage.mkdir()
        records = []
        total = 0
        for source in files:
            data = read_file(source, 5_000_000)
            total += len(data)
            if total > 10_000_000:
                raise ProjectError("Python refactoring installed package exceeds byte bound")
            relative = "lib/awq/" + source.relative_to(package).as_posix()
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            records.append({"path": relative, "sha256": refactor._hash(data)})
        manifest = {
            "schema_version": 1,
            "tool_version": refactor.TOOL_VERSION,
            "python_version": "3.12.14",
            "python": str(python),
            "python_sha256": python_sha256,
            "files": records,
        }
        (stage / "tool.json").write_bytes(canonical_bytes(manifest))
        (stage / "bin").mkdir()
        wrapper = (
            "#!" + str(python) + " -I\n"
            "import sys\nfrom pathlib import Path\n"
            "sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))\n"
            "from awq.refactor import adapter_main\nraise SystemExit(adapter_main())\n"
        )
        executable = stage / "bin/awq-refactor-check"
        executable.write_text(wrapper)
        executable.chmod(0o755)
        refactor.toolchain(stage)
        _publish(stage, prefix)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--python-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        install(args.prefix, args.python, args.python_sha256)
    except (OSError, ValueError, ProjectError):
        print("Python refactoring installation failed")
        return 1
    print("Installed offline pinned Python refactoring tools.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
