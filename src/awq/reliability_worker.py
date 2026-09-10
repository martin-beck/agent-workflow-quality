# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Fixed synthetic Git repository worker; never executes consumer extensions."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from awq import commands, project
from awq.registry import canonical_bytes
from awq.reliability import FIXTURES, digest


def normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: normalize(item) for key, item in value.items() if key != "duration_ms"}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    return value


def _git(root: Path, *args: str) -> None:
    subprocess.run(  # noqa: S603 - fixed synthetic Git operations, isolated parent environment.
        [
            "/usr/bin/git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=AWQ Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-C",
            str(root),
            *args,
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )


def prepare(root: Path, fixture: str) -> int:
    count, size = FIXTURES[fixture]
    payload = canonical_bytes({"padding": "x" * (size - len(canonical_bytes({"padding": ""})))})
    if len(payload) != size:
        raise ValueError("fixture-size")
    for index in range(count):
        (root / ("sample-" + str(index).zfill(4) + ".json")).write_bytes(payload)
    _git(root, "init", "--quiet", "--template=")
    commands.initialize(root, ["core", "schemas"], False)
    _git(root, "add", "--all")
    _git(root, "commit", "--quiet", "-m", "Synthetic benchmark fixture")
    return count + 3


def measure(operation: Callable[[], Any]) -> dict[str, Any]:
    start = time.perf_counter_ns()
    result = operation()
    elapsed = time.perf_counter_ns() - start
    if isinstance(result, dict) and result.get("status", result.get("result")) == "fail":
        raise ValueError("fixture-check-failed")
    normalized = normalize(result)
    if len(canonical_bytes(normalized)) > 65536:
        raise ValueError("fixture-evidence-truncated")
    return {"elapsed_ns": elapsed, "status": "pass", "semantic_sha256": digest(normalized)}


def benchmark(fixture: str, scratch: Path) -> dict[str, Any]:
    if (
        fixture not in FIXTURES
        or not scratch.is_absolute()
        or scratch.resolve(strict=True) != scratch
    ):
        raise ValueError("fixture-input")
    with tempfile.TemporaryDirectory(prefix="awq-benchmark-", dir=scratch) as directory:
        root = Path(directory)
        count = prepare(root, fixture)

        def discover() -> list[str]:
            files = project.tracked_files(root)
            if len(files) != count:
                raise ValueError("fixture-tracking")
            return [path.relative_to(root).as_posix() for path in files]

        return {
            "discovery": measure(discover),
            "checks": measure(lambda: commands.check(root, "pr")),
            "evidence": measure(lambda: commands.evidence(root, "pr")),
            "policy-diff": measure(lambda: commands.policy_diff(root, "HEAD", "HEAD")),
        }


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    try:
        if len(arguments) != 2:
            raise ValueError("arguments")
        result = benchmark(arguments[0], Path(arguments[1]))
        sys.stdout.buffer.write(canonical_bytes(result))
        return 0
    except Exception:
        sys.stdout.buffer.write(b'{"status":"error"}\n')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
