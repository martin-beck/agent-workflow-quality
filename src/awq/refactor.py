# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Pinned offline collection for the Python integer-function refactoring profile."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import platform
import re
import signal
import subprocess
import sys
from itertools import pairwise
from pathlib import Path
from typing import Any, Never

from awq import __version__, assurance, refactor_worker
from awq.project import ProjectError
from awq.registry import canonical_bytes
from awq.sbom import strict_json
from awq.trust import read_file

PROFILE = "python-integer-function-v1"
TOOL_VERSION = "1.0.0"
VERSION_OUTPUT = "awq-refactor-check 1.0.0 (CPython 3.12.14; integer-function-v1)"
MAX_BYTES = 100_000
METHODS = ("characterization", "differential", "mutation", "property")
PROPERTIES = ("nondecreasing", "odd", "zero-preserving")
LIMITATION = (
    "Executed bounded CPython integer-function observations, not general Python equivalence, "
    "a theorem, complete mutation coverage or authenticated review. Explicit mutants and finite "
    "cases may omit defects. The provisioned interpreter, standard library and host are trusted; "
    "AST restrictions and process limits are not a general hostile-code sandbox. "
    "Native gates retained."
)


def _fail(code: str) -> Never:
    raise ProjectError("Python refactoring failed: " + code)


def _object(value: Any, keys: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys.split()):
        _fail("fields")
    return dict(value)


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        _fail("digest")
    return str(value)


def _relative(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 160
        or re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_.-]+)*[.](?:py|json)", value) is None
        or any(part in (".", "..") for part in value.split("/"))
    ):
        _fail("path")
    return str(value)


def _source(root: Path, raw: Any) -> tuple[str, str]:
    record = _object(raw, "path sha256")
    relative = _relative(record["path"])
    if not relative.endswith(".py"):
        _fail("source-suffix")
    source = read_file(root / relative, refactor_worker.MAX_SOURCE)
    digest = _digest(record["sha256"])
    if _hash(source) != digest:
        _fail("source-digest")
    try:
        text = source.decode("utf-8")
        refactor_worker.validate_source(text)
    except (ValueError, SyntaxError, RecursionError) as error:
        raise ProjectError("Python refactoring failed: source-profile") from error
    return text, digest


def _cases(value: Any) -> list[dict[str, int]]:
    if not isinstance(value, list) or not 3 <= len(value) <= refactor_worker.MAX_CASES:
        _fail("case-count")
    records = []
    for raw in value:
        record = _object(raw, "input expected")
        for key, limit in (("input", 100), ("expected", 1_000_000)):
            if type(record[key]) is not int or abs(record[key]) > limit:
                _fail("case-bound")
        records.append(record)
    inputs = [record["input"] for record in records]
    if inputs != sorted(set(inputs)) or 0 not in inputs or set(inputs) != {-x for x in inputs}:
        _fail("case-domain")
    return records


def _policy(root: Path, relative: str) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    if not _relative(relative).endswith(".json"):
        _fail("policy-suffix")
    raw = read_file(root / relative, MAX_BYTES)
    value = _object(
        strict_json(raw),
        (
            "schema_version profile tool_version python_version owner review_sha256 before after "
            "mutants cases properties"
        ),
    )
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["profile"] != PROFILE
        or value["tool_version"] != TOOL_VERSION
        or value["python_version"] != refactor_worker.VERSION
    ):
        _fail("unsupported-profile")
    if (
        not isinstance(value["owner"], str)
        or re.fullmatch(r"OWNER-[A-Z0-9]{4,32}", value["owner"]) is None
    ):
        _fail("owner")
    _digest(value["review_sha256"])
    if value["properties"] != list(PROPERTIES):
        _fail("properties")
    value["cases"] = _cases(value["cases"])
    mutants = value["mutants"]
    if not isinstance(mutants, list) or not 1 <= len(mutants) <= 8:
        _fail("mutant-count")
    sources = [_source(root, item) for item in [value["before"], value["after"], *mutants]]
    paths = [item["path"] for item in [value["before"], value["after"], *mutants]]
    if len(set(paths)) != len(paths) or sources[0][1] == sources[1][1]:
        _fail("duplicate-or-unchanged-source")
    mutant_hashes = [item[1] for item in sources[2:]]
    if len(set(mutant_hashes)) != len(mutant_hashes):
        _fail("duplicate-mutant")
    return value, sources


def _platform() -> None:
    if sys.platform != "linux" or platform.machine() != "x86_64":
        _fail("unsupported-platform")


def _limits() -> None:
    import resource

    for kind, value in (
        (resource.RLIMIT_CPU, 2),
        (resource.RLIMIT_AS, 256 * 1024 * 1024),
        (resource.RLIMIT_FSIZE, 0),
        (resource.RLIMIT_NOFILE, 32),
    ):
        resource.setrlimit(kind, (value, value))


def _process(command: list[str], payload: bytes) -> bytes:
    process = subprocess.Popen(  # noqa: S603 - verified absolute binary, fixed isolated argv.
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd="/",
        env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/nonexistent"},
        start_new_session=True,
        preexec_fn=_limits,
    )
    try:
        output, _ = process.communicate(payload, timeout=3)
    except subprocess.TimeoutExpired as error:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.communicate(timeout=3)
        raise ProjectError("Python refactoring failed: timeout") from error
    if process.returncode or len(output) > 8192:
        _fail("execution-or-output")
    return bytes(output)


def _files(prefix: Path, records: Any) -> list[dict[str, str]]:
    if not isinstance(records, list) or not 1 <= len(records) <= 200:
        _fail("tool-files")
    names = []
    identities: list[dict[str, str]] = []
    total = 0
    for raw in records:
        item = _object(raw, "path sha256")
        name = _relative(item["path"])
        if not name.startswith("lib/awq/"):
            _fail("tool-file-path")
        data = read_file(prefix / name, 5_000_000)
        total += len(data)
        if total > 10_000_000:
            _fail("tool-byte-bound")
        if _hash(data) != _digest(item["sha256"]):
            _fail("tool-digest")
        names.append(name)
        identities.append({"path": name, "sha256": item["sha256"]})
    if names != sorted(set(names)) or "lib/awq/refactor_worker.py" not in names:
        _fail("tool-file-set")
    return identities


def toolchain(prefix: Path) -> tuple[Path, Path, str]:
    """Verify the local offline tool installation; do not expose its machine paths."""
    _platform()
    if not prefix.is_absolute() or prefix.is_symlink() or prefix.resolve(strict=True) != prefix:
        _fail("tool-prefix")
    manifest = _object(
        strict_json(read_file(prefix / "tool.json", MAX_BYTES)),
        "schema_version tool_version python_version python python_sha256 files",
    )
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 1
        or manifest["tool_version"] != TOOL_VERSION
        or manifest["python_version"] != refactor_worker.VERSION
    ):
        _fail("tool-version")
    raw_python = manifest["python"]
    if not isinstance(raw_python, str) or re.fullmatch(r"/[A-Za-z0-9_./-]+", raw_python) is None:
        _fail("interpreter")
    python = Path(raw_python)
    if not python.is_absolute() or python.resolve(strict=True) != python:
        _fail("interpreter")
    if _hash(read_file(python, 50_000_000)) != _digest(manifest["python_sha256"]):
        _fail("interpreter-digest")
    identities = _files(prefix, manifest["files"])
    worker = prefix / "lib/awq/refactor_worker.py"
    if read_file(worker, MAX_BYTES) != read_file(Path(refactor_worker.__file__), MAX_BYTES):
        _fail("worker-version")
    if _process([str(python), "-I", "-S", "-B", "--version"], b"") != b"Python 3.12.14\n":
        _fail("interpreter-version")
    commitment = {
        "python_version": refactor_worker.VERSION,
        "python_sha256": manifest["python_sha256"],
        "tool_version": TOOL_VERSION,
        "files": identities,
    }
    return python, worker, _hash(canonical_bytes(commitment))


def _execute(python: Path, worker: Path, source: str, inputs: list[int]) -> list[int]:
    output = _process(
        [str(python), "-I", "-S", "-B", str(worker)],
        canonical_bytes({"source": source, "cases": inputs}),
    )
    document = _object(strict_json(output), "values")
    values = document["values"]
    if (
        not isinstance(values, list)
        or len(values) != len(inputs)
        or any(type(value) is not int or abs(value) > 1_000_000 for value in values)
    ):
        _fail("result-protocol")
    return list(values)


def _property_failures(inputs: list[int], outputs: list[int]) -> int:
    mapping = dict(zip(inputs, outputs, strict=True))
    return (
        int(any(left > right for left, right in pairwise(outputs)))
        + int(any(mapping[-key] != -value for key, value in mapping.items()))
        + int(mapping[0] != 0)
    )


def _records(
    value: dict[str, Any], observations: list[list[int]], tool_digest: str
) -> list[dict[str, Any]]:
    before, after, *mutants = observations
    inputs = [case["input"] for case in value["cases"]]
    expected = [case["expected"] for case in value["cases"]]
    count = len(inputs)
    before_fail = sum(left != right for left, right in zip(before, expected, strict=True))
    after_fail = sum(left != right for left, right in zip(after, expected, strict=True))
    mismatch = sum(left != right for left, right in zip(before, after, strict=True))
    killed = sum(mutant != expected for mutant in mutants)
    result = []
    for method in METHODS:
        record = {
            "method": method,
            "tool_sha256": tool_digest,
            "cases_sha256": _hash(
                canonical_bytes({"cases": value["cases"], "properties": value["properties"]})
            ),
            "before_result_sha256": _hash(canonical_bytes(before)),
            "after_result_sha256": _hash(canonical_bytes(after)),
            "cases": count,
            "before_failures": before_fail,
            "after_failures": after_fail,
            "mismatches": mismatch,
            "mutants": len(mutants) if method == "mutation" else 0,
            "killed": killed if method == "mutation" else 0,
        }
        if method == "property":
            record["before_failures"] = _property_failures(inputs, before)
            record["after_failures"] = _property_failures(inputs, after)
        result.append(record)
    return result


def _collect(root: Path, relative: str, prefix: Path) -> dict[str, Any]:
    """Execute the four fixed methods and return only AR6-compatible minimized evidence."""
    _platform()
    if root.is_symlink() or not root.is_absolute() or root.resolve(strict=True) != root:
        _fail("root")
    value, sources = _policy(root, relative)
    python, worker, tool_digest = toolchain(prefix)
    plan = {
        "profile": PROFILE,
        "cases": value["cases"],
        "properties": value["properties"],
        "sources": [digest for _, digest in sources],
        "owner": value["owner"],
        "review_sha256": value["review_sha256"],
    }
    plan_digest = _hash(canonical_bytes(plan))
    tool_digest = _hash(
        canonical_bytes({"installation_sha256": tool_digest, "plan_sha256": plan_digest})
    )
    inputs = [case["input"] for case in value["cases"]]
    observations = [_execute(python, worker, text, inputs) for text, _ in sources]
    evidence = {
        "schema_version": 1,
        "kind": "refactor",
        "scope": "bounded-behavior-agreement",
        "identities": {"before_source_sha256": sources[0][1], "after_source_sha256": sources[1][1]},
        "owner": value["owner"],
        "review_sha256": value["review_sha256"],
        "records": _records(value, observations, tool_digest),
    }
    result = assurance.evaluate(evidence)
    return {
        **result,
        "awq_version": __version__,
        "profile": PROFILE,
        "records": evidence["records"],
        "execution": "bounded-native-observation",
        "plan_sha256": plan_digest,
        "mutant_set_sha256": _hash(canonical_bytes([digest for _, digest in sources[2:]])),
        "native_gate": "retain",
        "limitation": LIMITATION,
    }


def collect(root: Path, relative: str, prefix: Path) -> dict[str, Any]:
    """Keep host/private filesystem diagnostics outside the public CLI boundary."""
    try:
        return _collect(root, relative, prefix)
    except ProjectError:
        raise
    except (OSError, ValueError) as error:
        raise ProjectError("Python refactoring failed: invalid-or-unavailable-input") from error


def adapter_main(argv: list[str] | None = None) -> int:
    """Installed fixed-configuration adapter entry point."""
    arguments = sys.argv[1:] if argv is None else argv
    try:
        prefix = Path(__file__).resolve().parents[2]
        if arguments == ["--version"]:
            toolchain(prefix)
            print(VERSION_OUTPUT)
            return 0
        if arguments != ["collect"]:
            _fail("arguments")
        result = collect(Path.cwd().resolve(), "quality/python-refactor.json", prefix)
        if result["status"] != "pass":
            _fail("evidence")
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "pass",
                    "bindings": [
                        {
                            "kind": "refactor-evidence",
                            "id": PROFILE,
                            "sha256": _hash(canonical_bytes(result)),
                        }
                    ],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except (OSError, ValueError, ProjectError):
        print("Python refactoring adapter failed")
        return 1
