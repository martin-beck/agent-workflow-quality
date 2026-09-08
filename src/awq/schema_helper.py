# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Strict, bounded data and JSON Schema checks for the pinned schema tool bundle."""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

HELPER_VERSION = "1.0.0"
STRICTYAML_VERSION = "1.7.3"
JSONSCHEMA_VERSION = "16.3.0"
VERSION_OUTPUT = (
    f"awq-schema-check {HELPER_VERSION} "
    f"(StrictYAML {STRICTYAML_VERSION}; JSON Schema CLI {JSONSCHEMA_VERSION})"
)
MAX_FILES = 10_000
MAX_FILE_BYTES = 5_000_000
MAX_TOTAL_BYTES = 50_000_000
SCHEMA_REFERENCE_KEYS = {"$ref", "$dynamicRef", "$recursiveRef"}


class SchemaCheckError(ValueError):
    """A schema-tool input violated the strict execution contract."""


@dataclass
class ReadBudget:
    """Bound unique input reads across one invocation."""

    total: int = 0
    seen: set[Path] = field(default_factory=set)

    def read(self, root: Path, relative: str) -> tuple[Path, str]:
        path = _confined_file(root, relative)
        if path not in self.seen:
            if len(self.seen) >= MAX_FILES:
                raise SchemaCheckError("input file count exceeds the bound")
            size = path.stat().st_size
            if size > MAX_FILE_BYTES or self.total + size > MAX_TOTAL_BYTES:
                raise SchemaCheckError("input size limit exceeded")
            self.seen.add(path)
            self.total += size
        payload = path.read_bytes()
        if len(payload) > MAX_FILE_BYTES:
            raise SchemaCheckError("input size limit exceeded")
        return path, payload.decode("utf-8")


def _safe_relative(value: str) -> bool:
    candidate = PurePosixPath(value)
    return (
        bool(value)
        and "\\" not in value
        and not candidate.is_absolute()
        and ".." not in candidate.parts
        and value == candidate.as_posix()
    )


def _confined_file(root: Path, relative: str) -> Path:
    if not _safe_relative(relative):
        raise SchemaCheckError("input path is unsafe")
    path = (root / relative).resolve()
    if root not in (path, *path.parents) or not path.is_file():
        raise SchemaCheckError("input path is unavailable or escapes the root")
    return path


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SchemaCheckError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    del value
    raise SchemaCheckError("non-finite JSON number")


def _json_document(root: Path, relative: str, budget: ReadBudget) -> Any:
    _, text = budget.read(root, relative)
    return json.loads(
        text,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )


def _yaml_document(root: Path, relative: str, budget: ReadBudget) -> Any:
    _, text = budget.read(root, relative)
    module = importlib.import_module("strictyaml")
    try:
        return module.load(text, label=relative)
    except module.YAMLError:
        raise SchemaCheckError("invalid YAML document") from None


def _reference_targets(value: Any) -> list[str]:
    targets: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in SCHEMA_REFERENCE_KEYS:
                if not isinstance(item, str):
                    raise SchemaCheckError("schema reference is not a string")
                targets.append(item)
            targets.extend(_reference_targets(item))
    elif isinstance(value, list):
        for item in value:
            targets.extend(_reference_targets(item))
    return targets


def _local_reference(root: Path, source: Path, reference: str) -> Path | None:
    parsed = urlsplit(reference)
    if parsed.scheme or parsed.netloc or parsed.query or "\\" in reference:
        raise SchemaCheckError("schema reference is not repository-local")
    if not parsed.path:
        return None
    decoded = unquote(parsed.path)
    if not _safe_relative(decoded):
        raise SchemaCheckError("schema reference path is unsafe")
    candidate = (source.parent / decoded).resolve()
    if root not in (candidate, *candidate.parents) or not candidate.is_file():
        raise SchemaCheckError("schema reference is unavailable or escapes the root")
    if not candidate.name.endswith(".schema.json"):
        raise SchemaCheckError("local schema reference lacks the strict schema suffix")
    return candidate


def _schema_graph(root: Path, names: list[str], budget: ReadBudget) -> None:
    pending = [_confined_file(root, name) for name in names]
    inspected: set[Path] = set()
    while pending:
        source = pending.pop()
        if source in inspected:
            continue
        relative = source.relative_to(root).as_posix()
        document = _json_document(root, relative, budget)
        for reference in _reference_targets(document):
            target = _local_reference(root, source, reference)
            if target is not None and target not in inspected:
                pending.append(target)
        inspected.add(source)


def _tool_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _jsonschema_binary() -> Path:
    binary = _tool_root() / "bin" / "jsonschema"
    if not binary.is_file() or binary.is_symlink():
        raise SchemaCheckError("JSON Schema CLI is unavailable")
    return binary


def _tool_environment() -> dict[str, str]:
    return {
        "PATH": f"{_tool_root() / 'bin'}:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
    }


def _verify_toolset() -> None:
    importlib.import_module("strictyaml")
    completed = subprocess.run(  # noqa: S603 - exact executable inside the pinned prefix.
        [str(_jsonschema_binary()), "version"],
        cwd=Path.cwd(),
        env=_tool_environment(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if completed.returncode or (completed.stdout + completed.stderr).strip() != JSONSCHEMA_VERSION:
        raise SchemaCheckError("JSON Schema CLI version mismatch")


def _invoke_jsonschema(arguments: list[str]) -> None:
    completed = subprocess.run(  # noqa: S603 - exact executable inside the pinned prefix.
        [str(_jsonschema_binary()), *arguments],
        cwd=Path.cwd(),
        env=_tool_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=120,
        check=False,
    )
    if completed.returncode:
        raise SchemaCheckError("JSON Schema CLI rejected the input")


def _check_documents(root: Path, mode: str, names: list[str], budget: ReadBudget) -> None:
    parser = _json_document if mode == "json" else _yaml_document
    for name in names:
        parser(root, name, budget)


def _validate_instances(root: Path, schema: str, instances: list[str], budget: ReadBudget) -> None:
    _schema_graph(root, [schema], budget)
    for instance in instances:
        if instance.endswith(".json"):
            _json_document(root, instance, budget)
        elif instance.endswith((".yaml", ".yml")):
            _yaml_document(root, instance, budget)
        else:
            raise SchemaCheckError("instance format is unsupported")
    _invoke_jsonschema(["validate", schema, "--format-assertion", *instances])


def main(argv: list[str] | None = None) -> int:
    """Run a strict mode without returning document content."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        _verify_toolset()
        if arguments == ["--version"]:
            print(VERSION_OUTPUT)
            return 0
        if not arguments or len(arguments) > MAX_FILES + 1:
            raise SchemaCheckError("invalid argument count")
        root = Path.cwd().resolve()
        mode, *names = arguments
        budget = ReadBudget()
        if mode in {"json", "yaml"} and names:
            _check_documents(root, mode, names, budget)
        elif mode == "metaschema" and names:
            _schema_graph(root, names, budget)
            _invoke_jsonschema(["metaschema", "--format-assertion", *names])
        elif mode == "validate" and len(names) >= 2:
            _validate_instances(root, names[0], names[1:], budget)
        else:
            raise SchemaCheckError("unsupported schema check invocation")
    except (
        ImportError,
        OSError,
        UnicodeError,
        ValueError,
        RecursionError,
        subprocess.SubprocessError,
    ):
        print("awq-schema-check: validation failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
