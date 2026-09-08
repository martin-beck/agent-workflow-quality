# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Pinned, bounded external quality adapter contracts."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
from importlib.resources import files as resource_files
from pathlib import Path, PurePosixPath
from typing import Any

from awq.registry import EVIDENCE_CLASSES, TIERS, canonical_bytes

ADAPTER_OPTIONAL_KEYS = {"input_mode"}
ADAPTER_KEYS = {
    "id",
    "tool",
    "version",
    "version_argv",
    "version_output",
    "argv",
    "timeout_seconds",
    "tier",
    "evidence",
    "limitation",
    "remediation",
    "formats",
    "config_paths",
}
INPUT_MODES = {"explicit", "tracked-formats", "tracked-shell"}
MAX_SELECTED_INPUTS = 10_000
MAX_SELECTED_INPUT_BYTES = 1_000_000
ADAPTER_ID = re.compile(r"^ADAPTER-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
TOOL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]*$")
FORMAT = re.compile(r"^\.[a-z0-9]+$")
SHELL_SHEBANG = re.compile(
    rb"^#![ \t]*(?:/usr/bin/env(?:[ \t]+-S)?[ \t]+)?"
    rb"(?:/[^ \t\r\n]+/)?(?:sh|bash|dash|ksh|mksh|zsh|ash)(?:[ \t]|$)"
)
FAMILY_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
CATALOG_KEYS = {"schema_version", "families"}
FAMILY_KEYS = {"id", "title", "description", "assumptions", "contracts"}
MAX_PROBE_BYTES = 4096
MAX_ARGUMENTS = 100
MAX_ARGUMENT_LENGTH = 1000


class AdapterError(ValueError):
    """An adapter contract or invocation is unsafe or invalid."""


def _strings(value: object, *, nonempty: bool = False) -> bool:
    return isinstance(value, list) and all(
        isinstance(item, str)
        and "\0" not in item
        and len(item) <= MAX_ARGUMENT_LENGTH
        and (not nonempty or bool(item))
        for item in value
    )


def _safe_relative(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    candidate = PurePosixPath(value)
    return (
        value not in {".", ".."}
        and not value.startswith("/")
        and not re.match(r"^[A-Za-z]:", value)
        and ".." not in candidate.parts
        and value == candidate.as_posix()
    )


def _validate_identity(value: dict[str, Any]) -> None:
    identifier = value["id"]
    tool = value["tool"]
    if not isinstance(identifier, str) or not ADAPTER_ID.fullmatch(identifier):
        raise AdapterError("adapter identifier must match ADAPTER-NAME")
    if not isinstance(tool, str) or not TOOL_NAME.fullmatch(tool):
        raise AdapterError("adapter tool must be a portable executable name")
    version = value["version"]
    version_output = value["version_output"]
    if (
        not isinstance(version, str)
        or not version
        or len(version) > 100
        or not isinstance(version_output, str)
        or not version_output
        or len(version_output) > 200
        or version not in version_output
    ):
        raise AdapterError("adapter version pin and exact probe output are invalid")


def _validate_argv(value: dict[str, Any]) -> None:
    for field in ("version_argv", "argv"):
        argv = value[field]
        if (
            not _strings(argv, nonempty=True)
            or not argv
            or len(argv) > MAX_ARGUMENTS
            or argv[0] != value["tool"]
        ):
            raise AdapterError(f"adapter {field} must be a bounded argv led by its tool")


def _validate_classification(value: dict[str, Any]) -> None:
    timeout = value["timeout_seconds"]
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 3600:
        raise AdapterError("adapter deadline is outside the supported bound")
    if value["tier"] not in TIERS or value["evidence"] not in EVIDENCE_CLASSES:
        raise AdapterError("adapter has an unknown classification")
    for field in ("limitation", "remediation"):
        text = value[field]
        if not isinstance(text, str) or not text.strip() or len(text) > 500:
            raise AdapterError(f"adapter {field} must be bounded non-empty text")


def _validate_paths(value: dict[str, Any]) -> None:
    formats = value["formats"]
    if (
        not _strings(formats)
        or not formats
        or not all(FORMAT.fullmatch(item) for item in formats)
        or len(set(formats)) != len(formats)
    ):
        raise AdapterError("adapter formats must be unique lowercase suffixes")
    config_paths = value["config_paths"]
    if (
        not _strings(config_paths)
        or not all(_safe_relative(item) for item in config_paths)
        or len(set(config_paths)) != len(config_paths)
    ):
        raise AdapterError("adapter config paths must be unique safe repository paths")


def validate_adapter(value: dict[str, Any]) -> None:
    """Validate one exact adapter contract without third-party dependencies."""
    keys = set(value)
    if not keys >= ADAPTER_KEYS or not keys <= ADAPTER_KEYS | ADAPTER_OPTIONAL_KEYS:
        raise AdapterError("adapter has unknown or missing fields")
    if value.get("input_mode", "explicit") not in INPUT_MODES:
        raise AdapterError("adapter has an unsupported input mode")
    _validate_identity(value)
    _validate_argv(value)
    _validate_classification(value)
    _validate_paths(value)


def _family_text(family: dict[str, Any], field: str, maximum: int) -> None:
    text = family[field]
    if not isinstance(text, str) or not text.strip() or len(text) > maximum or "\0" in text:
        raise AdapterError(f"adapter family {field} must be bounded non-empty text")


def _validate_adapter_family(
    family: object, known_families: set[str], contract_ids: set[str]
) -> tuple[str, dict[str, Any]]:
    if not isinstance(family, dict) or set(family) != FAMILY_KEYS:
        raise AdapterError("adapter family has unknown or missing fields")
    identifier = family["id"]
    if (
        not isinstance(identifier, str)
        or len(identifier) > 100
        or not FAMILY_ID.fullmatch(identifier)
        or identifier in known_families
    ):
        raise AdapterError("adapter family identifier is invalid or duplicated")
    _family_text(family, "title", 200)
    _family_text(family, "description", 500)
    assumptions = family["assumptions"]
    if (
        not _strings(assumptions, nonempty=True)
        or not assumptions
        or len(assumptions) > 20
        or any(len(item) > 500 for item in assumptions)
        or len(set(assumptions)) != len(assumptions)
    ):
        raise AdapterError("adapter family assumptions must be unique bounded text")
    contracts = family["contracts"]
    if not isinstance(contracts, list) or not contracts or len(contracts) > 100:
        raise AdapterError("adapter family contracts must be a bounded non-empty list")
    observed_ids: list[str] = []
    prefix = f"ADAPTER-{identifier.upper()}-"
    for contract in contracts:
        if not isinstance(contract, dict):
            raise AdapterError("adapter family contract must be an object")
        validate_adapter(contract)
        contract_id = contract["id"]
        if not contract_id.startswith(prefix) or contract_id in contract_ids:
            raise AdapterError("adapter contract identifier has the wrong family or is duplicated")
        contract_ids.add(contract_id)
        observed_ids.append(contract_id)
    if observed_ids != sorted(observed_ids):
        raise AdapterError("adapter family contracts must be ordered by identifier")
    return identifier, family


def _validate_adapter_catalog(value: object) -> dict[str, dict[str, Any]]:
    """Validate the closed, immutable built-in adapter catalog."""
    if not isinstance(value, dict) or set(value) != CATALOG_KEYS:
        raise AdapterError("adapter catalog has unknown or missing fields")
    if value["schema_version"] != 1:
        raise AdapterError("adapter catalog has an unsupported schema version")
    declared = value["families"]
    if not isinstance(declared, list) or not declared or len(declared) > 100:
        raise AdapterError("adapter catalog families must be a bounded non-empty list")
    families: dict[str, dict[str, Any]] = {}
    contract_ids: set[str] = set()
    for family in declared:
        identifier, validated = _validate_adapter_family(family, set(families), contract_ids)
        families[identifier] = validated
    if list(families) != sorted(families):
        raise AdapterError("adapter families must be ordered by identifier")
    return families


def load_adapter_catalog() -> tuple[dict[str, dict[str, Any]], str]:
    """Load reviewed adapter families and their canonical digest."""
    document = json.loads(
        resource_files("awq.data").joinpath("adapter_catalog.json").read_text(encoding="utf-8")
    )
    families = _validate_adapter_catalog(document)
    return families, hashlib.sha256(canonical_bytes(document)).hexdigest()


def _environment() -> dict[str, str]:
    """Return a minimal locale-stable environment without credential variables."""
    result = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
    }
    for name in ("PATHEXT", "SYSTEMROOT", "WINDIR", "TMPDIR", "TEMP", "TMP"):
        if name in os.environ:
            result[name] = os.environ[name]
    return result


def _bounded_probe(
    argv: list[str], root: Path, environment: dict[str, str], timeout: int
) -> tuple[int, str, bool, bool]:
    """Run a version probe with one merged, capped output stream."""
    process = subprocess.Popen(  # noqa: S603 - validated argv and no shell.
        argv,
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    stream = process.stdout
    if stream is None:
        process.kill()
        process.wait()
        raise AdapterError("adapter version probe has no output stream")
    output = bytearray()
    overflow = threading.Event()

    def drain() -> None:
        while chunk := stream.read(1024):
            remaining = MAX_PROBE_BYTES - len(output)
            output.extend(chunk[:remaining])
            if len(chunk) > remaining:
                overflow.set()
                with contextlib.suppress(OSError):
                    process.kill()
                return

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        timed_out = False
        try:
            returncode = process.wait(timeout=min(timeout, 10))
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            returncode = process.wait()
        reader.join(timeout=1)
        if reader.is_alive():
            with contextlib.suppress(OSError):
                process.kill()
                stream.close()
            reader.join(timeout=1)
            raise AdapterError("adapter version probe did not terminate")
        observed = output.decode("utf-8", errors="replace").strip()
        return returncode, observed, timed_out, overflow.is_set()
    finally:
        with contextlib.suppress(OSError):
            stream.close()


def _result(
    contract: dict[str, Any],
    started: float,
    status: str,
    findings: list[dict[str, str]],
) -> dict[str, Any]:
    return {
        "id": contract["id"],
        "tool": contract["tool"],
        "version": contract["version"],
        "status": status,
        "evidence": contract["evidence"],
        "limitation": contract["limitation"],
        "remediation": contract["remediation"],
        "duration_ms": int((time.monotonic() - started) * 1000),
        "exceptions": [],
        "findings": findings,
    }


def _finding(code: str, path: str, message: str) -> list[dict[str, str]]:
    return [{"code": code, "path": path, "message": message}]


def _config_failure(root: Path, contract: dict[str, Any]) -> list[dict[str, str]] | None:
    from awq.project import ProjectError, confined_path

    for relative in contract["config_paths"]:
        try:
            path = confined_path(root, relative)
        except ProjectError:
            return _finding("adapter-config-unsafe", "", "declared configuration path is unsafe")
        except OSError:
            return _finding(
                "adapter-config-missing",
                relative,
                "declared project configuration is unavailable",
            )
        if not path.is_file():
            return _finding(
                "adapter-config-missing",
                relative,
                "declared project configuration is unavailable",
            )
    return None


def _probe_failure(
    returncode: int,
    observed: str,
    timed_out: bool,
    overflow: bool,
    expected: str,
) -> list[dict[str, str]] | None:
    if timed_out:
        return _finding(
            "adapter-version-timeout", "", "adapter version probe exceeded its deadline"
        )
    if overflow:
        return _finding(
            "adapter-version-output-limit", "", "adapter version probe exceeded its bound"
        )
    if returncode != 0 or observed != expected:
        return _finding(
            "adapter-version-mismatch", "", "adapter version does not match its exact pin"
        )
    return None


def _is_fixture(relative: str, fixtures: list[str]) -> bool:
    return any(
        relative == prefix or relative.startswith(prefix.rstrip("/") + "/") for prefix in fixtures
    )


def _shell_entrypoint(path: Path) -> bool:
    try:
        if path.is_symlink() or not path.is_file() or not path.stat().st_mode & 0o111:
            return False
        with path.open("rb") as stream:
            return SHELL_SHEBANG.match(stream.readline(256)) is not None
    except OSError:
        return False


def _selected_inputs(root: Path, contract: dict[str, Any]) -> list[str]:
    mode = contract.get("input_mode", "explicit")
    if mode == "explicit":
        return []
    from awq.project import load_project, policy_paths, tracked_files

    policy_path, _ = policy_paths(root)
    fixtures = load_project(root)[0]["fixture_paths"] if policy_path.is_file() else []
    selected: list[str] = []
    for path in tracked_files(root):
        relative = path.relative_to(root).as_posix()
        if _is_fixture(relative, fixtures):
            continue
        if path.suffix in contract["formats"] or (
            mode == "tracked-shell" and _shell_entrypoint(path)
        ):
            selected.append(relative)
    return selected


def _execution_failure(
    root: Path,
    executable: str,
    contract: dict[str, Any],
    environment: dict[str, str],
    inputs: list[str],
) -> list[dict[str, str]] | None:
    argv = [executable, *contract["argv"][1:], *inputs]
    try:
        completed = subprocess.run(  # noqa: S603 - validated argv and no shell.
            argv,
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=contract["timeout_seconds"],
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _finding("adapter-timeout", "", "adapter exceeded its deadline")
    except OSError:
        return _finding("adapter-tool-unavailable", "", "pinned adapter tool could not be started")
    if completed.returncode:
        return _finding("adapter-failed", "", "adapter returned a non-zero status")
    return None


def run_adapter(root: Path, contract: dict[str, Any]) -> dict[str, Any]:
    """Run one validated adapter with exact version and content-minimized evidence."""
    validate_adapter(contract)
    started = time.monotonic()
    failure = _config_failure(root, contract)
    if failure:
        return _result(contract, started, "fail", failure)
    executable = shutil.which(contract["tool"], path=os.environ.get("PATH"))
    if executable is None:
        failure = _finding("adapter-tool-unavailable", "", "pinned adapter tool is unavailable")
        return _result(contract, started, "fail", failure)
    environment = _environment()
    probe = [executable, *contract["version_argv"][1:]]
    try:
        outcome = _bounded_probe(probe, root, environment, contract["timeout_seconds"])
    except OSError:
        failure = _finding(
            "adapter-tool-unavailable", "", "pinned adapter tool could not be started"
        )
        return _result(contract, started, "fail", failure)
    except AdapterError:
        failure = _finding(
            "adapter-version-failed", "", "adapter version probe failed its safety contract"
        )
        return _result(contract, started, "fail", failure)
    failure = _probe_failure(*outcome, contract["version_output"])
    if failure:
        return _result(contract, started, "fail", failure)
    inputs = _selected_inputs(root, contract)
    if contract.get("input_mode", "explicit") != "explicit" and not inputs:
        failure = _finding(
            "adapter-inputs-missing", "", "adapter selected no tracked project inputs"
        )
        return _result(contract, started, "fail", failure)
    input_bytes = sum(len(os.fsencode(item)) + 1 for item in inputs)
    if len(inputs) > MAX_SELECTED_INPUTS or input_bytes > MAX_SELECTED_INPUT_BYTES:
        failure = _finding(
            "adapter-inputs-limit", "", "adapter selected inputs exceed the argv safety bound"
        )
        return _result(contract, started, "fail", failure)
    failure = _execution_failure(root, executable, contract, environment, inputs)
    return _result(contract, started, "fail" if failure else "pass", failure or [])
