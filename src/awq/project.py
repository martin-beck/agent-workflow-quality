"""Confined repository access and consumer policy generation."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from awq import __version__
from awq.registry import canonical_bytes, expand_profiles, load_registry

POLICY_KEYS = {
    "schema_version",
    "profiles",
    "unknown_formats",
    "fixture_paths",
    "extensions",
    "exceptions",
}
LOCK_KEYS = {"schema_version", "awq_version", "registry_sha256", "profiles", "requirements"}
EXTENSION_KEYS = {
    "id",
    "tier",
    "argv",
    "timeout_seconds",
    "evidence",
    "limitation",
    "remediation",
    "formats",
}
EXCEPTION_KEYS = {
    "id",
    "requirement",
    "owner",
    "reason",
    "scope",
    "created_at",
    "expires_at",
    "compensating_evidence",
    "review",
}


class ProjectError(ValueError):
    """A project path or consumer policy is unsafe or invalid."""


def confined_root(path: Path) -> Path:
    """Resolve an existing repository root without accepting a symlink root."""
    if path.is_symlink() or not path.is_dir():
        raise ProjectError("project root must be an existing non-symlink directory")
    return path.resolve(strict=True)


def confined_path(root: Path, relative: str) -> Path:
    """Resolve a repository-relative path and reject traversal or symlink components."""
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ProjectError(f"unsafe repository path: {relative}")
    current = root
    for part in candidate.parts:
        current = current / part
        if current.is_symlink():
            raise ProjectError(f"path traverses a symlink: {relative}")
    resolved_parent = current.parent.resolve(strict=True)
    if root not in (resolved_parent, *resolved_parent.parents):
        raise ProjectError(f"path escapes repository: {relative}")
    return current


def tracked_files(root: Path) -> list[Path]:
    """Return deterministic tracked files, falling back to a confined filesystem walk."""
    git = shutil.which("git")
    proc = (
        subprocess.run(  # noqa: S603 - resolved executable and fixed argv, without a shell.
            [git, "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            check=False,
            timeout=30,
        )
        if git
        else None
    )
    if proc is not None and proc.returncode == 0:
        names = [name for name in proc.stdout.decode("utf-8").split("\0") if name]
        return [confined_path(root, name) for name in sorted(names)]
    ignored = {".git", ".venv", "build", "dist", "__pycache__"}
    return sorted(
        (
            item
            for item in root.rglob("*")
            if item.is_file() and not ignored.intersection(item.parts)
        ),
        key=lambda item: item.relative_to(root).as_posix(),
    )


def load_json(path: Path) -> dict[str, Any]:
    """Read a JSON object with a useful path-bound error."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProjectError(f"cannot read JSON object {path.name}: {error}") from error
    if not isinstance(value, dict):
        raise ProjectError(f"{path.name} must contain an object")
    return value


def validate_policy(value: dict[str, Any]) -> None:
    """Validate fields required at runtime without third-party dependencies."""
    if set(value) != POLICY_KEYS or value.get("schema_version") != 1:
        raise ProjectError("project policy has unknown, missing or unsupported fields")
    if value.get("unknown_formats") not in {"error", "advisory"}:
        raise ProjectError("unknown_formats must be error or advisory")
    profiles = value.get("profiles")
    if not isinstance(profiles, list) or not profiles or len(set(profiles)) != len(profiles):
        raise ProjectError("profiles must be a non-empty unique list")
    expand_profiles(profiles)
    for field in ("fixture_paths", "extensions", "exceptions"):
        if not isinstance(value.get(field), list):
            raise ProjectError(f"{field} must be a list")
    _validate_extensions(value["extensions"])
    _validate_exceptions(value["exceptions"])


def _validate_extensions(extensions: list[object]) -> None:
    for extension in extensions:
        if not isinstance(extension, dict) or set(extension) != EXTENSION_KEYS:
            raise ProjectError("local extension has unknown or missing fields")
        if not isinstance(extension["argv"], list) or not extension["argv"]:
            raise ProjectError("local extension argv must be a non-empty array")
        if not 1 <= extension["timeout_seconds"] <= 3600:
            raise ProjectError("local extension deadline is outside the supported bound")


def _validate_exceptions(exceptions: list[object]) -> None:
    for exception in exceptions:
        if not isinstance(exception, dict) or set(exception) != EXCEPTION_KEYS:
            raise ProjectError("exception has unknown or missing fields")


def validate_lock(value: dict[str, Any]) -> None:
    """Validate the exact lock shape."""
    if set(value) != LOCK_KEYS or value.get("schema_version") != 1:
        raise ProjectError("policy lock has unknown, missing or unsupported fields")
    for field in ("profiles", "requirements"):
        if not isinstance(value.get(field), list) or len(set(value[field])) != len(value[field]):
            raise ProjectError(f"lock {field} must be a unique list")


def policy_paths(root: Path) -> tuple[Path, Path]:
    """Return the fixed consumer policy and lock locations."""
    return root / "quality" / "awq.json", root / "quality" / "awq.lock.json"


def load_project(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load and validate a consumer policy and its lock."""
    policy_path, lock_path = policy_paths(root)
    policy, lock = load_json(policy_path), load_json(lock_path)
    validate_policy(policy)
    validate_lock(lock)
    return policy, lock


def make_policy(profiles: list[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Create a deterministic consumer policy and expanded lock."""
    selected = sorted(set(profiles))
    expanded = expand_profiles(selected)
    _, _, digest = load_registry()
    policy = {
        "schema_version": 1,
        "profiles": selected,
        "unknown_formats": "error",
        "fixture_paths": ["fixtures/broken"],
        "extensions": [],
        "exceptions": [],
    }
    lock = {
        "schema_version": 1,
        "awq_version": __version__,
        "registry_sha256": digest,
        "profiles": selected,
        "requirements": expanded,
    }
    return policy, lock


def write_initialization(root: Path, policy: dict[str, Any], lock: dict[str, Any]) -> list[str]:
    """Write new consumer files atomically without overwriting existing policy."""
    policy_path, lock_path = policy_paths(root)
    wrapper = root / "tools" / "awq"
    targets = (policy_path, lock_path, wrapper)
    existing = [path for path in targets if path.exists()]
    if existing:
        raise ProjectError(
            "initialization refuses to overwrite: " + ", ".join(str(p) for p in existing)
        )
    policy_path.parent.mkdir(parents=True)
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_bytes(canonical_bytes(policy))
    lock_path.write_bytes(canonical_bytes(lock))
    wrapper.write_text('#!/bin/sh\nexec python3 -m awq "$@"\n', encoding="utf-8", newline="\n")
    wrapper.chmod(0o755)
    return [path.relative_to(root).as_posix() for path in targets]


def sha256_json(value: object) -> str:
    """Hash one canonical JSON value."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
