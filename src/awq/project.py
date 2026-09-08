# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Confined repository access and consumer policy generation."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from awq import __version__
from awq.adapters import AdapterError, validate_adapter
from awq.registry import EVIDENCE_CLASSES, TIERS, canonical_bytes, expand_profiles, load_registry

POLICY_KEYS = {
    "schema_version",
    "profiles",
    "unknown_formats",
    "fixture_paths",
    "extensions",
    "exceptions",
    "governance",
    "adapters",
}
LOCK_KEYS = {"schema_version", "awq_version", "registry_sha256", "profiles", "requirements"}
GOVERNANCE_KEYS = {"owners", "max_standard_days", "max_emergency_hours"}
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
    "kind",
    "requirement",
    "owner",
    "reason",
    "scope",
    "created_at",
    "expires_at",
    "compensating_evidence",
    "approval",
    "renewals",
    "revocation",
}
RENEWAL_KEYS = {
    "renewed_at",
    "previous_expires_at",
    "expires_at",
    "owner",
    "reason",
    "approval",
}
REVOCATION_KEYS = {"revoked_at", "owner", "reason", "approval"}
OWNER_PATTERN = re.compile(r"^@[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:/[A-Za-z0-9_.-]+)?$")
FORMAT_PATTERN = re.compile(r"^\.[a-z0-9]+$")
MAX_CONFIGURED_STANDARD_DAYS = 90
MAX_CONFIGURED_EMERGENCY_HOURS = 72


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


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _safe_relative_pattern(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not Path(value).is_absolute()
        and ".." not in Path(value).parts
    )


def _approval(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    parsed = urlsplit(value)
    if parsed.scheme == "urn":
        return bool(parsed.path)
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
    )


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ProjectError(f"{field} must be a timezone-aware timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ProjectError(f"{field} must be a timezone-aware timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ProjectError(f"{field} must be a timezone-aware timestamp")
    return parsed.astimezone(UTC)


def _validate_governance(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != GOVERNANCE_KEYS:
        raise ProjectError("governance has unknown or missing fields")
    owners = value["owners"]
    if (
        not isinstance(owners, list)
        or not owners
        or not all(isinstance(item, str) and OWNER_PATTERN.fullmatch(item) for item in owners)
        or len(set(owners)) != len(owners)
    ):
        raise ProjectError("governance owners must be unique GitHub users or teams")
    standard = value["max_standard_days"]
    emergency = value["max_emergency_hours"]
    if (
        not isinstance(standard, int)
        or isinstance(standard, bool)
        or not 1 <= standard <= MAX_CONFIGURED_STANDARD_DAYS
    ):
        raise ProjectError("standard exception lifetime is outside the supported bound")
    if (
        not isinstance(emergency, int)
        or isinstance(emergency, bool)
        or not 1 <= emergency <= MAX_CONFIGURED_EMERGENCY_HOURS
    ):
        raise ProjectError("emergency exception lifetime is outside the supported bound")
    return value


def _validate_adapters(adapters: list[object]) -> None:
    seen: set[str] = set()
    for adapter in adapters:
        if not isinstance(adapter, dict):
            raise ProjectError("adapter contracts must be objects")
        try:
            validate_adapter(adapter)
        except AdapterError as error:
            raise ProjectError(str(error)) from error
        if adapter["id"] in seen:
            raise ProjectError("adapter identifiers must be unique")
        seen.add(adapter["id"])


def validate_policy(value: dict[str, Any]) -> None:
    """Validate fields required at runtime without third-party dependencies."""
    if set(value) != POLICY_KEYS or value.get("schema_version") != 3:
        raise ProjectError("project policy has unknown, missing or unsupported fields")
    if value.get("unknown_formats") not in {"error", "advisory"}:
        raise ProjectError("unknown_formats must be error or advisory")
    profiles = value.get("profiles")
    if (
        not isinstance(profiles, list)
        or not profiles
        or not all(isinstance(item, str) for item in profiles)
        or len(set(profiles)) != len(profiles)
    ):
        raise ProjectError("profiles must be a non-empty unique list")
    expand_profiles(profiles)
    for field in ("fixture_paths", "extensions", "exceptions", "adapters"):
        if not isinstance(value.get(field), list):
            raise ProjectError(f"{field} must be a list")
    fixtures = value["fixture_paths"]
    if not all(_safe_relative_pattern(item) for item in fixtures) or len(set(fixtures)) != len(
        fixtures
    ):
        raise ProjectError("fixture paths must be unique safe repository-relative patterns")
    governance = _validate_governance(value["governance"])
    _validate_adapters(value["adapters"])
    _validate_extensions(value["extensions"])
    _validate_exceptions(value["exceptions"], governance)


def _validate_extensions(extensions: list[object]) -> None:
    seen: set[str] = set()
    for extension in extensions:
        if not isinstance(extension, dict) or set(extension) != EXTENSION_KEYS:
            raise ProjectError("local extension has unknown or missing fields")
        identifier = extension["id"]
        if not isinstance(identifier, str) or identifier in seen:
            raise ProjectError("local extension identifiers must be unique strings")
        seen.add(identifier)
        argv = extension["argv"]
        if not isinstance(argv, list) or not argv or not all(_nonempty(item) for item in argv):
            raise ProjectError("local extension argv must be a non-empty array")
        timeout = extension["timeout_seconds"]
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 3600:
            raise ProjectError("local extension deadline is outside the supported bound")
        if extension["tier"] not in TIERS or extension["evidence"] not in EVIDENCE_CLASSES:
            raise ProjectError("local extension has an unknown classification")
        if not _nonempty(extension["limitation"]) or not _nonempty(extension["remediation"]):
            raise ProjectError("local extension guidance must be non-empty")
        formats = extension["formats"]
        if (
            not isinstance(formats, list)
            or not all(isinstance(item, str) and FORMAT_PATTERN.fullmatch(item) for item in formats)
            or len(set(formats)) != len(formats)
        ):
            raise ProjectError("local extension formats must be unique lowercase suffixes")


def _validate_renewal(
    renewal: dict[str, Any],
    cursor: datetime,
    created: datetime,
    owners: set[str],
    maximum: timedelta,
) -> datetime:
    previous = _timestamp(renewal["previous_expires_at"], "previous_expires_at")
    renewed = _timestamp(renewal["renewed_at"], "renewed_at")
    expires = _timestamp(renewal["expires_at"], "renewal expires_at")
    if previous != cursor or not created <= renewed <= previous or not previous < expires:
        raise ProjectError("exception renewal history is not a continuous ordered chain")
    if expires - renewed > maximum:
        raise ProjectError("exception renewal lifetime is outside the policy bound")
    if renewal["owner"] not in owners or not _approval(renewal["approval"]):
        raise ProjectError("exception renewal owner or approval is invalid")
    if not _nonempty(renewal["reason"]):
        raise ProjectError("exception renewal reason must be non-empty")
    return expires


def _validate_renewals(
    exception: dict[str, Any],
    created: datetime,
    final_expiry: datetime,
    owners: set[str],
    maximum: timedelta,
) -> None:
    renewals = exception["renewals"]
    if not isinstance(renewals, list):
        raise ProjectError("exception renewals must be a list")
    if exception["kind"] == "emergency" and renewals:
        raise ProjectError("emergency exceptions cannot be renewed")
    for renewal in renewals:
        if not isinstance(renewal, dict) or set(renewal) != RENEWAL_KEYS:
            raise ProjectError("exception renewal has unknown or missing fields")
    cursor = (
        _timestamp(renewals[0]["previous_expires_at"], "previous_expires_at")
        if renewals
        else final_expiry
    )
    if cursor <= created or cursor - created > maximum:
        raise ProjectError("exception initial lifetime is outside the policy bound")
    for renewal in renewals:
        cursor = _validate_renewal(renewal, cursor, created, owners, maximum)
    if cursor != final_expiry:
        raise ProjectError("exception expiry does not match its renewal history")


def _validate_revocation(
    value: object,
    created: datetime,
    expires: datetime,
    owners: set[str],
) -> None:
    if value is None:
        return
    if not isinstance(value, dict) or set(value) != REVOCATION_KEYS:
        raise ProjectError("exception revocation has unknown or missing fields")
    revoked = _timestamp(value["revoked_at"], "revoked_at")
    if not created <= revoked <= expires:
        raise ProjectError("exception revocation is outside the exception lifetime")
    if value["owner"] not in owners or not _approval(value["approval"]):
        raise ProjectError("exception revocation owner or approval is invalid")
    if not _nonempty(value["reason"]):
        raise ProjectError("exception revocation reason must be non-empty")


def _validate_exception(exception: dict[str, Any], governance: dict[str, Any]) -> None:
    requirements, _, _ = load_registry()
    owners = set(governance["owners"])
    if not isinstance(exception["id"], str) or not re.fullmatch(r"EX-[0-9]{4}", exception["id"]):
        raise ProjectError("exception identifier must match EX-NNNN")
    if exception["kind"] not in {"standard", "emergency"}:
        raise ProjectError("exception kind must be standard or emergency")
    if exception["requirement"] not in requirements:
        raise ProjectError("exception targets an unknown requirement")
    if exception["owner"] not in owners:
        raise ProjectError("exception owner is not a current governance owner")
    if not _nonempty(exception["reason"]) or not _nonempty(exception["compensating_evidence"]):
        raise ProjectError("exception rationale and compensating evidence must be non-empty")
    scopes = exception["scope"]
    if (
        not isinstance(scopes, list)
        or not scopes
        or not all(_safe_relative_pattern(item) for item in scopes)
        or len(set(scopes)) != len(scopes)
    ):
        raise ProjectError("exception scope must contain unique safe repository patterns")
    if not _approval(exception["approval"]):
        raise ProjectError("exception approval must be an HTTPS or URN reference")
    created = _timestamp(exception["created_at"], "created_at")
    expires = _timestamp(exception["expires_at"], "expires_at")
    maximum = (
        timedelta(hours=governance["max_emergency_hours"])
        if exception["kind"] == "emergency"
        else timedelta(days=governance["max_standard_days"])
    )
    _validate_renewals(exception, created, expires, owners, maximum)
    _validate_revocation(exception["revocation"], created, expires, owners)


def _validate_exceptions(exceptions: list[object], governance: dict[str, Any]) -> None:
    seen: set[str] = set()
    for exception in exceptions:
        if not isinstance(exception, dict) or set(exception) != EXCEPTION_KEYS:
            raise ProjectError("exception has unknown or missing fields")
        identifier = exception["id"]
        if not isinstance(identifier, str) or identifier in seen:
            raise ProjectError("exception identifiers must be unique strings")
        seen.add(identifier)
        _validate_exception(exception, governance)


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
        "schema_version": 3,
        "profiles": selected,
        "unknown_formats": "error",
        "fixture_paths": ["fixtures/broken"],
        "extensions": [],
        "exceptions": [],
        "governance": {
            "owners": ["@project-maintainers"],
            "max_standard_days": 30,
            "max_emergency_hours": 24,
        },
        "adapters": [],
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
