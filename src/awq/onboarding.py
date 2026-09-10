# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Offline agent onboarding, conservative compatibility and data-only migration previews."""

from __future__ import annotations

import hashlib
import importlib.metadata
import platform
import re
import shutil
import sys
from importlib.resources import files
from pathlib import Path
from typing import Any

from awq import __version__, project
from awq.registry import canonical_bytes
from awq.release import REQUIRED_SCHEMAS
from awq.sbom import strict_json
from awq.trust import read_file

CAPABILITIES = ("core", "verified-update", "reliability-collect", "pinned-adapters")
VERSION = re.compile(r"^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$")
SHA = re.compile(r"^[0-9a-f]{64}$")
OID = re.compile(r"^[0-9a-f]{40}$")
LIMITATION = (
    "Offline preflight and data-only review guidance, not execution, publisher authentication, "
    "migration approval or native-tool availability proof. Native gates retained. "
    "Cross-platform core paths require their hosted smoke result; native adapters are not portable."
)


def compatibility() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "awq-compatibility",
        "awq_version": __version__,
        "python": {
            "minimum": "3.12",
            "reviewed_minors": ["3.12", "3.13"],
            "ci_pins": ["3.12.14", "3.13.15"],
        },
        "platforms": [
            {
                "id": name,
                "core": "ci-targeted",
                "native": "linux-x86_64-only" if name == "linux" else "not-reviewed",
            }
            for name in ("linux", "macos", "windows")
        ],
        "capabilities": list(CAPABILITIES),
        "migration": {
            "policy_schemas": [3],
            "lock_schemas": [1, 2],
            "manifest_schemas": [1, 2, 3],
            "downgrade": "reject",
            "update": "authenticated-only",
        },
        "channels": {
            "release-assets": "reviewed-local-wheel",
            "source-pin": "reviewed-full-commit",
            "package-index": "not-configured",
        },
        "exit_codes": {"success": 0, "blocked-or-failed": 1, "argument-error": 2},
    }


def recipes() -> dict[str, Any]:
    prefix = ["python", "-m", "awq", "--root", "{consumer}"]
    update = [
        *prefix,
        "update",
        "--to",
        "{target-version}",
        "--manifest",
        "{manifest}",
        "--trust-policy",
        "{external-trust-policy}",
        "--source",
        "{candidate-source}",
        "--tag",
        "{tag-ref}",
        "--tag-object",
        "{tag-object}",
    ]
    return {
        "schema_version": 1,
        "kind": "awq-agent-recipes",
        "awq_version": __version__,
        "recipes": [
            {
                "id": "inspect",
                "approval": "read-only",
                "argv": [*prefix, "onboarding", "--format", "json"],
            },
            {
                "id": "preview-init",
                "approval": "read-only",
                "argv": [*prefix, "init", "--profiles", "core", "--dry-run", "--format", "json"],
            },
            {
                "id": "initialize",
                "approval": "explicit-project-change",
                "argv": [*prefix, "init", "--profiles", "core", "--format", "json"],
            },
            {
                "id": "check",
                "approval": "run-reviewed-gates",
                "argv": [*prefix, "check", "--tier", "pr", "--format", "json"],
            },
            {
                "id": "explain",
                "approval": "read-only",
                "argv": [*prefix, "explain", "AWQ-CORE-001", "--format", "json"],
            },
            {
                "id": "preview-migration",
                "approval": "read-only",
                "argv": [*prefix, "migration-preview", "{migration-contract}", "--format", "json"],
            },
            {
                "id": "authenticated-dry-run",
                "approval": "review-external-trust",
                "argv": [*update, "--dry-run", "--format", "json"],
            },
            {
                "id": "authenticated-update",
                "approval": "explicit-lock-only-change",
                "argv": [*update, "--format", "json"],
            },
        ],
        "execution": "instructions-only",
        "native_gate": "retain",
    }


def validate_metadata(value: Any, kind: str) -> dict[str, Any]:
    expected = (
        compatibility()
        if kind == "awq-compatibility"
        else recipes()
        if kind == "awq-agent-recipes"
        else None
    )
    if expected is None or canonical_bytes(value) != canonical_bytes(expected):
        raise project.ProjectError("onboarding metadata differs from the reviewed contract")
    return dict(value)


def _data(name: str) -> bytes:
    with files("awq.data").joinpath(name).open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise project.ProjectError("onboarding data exceeds its byte bound")
    return raw


def load_metadata() -> tuple[dict[str, Any], dict[str, Any]]:
    return (
        validate_metadata(strict_json(_data("compatibility.json")), "awq-compatibility"),
        validate_metadata(strict_json(_data("agent_recipes.json")), "awq-agent-recipes"),
    )


def _schema_bytes(name: str) -> bytes:
    resource = files("awq").joinpath("schemas", name)
    if resource.is_file():
        with resource.open("rb") as stream:
            raw = stream.read(1_000_001)
        if len(raw) > 1_000_000:
            raise project.ProjectError("packaged schema exceeds its byte bound")
        return raw
    source = Path(__file__).resolve()
    if source.parent.parent.name != "src" or not (source.parents[2] / "pyproject.toml").is_file():
        raise project.ProjectError("required installed schema is missing")
    return read_file(source.parents[2] / "schemas" / name, 1_000_000)


def package_diagnostic() -> dict[str, Any]:
    try:
        distribution = importlib.metadata.distribution("agent-workflow-quality")
        matches = distribution.version == __version__
        no_dependencies = not distribution.requires
        catalog, instructions = load_metadata()
        assets = {
            name: hashlib.sha256(_schema_bytes(name)).hexdigest()
            for name in sorted(REQUIRED_SCHEMAS)
        }
        assets["compatibility.json"] = hashlib.sha256(canonical_bytes(catalog)).hexdigest()
        assets["agent_recipes.json"] = hashlib.sha256(canonical_bytes(instructions)).hexdigest()
        return {
            "version_matches": matches,
            "zero_runtime_dependencies": no_dependencies,
            "assets_complete": True,
            "assets_sha256": hashlib.sha256(canonical_bytes(assets)).hexdigest(),
        }
    except Exception:
        return {
            "version_matches": False,
            "zero_runtime_dependencies": False,
            "assets_complete": False,
            "assets_sha256": None,
        }


def environment() -> dict[str, str]:
    system = {"linux": "linux", "darwin": "macos", "win32": "windows"}.get(
        sys.platform, "unsupported"
    )
    machine = platform.machine().lower()
    architecture = (
        "x86_64"
        if machine in {"x86_64", "amd64"}
        else "arm64"
        if machine in {"arm64", "aarch64"}
        else "unsupported"
    )
    return {
        "platform": system,
        "architecture": architecture,
        "python_minor": str(sys.version_info.major) + "." + str(sys.version_info.minor),
    }


def diagnose(capability: str = "core") -> dict[str, Any]:
    if capability not in CAPABILITIES:
        raise project.ProjectError("onboarding capability is unknown")
    observed = environment()
    package = package_diagnostic()
    findings = []
    if observed["platform"] == "unsupported" or observed["architecture"] == "unsupported":
        findings.append("unsupported-platform")
    if observed["python_minor"] not in ("3.12", "3.13"):
        findings.append("unreviewed-python")
    if not all(
        package[key] for key in ("version_matches", "zero_runtime_dependencies", "assets_complete")
    ):
        findings.append("package-integrity-or-metadata")
    if shutil.which("git") is None:
        findings.append("git-unavailable")
    if capability != "core" and (observed["platform"], observed["architecture"]) != (
        "linux",
        "x86_64",
    ):
        findings.append("native-environment-unreviewed")
    if capability == "verified-update" and shutil.which("ssh-keygen") is None:
        findings.append("ssh-verifier-unavailable")
    if capability == "pinned-adapters":
        findings.append("native-tools-not-probed")
    return {
        "schema_version": 1,
        "awq_version": __version__,
        "status": "fail" if findings else "pass",
        "capability": capability,
        "environment": observed,
        "package": package,
        "findings": findings,
        "remediation": "docs/ONBOARDING.md#diagnostics-and-exit-codes",
        "compatibility": compatibility(),
        "instructions": recipes(),
        "execution": "not-performed",
        "native_gate": "retain",
        "limitation": LIMITATION,
    }


def _version(value: object) -> tuple[int, int, int]:
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise project.ProjectError("migration version must be a bounded exact release")
    major, minor, patch = (int(part) for part in value.split("."))
    return major, minor, patch


def _migration_input(value: Any) -> dict[str, Any]:
    keys = {
        "schema_version",
        "from_version",
        "to_version",
        "policy_schema",
        "lock_schema",
        "current_policy_sha256",
        "candidate_policy_sha256",
        "source_commit",
        "tag_object",
        "trust_policy_sha256",
    }
    if (
        not isinstance(value, dict)
        or set(value) != keys
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        raise project.ProjectError("migration fields or version are invalid")
    for key in ("policy_schema", "lock_schema"):
        if type(value[key]) is not int or not 1 <= value[key] <= 100:
            raise project.ProjectError("migration schema number is invalid")
    for key in ("current_policy_sha256", "candidate_policy_sha256", "trust_policy_sha256"):
        if not isinstance(value[key], str) or not SHA.fullmatch(value[key]):
            raise project.ProjectError("migration policy digest is invalid")
    for key in ("source_commit", "tag_object"):
        if not isinstance(value[key], str) or not OID.fullmatch(value[key]):
            raise project.ProjectError("migration source and tag need exact reviewed object pins")
    return value


def migration(value: Any) -> dict[str, Any]:
    value = _migration_input(value)
    before, after = _version(value["from_version"]), _version(value["to_version"])
    findings = []
    direction = "upgrade" if after > before else "same" if after == before else "downgrade"
    if after > _version(__version__):
        findings.append("future-target-unreviewed")
    if after < before:
        findings.append("downgrade-rejected")
    if value["policy_schema"] != 3 or value["lock_schema"] not in (1, 2):
        findings.append("manual-schema-migration-required")
    if before < (0, 15, 0) or after < (0, 15, 0) or after[0] != 0:
        findings.append("unsupported-version-family")
    policy_changed = value["current_policy_sha256"] != value["candidate_policy_sha256"]
    if policy_changed:
        findings.append("policy-change-requires-separate-review")
    return {
        "schema_version": 1,
        "status": "fail" if findings else "pass",
        "direction": direction,
        "review_required": True,
        "authorization": "not-granted",
        "policy_changed": policy_changed,
        "source_authenticated": False,
        "findings": findings,
        "input_sha256": hashlib.sha256(canonical_bytes(value)).hexdigest(),
        "next_step": "authenticated-update-dry-run" if not findings else "manual-policy-review",
        "remediation": "docs/ONBOARDING.md#migrations",
        "mutation": "none",
        "native_gate": "retain",
        "limitation": LIMITATION,
    }


def migration_file(root: Path, relative: str) -> dict[str, Any]:
    try:
        return migration(strict_json(read_file(project.confined_path(root, relative), 16384)))
    except Exception as error:
        raise project.ProjectError("migration input is invalid or unavailable") from error
