# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Strict, offline access to the generated public contract catalog."""

from __future__ import annotations

import hashlib
import json
import re
from importlib.resources import files
from pathlib import PurePosixPath
from typing import Any

from awq.registry import canonical_bytes

CATALOG_KEYS = {"schema_version", "contracts"}
CONTRACT_KEYS = {
    "id",
    "version",
    "path",
    "kind",
    "status",
    "assurance",
    "positive_fixtures",
    "hostile_fixtures",
    "implementation_conformance",
    "test_argv",
    "documentation",
    "limitation",
}
FIXTURE_KEYS = {"path", "case"}
KINDS = {"json-schema", "structured-registry"}
STATUSES = {"active", "historical", "deprecated"}
ASSURANCE = {"shape", "implementation-conformance"}
IDENTIFIER = re.compile(r"^AWQ-CONTRACT-[A-Z0-9][A-Z0-9-]{2,79}-V([1-9][0-9]*)$")
CASE = re.compile(r"^[a-z][a-z0-9_]{2,99}$")
SAFE_PATH = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.?(?:/|$))[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
CONFORMANCE = re.compile(r"^awq\.[A-Za-z0-9_.-]{3,120}$")
MAX_CONTRACTS = 256


class ContractCatalogError(ValueError):
    """A public contract catalog or compatibility baseline is invalid."""


def _safe_path(value: object) -> bool:
    if not isinstance(value, str) or not value or len(value) > 240 or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        SAFE_PATH.fullmatch(value) is not None
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _fixtures(identifier: str, value: object, label: str) -> None:
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        raise ContractCatalogError(f"{identifier} must declare bounded {label} fixtures")
    seen: set[tuple[str, str]] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != FIXTURE_KEYS:
            raise ContractCatalogError(
                f"{identifier} {label} fixture has unknown or missing fields"
            )
        path, case = item["path"], item["case"]
        if not _safe_path(path) or not isinstance(case, str) or not CASE.fullmatch(case):
            raise ContractCatalogError(f"{identifier} {label} fixture is invalid")
        key = (path, case)
        if key in seen:
            raise ContractCatalogError(f"{identifier} has duplicate {label} fixtures")
        seen.add(key)


def validate_catalog(value: object) -> dict[str, dict[str, Any]]:  # noqa: C901
    """Validate the closed catalog and return entries keyed by stable identifier."""
    if not isinstance(value, dict) or set(value) != CATALOG_KEYS or value["schema_version"] != 1:
        raise ContractCatalogError("contract catalog has unknown fields or schema version")
    raw = value["contracts"]
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_CONTRACTS:
        raise ContractCatalogError("contract catalog must contain a bounded non-empty list")
    entries: dict[str, dict[str, Any]] = {}
    paths: set[str] = set()
    for item in raw:
        if not isinstance(item, dict) or set(item) != CONTRACT_KEYS:
            raise ContractCatalogError("contract entry has unknown or missing fields")
        identifier = item["id"]
        match = IDENTIFIER.fullmatch(identifier) if isinstance(identifier, str) else None
        if match is None or identifier in entries:
            raise ContractCatalogError("contract identifiers must be unique stable strings")
        if item["version"] != int(match.group(1)):
            raise ContractCatalogError(f"{identifier} identifier and version disagree")
        if not _safe_path(item["path"]) or item["path"] in paths:
            raise ContractCatalogError(f"{identifier} path is unsafe or duplicated")
        if (
            item["kind"] not in KINDS
            or item["status"] not in STATUSES
            or item["assurance"] not in ASSURANCE
        ):
            raise ContractCatalogError(f"{identifier} has an unknown classification")
        _fixtures(identifier, item["positive_fixtures"], "positive")
        _fixtures(identifier, item["hostile_fixtures"], "hostile")
        argv = item["test_argv"]
        if (
            not isinstance(argv, list)
            or not 4 <= len(argv) <= 12
            or argv[:3] != ["python", "-m", "unittest"]
            or any(not isinstance(arg, str) or not arg or len(arg) > 160 for arg in argv)
        ):
            raise ContractCatalogError(f"{identifier} test argv is not fixed and bounded")
        if not _safe_path(item["documentation"]):
            raise ContractCatalogError(f"{identifier} documentation path is unsafe")
        conformance = item["implementation_conformance"]
        if not isinstance(conformance, str) or CONFORMANCE.fullmatch(conformance) is None:
            raise ContractCatalogError(f"{identifier} implementation_conformance is invalid")
        limitation = item["limitation"]
        if not isinstance(limitation, str) or not 20 <= len(limitation) <= 500:
            raise ContractCatalogError(f"{identifier} limitation length is invalid")
        if item["assurance"] == "shape" and "semantic" not in item["limitation"].casefold():
            raise ContractCatalogError(
                f"{identifier} shape-only entry must disclaim semantic execution"
            )
        entries[identifier] = item
        paths.add(item["path"])
    if list(entries) != sorted(entries):
        raise ContractCatalogError("contract catalog entries must be sorted by identifier")
    return entries


def load_contract_catalog() -> tuple[dict[str, dict[str, Any]], str]:
    """Load the packaged catalog and return entries plus its canonical digest."""
    raw = files("awq.data").joinpath("contract_catalog.json").read_text(encoding="utf-8")
    value = json.loads(raw)
    entries = validate_catalog(value)
    return entries, hashlib.sha256(canonical_bytes(value)).hexdigest()


def summary() -> dict[str, Any]:
    """Return content-minimized inventory metadata without executing tests."""
    entries, digest = load_contract_catalog()
    return {
        "status": "ok",
        "schema_version": 1,
        "catalog_sha256": digest,
        "contracts": len(entries),
        "kinds": {
            kind: sum(item["kind"] == kind for item in entries.values()) for kind in sorted(KINDS)
        },
        "limitation": "Catalog presence is inventory evidence, not semantic execution evidence.",
    }
