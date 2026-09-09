# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Strict data-only interpretation of an authenticated candidate policy registry."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from awq.adapters import AdapterError, validate_adapter_catalog
from awq.registry import (
    EVIDENCE_CLASSES,
    PROFILE_KEYS,
    REQUIREMENT_KEYS,
    TIERS,
    RegistryError,
    canonical_bytes,
    validate_standards_documents,
)
from awq.release import REGISTRY_PATHS, ReleaseError
from awq.trust import read_file

IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ReleaseError("candidate data contains duplicate keys")
        result[name] = value
    return result


def _constant(_value: str) -> None:
    raise ReleaseError("candidate data contains non-finite numbers")


def document(path: Path, expected_sha256: str | None = None) -> dict[str, Any]:
    """Decode bounded duplicate-free source JSON, permitting reviewed pretty-printing."""
    raw = read_file(path, 2_000_000)
    if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ReleaseError("candidate registry bytes differ from the authenticated manifest")
    try:
        value = json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ReleaseError("candidate data is not strict JSON") from error
    if not isinstance(value, dict):
        raise ReleaseError("candidate data is not an object")
    return value


def _text(value: object) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 4000 and "\x00" not in value


def _ids(value: object, *, nonempty: bool = True) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > 2000
        or (nonempty and not value)
        or not all(isinstance(item, str) and IDENTIFIER.fullmatch(item) for item in value)
        or len(value) != len(set(value))
    ):
        raise ReleaseError("candidate identifier list is invalid")
    return value


def _items(value: dict[str, Any], name: str) -> list[Any]:
    if (
        set(value) != {"schema_version", name}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or not isinstance(value[name], list)
        or not 1 <= len(value[name]) <= 2000
    ):
        raise ReleaseError("candidate registry has unknown, missing or unsupported fields")
    return list(value[name])


def _requirements(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in _items(value, "requirements"):
        if not isinstance(item, dict) or set(item) != REQUIREMENT_KEYS:
            raise ReleaseError("candidate requirement has unknown or missing fields")
        identifier = item["id"]
        if (
            not isinstance(identifier, str)
            or not re.fullmatch(r"AWQ-[A-Z]+-[0-9]{3}", identifier)
            or identifier in result
        ):
            raise ReleaseError("candidate requirement identity is invalid")
        for name in REQUIREMENT_KEYS - {"profiles", "standards", "deterministic", "network"}:
            if not _text(item[name]):
                raise ReleaseError("candidate requirement text is invalid")
        if (
            item["tier"] not in TIERS
            or item["evidence"] not in EVIDENCE_CLASSES
            or item["severity"] not in {"error", "warning"}
            or type(item["deterministic"]) is not bool
            or type(item["network"]) is not bool
        ):
            raise ReleaseError("candidate requirement classification is invalid")
        _ids(item["profiles"])
        _ids(item["standards"])
        result[identifier] = item
    return result


def _profiles(
    profiles_doc: dict[str, Any], requirements: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    profiles: dict[str, dict[str, Any]] = {}
    for item in _items(profiles_doc, "profiles"):
        if not isinstance(item, dict) or set(item) != PROFILE_KEYS:
            raise ReleaseError("candidate profile has unknown or missing fields")
        name = item["name"]
        if (
            not isinstance(name, str)
            or not IDENTIFIER.fullmatch(name)
            or name in profiles
            or not _text(item["description"])
        ):
            raise ReleaseError("candidate profile identity is invalid")
        if not set(_ids(item["requirements"])) <= requirements.keys():
            raise ReleaseError("candidate profile references unknown requirements")
        profiles[name] = item
    if any(not set(item["profiles"]) <= profiles.keys() for item in requirements.values()):
        raise ReleaseError("candidate requirement references unknown profiles")
    for name, profile in profiles.items():
        if any(
            name not in requirements[identifier]["profiles"]
            for identifier in profile["requirements"]
        ):
            raise ReleaseError("candidate profile membership is inconsistent")
    return profiles


def _standards(
    documents: dict[str, dict[str, Any]], requirements: dict[str, dict[str, Any]]
) -> None:
    _items(documents["standards_sources"], "sources")
    _items(documents["standards_mappings"], "mappings")
    try:
        validate_standards_documents(
            requirements, documents["standards_sources"], documents["standards_mappings"]
        )
    except (RegistryError, TypeError, ValueError) as error:
        raise ReleaseError("candidate standards registries are invalid") from error


def candidate_lock(
    source: Path, version: str, selected: list[str], expected: dict[str, str]
) -> dict[str, Any]:
    """Expand authenticated source bytes without importing or executing candidate code."""
    if set(expected) != set(REGISTRY_PATHS):
        raise ReleaseError("candidate registry binding set differs")
    documents = {
        name: document(source / relative, expected[name])
        for name, relative in REGISTRY_PATHS.items()
    }
    requirements_doc = documents["requirements"]
    profiles_doc = documents["profiles"]
    requirements = _requirements(requirements_doc)
    profiles = _profiles(profiles_doc, requirements)
    _standards(documents, requirements)
    chosen = sorted(_ids(selected))
    if not set(chosen) <= profiles.keys():
        raise ReleaseError("candidate does not provide the consumer profiles")
    catalog = documents["adapter_catalog"]
    try:
        if type(catalog.get("schema_version")) is not int:
            raise AdapterError("invalid version")
        validate_adapter_catalog(catalog)
    except (AdapterError, TypeError, ValueError) as error:
        raise ReleaseError("candidate adapter catalog is invalid") from error
    payload = {"requirements": requirements_doc, "profiles": profiles_doc}
    return {
        "schema_version": 2,
        "awq_version": version,
        "registry_sha256": hashlib.sha256(canonical_bytes(payload)).hexdigest(),
        "profiles": chosen,
        "requirements": sorted(
            {identifier for name in chosen for identifier in profiles[name]["requirements"]}
        ),
    }
