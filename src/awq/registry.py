# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Load and validate the immutable built-in policy registry."""

from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from typing import Any

REQUIREMENT_KEYS = {
    "id",
    "title",
    "statement",
    "profiles",
    "tier",
    "severity",
    "deterministic",
    "network",
    "command",
    "evidence",
    "limitation",
    "remediation",
    "exception_policy",
    "standards",
}
PROFILE_KEYS = {"name", "description", "requirements"}
SOURCE_KEYS = {
    "id",
    "title",
    "publisher",
    "edition",
    "source_url",
    "scope",
    "limitation",
    "controls",
}
CONTROL_KEYS = {"id", "title", "url"}
MAPPING_KEYS = {
    "id",
    "requirement",
    "source",
    "edition",
    "control",
    "relationship",
    "rationale",
    "evidence",
    "limitation",
    "reviewer",
    "claim",
}
TIERS = ("local", "pr", "scheduled", "trusted-host", "release")
EVIDENCE_CLASSES = {
    "mechanical",
    "contract-test",
    "property-or-fuzz",
    "bounded-model",
    "environmental",
}
RELATIONSHIPS = {"aligned", "supports", "related"}
ALIGNMENT_CLAIM = "alignment-not-certification"
FLOATING_EDITIONS = {"current", "head", "latest", "main", "master", "stable", "tip", "trunk"}


class RegistryError(ValueError):
    """A built-in or consumer registry contract is invalid."""


def canonical_bytes(value: object) -> bytes:
    """Return the stable JSON representation used for every digest."""
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _read(name: str) -> dict[str, Any]:
    raw = files("awq.data").joinpath(name).read_text(encoding="utf-8")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RegistryError(f"{name} must contain an object")
    return value


def load_registry() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], str]:
    """Return validated requirements, profiles and their combined SHA-256."""
    requirement_doc = _read("requirements.json")
    profile_doc = _read("profiles.json")
    if set(requirement_doc) != {"schema_version", "requirements"}:
        raise RegistryError("requirement registry has unknown or missing fields")
    if set(profile_doc) != {"schema_version", "profiles"}:
        raise RegistryError("profile registry has unknown or missing fields")
    if requirement_doc["schema_version"] != 1 or profile_doc["schema_version"] != 1:
        raise RegistryError("unsupported registry schema version")
    requirements = _validated_requirements(requirement_doc["requirements"])
    profiles = _validated_profiles(profile_doc["profiles"], requirements)
    payload = {"requirements": requirement_doc, "profiles": profile_doc}
    return requirements, profiles, hashlib.sha256(canonical_bytes(payload)).hexdigest()


def load_standards() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], str]:
    """Return the validated control catalogue, mappings and their SHA-256."""
    requirements, _, _ = load_registry()
    source_doc = _read("control_sources.json")
    mapping_doc = _read("requirement_mappings.json")
    if set(source_doc) != {"schema_version", "sources"}:
        raise RegistryError("control source registry has unknown or missing fields")
    if set(mapping_doc) != {"schema_version", "mappings"}:
        raise RegistryError("standards mapping registry has unknown or missing fields")
    if source_doc["schema_version"] != 1 or mapping_doc["schema_version"] != 1:
        raise RegistryError("unsupported standards registry schema version")
    sources = _validated_sources(source_doc["sources"])
    mappings = _validated_mappings(mapping_doc["mappings"], requirements, sources)
    missing = sorted(set(requirements) - {item["requirement"] for item in mappings.values()})
    if missing:
        raise RegistryError(f"requirements without standards traceability: {missing}")
    payload = {"sources": source_doc, "mappings": mapping_doc}
    return sources, mappings, hashlib.sha256(canonical_bytes(payload)).hexdigest()


def _validated_requirements(items: list[object]) -> dict[str, dict[str, Any]]:
    requirements: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict) or set(item) != REQUIREMENT_KEYS:
            raise RegistryError("requirement has unknown or missing fields")
        identifier = item["id"]
        if not isinstance(identifier, str) or identifier in requirements:
            raise RegistryError("requirement identifiers must be unique strings")
        if item["tier"] not in TIERS or item["evidence"] not in EVIDENCE_CLASSES:
            raise RegistryError(f"{identifier} has an unknown classification")
        requirements[identifier] = item
    return requirements


def _validated_profiles(
    items: list[object], requirements: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    profiles: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict) or set(item) != PROFILE_KEYS:
            raise RegistryError("profile has unknown or missing fields")
        name = item["name"]
        if not isinstance(name, str) or name in profiles:
            raise RegistryError("profile names must be unique strings")
        unknown = set(item["requirements"]) - set(requirements)
        if unknown:
            raise RegistryError(
                f"profile {name} references unknown requirements: {sorted(unknown)}"
            )
        profiles[name] = item
    return profiles


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validated_controls(identifier: str, value: object) -> set[str]:
    if not isinstance(value, list) or not value:
        raise RegistryError(f"{identifier} must catalogue at least one control")
    seen: set[str] = set()
    for control in value:
        if not isinstance(control, dict) or set(control) != CONTROL_KEYS:
            raise RegistryError(f"{identifier} control has unknown or missing fields")
        if not all(_nonempty(control[field]) for field in CONTROL_KEYS):
            raise RegistryError(f"{identifier} control fields must be non-empty strings")
        if not control["url"].startswith("https://"):
            raise RegistryError(f"{identifier} control URL must use HTTPS")
        if control["id"] in seen:
            raise RegistryError(f"{identifier} control identifiers must be unique")
        seen.add(control["id"])
    return seen


def _validated_sources(items: list[object]) -> dict[str, dict[str, Any]]:
    sources: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict) or set(item) != SOURCE_KEYS:
            raise RegistryError("control source has unknown or missing fields")
        identifier = item["id"]
        edition = item["edition"]
        text_fields = (
            "id",
            "title",
            "publisher",
            "edition",
            "source_url",
            "scope",
            "limitation",
        )
        if not all(_nonempty(item[field]) for field in text_fields):
            raise RegistryError("control source text fields must be non-empty strings")
        if identifier in sources:
            raise RegistryError("control source identifiers must be unique")
        if edition.casefold() in FLOATING_EDITIONS:
            raise RegistryError(f"{identifier} uses floating edition {edition}")
        if not item["source_url"].startswith("https://"):
            raise RegistryError(f"{identifier} source URL must use HTTPS")
        _validated_controls(identifier, item["controls"])
        sources[identifier] = item
    return sources


def _validate_mapping_references(
    identifier: str,
    item: dict[str, Any],
    requirements: dict[str, dict[str, Any]],
    sources: dict[str, dict[str, Any]],
) -> None:
    if item["requirement"] not in requirements:
        raise RegistryError(f"{identifier} references unknown requirement")
    source = sources.get(item["source"])
    if source is None:
        raise RegistryError(f"{identifier} references unknown control source")
    if item["edition"] != source["edition"]:
        raise RegistryError(
            f"{identifier} maps stale edition {item['edition']}; catalogue pins {source['edition']}"
        )
    controls = {control["id"] for control in source["controls"]}
    if item["control"] not in controls:
        raise RegistryError(f"{identifier} references unknown or removed control")


def _validated_mappings(
    items: list[object],
    requirements: dict[str, dict[str, Any]],
    sources: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    mappings: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict) or set(item) != MAPPING_KEYS:
            raise RegistryError("standards mapping has unknown or missing fields")
        identifier = item["id"]
        text_fields = MAPPING_KEYS - {"evidence"}
        if not all(_nonempty(item[field]) for field in text_fields):
            raise RegistryError("standards mapping text fields must be non-empty strings")
        if identifier in mappings:
            raise RegistryError("standards mapping identifiers must be unique")
        _validate_mapping_references(identifier, item, requirements, sources)
        if item["relationship"] not in RELATIONSHIPS:
            raise RegistryError(f"{identifier} has unknown relationship")
        if item["evidence"] not in EVIDENCE_CLASSES:
            raise RegistryError(f"{identifier} has unknown evidence class")
        if item["claim"] != ALIGNMENT_CLAIM:
            raise RegistryError(f"{identifier} makes a certification claim")
        mappings[identifier] = item
    return mappings


def standards_drift(
    sources: dict[str, dict[str, Any]], mappings: dict[str, dict[str, Any]]
) -> list[dict[str, str]]:
    """Return deterministic source-edition mismatches for review tooling."""
    return [
        {
            "mapping": identifier,
            "source": item["source"],
            "mapped_edition": item["edition"],
            "catalogue_edition": sources[item["source"]]["edition"],
        }
        for identifier, item in sorted(mappings.items())
        if item["source"] in sources and item["edition"] != sources[item["source"]]["edition"]
    ]


def expand_profiles(selected: list[str]) -> list[str]:
    """Expand profile names to sorted unique requirement identifiers."""
    requirements, profiles, _ = load_registry()
    unknown = set(selected) - set(profiles)
    if unknown:
        raise RegistryError(f"unknown profiles: {', '.join(sorted(unknown))}")
    expanded = {identifier for name in selected for identifier in profiles[name]["requirements"]}
    if not expanded <= requirements.keys():
        raise RegistryError("profile expansion escaped the registry")
    return sorted(expanded)
