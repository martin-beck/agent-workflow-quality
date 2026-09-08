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
TIERS = ("local", "pr", "scheduled", "trusted-host", "release")
EVIDENCE_CLASSES = {
    "mechanical",
    "contract-test",
    "property-or-fuzz",
    "bounded-model",
    "environmental",
}


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
