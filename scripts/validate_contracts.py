# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Validate every shipped JSON contract and live AWQ record."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any

import jsonschema
from referencing import Registry, Resource

from awq.commands import evidence

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DOCUMENTS: dict[str, dict[str, Any]] = {
    path.name: json.loads(path.read_text(encoding="utf-8"))
    for path in sorted((ROOT / "schemas").glob("*.json"))
}
SCHEMA_REGISTRY = Registry().with_resources(
    (document["$id"], Resource.from_contents(document))
    for document in SCHEMA_DOCUMENTS.values()
    if "$id" in document
)


def validate(instance: object, schema_name: str) -> None:
    schema = SCHEMA_DOCUMENTS[schema_name]
    jsonschema.Draft202012Validator(
        schema,
        registry=SCHEMA_REGISTRY,
        format_checker=jsonschema.FormatChecker(),
    ).validate(instance)


def main() -> int:
    requirements = json.loads(files("awq.data").joinpath("requirements.json").read_text())
    profiles = json.loads(files("awq.data").joinpath("profiles.json").read_text())
    adapter_catalog = json.loads(files("awq.data").joinpath("adapter_catalog.json").read_text())
    sources = json.loads(files("awq.data").joinpath("control_sources.json").read_text())
    mappings = json.loads(files("awq.data").joinpath("requirement_mappings.json").read_text())
    policy = json.loads((ROOT / "quality" / "awq.json").read_text())
    lock = json.loads((ROOT / "quality" / "awq.lock.json").read_text())
    exception = {
        "id": "EX-0001",
        "kind": "standard",
        "requirement": "AWQ-CORE-001",
        "owner": "@martin-beck",
        "reason": "Contract validation fixture.",
        "scope": ["README.md"],
        "created_at": "2026-09-01T00:00:00+00:00",
        "expires_at": "2026-09-02T00:00:00+00:00",
        "compensating_evidence": "Schema validation.",
        "approval": "urn:awq:fixture:EX-0001",
        "renewals": [],
        "revocation": None,
    }
    hosting = {
        "status": "pass",
        "schema_version": 1,
        "repository": "example/project",
        "default_branch": "main",
        "observed_at": "2026-09-08T00:00:00+00:00",
        "tier": "scheduled",
        "evidence": "environmental",
        "network": True,
        "rulesets": [
            {
                "id": 1,
                "name": "Protected main",
                "target": "branch",
                "enforcement": "active",
                "applies_to_default_branch": True,
                "rule_types": ["pull_request", "required_status_checks"],
                "required_status_checks": ["verify"],
            }
        ],
        "findings": [],
        "limitation": "Point-in-time fixture; not offline proof.",
    }
    adapter = {
        "id": "ADAPTER-PYTHON-RUFF",
        "tool": "ruff",
        "version": "0.16.5",
        "version_argv": ["ruff", "--version"],
        "version_output": "ruff 0.16.5",
        "argv": ["ruff", "check", "--config", "pyproject.toml", "."],
        "timeout_seconds": 120,
        "tier": "pr",
        "evidence": "mechanical",
        "limitation": "Static analysis cannot prove runtime correctness.",
        "remediation": "Repair reported findings using project-owned configuration.",
        "formats": [".py", ".pyi"],
        "config_paths": ["pyproject.toml"],
    }
    adapter_result = {
        "id": adapter["id"],
        "tool": adapter["tool"],
        "version": adapter["version"],
        "status": "pass",
        "evidence": adapter["evidence"],
        "limitation": adapter["limitation"],
        "remediation": adapter["remediation"],
        "duration_ms": 1,
        "exceptions": [],
        "findings": [],
    }
    validate(requirements, "requirement-registry.schema.json")
    validate(profiles, "profile-registry.schema.json")
    validate(adapter_catalog, "adapter-catalog.schema.json")
    validate(sources, "control-source-registry.schema.json")
    validate(mappings, "standards-mapping-registry.schema.json")
    validate(exception, "exception.schema.json")
    validate({**policy, "exceptions": [exception]}, "project-policy.schema.json")
    validate({**policy, "adapters": [adapter]}, "project-policy.schema.json")
    validate(policy, "project-policy.schema.json")
    validate(lock, "lock.schema.json")
    validate(adapter, "adapter-contract.schema.json")
    validate(adapter_result, "adapter-result.schema.json")
    envelope = evidence(ROOT, "pr")
    envelope["requirements"].append(adapter_result)
    validate(envelope, "evidence.schema.json")
    validate(hosting, "hosting-observation.schema.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
