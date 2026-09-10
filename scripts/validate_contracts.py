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

from awq import lifecycle_model, sbom
from awq.commands import evidence
from awq.contracts import load_contract_catalog
from awq.release import BUILD_CONSTRAINTS_SHA256

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


def _validate_reliability_fixtures() -> None:
    for name in (
        "templates/reliability-pr.json",
        "templates/reliability-scheduled.json",
        "fixtures/conforming/reliability/pr.json",
        "fixtures/conforming/reliability/scheduled.json",
        "fixtures/conforming/reliability/observation.json",
        "fixtures/nonconforming/reliability/runtime-regression.json",
        "fixtures/nonconforming/reliability/timeout.json",
        "fixtures/nonconforming/reliability/truncation.json",
        "fixtures/nonconforming/reliability/nondeterministic.json",
        "fixtures/nonconforming/reliability/retention.json",
    ):
        validate(json.loads((ROOT / name).read_bytes()), "reliability-budget.schema.json")


def _validate_onboarding_fixtures() -> None:
    for name in (
        "src/awq/data/compatibility.json",
        "src/awq/data/agent_recipes.json",
        "templates/migration-preview.json",
        "fixtures/conforming/onboarding/upgrade.json",
        "fixtures/conforming/onboarding/same.json",
        "fixtures/nonconforming/onboarding/downgrade.json",
        "fixtures/nonconforming/onboarding/legacy-policy.json",
        "fixtures/nonconforming/onboarding/policy-change.json",
        "fixtures/nonconforming/onboarding/future.json",
    ):
        validate(json.loads((ROOT / name).read_bytes()), "onboarding.schema.json")


def _validate_formal_evidence_fixtures() -> None:
    for name in ("templates/formal-evidence.json",):
        validate(json.loads((ROOT / name).read_bytes()), "formal-evidence.schema.json")


def _validate_terminology_fixtures() -> None:
    for name in (
        "templates/terminology.json",
        "fixtures/broken/terminology/quality/terminology.json",
    ):
        validate(json.loads((ROOT / name).read_bytes()), "terminology-registry.schema.json")


def _validate_native_mapping_fixtures() -> None:
    for name in (
        "fixtures/conforming/native-gate-mapping.json",
        "fixtures/conforming/native-gate-mapping-v2.json",
        "fixtures/nonconforming/native-gate-mapping/missing-evidence.json",
        "fixtures/nonconforming/native-gate-mapping/contradictory-evidence.json",
    ):
        validate(json.loads((ROOT / name).read_bytes()), "native-gate-mapping.schema.json")
    v2 = json.loads((ROOT / "fixtures/conforming/native-gate-mapping-v2.json").read_bytes())
    for observation in v2["observations"]:
        validate(observation["identity"], "evidence-identity.schema.json")


def main() -> int:
    contract_catalog, _ = load_contract_catalog()
    requirements = json.loads(files("awq.data").joinpath("requirements.json").read_text())
    profiles = json.loads(files("awq.data").joinpath("profiles.json").read_text())
    adapter_catalog = json.loads(files("awq.data").joinpath("adapter_catalog.json").read_text())
    android_jvm = json.loads(
        (ROOT / "fixtures/conforming/android-jvm/quality/android-jvm.json").read_text()
    )
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
    release = {
        "schema_version": 1,
        "package": "agent-workflow-quality",
        "version": "0.13.0",
        "source": {
            "repository": "https://github.com/martin-beck/agent-workflow-quality",
            "commit": "a" * 40,
            "tree": "b" * 40,
            "source_date_epoch": 1_788_930_927,
        },
        "builder": {
            "recipe": "awq-release-v1",
            "python_version": "3.13.15",
            "uv_version": "0.12.8",
            "hatchling_version": "1.27.0",
            "host": "linux-x86_64",
            "build_constraints_sha256": BUILD_CONSTRAINTS_SHA256,
        },
        "registries": {
            "adapter_catalog": "c" * 64,
            "profiles": "d" * 64,
            "requirements": "e" * 64,
            "standards_mappings": "f" * 64,
            "standards_sources": "0" * 64,
        },
        "artifacts": [
            {
                "name": "agent_workflow_quality-0.13.0-py3-none-any.whl",
                "kind": "wheel",
                "media_type": "application/zip",
                "size": 1,
                "sha256": "1" * 64,
            },
            {
                "name": "agent_workflow_quality-0.13.0.tar.gz",
                "kind": "sdist",
                "media_type": "application/gzip",
                "size": 1,
                "sha256": "2" * 64,
            },
        ],
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
    for name in (
        "fixtures/conforming/consumer-equivalence.json",
        "templates/consumer-equivalence.json",
    ):
        validate(json.loads((ROOT / name).read_bytes()), "consumer-equivalence.schema.json")
    _validate_native_mapping_fixtures()
    for name in (
        "fixtures/conforming/assurance/model.json",
        "fixtures/conforming/assurance/refactor.json",
        "templates/formal-model.json",
        "templates/refactor-evidence.json",
    ):
        validate(json.loads((ROOT / name).read_bytes()), "assurance-contract.schema.json")
    for mutation in ("stale-review", "expired-review", "self-review"):
        validate(
            json.loads(
                (ROOT / "fixtures/nonconforming/assurance" / (mutation + ".json")).read_bytes()
            ),
            "assurance-contract.schema.json",
        )
    for name in ("fixtures/conforming/lifecycle/model.json", "templates/lifecycle-model.json"):
        value = json.loads((ROOT / name).read_bytes())
        validate(value, "lifecycle-model.schema.json")
        validate(value, "assurance-contract.schema.json")
    for mutation in lifecycle_model.MUTATIONS[1:]:
        value = json.loads(
            (ROOT / "fixtures/nonconforming/lifecycle" / (mutation + ".json")).read_bytes()
        )
        validate(value, "lifecycle-model.schema.json")
        validate(value, "assurance-contract.schema.json")
    for name in (
        "fixtures/conforming/refinement/map.json",
        "templates/refinement-map.json",
        "fixtures/nonconforming/refinement/contradictory-trace.json",
    ):
        value = json.loads((ROOT / name).read_bytes())
        validate(value, "refinement-map.schema.json")
        validate(value, "assurance-contract.schema.json")
    for name in (
        "fixtures/conforming/refactoring/quality/python-refactor.json",
        "templates/python-refactor.json",
        "fixtures/nonconforming/refactoring/mismatch.json",
        "fixtures/nonconforming/refactoring/survivor.json",
        "fixtures/nonconforming/refactoring/error.json",
        "fixtures/nonconforming/refactoring/property.json",
    ):
        validate(json.loads((ROOT / name).read_bytes()), "python-refactor.schema.json")
    for name in (
        "templates/adversarial-pr.json",
        "templates/adversarial-scheduled.json",
        "fixtures/conforming/adversarial/pr.json",
        "fixtures/conforming/adversarial/scheduled.json",
        "fixtures/conforming/adversarial/workflow-redaction.json",
    ):
        validate(json.loads((ROOT / name).read_bytes()), "adversarial-campaign.schema.json")
    _validate_onboarding_fixtures()
    _validate_formal_evidence_fixtures()
    _validate_terminology_fixtures()
    _validate_reliability_fixtures()
    validate(requirements, "requirement-registry.schema.json")
    validate(profiles, "profile-registry.schema.json")
    validate(adapter_catalog, "adapter-catalog.schema.json")
    validate(
        {"schema_version": 1, "contracts": list(contract_catalog.values())},
        "contract-catalog.schema.json",
    )
    formal_adapter = next(
        family for family in adapter_catalog["families"] if family["id"] == "formal-model"
    )
    validate(formal_adapter["contracts"][0], "formal-adapter-contract.schema.json")
    validate(android_jvm, "android-jvm-policy.schema.json")
    validate(sources, "control-source-registry.schema.json")
    validate(mappings, "standards-mapping-registry.schema.json")
    validate(exception, "exception.schema.json")
    validate({**policy, "exceptions": [exception]}, "project-policy.schema.json")
    validate({**policy, "adapters": [adapter]}, "project-policy.schema.json")
    validate(policy, "project-policy.schema.json")
    validate(lock, "lock.schema.json")
    validate(adapter, "adapter-contract.schema.json")
    validate(adapter_result, "adapter-result.schema.json")
    validate(release, "release-manifest.schema.json")
    sbom_inputs = sbom.source_inputs(ROOT)
    sbom_document = json.loads(
        (ROOT / "fixtures/conforming/release-sbom/document.spdx.json").read_bytes()
    )
    sbom_manifest = json.loads(
        (ROOT / "fixtures/conforming/release-sbom/manifest.json").read_bytes()
    )
    jsonschema.Draft202012Validator(
        sbom.schema_document(sbom_inputs[sbom.SCHEMA_PATH]),
        format_checker=jsonschema.FormatChecker(),
    ).validate(sbom_document)
    validate(sbom_manifest, "release-manifest.schema.json")
    provenance_fixture = ROOT / "fixtures/conforming/release-provenance"
    for name, schema_name in [
        ("manifest.json", "release-manifest.schema.json"),
        ("trust-policy.json", "release-trust-policy.schema.json"),
        ("statement.json", "release-provenance.schema.json"),
    ]:
        validate(json.loads((provenance_fixture / name).read_bytes()), schema_name)
    validate(json.loads(sbom_inputs[sbom.LICENSE_PATH]), "release-license-inventory.schema.json")
    sbom.verify(
        (ROOT / "fixtures/conforming/release-sbom/document.spdx.json").read_bytes(),
        sbom_inputs,
        sbom_manifest,
    )
    envelope = evidence(ROOT, "pr")
    envelope["requirements"].append(adapter_result)
    validate(envelope, "evidence.schema.json")
    validate(hosting, "hosting-observation.schema.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
