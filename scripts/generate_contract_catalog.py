# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Generate and verify the exhaustive public-contract inventory and baseline."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from awq.contracts import validate_catalog
from awq.registry import canonical_bytes

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "src/awq/data/contract_catalog.json"
BASELINE = ROOT / "contracts/contract-baseline-v1.json"
DOCUMENT = ROOT / "docs/CONTRACTS.md"
RELEASE_VERSION = re.compile(r"^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$")

# module, class, positive case, hostile case, documentation
FAMILIES: dict[str, tuple[str, str, str, str, str]] = {
    "adapter-catalog": (
        "adapters",
        "AdapterContractTests",
        "test_runtime_and_schema_accept_the_same_contract",
        "test_invalid_contract_dimensions_fail_closed",
        "docs/ADAPTERS.md",
    ),
    "adapter-contract": (
        "adapters",
        "AdapterContractTests",
        "test_runtime_and_schema_accept_the_same_contract",
        "test_invalid_contract_dimensions_fail_closed",
        "docs/ADAPTERS.md",
    ),
    "adapter-result": (
        "adapters",
        "AdapterRunnerTests",
        "test_native_and_adapter_results_agree_and_redact_output",
        "test_binding_protocol_rejects_ambiguous_or_unsafe_documents",
        "docs/ADAPTERS.md",
    ),
    "adversarial-campaign": (
        "adversarial",
        "AdversarialTests",
        "test_pr_and_scheduled_are_deterministic_and_bounded",
        "test_unknown_types_bounds_and_floor_fail_before_execution",
        "docs/ADVERSARIAL.md",
    ),
    "android-jvm-policy": (
        "android_jvm_adapters",
        "AndroidJvmAdapterTests",
        "test_catalog_is_exact_and_schema_valid",
        "test_task_contracts_match_native_success_and_failure",
        "docs/ANDROID_JVM_ADAPTERS.md",
    ),
    "assurance-contract": (
        "assurance",
        "FormalAssuranceTests",
        "test_complete_exploration_is_exact_and_deterministic",
        "test_unknown_bounds_and_kind_fail_before_exploration",
        "docs/FORMAL_ASSURANCE.md",
    ),
    "consumer-equivalence": (
        "promotion",
        "PromotionTests",
        "test_example_schema_canonical_and_determinism",
        "test_invalid_fields_tokens_types_counts_and_enumerations",
        "docs/PROMOTION.md",
    ),
    "contract-catalog": (
        "contract_catalog",
        "ContractCatalogTests",
        "test_catalog_is_exhaustive_deterministic_and_schema_valid",
        "test_closed_shapes_duplicates_missing_evidence_and_command_drift",
        "docs/CONTRACTS.md",
    ),
    "control-source-registry": (
        "standards",
        "StandardsRegistryTests",
        "test_catalogue_is_pinned_complete_and_stable",
        "test_source_shape_versions_controls_and_urls_fail_closed",
        "docs/STANDARDS.md",
    ),
    "evidence": (
        "commands_cli",
        "CommandTests",
        "test_inspect_init_plan_check_evidence_explain",
        "test_cli_json_success_failure_and_error",
        "docs/QUALITY.md",
    ),
    "exception": (
        "governance",
        "ExceptionLifecycleTests",
        "test_valid_standard_renewal_emergency_and_revocation",
        "test_invalid_lifecycle_records_fail_closed",
        "docs/GOVERNANCE.md",
    ),
    "formal-adapter-contract": (
        "formal_adapters",
        "FormalAdapterExecutionTests",
        "test_catalog_profile_schema_and_fixed_native_success",
        "test_unsupported_or_dynamic_model_contracts_fail_closed",
        "docs/FORMAL_ADAPTERS.md",
    ),
    "formal-evidence": (
        "formal_adapters",
        "FormalAdapterExecutionTests",
        "test_catalog_profile_schema_and_fixed_native_success",
        "test_unsupported_or_dynamic_model_contracts_fail_closed",
        "docs/FORMAL_EVIDENCE.md",
    ),
    "hosting-observation": (
        "governance",
        "HostingObservationTests",
        "test_detailed_rulesets_are_environmental_and_schema_valid",
        "test_network_shape_and_size_fail_closed",
        "docs/GOVERNANCE.md",
    ),
    "lifecycle-model": (
        "lifecycle_model",
        "LifecycleTests",
        "test_default_components_exhaustive_deterministic_and_noncompositional",
        "test_invalid_model_bounds_and_assumptions_fail_before_exploration",
        "docs/FORMAL_ASSURANCE.md",
    ),
    "lock": (
        "registry_project",
        "ProjectTests",
        "test_policy_generation_loading_and_collision",
        "test_runtime_validators_reject_unknown_shapes",
        "docs/ARCHITECTURE.md",
    ),
    "native-gate-mapping": (
        "native_mapping",
        "NativeMappingTests",
        "test_schema_examples_coverage_and_determinism",
        "test_unknown_references_classification_and_claim_fail_closed",
        "docs/NATIVE_GATE_MAPPINGS.md",
    ),
    "evidence-identity": (
        "native_mapping",
        "NativeMappingTests",
        "test_v2_correlates_sequential_observations_without_equating_producers",
        "test_v2_dirty_tree_unknown_fields_and_malformed_identity_are_rejected",
        "docs/NATIVE_GATE_MAPPINGS.md",
    ),
    "onboarding": (
        "onboarding",
        "OnboardingTests",
        "test_packaged_metadata_schema_and_exact_closed_profile",
        "test_malformed_migrations_and_confined_inputs_never_mutate",
        "docs/ONBOARDING.md",
    ),
    "profile-registry": (
        "registry_project",
        "RegistryTests",
        "test_registry_is_complete_and_stable",
        "test_profile_expansion_rejects_unknown",
        "docs/REQUIREMENTS.md",
    ),
    "project-policy": (
        "registry_project",
        "ProjectTests",
        "test_policy_generation_loading_and_collision",
        "test_runtime_validators_reject_unknown_shapes",
        "docs/ARCHITECTURE.md",
    ),
    "python-refactor": (
        "refactor",
        "RefactorTests",
        "test_four_methods_match_independent_native_observations",
        "test_native_mismatch_property_survivor_and_error_fixtures",
        "docs/PYTHON_REFACTORING.md",
    ),
    "refinement-map": (
        "refinement",
        "RefinementTests",
        "test_positive_complete_mapping_and_explicit_limits",
        "test_reviewed_hostile_fixtures",
        "docs/FORMAL_ASSURANCE.md",
    ),
    "release-license-inventory": (
        "sbom",
        "SbomTests",
        "test_inventory_scopes_origins_hashes_and_zero_runtime_are_explicit",
        "test_invalid_license_inventory_fails",
        "docs/SBOM.md",
    ),
    "release-manifest": (
        "release",
        "ReleaseVerificationTests",
        "test_complete_bundle_verifies_and_reports_only_public_bindings",
        "test_manifest_rejects_shapes_unknowns_duplicates_and_noncanonical_bytes",
        "docs/RELEASES.md",
    ),
    "release-provenance": (
        "verified_update",
        "AuthenticatedUpdateTests",
        "test_provenance_exact_canonical_subject_source_material_and_workflow_profile",
        "test_missing_unknown_tampered_expired_and_revoked_trust_fail_unchanged",
        "docs/PROVENANCE.md",
    ),
    "release-trust-policy": (
        "verified_update",
        "TrustBoundaryTests",
        "test_rotation_rejects_generation_conflict_lost_overlap_and_key_reuse",
        "test_policy_and_receipt_reject_unknown_types_bounds_and_conflicts",
        "docs/PROVENANCE.md",
    ),
    "reliability-budget": (
        "reliability",
        "ReliabilityTests",
        "test_real_pr_collection_and_scheduled_repeat_contract",
        "test_closed_shapes_numeric_bounds_and_chronology",
        "docs/RELIABILITY.md",
    ),
    "requirement-registry": (
        "registry_project",
        "RegistryTests",
        "test_registry_is_complete_and_stable",
        "test_profile_expansion_rejects_unknown",
        "docs/REQUIREMENTS.md",
    ),
    "standards-mapping-registry": (
        "standards",
        "StandardsRegistryTests",
        "test_catalogue_is_pinned_complete_and_stable",
        "test_mapping_references_editions_and_claims_fail_closed",
        "docs/STANDARDS.md",
    ),
    "terminology-registry": (
        "terminology",
        "TerminologyTests",
        "test_profile_and_canonical_positive_case",
        "test_public_schema_accepts_template_and_rejects_unknown_fields",
        "docs/TERMINOLOGY.md",
    ),
}
VERSIONS = {"project-policy": 3, "lock": 2, "release-manifest": 3}
REGISTRIES = {
    "adapter_catalog": "adapter-catalog",
    "agent_recipes": "onboarding",
    "compatibility": "onboarding",
    "contract_catalog": "contract-catalog",
    "control_sources": "control-source-registry",
    "profiles": "profile-registry",
    "requirement_mappings": "standards-mapping-registry",
    "requirements": "requirement-registry",
}


def _entry(identifier: str, path: str, family: str, kind: str) -> dict[str, Any]:
    module, klass, positive, hostile, documentation = FAMILIES[family]
    version = VERSIONS.get(family, 1)
    fixture_path = f"tests/test_{module}.py"
    slug = identifier.upper().replace("_", "-")
    return {
        "id": f"AWQ-CONTRACT-{slug}-V{version}",
        "version": version,
        "path": path,
        "kind": kind,
        "status": "active",
        "assurance": "implementation-conformance",
        "positive_fixtures": [{"path": fixture_path, "case": positive}],
        "hostile_fixtures": [{"path": fixture_path, "case": hostile}],
        "implementation_conformance": f"awq.tests.{module}.{klass}",
        "test_argv": ["python", "-m", "unittest", f"tests.test_{module}.{klass}"],
        "documentation": documentation,
        "limitation": (
            "Registration and executable tests establish only the declared bounded contract; "
            "downstream semantics remain consumer-owned."
        ),
    }


def build_catalog() -> dict[str, Any]:
    schema_names = {
        path.name.removesuffix(".schema.json") for path in (ROOT / "schemas").glob("*.schema.json")
    }
    if schema_names != set(FAMILIES):
        missing = sorted(schema_names - set(FAMILIES))
        stale = sorted(set(FAMILIES) - schema_names)
        raise SystemExit(f"schema discovery mismatch; unregistered={missing}, missing={stale}")
    entries = [
        _entry(name, f"schemas/{name}.schema.json", name, "json-schema")
        for name in sorted(schema_names)
    ]
    for data_name, family in REGISTRIES.items():
        entries.append(
            _entry(
                f"{data_name}-registry",
                f"src/awq/data/{data_name}.json",
                family,
                "structured-registry",
            )
        )
    value = {"schema_version": 1, "contracts": sorted(entries, key=lambda item: item["id"])}
    validate_catalog(value)
    return value


def _contract_semantic_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                "<release-version>"
                if key == "awq_version"
                and isinstance(item, str)
                and RELEASE_VERSION.fullmatch(item)
                else _contract_semantic_value(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_contract_semantic_value(item) for item in value]
    return value


def _semantic(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    semantic_value = _contract_semantic_value(value)
    document_sha256 = hashlib.sha256(canonical_bytes(semantic_value)).hexdigest()
    if path.name.endswith(".schema.json"):
        properties = value.get("properties", {})
        return {
            "kind": "json-schema",
            "id": value.get("$id"),
            "type": value.get("type"),
            "required": sorted(value.get("required", [])),
            "properties": sorted(properties),
            "additional_properties": value.get("additionalProperties"),
            "one_of": len(value.get("oneOf", [])),
            "all_of": len(value.get("allOf", [])),
            "canonical_document_sha256": document_sha256,
        }
    # Release identity changes on every package publication but does not change
    # the registry contract. Exact bytes remain independently frozen by sha256.
    return {
        "kind": "structured-registry",
        "schema_version": value.get("schema_version"),
        "keys": sorted(value),
    }


def build_baseline(catalog: dict[str, Any]) -> dict[str, Any]:
    entries = []
    for item in catalog["contracts"]:
        path = ROOT / item["path"]
        semantic = _semantic(path)
        entries.append(
            {
                "id": item["id"],
                "path": item["path"],
                "history": [
                    {
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        "semantic": semantic,
                        "semantic_sha256": hashlib.sha256(canonical_bytes(semantic)).hexdigest(),
                        "classification": "initial",
                        "reason": "Initial exhaustive AWQ public-contract baseline.",
                    }
                ],
            }
        )
    return {"schema_version": 1, "entries": entries}


def verify_baseline(catalog: dict[str, Any], baseline: object) -> None:  # noqa: C901
    """Reject missing, stale, malformed, duplicate or semantically changed baselines."""
    if (
        not isinstance(baseline, dict)
        or set(baseline) != {"schema_version", "entries"}
        or baseline["schema_version"] != 1
        or not isinstance(baseline["entries"], list)
    ):
        raise ValueError("contract compatibility baseline has unknown or missing fields")
    expected = {item["id"]: item for item in build_baseline(catalog)["entries"]}
    actual: dict[str, dict[str, Any]] = {}
    keys = {"id", "path", "history"}
    record_keys = {"sha256", "semantic", "semantic_sha256", "classification", "reason"}
    for item in baseline["entries"]:
        if not isinstance(item, dict) or set(item) != keys:
            raise ValueError("contract compatibility entry has unknown or missing fields")
        identifier = item["id"]
        if not isinstance(identifier, str) or identifier in actual:
            raise ValueError("contract compatibility identifiers must be unique strings")
        history = item["history"]
        if not isinstance(history, list) or not 1 <= len(history) <= 64:
            raise ValueError(f"{identifier} compatibility history is not bounded")
        seen_hashes: set[str] = set()
        initial_semantic: object | None = None
        for index, record in enumerate(history):
            if not isinstance(record, dict) or set(record) != record_keys:
                raise ValueError(f"{identifier} compatibility record has unknown fields")
            expected_classification = "initial" if index == 0 else "compatible"
            if (
                record["classification"] != expected_classification
                or not isinstance(record["reason"], str)
                or len(record["reason"].strip()) < 20
            ):
                raise ValueError(f"{identifier} lacks an explicit compatibility classification")
            if record["sha256"] in seen_hashes:
                raise ValueError(f"{identifier} compatibility history repeats contract bytes")
            seen_hashes.add(record["sha256"])
            if index == 0:
                initial_semantic = record["semantic"]
            elif record["semantic"] != initial_semantic:
                raise ValueError(f"{identifier} compatible history changes semantics")
        actual[identifier] = item
    if list(actual) != sorted(actual) or set(actual) != set(expected):
        raise ValueError("contract compatibility baseline inventory is incomplete or unordered")
    for identifier, current in expected.items():
        recorded = actual[identifier]
        if recorded["path"] != current["path"]:
            raise ValueError(f"{identifier} contract path changed in place")
        latest = recorded["history"][-1]
        expected_latest = current["history"][-1]
        for field in ("sha256", "semantic", "semantic_sha256"):
            if latest[field] != expected_latest[field]:
                raise ValueError(f"{identifier} contract bytes or semantics changed in place")


def _resolve_test_handler(item: dict[str, Any]) -> tuple[Path, set[str]]:
    contract_id = item["id"]
    conformance = item["implementation_conformance"]
    target = item["test_argv"][3]
    try:
        conformance_module, conformance_class = conformance.removeprefix("awq.tests.").rsplit(
            ".", 1
        )
        test_module, test_class = target.removeprefix("tests.test_").rsplit(".", 1)
    except ValueError as error:
        raise SystemExit(f"{contract_id} has an invalid test handler") from error
    if (
        not conformance.startswith("awq.tests.")
        or not target.startswith("tests.test_")
        or conformance_module != test_module
        or conformance_class != test_class
    ):
        raise SystemExit(f"{contract_id} test handler identities disagree")
    module = ROOT / "tests" / f"test_{test_module}.py"
    if not module.is_file():
        raise SystemExit(f"{contract_id} test argv does not name a real module")
    try:
        tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
    except (OSError, UnicodeError, SyntaxError) as error:
        raise SystemExit(f"{contract_id} test module is unavailable") from error
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
    handler = classes.get(test_class)
    if handler is None or not any(
        (isinstance(base, ast.Name) and base.id == "TestCase")
        or (isinstance(base, ast.Attribute) and base.attr == "TestCase")
        for base in handler.bases
    ):
        raise SystemExit(f"{contract_id} test argv does not name a unittest class")
    methods = {node.name for node in handler.body if isinstance(node, ast.FunctionDef)}
    return module, methods


def _verify_evidence(catalog: dict[str, Any]) -> None:
    for item in catalog["contracts"]:
        contract_id = item["id"]
        module, methods = _resolve_test_handler(item)
        for field in ("positive_fixtures", "hostile_fixtures"):
            for fixture in item[field]:
                path = ROOT / fixture["path"]
                case_name = fixture["case"]
                if path != module or case_name not in methods:
                    raise SystemExit(f"{contract_id} has missing {field} evidence")
        if not (ROOT / item["documentation"]).is_file():
            raise SystemExit(f"{contract_id} documentation target is missing")


def render(catalog: dict[str, Any]) -> str:
    lines = [
        "# Public contract catalog",
        "",
        "This file is generated from the exhaustive machine-readable catalog. "
        "Do not edit it directly.",
        "Catalog presence is inventory evidence; only each listed executable conformance "
        "test supports its bounded implementation claim.",
        "",
        "| Contract | Version | Kind | Path | Conformance | Documentation |",
        "| --- | ---: | --- | --- | --- | --- |",
    ]
    for item in catalog["contracts"]:
        identifier = item["id"]
        version = item["version"]
        kind = item["kind"]
        path = item["path"]
        conformance = item["implementation_conformance"]
        documentation = item["documentation"]
        lines.append(
            f"| `{identifier}` | {version} | `{kind}` | `{path}` | `{conformance}` | "
            f"[{documentation}]({Path(documentation).name}) |"
        )
    lines.extend(
        [
            "",
            "## Compatibility policy",
            "",
            "Published bytes and a conservative semantic summary are frozen in "
            "`contracts/contract-baseline-v1.json`. Byte changes require an explicit reviewed "
            "baseline classification. Any change to root properties, required fields, type, "
            "composition, or closure is incompatible and requires a new versioned contract "
            "identifier and path. Structured-registry content may evolve only through an explicit "
            "compatible classification; changing its schema version or root keys requires a new "
            "versioned contract.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:  # noqa: C901
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--accept-initial", action="store_true")
    parser.add_argument("--accept-compatible", action="append", default=[])
    parser.add_argument("--reason")
    args = parser.parse_args()
    if sum((args.check, args.accept_initial, bool(args.accept_compatible))) > 1:
        raise SystemExit("catalog generation modes are mutually exclusive")
    catalog = build_catalog()
    outputs = {CATALOG: canonical_bytes(catalog), DOCUMENT: render(catalog).encode()}
    if args.accept_initial:
        if BASELINE.exists():
            raise SystemExit("initial baseline already exists; it cannot be regenerated")
        CATALOG.parent.mkdir(parents=True, exist_ok=True)
        CATALOG.write_bytes(outputs[CATALOG])
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_bytes(canonical_bytes(build_baseline(catalog)))
        DOCUMENT.write_bytes(outputs[DOCUMENT])
    elif args.accept_compatible:
        if not args.reason or len(args.reason.strip()) < 20:
            raise SystemExit("compatible baseline updates require a reviewed reason")
        baseline = json.loads(BASELINE.read_bytes())
        current = {item["id"]: item for item in build_baseline(catalog)["entries"]}
        selected = set(args.accept_compatible)
        if len(selected) != len(args.accept_compatible) or not selected <= set(current):
            raise SystemExit("compatible baseline update names unknown or duplicate contracts")
        for item in baseline["entries"]:
            if item["id"] in selected:
                selected_id = item["id"]
                candidate = current[selected_id]["history"][-1]
                latest = item["history"][-1]
                if (
                    latest["semantic"] != candidate["semantic"]
                    or latest["semantic_sha256"] != candidate["semantic_sha256"]
                ):
                    raise SystemExit(
                        f"{selected_id} is semantically incompatible; add a new versioned "
                        "contract path"
                    )
                item["history"].append(
                    {**candidate, "classification": "compatible", "reason": args.reason}
                )
        verify_baseline(catalog, baseline)
        BASELINE.write_bytes(canonical_bytes(baseline))
        CATALOG.write_bytes(outputs[CATALOG])
        DOCUMENT.write_bytes(outputs[DOCUMENT])
    elif args.check:
        for path, expected in outputs.items():
            if not path.is_file() or path.read_bytes() != expected:
                raise SystemExit(f"generated contract artifact is stale: {path.relative_to(ROOT)}")
        _verify_evidence(catalog)
        if not BASELINE.is_file():
            raise SystemExit("contract compatibility baseline is missing")
        try:
            verify_baseline(catalog, json.loads(BASELINE.read_bytes()))
        except (ValueError, json.JSONDecodeError) as error:
            raise SystemExit(str(error)) from error
    else:
        CATALOG.write_bytes(outputs[CATALOG])
        DOCUMENT.write_bytes(outputs[DOCUMENT])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
