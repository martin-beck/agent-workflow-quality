# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Strict benchmark-neutral experiment receipt validation."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any, cast

from awq import __version__, project
from awq.registry import canonical_bytes

SHA256 = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER = re.compile(r"^EXP-[A-Z0-9][A-Z0-9-]{0,31}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
LIMITATIONS = (
    "Receipt validation checks declared structure and cross-field consistency, not workload "
    "representativeness, environmental control, statistical method suitability, or result truth.",
    "AWQ does not select scores, thresholds, estimators, baselines, regressions, or capacity.",
    "Raw results are digest-bound external artifacts; AWQ retains only bounded aggregate metadata.",
)


def _fail(message: str) -> None:
    raise project.ProjectError(f"experiment receipt {message}")


def _shape(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(f"{label} fields are invalid")
    return cast(dict[str, Any], value)


def _integer(value: object, lower: int, upper: int, label: str) -> int:
    if type(value) is not int or not lower <= value <= upper:
        _fail(f"{label} is outside the bound")
    return cast(int, value)


def _string(value: object, lower: int, upper: int, label: str) -> str:
    if not isinstance(value, str) or not lower <= len(value.strip()) <= upper:
        _fail(f"{label} is invalid")
    return cast(str, value)


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        _fail(f"{label} digest is invalid")
    return cast(str, value)


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        _fail(f"{label} timestamp is invalid")
    try:
        return datetime.strptime(cast(str, value), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise project.ProjectError(f"experiment receipt {label} timestamp is invalid") from error


def _choice(value: object, choices: tuple[str, ...], label: str) -> str:
    if not isinstance(value, str) or value not in choices:
        _fail(f"{label} is invalid")
    return cast(str, value)


def _source(value: Any) -> dict[str, Any]:
    item = _shape(value, {"revision", "tree_sha256"}, "source")
    if not isinstance(item["revision"], str) or REVISION.fullmatch(item["revision"]) is None:
        _fail("source revision is invalid")
    _digest(item["tree_sha256"], "source tree")
    return item


def _predeclaration(value: Any) -> tuple[dict[str, Any], datetime]:
    item = _shape(
        value,
        {
            "registered_at",
            "design_sha256",
            "population",
            "planned_samples",
            "repeats",
            "warmup_samples",
            "precision_target_ppm",
            "confidence",
            "stopping_rule",
            "resource_budget",
        },
        "predeclaration",
    )
    registered = _timestamp(item["registered_at"], "predeclaration")
    _digest(item["design_sha256"], "design")
    _string(item["population"], 1, 256, "population")
    _integer(item["planned_samples"], 1, 1_000_000, "planned samples")
    _integer(item["repeats"], 1, 10_000, "repeats")
    _integer(item["warmup_samples"], 0, 100_000, "warmup samples")
    _integer(item["precision_target_ppm"], 1, 1_000_000, "precision target")
    confidence = _shape(item["confidence"], {"method", "level_ppm"}, "confidence")
    _choice(confidence["method"], ("t-interval", "bootstrap", "exact"), "confidence method")
    _integer(confidence["level_ppm"], 500_000, 999_999, "confidence level")
    stopping = _shape(
        item["stopping_rule"], {"kind", "max_samples", "max_duration_seconds"}, "stopping rule"
    )
    _choice(stopping["kind"], ("fixed-samples", "precision-or-budget"), "stopping kind")
    _integer(stopping["max_samples"], 1, 1_000_000, "maximum samples")
    _integer(stopping["max_duration_seconds"], 1, 604_800, "maximum duration")
    if stopping["max_samples"] != item["planned_samples"]:
        _fail("stopping sample bound differs from predeclaration")
    budget = _shape(
        item["resource_budget"],
        {"cpu_seconds", "wall_seconds", "memory_bytes"},
        "resource budget",
    )
    _integer(budget["cpu_seconds"], 1, 604_800, "CPU budget")
    _integer(budget["wall_seconds"], 1, 604_800, "wall budget")
    _integer(budget["memory_bytes"], 1_048_576, 1_099_511_627_776, "memory budget")
    return item, registered


def _conditions(value: Any) -> dict[str, Any]:
    item = _shape(
        value,
        {
            "load_model",
            "concurrency",
            "cache_state",
            "network_state",
            "retries",
            "timeout_seconds",
        },
        "conditions",
    )
    _choice(item["load_model"], ("open", "closed"), "load model")
    _integer(item["concurrency"], 1, 1_000_000, "concurrency")
    _choice(item["cache_state"], ("cold", "warm", "mixed"), "cache state")
    _choice(item["network_state"], ("offline", "controlled", "external"), "network state")
    _integer(item["retries"], 0, 100, "retries")
    _integer(item["timeout_seconds"], 1, 86_400, "timeout")
    return item


def _observations(
    value: Any, source: dict[str, Any], predeclared: dict[str, Any], registered: datetime
) -> tuple[dict[str, Any], datetime]:
    item = _shape(
        value,
        {
            "source_revisions",
            "attempted",
            "completed",
            "failed",
            "timed_out",
            "cancelled",
            "missing",
            "contaminated",
            "highest_tested_capacity",
            "claimed_capacity",
            "raw_result_sha256",
            "observed_at",
        },
        "observations",
    )
    revisions = item["source_revisions"]
    if revisions != [source["revision"]]:
        _fail("observations mix or mismatch source revisions")
    for field in ("attempted", "completed", "failed", "timed_out", "cancelled", "missing"):
        _integer(item[field], 0, 1_000_000, field.replace("_", " "))
    if item["attempted"] != sum(
        item[field] for field in ("completed", "failed", "timed_out", "cancelled", "missing")
    ):
        _fail("attempt accounting omits outcomes")
    if item["attempted"] > predeclared["planned_samples"]:
        _fail("observed samples exceed the predeclared bound")
    _integer(item["contaminated"], 0, item["completed"], "contaminated observations")
    _integer(item["highest_tested_capacity"], 0, 1_000_000_000, "highest tested capacity")
    _integer(item["claimed_capacity"], 0, 1_000_000_000, "claimed capacity")
    if item["claimed_capacity"] > item["highest_tested_capacity"]:
        _fail("capacity claim exceeds the highest tested capacity")
    _digest(item["raw_result_sha256"], "raw result")
    observed = _timestamp(item["observed_at"], "observation")
    if observed <= registered:
        _fail("observation predates or equals predeclaration")
    return item, observed


def _bias(value: Any, observations: dict[str, Any]) -> dict[str, Any]:
    item = _shape(
        value,
        {
            "coordinated_omission",
            "survivorship_bias",
            "capacity_basis",
            "contamination_disposition",
            "contamination_rationale",
        },
        "bias treatment",
    )
    _choice(
        item["coordinated_omission"],
        ("avoided", "measured", "not-applicable"),
        "coordinated omission treatment",
    )
    _choice(
        item["survivorship_bias"],
        ("included-failures", "adjusted", "not-applicable"),
        "survivorship treatment",
    )
    _choice(item["capacity_basis"], ("highest-tested", "inferred"), "capacity basis")
    _choice(
        item["contamination_disposition"],
        ("none", "included", "excluded-with-rationale"),
        "contamination disposition",
    )
    rationale = item["contamination_rationale"]
    if observations["contaminated"]:
        if item["contamination_disposition"] == "none":
            _fail("contamination is unreported")
        _string(rationale, 20, 512, "contamination rationale")
    elif item["contamination_disposition"] != "none" or rationale != "":
        _fail("contamination treatment contradicts observations")
    if observations["claimed_capacity"] and item["capacity_basis"] != "highest-tested":
        _fail("capacity claim is inferred rather than highest-tested")
    return item


def _uncertainty(
    value: Any, predeclared: dict[str, Any], observations: dict[str, Any]
) -> dict[str, Any]:
    item = _shape(
        value,
        {
            "method",
            "level_ppm",
            "estimate",
            "lower",
            "upper",
            "precision_achieved_ppm",
            "status",
        },
        "uncertainty",
    )
    if (
        item["method"] != predeclared["confidence"]["method"]
        or item["level_ppm"] != predeclared["confidence"]["level_ppm"]
    ):
        _fail("uncertainty differs from the predeclared confidence method")
    for field in ("estimate", "lower", "upper"):
        _integer(item[field], -1_000_000_000_000, 1_000_000_000_000, field)
    if not item["lower"] <= item["estimate"] <= item["upper"]:
        _fail("confidence interval is impossible")
    _integer(item["precision_achieved_ppm"], 0, 1_000_000, "achieved precision")
    _choice(item["status"], ("met", "not-met"), "uncertainty status")
    met = item["precision_achieved_ppm"] <= predeclared["precision_target_ppm"]
    if (item["status"] == "met") != met:
        _fail("precision status contradicts the declared target")
    stopping = predeclared["stopping_rule"]
    if stopping["kind"] == "fixed-samples" and observations["attempted"] != stopping["max_samples"]:
        _fail("fixed sampling changed after predeclaration")
    if (
        stopping["kind"] == "precision-or-budget"
        and observations["attempted"] < stopping["max_samples"]
        and item["status"] != "met"
    ):
        _fail("adaptive sampling stopped without precision or budget exhaustion")
    return item


def _artifacts(value: Any, observations: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        _fail("raw artifact inventory is invalid")
    seen_ids: set[str] = set()
    seen_hashes: set[str] = set()
    for record in value:
        item = _shape(record, {"id", "sha256", "bytes"}, "raw artifact")
        identifier = _string(item["id"], 1, 64, "artifact identifier")
        digest = _digest(item["sha256"], "artifact")
        _integer(item["bytes"], 1, 1_073_741_824, "artifact bytes")
        if identifier in seen_ids or digest in seen_hashes:
            _fail("raw artifact identity is duplicated")
        seen_ids.add(identifier)
        seen_hashes.add(digest)
    if observations["raw_result_sha256"] not in seen_hashes:
        _fail("raw result digest is not bound to an artifact")
    return cast(list[dict[str, Any]], value)


def validate_receipt(value: Any) -> dict[str, Any]:
    """Validate a closed receipt and its benchmark-neutral cross-field obligations."""
    item = _shape(
        value,
        {
            "schema_version",
            "kind",
            "experiment_id",
            "source",
            "workload_sha256",
            "config_sha256",
            "predeclaration",
            "conditions",
            "observations",
            "bias_treatment",
            "uncertainty",
            "raw_artifacts",
            "methodology_review",
            "environmental_validity",
        },
        "root",
    )
    if item["schema_version"] != 1 or item["kind"] != "experiment-receipt":
        _fail("kind or version is invalid")
    if (
        not isinstance(item["experiment_id"], str)
        or IDENTIFIER.fullmatch(item["experiment_id"]) is None
    ):
        _fail("identifier is invalid")
    source = _source(item["source"])
    _digest(item["workload_sha256"], "workload")
    _digest(item["config_sha256"], "configuration")
    predeclared, registered = _predeclaration(item["predeclaration"])
    _conditions(item["conditions"])
    observations, _ = _observations(item["observations"], source, predeclared, registered)
    _bias(item["bias_treatment"], observations)
    _uncertainty(item["uncertainty"], predeclared, observations)
    _artifacts(item["raw_artifacts"], observations)
    _string(item["methodology_review"], 20, 512, "methodology review")
    _choice(item["environmental_validity"], ("unverified", "reviewed"), "environmental validity")
    return item


def evaluate(value: Any) -> dict[str, Any]:
    """Return deterministic content-minimized mechanical evidence."""
    item = validate_receipt(value)
    observations = item["observations"]
    return {
        "schema_version": 1,
        "awq_version": __version__,
        "kind": "experiment-receipt-result",
        "status": "pass",
        "experiment_id": item["experiment_id"],
        "receipt_sha256": hashlib.sha256(canonical_bytes(item)).hexdigest(),
        "source_revision": item["source"]["revision"],
        "attempted": observations["attempted"],
        "completed": observations["completed"],
        "failed": observations["failed"],
        "timed_out": observations["timed_out"],
        "cancelled": observations["cancelled"],
        "missing": observations["missing"],
        "contaminated": observations["contaminated"],
        "environmental_validity": item["environmental_validity"],
        "methodology_review": "consumer-supplied",
        "baseline_action": "none",
        "regression_decision": "consumer-owned",
        "limitations": list(LIMITATIONS),
    }
