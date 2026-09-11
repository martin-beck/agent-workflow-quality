# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Immutable evidence lineage and non-authorizing retention planning."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn, cast

from awq import __version__, project
from awq.registry import canonical_bytes
from awq.sbom import strict_json
from awq.trust import read_file

HASH = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){1,8}$")
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
EVIDENCE_CLASSES = {
    "mechanical",
    "contract-test",
    "property-or-fuzz",
    "bounded-model",
    "environmental",
}
OUTCOMES = {"pass", "fail", "error", "cancelled", "unavailable"}
PUBLICATION_STATES = {"pending", "published", "failed", "unavailable", "cancelled", "not-requested"}
ROLES = {"gate-evidence", "publication", "diagnostic", "release"}
LIMITATION = (
    "Caller-declared bounded metadata and time only; hashes identify bytes but do not authenticate "
    "execution or hosting state. Candidates require owner review and authorize neither deletion "
    "nor upload. Required native and quality gates remain visible and retained."
)


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _fail(code: str) -> NoReturn:
    raise project.ProjectError("evidence lifecycle invalid: " + code)


def _object(value: Any, fields: str) -> dict[str, Any]:
    expected = set(fields.split())
    if not isinstance(value, dict) or set(value) != expected:
        _fail("fields")
    return cast(dict[str, Any], value)


def _hash(value: object) -> str:
    if not isinstance(value, str) or HASH.fullmatch(value) is None:
        _fail("digest")
    return value


def _revision(value: object) -> str:
    if not isinstance(value, str) or REVISION.fullmatch(value) is None:
        _fail("source-revision")
    return value


def _identifier(value: object, prefix: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 100
        or IDENTIFIER.fullmatch(value) is None
        or not value.startswith(prefix + "-")
    ):
        _fail("identifier")
    return value


def _run_id(value: object) -> str:
    if not isinstance(value, str) or RUN_ID.fullmatch(value) is None:
        _fail("run-id")
    return value


def timestamp(value: object) -> datetime:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        _fail("timestamp")
    try:
        result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise project.ProjectError("evidence lifecycle invalid: timestamp") from error
    return result


def _lineage_record(
    raw: Any,
    source_revision: str,
    previous: str | None,
    last_time: datetime | None,
    as_of: datetime,
) -> tuple[dict[str, Any], str, datetime, str, str]:
    item = _object(
        raw,
        "id kind parent_sha256 record_sha256 source_revision verifier_contract_sha256 "
        "artifact_sha256 evidence_class attempt_id outcome score observed_at",
    )
    identifier = _identifier(item["id"], "LINEAGE")
    attempt = _run_id(item["attempt_id"])
    if item["kind"] not in ("observation", "decision"):
        _fail("lineage-kind")
    if item["source_revision"] != source_revision:
        _fail("lineage-source-revision")
    _hash(item["verifier_contract_sha256"])
    _hash(item["artifact_sha256"])
    if item["evidence_class"] not in EVIDENCE_CLASSES or item["outcome"] not in OUTCOMES:
        _fail("lineage-class-or-outcome")
    if item["score"] is not None and (
        type(item["score"]) is not int or not -1_000_000 <= item["score"] <= 1_000_000
    ):
        _fail("lineage-score")
    observed = timestamp(item["observed_at"])
    if observed > as_of or (last_time is not None and observed < last_time):
        _fail("lineage-chronology")
    if item["parent_sha256"] != previous:
        _fail("lineage-parent")
    claimed = _hash(item["record_sha256"])
    calculated = digest({key: entry for key, entry in item.items() if key != "record_sha256"})
    if claimed != calculated:
        _fail("lineage-record-digest")
    return item, claimed, observed, identifier, attempt


def _lineage(
    value: Any, source_revision: str, as_of: datetime
) -> tuple[list[dict[str, Any]], str, set[str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 256:
        _fail("lineage-bound")
    previous: str | None = None
    attempts: set[str] = set()
    identifiers: set[str] = set()
    artifacts: set[str] = set()
    last_time: datetime | None = None
    normalized = []
    for raw in value:
        item, claimed, observed, identifier, attempt = _lineage_record(
            raw, source_revision, previous, last_time, as_of
        )
        if identifier in identifiers or attempt in attempts:
            _fail("lineage-identity-reused")
        identifiers.add(identifier)
        attempts.add(attempt)
        artifacts.add(item["artifact_sha256"])
        previous, last_time = claimed, observed
        normalized.append(item)
    if previous is None:
        _fail("lineage-bound")
    return normalized, previous, artifacts


def _publication_record(
    raw: Any, seen: dict[str, dict[str, Any]], lineage_artifacts: set[str]
) -> tuple[str, dict[str, Any]]:
    item = _object(
        raw,
        "id artifact_sha256 requirement validation_outcome publication_state "
        "prerequisites continue_on_error",
    )
    identifier = _identifier(item["id"], "ARTIFACT")
    if identifier in seen or (seen and identifier <= next(reversed(seen))):
        _fail("publication-identity-or-order")
    if _hash(item["artifact_sha256"]) not in lineage_artifacts:
        _fail("publication-artifact-lineage")
    if item["requirement"] not in ("required", "optional"):
        _fail("publication-requirement")
    if (
        item["validation_outcome"] not in OUTCOMES
        or item["publication_state"] not in PUBLICATION_STATES
    ):
        _fail("publication-outcome")
    if type(item["continue_on_error"]) is not bool:
        _fail("publication-continue-on-error")
    prerequisites = item["prerequisites"]
    if not isinstance(prerequisites, list) or len(prerequisites) > 16:
        _fail("publication-prerequisites")
    normalized_prerequisites = [_identifier(parent, "ARTIFACT") for parent in prerequisites]
    if normalized_prerequisites != sorted(set(normalized_prerequisites)) or any(
        parent not in seen for parent in normalized_prerequisites
    ):
        _fail("publication-prerequisites")
    if item["requirement"] == "required" and item["continue_on_error"]:
        _fail("required-gate-continue-on-error")
    if item["publication_state"] == "published" and any(
        seen[parent]["publication_state"] != "published" for parent in normalized_prerequisites
    ):
        _fail("publication-without-prerequisite")
    return identifier, item


def _publications(value: Any, lineage_artifacts: set[str]) -> tuple[list[dict[str, str]], str, str]:
    if not isinstance(value, list) or len(value) > 64:
        _fail("publication-bound")
    seen: dict[str, dict[str, Any]] = {}
    summaries = []
    quality_failed = required_publication_failed = optional_publication_failed = False
    for raw in value:
        identifier, item = _publication_record(raw, seen, lineage_artifacts)
        if item["requirement"] == "required":
            quality_failed |= item["validation_outcome"] != "pass"
            required_publication_failed |= item["publication_state"] != "published"
        else:
            optional_publication_failed |= item["publication_state"] not in (
                "published",
                "not-requested",
            )
        seen[identifier] = item
        summaries.append(
            {
                "id": identifier,
                "requirement": item["requirement"],
                "validation_outcome": item["validation_outcome"],
                "publication_state": item["publication_state"],
            }
        )
    quality = "fail" if quality_failed else "pass"
    publication = (
        "fail"
        if required_publication_failed
        else "partial"
        if optional_publication_failed
        else "pass"
    )
    return summaries, quality, publication


def _string_list(value: Any, kind: str, validator: Any, maximum: int = 64) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        _fail(kind + "-references")
    normalized = [validator(item) for item in value]
    if normalized != sorted(set(normalized)):
        _fail(kind + "-references")
    return normalized


def _retention_config(policy: Any) -> tuple[dict[str, Any], set[str], set[str]]:
    config = _object(
        policy,
        "minimum_age_seconds diagnostic_window_seconds high_watermark_bytes "
        "low_watermark_bytes maximum_selection_count protected_references",
    )
    for field, lower, upper in (
        ("minimum_age_seconds", 0, 31_536_000),
        ("diagnostic_window_seconds", 0, 2_678_400),
        ("high_watermark_bytes", 1, 1_000_000_000_000),
        ("low_watermark_bytes", 0, 1_000_000_000_000),
        ("maximum_selection_count", 1, 100),
    ):
        if type(config[field]) is not int or not lower <= config[field] <= upper:
            _fail("retention-policy-bound")
    if config["low_watermark_bytes"] >= config["high_watermark_bytes"]:
        _fail("retention-watermarks")
    refs = _object(
        config["protected_references"],
        "current_main open_pr_heads release_heads active_run_ids",
    )
    protected_heads = {_revision(refs["current_main"])}
    protected_heads.update(_string_list(refs["open_pr_heads"], "open-pr", _revision))
    protected_heads.update(_string_list(refs["release_heads"], "release", _revision))
    active_runs = set(_string_list(refs["active_run_ids"], "active-run", _run_id))
    return config, protected_heads, active_runs


def _inventory_record(
    raw: Any, as_of: datetime, lineage_artifacts: set[str]
) -> tuple[datetime, dict[str, Any], str, str]:
    item = _object(
        raw,
        "id artifact_sha256 artifact_role bytes created_at source_head run_id run_state provenance",
    )
    identifier = _identifier(item["id"], "EVIDENCE")
    artifact = _hash(item["artifact_sha256"])
    if artifact not in lineage_artifacts:
        _fail("retention-artifact-lineage")
    if item["artifact_role"] not in ROLES:
        _fail("retention-role")
    if type(item["bytes"]) is not int or not 1 <= item["bytes"] <= 100_000_000_000:
        _fail("retention-bytes")
    created = timestamp(item["created_at"])
    if created > as_of:
        _fail("retention-chronology")
    _revision(item["source_head"])
    if item["run_id"] is not None:
        _run_id(item["run_id"])
    if item["run_state"] not in ("active", "completed", "cancelled", "unknown"):
        _fail("retention-run-state")
    if item["provenance"] not in ("complete", "partial", "unknown"):
        _fail("retention-provenance")
    return created, item, identifier, artifact


def _retention(
    policy: Any, inventory: Any, as_of: datetime, lineage_artifacts: set[str]
) -> tuple[list[dict[str, str]], int, bool]:
    config, protected_heads, active_runs = _retention_config(policy)
    if not isinstance(inventory, list) or len(inventory) > 512:
        _fail("retention-inventory-bound")
    records = []
    identifiers: set[str] = set()
    digests: set[str] = set()
    total = 0
    for raw in inventory:
        created, item, identifier, artifact = _inventory_record(raw, as_of, lineage_artifacts)
        if identifier in identifiers or artifact in digests:
            _fail("retention-identity-reused")
        identifiers.add(identifier)
        digests.add(artifact)
        total += item["bytes"]
        records.append((created, item))
    candidates: list[dict[str, str]] = []
    remaining = total
    if total > config["high_watermark_bytes"]:
        for created, item in sorted(records, key=lambda pair: (pair[0], pair[1]["id"])):
            age = int((as_of - created).total_seconds())
            protected = (
                item["source_head"] in protected_heads
                or item["artifact_role"] == "release"
                or item["run_state"] in ("active", "unknown")
                or item["run_id"] in active_runs
                or item["provenance"] != "complete"
                or age < config["minimum_age_seconds"]
                or (
                    item["artifact_role"] == "diagnostic"
                    and age < config["diagnostic_window_seconds"]
                )
            )
            if protected:
                continue
            candidates.append(
                {"id": item["id"], "action": "review-for-removal", "reason": "watermark-hysteresis"}
            )
            remaining -= item["bytes"]
            if (
                remaining <= config["low_watermark_bytes"]
                or len(candidates) >= config["maximum_selection_count"]
            ):
                break
    return candidates, remaining, remaining <= config["low_watermark_bytes"]


def evaluate(value: Any, as_of: str) -> dict[str, Any]:
    item = _object(
        value,
        "schema_version kind source_revision lineage_head_sha256 lineage publications "
        "retention_policy inventory",
    )
    if (
        type(item["schema_version"]) is not int
        or item["schema_version"] != 1
        or item["kind"] != "evidence-lifecycle"
    ):
        _fail("kind-or-version")
    source_revision = _revision(item["source_revision"])
    now = timestamp(as_of)
    lineage, head, lineage_artifacts = _lineage(item["lineage"], source_revision, now)
    if _hash(item["lineage_head_sha256"]) != head:
        _fail("lineage-head")
    publications, quality_status, publication_status = _publications(
        item["publications"], lineage_artifacts
    )
    candidates, retained_bytes, watermark_reached = _retention(
        item["retention_policy"], item["inventory"], now, lineage_artifacts
    )
    outcomes = {
        name: sum(record["outcome"] == name for record in lineage) for name in sorted(OUTCOMES)
    }
    status = "fail" if quality_status == "fail" or publication_status == "fail" else "pass"
    return {
        "schema_version": 1,
        "awq_version": __version__,
        "status": status,
        "lineage": {"records": len(lineage), "head_sha256": head, "outcomes": outcomes},
        "quality_status": quality_status,
        "publication_status": publication_status,
        "publications": publications,
        "retention": {
            "mode": "dry-run",
            "authorization": "not-granted",
            "candidates": candidates,
            "retained_bytes_after_candidates": retained_bytes,
            "low_watermark_reached": watermark_reached,
        },
        "native_gate": "retain",
        "limitation": LIMITATION,
    }


def evaluate_file(root: Path, relative: str, as_of: str) -> dict[str, Any]:
    try:
        value = strict_json(read_file(project.confined_path(root, relative), 512_000))
        return evaluate(value, as_of)
    except Exception as error:
        raise project.ProjectError("evidence lifecycle input is invalid or unavailable") from error
