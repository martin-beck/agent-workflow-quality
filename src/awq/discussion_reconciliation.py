# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT
"""Fail-closed validation for completed discussion reconciliation evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from awq.project import ProjectError, confined_path
from awq.registry import canonical_bytes

_DIGEST = "0123456789abcdef"
_ARTIFACTS = ("plan", "design", "dependency_graph", "specification")
_LIMITATIONS = {
    "user_intent_not_proven",
    "implementation_correctness_not_proven",
    "consumer_native_gates_remain_authoritative",
    "formal_refinement_not_proven",
}
_REQUIRED = {
    "schema_version",
    "discussion_id",
    "task",
    "event_refs",
    "before",
    "after",
    "changed_artifacts",
    "prior_formal_result_sha256",
    "formal_spec",
    "affected_ars",
    "acceptance",
    "limitations",
    "privacy_projection",
}


def _digest(value: Any, field: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(char not in _DIGEST for char in value):
        raise ProjectError(f"discussion-reconciliation {field} must be a SHA-256 digest")


def _artifacts(value: Any, label: str) -> None:
    if not isinstance(value, dict) or set(value) != {f"{name}_sha256" for name in _ARTIFACTS}:
        raise ProjectError(f"discussion-reconciliation {label} artifacts are incomplete")
    for name in _ARTIFACTS:
        _digest(value[f"{name}_sha256"], f"{label}_{name}_sha256")


def _task(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {"id", "revision"}:
        raise ProjectError("discussion-reconciliation task context is invalid")
    if (
        not isinstance(value["id"], str)
        or len(value["id"]) != 7
        or not value["id"].startswith("AR-")
        or not value["id"][3:].isdigit()
        or not isinstance(value["revision"], int)
        or isinstance(value["revision"], bool)
        or not 1 <= value["revision"] <= 1_000_000
    ):
        raise ProjectError("discussion-reconciliation task context is invalid")


def _formal(value: Any, task_revision: int, after_specification: str, prior_result: str) -> None:
    required = {"specification_sha256", "result_sha256", "review_sha256", "task_revision", "status"}
    if not isinstance(value, dict) or set(value) != required or value["status"] != "pass":
        raise ProjectError("discussion-reconciliation formal result is not a complete pass")
    for field in ("specification_sha256", "result_sha256", "review_sha256"):
        _digest(value[field], field)
    if value["specification_sha256"] != after_specification:
        raise ProjectError("discussion-reconciliation formal specification is stale")
    if value["task_revision"] != task_revision:
        raise ProjectError("discussion-reconciliation formal task revision is stale")
    if value["result_sha256"] == prior_result:
        raise ProjectError("discussion-reconciliation formal result was not refreshed")


def _affected(value: Any) -> None:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise ProjectError("discussion-reconciliation affected AR list is invalid")
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "id",
            "before_revision",
            "after_revision",
            "disposition",
        }:
            raise ProjectError("discussion-reconciliation affected AR entry is invalid")
        identifier = item["id"]
        if (
            not isinstance(identifier, str)
            or len(identifier) != 7
            or not identifier.startswith("AR-")
            or not identifier[3:].isdigit()
            or identifier in seen
            or not isinstance(item["before_revision"], int)
            or isinstance(item["before_revision"], bool)
            or not isinstance(item["after_revision"], int)
            or isinstance(item["after_revision"], bool)
            or item["before_revision"] < 1
            or item["after_revision"] < item["before_revision"]
            or item["disposition"] not in {"unchanged", "closed", "reopened"}
        ):
            raise ProjectError("discussion-reconciliation affected AR entry is invalid")
        seen.add(identifier)


def validate(value: Any) -> dict[str, Any]:
    """Validate one public, digest-only reconciliation record."""
    if not isinstance(value, dict) or set(value) != _REQUIRED or value["schema_version"] != 1:
        raise ProjectError("discussion-reconciliation record has unknown or missing fields")
    if (
        not isinstance(value["discussion_id"], str)
        or not value["discussion_id"].startswith("DISC-")
        or not 6 <= len(value["discussion_id"]) <= 72
    ):
        raise ProjectError("discussion-reconciliation discussion identity is invalid")
    _task(value["task"])
    refs = value["event_refs"]
    if (
        not isinstance(refs, list)
        or not 1 <= len(refs) <= 32
        or len(set(refs)) != len(refs)
        or any(not isinstance(item, str) or not item.startswith("EV-") for item in refs)
    ):
        raise ProjectError("discussion-reconciliation event references are invalid")
    _artifacts(value["before"], "before")
    _artifacts(value["after"], "after")
    changed = value["changed_artifacts"]
    if (
        not isinstance(changed, list)
        or not 1 <= len(changed) <= len(_ARTIFACTS)
        or len(set(changed)) != len(changed)
        or any(item not in _ARTIFACTS for item in changed)
    ):
        raise ProjectError("discussion-reconciliation changed-artifact list is invalid")
    changed_set = set(changed)
    for name in _ARTIFACTS:
        differs = value["before"][f"{name}_sha256"] != value["after"][f"{name}_sha256"]
        if differs != (name in changed_set):
            raise ProjectError("discussion-reconciliation changed-artifact list is inconsistent")
    _digest(value["prior_formal_result_sha256"], "prior_formal_result_sha256")
    _formal(
        value["formal_spec"],
        value["task"]["revision"],
        value["after"]["specification_sha256"],
        value["prior_formal_result_sha256"],
    )
    _affected(value["affected_ars"])
    acceptance = value["acceptance"]
    if (
        not isinstance(acceptance, dict)
        or set(acceptance) != {"user_guidance", "quality_evidence", "implementation_verification"}
        or acceptance["user_guidance"] not in {"accepted", "rejected"}
        or acceptance["quality_evidence"] != "pass"
        or acceptance["implementation_verification"]
        not in {"verified", "not_verified", "not_applicable"}
    ):
        raise ProjectError("discussion-reconciliation acceptance dimensions are invalid")
    limitations = value["limitations"]
    if (
        not isinstance(limitations, list)
        or set(limitations) != _LIMITATIONS
        or any(not isinstance(item, str) for item in limitations)
    ):
        raise ProjectError("discussion-reconciliation limitations are incomplete")
    privacy = value["privacy_projection"]
    if (
        not isinstance(privacy, dict)
        or set(privacy) != {"public_safe", "projection_sha256", "redacted_fields"}
        or privacy["public_safe"] is not True
        or not isinstance(privacy["redacted_fields"], list)
        or len(set(privacy["redacted_fields"])) != len(privacy["redacted_fields"])
        or any(not isinstance(item, str) or not item for item in privacy["redacted_fields"])
    ):
        raise ProjectError("discussion-reconciliation privacy projection is not public-safe")
    _digest(privacy["projection_sha256"], "projection_sha256")
    return value


def evaluate_file(root: Path, relative: str) -> dict[str, Any]:
    """Validate one confined record and return only its public identity."""
    path = confined_path(root, relative)
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProjectError("discussion-reconciliation record is not valid JSON") from error
    validate(value)
    if canonical_bytes(value) != raw:
        raise ProjectError("discussion-reconciliation record is not canonical JSON")
    return {
        "status": "pass",
        "kind": "discussion-reconciliation",
        "task": value["task"],
        "record_sha256": hashlib.sha256(raw).hexdigest(),
    }


def check(root: Path, paths: list[Path]) -> list[dict[str, str]]:
    """Check declared reconciliation records; an empty declaration fails closed."""
    candidates = sorted(
        path
        for path in paths
        if path.relative_to(root).as_posix().startswith("quality/discussion-reconciliation/")
        and path.suffix == ".json"
    )
    if not candidates:
        return [
            {
                "code": "missing-discussion-reconciliation",
                "path": "quality/discussion-reconciliation",
                "message": "no discussion-reconciliation record is declared",
            }
        ]
    findings: list[dict[str, str]] = []
    for path in candidates[:128]:
        try:
            evaluate_file(root, path.relative_to(root).as_posix())
        except ProjectError as error:
            findings.append(
                {
                    "code": "invalid-discussion-reconciliation",
                    "path": path.relative_to(root).as_posix(),
                    "message": str(error),
                }
            )
    return findings
