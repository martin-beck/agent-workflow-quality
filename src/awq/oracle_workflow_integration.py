# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT
"""Fail-closed validation for the synthetic Coordinator/AWG/AWQ oracle trace."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from awq.project import ProjectError, confined_path
from awq.registry import canonical_bytes

_NAMES = ("intake", "planning-review", "discussion", "specification-review", "reconciliation", "implementation", "quality", "handoff")
_OWNERS = ("coordinator", "coordinator", "awg", "awg", "coordinator", "coordinator", "awq", "coordinator")
_CLASSES = ("coordinator-event", "coordinator-event", "oracle-decision", "formal-review", "coordinator-event", "implementation", "quality", "coordinator-event")
_LIMITATIONS = ["user_intent_not_proven", "implementation_correctness_not_proven", "formal_refinement_not_proven", "consumer_native_gates_remain_authoritative"]


def _sha(value: Any, label: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ProjectError(f"oracle-workflow-integration {label} must be a SHA-256 digest")


def _ref(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value or value.startswith("/") or ".." in value or "//" in value:
        raise ProjectError(f"oracle-workflow-integration {label} must be public-safe")


def validate(value: Any) -> dict[str, Any]:  # noqa: C901
    required = {"schema_version", "trace_id", "task", "stages", "awg_decision", "awq_quality", "privacy_projection", "limitations"}
    if not isinstance(value, dict) or set(value) != required or value["schema_version"] != 1:
        raise ProjectError("oracle-workflow-integration record has unknown or missing fields")
    if not isinstance(value["trace_id"], str) or not value["trace_id"].startswith("TRACE-"):
        raise ProjectError("oracle-workflow-integration trace identity is invalid")
    task = value["task"]
    if not isinstance(task, dict) or set(task) != {"id", "revision"} or not isinstance(task["id"], str) or len(task["id"]) != 7 or not task["id"].startswith("AR-") or not task["id"][3:].isdigit() or not isinstance(task["revision"], int) or isinstance(task["revision"], bool) or task["revision"] < 1:
        raise ProjectError("oracle-workflow-integration task is invalid")
    stages = value["stages"]
    if not isinstance(stages, list) or len(stages) != len(_NAMES):
        raise ProjectError("oracle-workflow-integration mandatory stages are incomplete")
    revisions: set[int] = set()
    for item, name, owner, evidence_class in zip(stages, _NAMES, _OWNERS, _CLASSES, strict=True):
        expected = {"name", "owner", "event_ref", "task_revision", "status", "evidence_class", "evidence_ref"}
        if not isinstance(item, dict) or set(item) != expected or item["name"] != name or item["owner"] != owner or item["status"] != "complete" or item["evidence_class"] != evidence_class:
            raise ProjectError(f"oracle-workflow-integration {name} stage is invalid or skipped")
        if not isinstance(item["event_ref"], str) or not item["event_ref"].startswith("EV-") or not isinstance(item["task_revision"], int) or item["task_revision"] in revisions or item["task_revision"] < task["revision"]:
            raise ProjectError("oracle-workflow-integration stage revision is stale or duplicated")
        revisions.add(item["task_revision"])
        _ref(item["evidence_ref"], f"{name} evidence_ref")
    decision = value["awg_decision"]
    if not isinstance(decision, dict) or set(decision) != {"disposition", "packet_ref", "decision_sha256"} or decision["disposition"] != "accepted":
        raise ProjectError("oracle-workflow-integration AWG decision is not accepting")
    _ref(decision["packet_ref"], "AWG packet_ref")
    _sha(decision["decision_sha256"], "AWG decision_sha256")
    quality = value["awq_quality"]
    if not isinstance(quality, dict) or set(quality) != {"status", "evidence_ref", "requirement_sha256"} or quality["status"] != "passed":
        raise ProjectError("oracle-workflow-integration AWQ quality evidence did not pass")
    _ref(quality["evidence_ref"], "AWQ evidence_ref")
    _sha(quality["requirement_sha256"], "AWQ requirement_sha256")
    privacy = value["privacy_projection"]
    if not isinstance(privacy, dict) or set(privacy) != {"public_safe", "projection_sha256", "redacted_fields"} or privacy["public_safe"] is not True or not isinstance(privacy["redacted_fields"], list) or len(set(privacy["redacted_fields"])) != len(privacy["redacted_fields"]):
        raise ProjectError("oracle-workflow-integration privacy projection is not public-safe")
    _sha(privacy["projection_sha256"], "projection_sha256")
    if any(not isinstance(x, str) or not x for x in privacy["redacted_fields"]):
        raise ProjectError("oracle-workflow-integration redaction list is invalid")
    if value["limitations"] != _LIMITATIONS:
        raise ProjectError("oracle-workflow-integration limitations are incomplete")
    return value


def evaluate_file(root: Path, relative: str) -> dict[str, Any]:
    path = confined_path(root, relative)
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProjectError("oracle-workflow-integration record is not valid JSON") from error
    validate(value)
    if canonical_bytes(value) != raw:
        raise ProjectError("oracle-workflow-integration record is not canonical JSON")
    return {"status": "pass", "kind": "oracle-workflow-integration", "task": value["task"], "record_sha256": hashlib.sha256(raw).hexdigest()}


def check(root: Path, paths: list[Path]) -> list[dict[str, str]]:
    candidates = sorted(p for p in paths if p.relative_to(root).as_posix().startswith("quality/oracle-workflow-integration/") and p.suffix == ".json")
    if not candidates:
        return [{"code": "missing-oracle-workflow-integration", "path": "quality/oracle-workflow-integration", "message": "no oracle workflow integration trace is declared"}]
    findings: list[dict[str, str]] = []
    for path in candidates[:128]:
        try:
            evaluate_file(root, path.relative_to(root).as_posix())
        except ProjectError as error:
            findings.append({"code": "invalid-oracle-workflow-integration", "path": path.relative_to(root).as_posix(), "message": str(error)})
    return findings
