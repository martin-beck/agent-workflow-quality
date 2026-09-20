# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT
"""Fail-closed validation for the bounded end-to-end discussion TUI trace."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from awq.project import ProjectError, confined_path
from awq.registry import canonical_bytes

_STAGES = (
    "session",
    "pane-sync",
    "batching",
    "evaluation",
    "persistence",
    "reconciliation",
    "handoff",
)
_LIMITATIONS = [
    "ui_behavior_not_proven",
    "user_intent_not_proven",
    "implementation_refinement_not_proven",
    "provider_execution_not_proven",
    "consumer_native_gates_remain_authoritative",
]


def _sha(value: Any, field: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise ProjectError(f"discussion-tui-integration {field} must be a SHA-256 digest")


def _ref(value: Any, field: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or ".." in value
        or "//" in value
    ):
        raise ProjectError(f"discussion-tui-integration {field} must be public-safe")


def validate(value: Any) -> dict[str, Any]:  # noqa: C901
    required = {
        "schema_version",
        "task",
        "session_mode",
        "event_refs",
        "stages",
        "panes",
        "batch",
        "proposals",
        "persistence",
        "reconciliation",
        "handoff",
        "privacy_projection",
        "limitations",
    }
    if not isinstance(value, dict) or set(value) != required or value["schema_version"] != 1:
        raise ProjectError("discussion-tui-integration record has unknown or missing fields")
    task = value["task"]
    if (
        not isinstance(task, dict)
        or set(task) != {"id", "revision"}
        or not isinstance(task["id"], str)
        or not task["id"].startswith("AR-")
        or len(task["id"]) != 7
        or not task["id"][3:].isdigit()
        or not isinstance(task["revision"], int)
        or isinstance(task["revision"], bool)
        or task["revision"] < 1
    ):
        raise ProjectError("discussion-tui-integration task is invalid")
    if value["session_mode"] not in {"agent-initiated", "user-initiated"}:
        raise ProjectError("discussion-tui-integration session mode is invalid")
    refs = value["event_refs"]
    if (
        not isinstance(refs, list)
        or not refs
        or len(set(refs)) != len(refs)
        or any(not isinstance(x, str) or not x.startswith("EV-") for x in refs)
    ):
        raise ProjectError("discussion-tui-integration event references are invalid")
    stages = value["stages"]
    if not isinstance(stages, list) or len(stages) != len(_STAGES):
        raise ProjectError("discussion-tui-integration stages are incomplete")
    seen: set[int] = set()
    for stage, name in zip(stages, _STAGES, strict=True):
        if (
            not isinstance(stage, dict)
            or set(stage) != {"name", "event_ref", "task_revision", "evidence_ref", "status"}
            or stage["name"] != name
            or stage["status"] != "complete"
            or not isinstance(stage["event_ref"], str)
            or not stage["event_ref"].startswith("EV-")
            or not isinstance(stage["task_revision"], int)
            or stage["task_revision"] < task["revision"]
            or stage["task_revision"] in seen
        ):
            raise ProjectError(f"discussion-tui-integration {name} stage is invalid")
        _ref(stage["evidence_ref"], f"{name} evidence_ref")
        seen.add(stage["task_revision"])
    panes = value["panes"]
    if (
        not isinstance(panes, dict)
        or set(panes)
        != {
            "left_point_id",
            "right_point_id",
            "left_document_sha256",
            "right_document_sha256",
            "synchronized",
        }
        or panes["left_point_id"] != panes["right_point_id"]
        or panes["synchronized"] is not True
    ):
        raise ProjectError("discussion-tui-integration panes are not synchronized")
    _sha(panes["left_document_sha256"], "left_document_sha256")
    _sha(panes["right_document_sha256"], "right_document_sha256")
    if not isinstance(panes["left_point_id"], str) or not panes["left_point_id"].startswith(
        "POINT-"
    ):
        raise ProjectError("discussion-tui-integration pane point is invalid")
    batch = value["batch"]
    if (
        not isinstance(batch, dict)
        or set(batch)
        != {"point_count", "candidate_count", "custom_count", "independent_evaluation"}
        or not all(
            isinstance(batch[x], int) and not isinstance(batch[x], bool) and batch[x] >= 1
            for x in ("point_count", "candidate_count")
        )
        or not isinstance(batch["custom_count"], int)
        or batch["custom_count"] < 0
        or batch["independent_evaluation"] is not True
    ):
        raise ProjectError("discussion-tui-integration batch is invalid")
    proposals = value["proposals"]
    if (
        not isinstance(proposals, list)
        or len(proposals) != batch["candidate_count"] + batch["custom_count"]
    ):
        raise ProjectError("discussion-tui-integration proposal evaluation is incomplete")
    kinds: list[str] = []
    for proposal in proposals:
        if (
            not isinstance(proposal, dict)
            or set(proposal) != {"id", "kind", "evaluation_sha256", "status"}
            or proposal["kind"] not in {"candidate", "custom"}
            or proposal["status"] != "evaluated"
            or not isinstance(proposal["id"], str)
            or not proposal["id"].startswith("PROP-")
        ):
            raise ProjectError("discussion-tui-integration proposal is invalid")
        _sha(proposal["evaluation_sha256"], "evaluation_sha256")
        kinds.append(proposal["kind"])
    if (
        kinds.count("candidate") != batch["candidate_count"]
        or kinds.count("custom") != batch["custom_count"]
    ):
        raise ProjectError("discussion-tui-integration proposal classes are incomplete")
    persistence = value["persistence"]
    if (
        not isinstance(persistence, dict)
        or set(persistence) != {"record_ref", "record_sha256", "safe_exit", "reask_required"}
        or persistence["safe_exit"] is not True
        or not isinstance(persistence["reask_required"], bool)
    ):
        raise ProjectError("discussion-tui-integration persistence is invalid")
    _ref(persistence["record_ref"], "persistence record_ref")
    _sha(persistence["record_sha256"], "persistence record_sha256")
    reconciliation = value["reconciliation"]
    if (
        not isinstance(reconciliation, dict)
        or set(reconciliation) != {"status", "evidence_ref", "result_sha256"}
        or reconciliation["status"] != "passed"
    ):
        raise ProjectError("discussion-tui-integration reconciliation did not pass")
    _ref(reconciliation["evidence_ref"], "reconciliation evidence_ref")
    _sha(reconciliation["result_sha256"], "reconciliation result_sha256")
    handoff = value["handoff"]
    if (
        not isinstance(handoff, dict)
        or set(handoff) != {"classification", "ar_ref", "authorized"}
        or handoff["classification"] not in {"existing-ar", "new-ar", "rejected"}
        or handoff["authorized"] is not False
    ):
        raise ProjectError("discussion-tui-integration handoff is authorizing")
    if handoff["classification"] == "rejected" and handoff["ar_ref"] is not None:
        raise ProjectError("discussion-tui-integration rejected handoff has AR mapping")
    if handoff["classification"] != "rejected" and (
        not isinstance(handoff["ar_ref"], str) or not handoff["ar_ref"].startswith("AR-")
    ):
        raise ProjectError("discussion-tui-integration handoff mapping is invalid")
    privacy = value["privacy_projection"]
    if (
        not isinstance(privacy, dict)
        or set(privacy) != {"public_safe", "projection_sha256", "redacted_fields"}
        or privacy["public_safe"] is not True
        or not isinstance(privacy["redacted_fields"], list)
        or len(set(privacy["redacted_fields"])) != len(privacy["redacted_fields"])
    ):
        raise ProjectError("discussion-tui-integration privacy projection is not public-safe")
    _sha(privacy["projection_sha256"], "projection_sha256")
    if any(not isinstance(x, str) or not x for x in privacy["redacted_fields"]):
        raise ProjectError("discussion-tui-integration redaction list is invalid")
    if value["limitations"] != _LIMITATIONS:
        raise ProjectError("discussion-tui-integration limitations are incomplete")
    return value


def evaluate_file(root: Path, relative: str) -> dict[str, Any]:
    path = confined_path(root, relative)
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProjectError("discussion-tui-integration record is not valid JSON") from error
    validate(value)
    if canonical_bytes(value) != raw:
        raise ProjectError("discussion-tui-integration record is not canonical JSON")
    return {
        "status": "pass",
        "kind": "discussion-tui-integration",
        "task": value["task"],
        "record_sha256": hashlib.sha256(raw).hexdigest(),
    }


def check(root: Path, paths: list[Path]) -> list[dict[str, str]]:
    candidates = sorted(
        p
        for p in paths
        if p.relative_to(root).as_posix().startswith("quality/discussion-tui-integration/")
        and p.suffix == ".json"
    )
    if not candidates:
        return [
            {
                "code": "missing-discussion-tui-integration",
                "path": "quality/discussion-tui-integration",
                "message": "no end-to-end discussion TUI trace is declared",
            }
        ]
    findings: list[dict[str, str]] = []
    for path in candidates[:128]:
        try:
            evaluate_file(root, path.relative_to(root).as_posix())
        except ProjectError as error:
            findings.append(
                {
                    "code": "invalid-discussion-tui-integration",
                    "path": path.relative_to(root).as_posix(),
                    "message": str(error),
                }
            )
    return findings
