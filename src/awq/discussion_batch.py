# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT
"""Fail-closed validation for batched discussion proposal evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from awq.project import ProjectError, confined_path
from awq.registry import canonical_bytes

_SHA = "0123456789abcdef"
_REQUIRED = {
    "schema_version",
    "kind",
    "task",
    "batch",
    "points",
    "responses",
    "formal_spec",
    "privacy_projection",
    "limitations",
}
_LIMITATIONS = [
    "bounded_packet_quality_only",
    "user_intent_not_proven",
    "implementation_correctness_not_proven",
    "consumer_native_gates_remain_authoritative",
]


def _digest(value: Any, field: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(c not in _SHA for c in value):
        raise ProjectError(f"discussion-batch {field} must be a SHA-256 digest")


def _confidence(value: Any, field: str) -> None:
    if not isinstance(value, dict) or set(value) != {"applicability", "outcome", "downstream"}:
        raise ProjectError(f"discussion-batch {field} confidence is incomplete")
    for item in value.values():
        if isinstance(item, bool) or not isinstance(item, (int, float)) or not 0 <= item <= 1:
            raise ProjectError(f"discussion-batch {field} confidence is invalid")


def _evaluation(value: Any, field: str) -> None:
    if not isinstance(value, dict) or set(value) != {
        "confidence",
        "implications",
        "evidence_limits",
        "formal_refs",
    }:
        raise ProjectError(f"discussion-batch {field} evaluation is incomplete")
    _confidence(value["confidence"], field)
    for key in ("implications", "evidence_limits", "formal_refs"):
        item = value[key]
        if (
            not isinstance(item, list)
            or not item
            or len(item) > 16
            or any(not isinstance(x, str) or not x for x in item)
        ):
            raise ProjectError(f"discussion-batch {field} {key} is invalid")


def validate(value: Any) -> dict[str, Any]:  # noqa: C901
    if (
        not isinstance(value, dict)
        or set(value) != _REQUIRED
        or value["schema_version"] != 1
        or value["kind"] != "batched-discussion-quality"
    ):
        raise ProjectError("discussion-batch record has unknown or missing fields")
    task = value["task"]
    if (
        not isinstance(task, dict)
        or set(task) != {"id", "revision"}
        or not isinstance(task["id"], str)
        or not task["id"].startswith("AR-")
        or not task["id"][3:].isdigit()
        or isinstance(task["revision"], bool)
        or not isinstance(task["revision"], int)
        or not 1 <= task["revision"] <= 1_000_000
    ):
        raise ProjectError("discussion-batch task is invalid")
    batch = value["batch"]
    if (
        not isinstance(batch, dict)
        or set(batch) != {"id", "relation", "query_count", "point_ids"}
        or not isinstance(batch["id"], str)
        or not batch["id"].startswith("BATCH-")
        or batch["relation"] not in {"independent", "coupled"}
        or batch["query_count"] != 1
        or not isinstance(batch["point_ids"], list)
        or not 2 <= len(batch["point_ids"]) <= 64
        or len(set(batch["point_ids"])) != len(batch["point_ids"])
    ):
        raise ProjectError("discussion-batch batch identity or batching is invalid")
    points = value["points"]
    if not isinstance(points, list) or len(points) != len(batch["point_ids"]):
        raise ProjectError("discussion-batch points do not match the batch")
    point_ids: set[str] = set()
    for point in points:
        if (
            not isinstance(point, dict)
            or set(point) != {"id", "proposals"}
            or not isinstance(point["id"], str)
            or point["id"] in point_ids
            or point["id"] not in batch["point_ids"]
        ):
            raise ProjectError("discussion-batch point identity is invalid")
        point_ids.add(point["id"])
        proposals = point["proposals"]
        if not isinstance(proposals, list) or not 2 <= len(proposals) <= 16:
            raise ProjectError("discussion-batch requires at least two proposals per point")
        ranks: list[int] = []
        proposal_ids: set[str] = set()
        for proposal in proposals:
            if (
                not isinstance(proposal, dict)
                or set(proposal) != {"id", "rank", "summary", "evaluation"}
                or not isinstance(proposal["id"], str)
                or proposal["id"] in proposal_ids
                or not isinstance(proposal["rank"], int)
                or proposal["rank"] < 1
                or not isinstance(proposal["summary"], str)
                or not proposal["summary"]
            ):
                raise ProjectError("discussion-batch proposal is invalid")
            proposal_ids.add(proposal["id"])
            ranks.append(proposal["rank"])
            _evaluation(proposal["evaluation"], f"proposal {proposal['id']}")
        if sorted(ranks) != list(range(1, len(ranks) + 1)):
            raise ProjectError("discussion-batch proposal ranks are not contiguous")
    responses = value["responses"]
    if not isinstance(responses, list) or len(responses) > len(points):
        raise ProjectError("discussion-batch responses are invalid")
    responded: set[str] = set()
    proposal_map = {p["id"]: {x["id"] for x in p["proposals"]} for p in points}
    for response in responses:
        if (
            not isinstance(response, dict)
            or set(response)
            != {"point_id", "disposition", "proposal_id", "user_proposal", "authorized"}
            or response["point_id"] not in point_ids
            or response["point_id"] in responded
            or response["disposition"] not in {"select", "reject", "request-clarification"}
            or not isinstance(response["authorized"], bool)
        ):
            raise ProjectError("discussion-batch response binding is invalid")
        responded.add(response["point_id"])
        proposal_id = response["proposal_id"]
        user = response["user_proposal"]
        if proposal_id is not None and proposal_id not in proposal_map[response["point_id"]]:
            raise ProjectError("discussion-batch response selects another point's proposal")
        if user is not None:
            if (
                not isinstance(user, dict)
                or set(user) != {"id", "summary", "evaluation"}
                or not isinstance(user["id"], str)
                or not user["id"].startswith("USER-")
                or not isinstance(user["summary"], str)
                or not user["summary"]
            ):
                raise ProjectError("discussion-batch user proposal is invalid")
            _evaluation(user["evaluation"], f"user proposal {user['id']}")
        if response["authorized"] and (
            response["disposition"] != "select" or (proposal_id is None and user is None)
        ):
            raise ProjectError(
                "discussion-batch authorization is not bound to an evaluated selection"
            )
    if any(response["authorized"] for response in responses) and batch["relation"] != "independent":
        raise ProjectError("discussion-batch coupled points cannot be independently authorized")
    formal = value["formal_spec"]
    if (
        not isinstance(formal, dict)
        or set(formal) != {"specification_sha256", "result_sha256", "review_sha256", "status"}
        or formal["status"] != "pass"
    ):
        raise ProjectError("discussion-batch formal evidence is incomplete")
    for key in ("specification_sha256", "result_sha256", "review_sha256"):
        _digest(formal[key], key)
    privacy = value["privacy_projection"]
    if (
        not isinstance(privacy, dict)
        or set(privacy) != {"public_safe", "projection_sha256", "redacted_fields"}
        or privacy["public_safe"] is not True
        or not isinstance(privacy["redacted_fields"], list)
        or len(set(privacy["redacted_fields"])) != len(privacy["redacted_fields"])
    ):
        raise ProjectError("discussion-batch privacy projection is not public-safe")
    _digest(privacy["projection_sha256"], "projection_sha256")
    if any(not isinstance(x, str) or not x for x in privacy["redacted_fields"]):
        raise ProjectError("discussion-batch redaction list is invalid")
    if value["limitations"] != _LIMITATIONS:
        raise ProjectError("discussion-batch limitations are incomplete")
    return value


def evaluate_file(root: Path, relative: str) -> dict[str, Any]:
    path = confined_path(root, relative)
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProjectError("discussion-batch record is not valid JSON") from error
    validate(value)
    if canonical_bytes(value) != raw:
        raise ProjectError("discussion-batch record is not canonical JSON")
    return {
        "status": "pass",
        "kind": "discussion-batch-evidence",
        "task": value["task"],
        "record_sha256": hashlib.sha256(raw).hexdigest(),
    }


def check(root: Path, paths: list[Path]) -> list[dict[str, str]]:
    candidates = sorted(
        p
        for p in paths
        if p.relative_to(root).as_posix().startswith("quality/discussion-batch/")
        and p.suffix == ".json"
    )
    if not candidates:
        return [
            {
                "code": "missing-discussion-batch",
                "path": "quality/discussion-batch",
                "message": "no batched discussion quality record is declared",
            }
        ]
    findings: list[dict[str, str]] = []
    for path in candidates[:128]:
        try:
            evaluate_file(root, path.relative_to(root).as_posix())
        except ProjectError as error:
            findings.append(
                {
                    "code": "invalid-discussion-batch",
                    "path": path.relative_to(root).as_posix(),
                    "message": str(error),
                }
            )
    return findings
