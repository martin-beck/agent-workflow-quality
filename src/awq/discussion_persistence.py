# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT
"""Fail-closed, public-safe discussion persistence evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from awq.project import ProjectError, confined_path
from awq.registry import canonical_bytes

_DIGEST = "0123456789abcdef"
_REQUIRED = {
    "schema_version",
    "kind",
    "task",
    "journal_id",
    "revision",
    "status",
    "points",
    "safe_exit",
    "resume_revision",
    "reask",
    "future_requests",
    "formal_spec",
    "privacy_projection",
    "limitations",
}
_LIMITATIONS = [
    "bounded_journal_shape_only",
    "filesystem_crash_guarantees_not_proven",
    "user_intent_not_proven",
    "provider_and_network_execution_out_of_scope",
    "consumer_native_gates_remain_authoritative",
]


def _sha(value: Any, field: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(c not in _DIGEST for c in value):
        raise ProjectError(f"discussion-persistence {field} must be a SHA-256 digest")


def _ar(value: Any, field: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 7
        or not value.startswith("AR-")
        or not value[3:].isdigit()
    ):
        raise ProjectError(f"discussion-persistence {field} must be an AR reference")


def validate(value: Any) -> dict[str, Any]:  # noqa: C901
    if (
        not isinstance(value, dict)
        or set(value) != _REQUIRED
        or value["schema_version"] != 1
        or value["kind"] != "discussion-persistence"
    ):
        raise ProjectError("discussion-persistence record has unknown or missing fields")
    task = value["task"]
    if not isinstance(task, dict) or set(task) != {"id", "revision"}:
        raise ProjectError("discussion-persistence task identity is invalid")
    _ar(task["id"], "task.id")
    if (
        not isinstance(task["revision"], int)
        or isinstance(task["revision"], bool)
        or not 1 <= task["revision"] <= 1_000_000
    ):
        raise ProjectError("discussion-persistence task revision is invalid")
    if not isinstance(value["journal_id"], str) or not value["journal_id"].startswith("JOURNAL-"):
        raise ProjectError("discussion-persistence journal identity is invalid")
    if (
        not isinstance(value["revision"], int)
        or isinstance(value["revision"], bool)
        or value["revision"] < 1
    ):
        raise ProjectError("discussion-persistence revision is invalid")
    if value["status"] not in {"saved", "re-ask", "resumed"}:
        raise ProjectError("discussion-persistence status is invalid")
    points = value["points"]
    if not isinstance(points, list) or not points or len(points) > 64:
        raise ProjectError("discussion-persistence points are incomplete")
    seen: set[str] = set()
    for point in points:
        if not isinstance(point, dict) or set(point) != {
            "id",
            "proposals",
            "response",
            "unresolved",
        }:
            raise ProjectError("discussion-persistence point is not lossless")
        if (
            not isinstance(point["id"], str)
            or not point["id"].startswith("POINT-")
            or point["id"] in seen
        ):
            raise ProjectError("discussion-persistence point identity is invalid")
        seen.add(point["id"])
        if not isinstance(point["proposals"], list) or not point["proposals"]:
            raise ProjectError("discussion-persistence proposals are missing")
        if not isinstance(point["response"], dict) or set(point["response"]) != {
            "disposition",
            "proposal_id",
            "user_proposal",
        }:
            raise ProjectError("discussion-persistence response is missing")
        if point["response"]["disposition"] not in {"select", "reject", "request-clarification"}:
            raise ProjectError("discussion-persistence response disposition is invalid")
        if not isinstance(point["unresolved"], bool):
            raise ProjectError("discussion-persistence unresolved marker is invalid")
    safe = value["safe_exit"]
    if (
        not isinstance(safe, dict)
        or set(safe) != {"saved", "atomic", "complete", "commit_sha256"}
        or safe["saved"] is not True
        or safe["atomic"] is not True
        or safe["complete"] is not True
    ):
        raise ProjectError("discussion-persistence safe exit is incomplete")
    _sha(safe["commit_sha256"], "safe_exit.commit_sha256")
    resume = value["resume_revision"]
    if resume is not None and (
        not isinstance(resume, int) or isinstance(resume, bool) or resume != value["revision"]
    ):
        raise ProjectError("discussion-persistence stale resume")
    reask = value["reask"]
    if (
        not isinstance(reask, dict)
        or set(reask) != {"required", "point_ids", "reason"}
        or not isinstance(reask["required"], bool)
        or not isinstance(reask["point_ids"], list)
        or not isinstance(reask["reason"], str)
        or not reask["reason"]
    ):
        raise ProjectError("discussion-persistence re-ask lifecycle is incomplete")
    if any(item not in seen for item in reask["point_ids"]):
        raise ProjectError("discussion-persistence re-ask point is unknown")
    requests = value["future_requests"]
    if not isinstance(requests, list) or len(requests) > 64:
        raise ProjectError("discussion-persistence future requests are invalid")
    for request in requests:
        if not isinstance(request, dict) or set(request) != {
            "request_sha256",
            "classification",
            "ar_ref",
            "reason",
        }:
            raise ProjectError("discussion-persistence future request mapping is incomplete")
        _sha(request["request_sha256"], "future request")
        if (
            request["classification"] not in {"existing-ar", "new-ar", "rejected"}
            or not isinstance(request["reason"], str)
            or not request["reason"]
        ):
            raise ProjectError("discussion-persistence future request classification is invalid")
        if request["classification"] == "rejected":
            if request["ar_ref"] is not None:
                raise ProjectError("rejected future request must not map to an AR")
        else:
            _ar(request["ar_ref"], "future request ar_ref")
    formal = value["formal_spec"]
    if (
        not isinstance(formal, dict)
        or set(formal) != {"specification_sha256", "result_sha256", "review_sha256", "status"}
        or formal["status"] != "pass"
    ):
        raise ProjectError("discussion-persistence formal evidence is incomplete")
    for field in ("specification_sha256", "result_sha256", "review_sha256"):
        _sha(formal[field], field)
    privacy = value["privacy_projection"]
    if (
        not isinstance(privacy, dict)
        or set(privacy) != {"public_safe", "projection_sha256", "redacted_fields"}
        or privacy["public_safe"] is not True
        or not isinstance(privacy["redacted_fields"], list)
        or len(set(privacy["redacted_fields"])) != len(privacy["redacted_fields"])
    ):
        raise ProjectError("discussion-persistence privacy projection is not public-safe")
    _sha(privacy["projection_sha256"], "projection_sha256")
    if any(not isinstance(item, str) or not item for item in privacy["redacted_fields"]):
        raise ProjectError("discussion-persistence redaction list is invalid")
    if value["limitations"] != _LIMITATIONS:
        raise ProjectError("discussion-persistence limitations are incomplete")
    return value


def evaluate_file(root: Path, relative: str) -> dict[str, Any]:
    path = confined_path(root, relative)
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProjectError("discussion-persistence record is not valid JSON") from error
    validate(value)
    if canonical_bytes(value) != raw:
        raise ProjectError("discussion-persistence record is not canonical JSON")
    return {
        "status": "pass",
        "kind": "discussion-persistence",
        "task": value["task"],
        "record_sha256": hashlib.sha256(raw).hexdigest(),
    }


def check(root: Path, paths: list[Path]) -> list[dict[str, str]]:
    candidates = sorted(
        p
        for p in paths
        if p.relative_to(root).as_posix().startswith("quality/discussion-persistence/")
        and p.suffix == ".json"
    )
    if not candidates:
        return [
            {
                "code": "missing-discussion-persistence",
                "path": "quality/discussion-persistence",
                "message": "no discussion persistence record is declared",
            }
        ]
    findings: list[dict[str, str]] = []
    for path in candidates[:128]:
        try:
            evaluate_file(root, path.relative_to(root).as_posix())
        except ProjectError as error:
            findings.append(
                {
                    "code": "invalid-discussion-persistence",
                    "path": path.relative_to(root).as_posix(),
                    "message": str(error),
                }
            )
    return findings
