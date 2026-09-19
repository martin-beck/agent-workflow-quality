# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT
"""Fail-closed, privacy-safe guidance contradiction and reopen evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from awq.project import ProjectError, confined_path
from awq.registry import canonical_bytes

_DIGEST = "0123456789abcdef"
_STATES = {
    "pending_clarification",
    "rejected_proposal",
    "user_added_alternative",
    "reconciled",
    "reopened",
}
_ISSUES = {"no_op", "contradiction", "scope_change", "stale_response", "repeated_discussion"}
_RESULTS = {"clarification", "rejection", "alternative", "reconciliation", "reopen"}
_LIMITATIONS = {
    "user_intent_not_proven",
    "implementation_correctness_not_proven",
    "formal_refinement_not_proven",
    "consumer_native_gates_remain_authoritative",
}
_REQUIRED = {
    "schema_version",
    "discussion_id",
    "task",
    "event_refs",
    "issue",
    "before_state",
    "after_state",
    "user_result",
    "formal_spec",
    "affected_ars",
    "authorization",
    "limitations",
    "privacy_projection",
}


def _digest(value: Any, field: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(c not in _DIGEST for c in value):
        raise ProjectError(f"guidance-resolution {field} must be a SHA-256 digest")


def _task(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {"id", "revision"}:
        raise ProjectError("guidance-resolution task context is invalid")
    if (
        not isinstance(value["id"], str)
        or len(value["id"]) != 7
        or not value["id"].startswith("AR-")
        or not value["id"][3:].isdigit()
        or not isinstance(value["revision"], int)
        or isinstance(value["revision"], bool)
        or not 1 <= value["revision"] <= 1_000_000
    ):
        raise ProjectError("guidance-resolution task context is invalid")


def _formal(value: Any, task_revision: int, after_state: str) -> None:
    required = {"specification_sha256", "result_sha256", "review_sha256", "task_revision", "status"}
    if not isinstance(value, dict) or set(value) != required or value["status"] != "pass":
        raise ProjectError("guidance-resolution formal review must be a complete pass")
    for field in ("specification_sha256", "result_sha256", "review_sha256"):
        _digest(value[field], field)
    if value["task_revision"] != task_revision:
        raise ProjectError("guidance-resolution formal task revision is stale")
    if after_state != "reconciled" and value["status"] == "pass":
        # A formal pass does not authorize unresolved guidance.
        return


def _affected(value: Any) -> None:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise ProjectError("guidance-resolution affected AR list is invalid")
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "id",
            "before_revision",
            "after_revision",
            "reopen",
        }:
            raise ProjectError("guidance-resolution affected AR entry is invalid")
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
            or not isinstance(item["reopen"], bool)
        ):
            raise ProjectError("guidance-resolution affected AR entry is invalid")
        seen.add(identifier)


def validate(value: Any) -> dict[str, Any]:  # noqa: C901
    """Validate one bounded state transition without selecting user guidance."""
    if not isinstance(value, dict) or set(value) != _REQUIRED or value["schema_version"] != 1:
        raise ProjectError("guidance-resolution record has unknown or missing fields")
    if (
        not isinstance(value["discussion_id"], str)
        or not value["discussion_id"].startswith("DISC-")
        or not 6 <= len(value["discussion_id"]) <= 72
    ):
        raise ProjectError("guidance-resolution discussion identity is invalid")
    _task(value["task"])
    refs = value["event_refs"]
    if (
        not isinstance(refs, list)
        or not 1 <= len(refs) <= 32
        or len(set(refs)) != len(refs)
        or any(not isinstance(x, str) or not x.startswith("EV-") for x in refs)
    ):
        raise ProjectError("guidance-resolution event references are invalid")
    issue = value["issue"]
    if not isinstance(issue, str) or issue not in _ISSUES:
        raise ProjectError("guidance-resolution issue is invalid")
    before, after, result = value["before_state"], value["after_state"], value["user_result"]
    if before not in _STATES or after not in _STATES or result not in _RESULTS:
        raise ProjectError("guidance-resolution state or result is invalid")
    expected = {
        "pending_clarification": "clarification",
        "rejected_proposal": "rejection",
        "user_added_alternative": "alternative",
        "reconciled": "reconciliation",
        "reopened": "reopen",
    }[after]
    if result != expected:
        raise ProjectError("guidance-resolution result does not match resulting state")
    if issue == "no_op" and before != after:
        raise ProjectError("guidance-resolution no-op changed state")
    if (
        issue in {"contradiction", "scope_change", "stale_response", "repeated_discussion"}
        and before == after
    ):
        raise ProjectError("guidance-resolution material issue did not change state")
    _formal(value["formal_spec"], value["task"]["revision"], after)
    _affected(value["affected_ars"])
    auth = value["authorization"]
    if auth not in {"non_authorizing", "authorizing"}:
        raise ProjectError("guidance-resolution authorization is invalid")
    if auth == "authorizing" and (after != "reconciled" or result != "reconciliation"):
        raise ProjectError("guidance-resolution unresolved guidance cannot authorize work")
    limitations = value["limitations"]
    if not isinstance(limitations, list) or set(limitations) != _LIMITATIONS:
        raise ProjectError("guidance-resolution limitations are incomplete")
    privacy = value["privacy_projection"]
    if (
        not isinstance(privacy, dict)
        or set(privacy) != {"public_safe", "projection_sha256", "redacted_fields"}
        or privacy["public_safe"] is not True
        or not isinstance(privacy["redacted_fields"], list)
        or len(set(privacy["redacted_fields"])) != len(privacy["redacted_fields"])
        or any(not isinstance(x, str) or not x for x in privacy["redacted_fields"])
    ):
        raise ProjectError("guidance-resolution privacy projection is not public-safe")
    _digest(privacy["projection_sha256"], "projection_sha256")
    return value


def evaluate_file(root: Path, relative: str) -> dict[str, Any]:
    """Validate one confined canonical record and return only public identity."""
    path = confined_path(root, relative)
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProjectError("guidance-resolution record is not valid JSON") from error
    validate(value)
    if canonical_bytes(value) != raw:
        raise ProjectError("guidance-resolution record is not canonical JSON")
    return {
        "status": "pass",
        "kind": "guidance-resolution",
        "task": value["task"],
        "record_sha256": hashlib.sha256(raw).hexdigest(),
    }


def check(root: Path, paths: list[Path]) -> list[dict[str, str]]:
    """Check declared guidance-resolution records; no declaration fails closed."""
    candidates = sorted(
        path
        for path in paths
        if path.relative_to(root).as_posix().startswith("quality/guidance-resolution/")
        and path.suffix == ".json"
    )
    if not candidates:
        return [
            {
                "code": "missing-guidance-resolution",
                "path": "quality/guidance-resolution",
                "message": "no guidance-resolution record is declared",
            }
        ]
    findings: list[dict[str, str]] = []
    for path in candidates[:128]:
        try:
            evaluate_file(root, path.relative_to(root).as_posix())
        except ProjectError as error:
            findings.append(
                {
                    "code": "invalid-guidance-resolution",
                    "path": path.relative_to(root).as_posix(),
                    "message": str(error),
                }
            )
    return findings
