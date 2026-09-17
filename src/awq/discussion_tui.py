# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT
"""Fail-closed, public-safe discussion TUI render-state contract."""

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
    "task",
    "event_refs",
    "active_point",
    "left_anchor",
    "render",
    "privacy_projection",
    "limitations",
}


def _sha(value: Any, field: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(c not in _DIGEST for c in value):
        raise ProjectError(f"discussion-tui {field} must be a SHA-256 digest")


def validate(value: Any) -> dict[str, Any]:  # noqa: C901
    if not isinstance(value, dict) or set(value) != _REQUIRED or value["schema_version"] != 1:
        raise ProjectError("discussion-tui record has unknown or missing fields")
    task = value["task"]
    if (
        not isinstance(task, dict)
        or set(task) != {"id", "revision"}
        or not isinstance(task["id"], str)
        or len(task["id"]) != 7
        or not task["id"].startswith("AR-")
        or not task["id"][3:].isdigit()
        or not isinstance(task["revision"], int)
        or isinstance(task["revision"], bool)
        or not 1 <= task["revision"] <= 1_000_000
    ):
        raise ProjectError("discussion-tui task is invalid")
    refs = value["event_refs"]
    if (
        not isinstance(refs, list)
        or not 1 <= len(refs) <= 32
        or len(set(refs)) != len(refs)
        or any(not isinstance(x, str) or not x.startswith("EV-") for x in refs)
    ):
        raise ProjectError("discussion-tui event references are invalid")
    point = value["active_point"]
    if (
        not isinstance(point, dict)
        or set(point) != {"id", "kind", "document_sha256", "unresolved"}
        or not isinstance(point["id"], str)
        or not point["id"].startswith("POINT-")
        or point["kind"] not in {"discussion", "work-plan", "design", "specification"}
        or not isinstance(point["unresolved"], bool)
    ):
        raise ProjectError("discussion-tui active point is invalid")
    _sha(point["document_sha256"], "document_sha256")
    anchor = value["left_anchor"]
    if (
        not isinstance(anchor, dict)
        or set(anchor) != {"point_id", "document_sha256", "offset"}
        or anchor["point_id"] != point["id"]
        or anchor["document_sha256"] != point["document_sha256"]
        or not isinstance(anchor["offset"], int)
        or isinstance(anchor["offset"], bool)
        or not 0 <= anchor["offset"] <= 1_000_000
    ):
        raise ProjectError("discussion-tui left anchor is stale or invalid")
    render = value["render"]
    expected = {
        "active_pane",
        "layout",
        "highlighted_point_id",
        "highlighted_unresolved",
        "unresolved_point_ids",
        "left_scroll",
        "right_scroll",
        "narrow_terminal",
        "accessibility",
    }
    if (
        not isinstance(render, dict)
        or set(render) != expected
        or render["active_pane"] not in {"left", "right"}
        or render["layout"] != "two-pane"
        or render["highlighted_point_id"] != point["id"]
        or render["highlighted_unresolved"] != point["unresolved"]
        or not isinstance(render["unresolved_point_ids"], list)
        or len(render["unresolved_point_ids"]) > 64
        or len(set(render["unresolved_point_ids"])) != len(render["unresolved_point_ids"])
    ):
        raise ProjectError("discussion-tui render identity or unresolved status is invalid")
    if any(
        not isinstance(x, str) or not x.startswith("POINT-") for x in render["unresolved_point_ids"]
    ) or ((point["id"] in render["unresolved_point_ids"]) != point["unresolved"]):
        raise ProjectError("discussion-tui unresolved point is rendered inconsistently")
    for field in ("left_scroll", "right_scroll"):
        if (
            not isinstance(render[field], int)
            or isinstance(render[field], bool)
            or not 0 <= render[field] <= 1_000_000
        ):
            raise ProjectError("discussion-tui scroll position is invalid")
    if (
        render["narrow_terminal"] not in {"full", "degraded"}
        or render["accessibility"] != "keyboard-navigable"
    ):
        raise ProjectError("discussion-tui terminal or accessibility state is invalid")
    privacy = value["privacy_projection"]
    if (
        not isinstance(privacy, dict)
        or set(privacy) != {"public_safe", "projection_sha256", "redacted_fields"}
        or privacy["public_safe"] is not True
        or not isinstance(privacy["redacted_fields"], list)
        or len(set(privacy["redacted_fields"])) != len(privacy["redacted_fields"])
    ):
        raise ProjectError("discussion-tui privacy projection is not public-safe")
    _sha(privacy["projection_sha256"], "projection_sha256")
    if any(not isinstance(x, str) or not x for x in privacy["redacted_fields"]):
        raise ProjectError("discussion-tui redaction list is invalid")
    if value["limitations"] != [
        "ui_behavior_not_proven",
        "user_intent_not_proven",
        "consumer_native_gates_remain_authoritative",
    ]:
        raise ProjectError("discussion-tui limitations are incomplete")
    return value


def evaluate_file(root: Path, relative: str) -> dict[str, Any]:
    path = confined_path(root, relative)
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProjectError("discussion-tui record is not valid JSON") from error
    validate(value)
    if canonical_bytes(value) != raw:
        raise ProjectError("discussion-tui record is not canonical JSON")
    return {
        "status": "pass",
        "kind": "discussion-tui-evidence",
        "task": value["task"],
        "record_sha256": hashlib.sha256(raw).hexdigest(),
    }


def check(root: Path, paths: list[Path]) -> list[dict[str, str]]:
    candidates = sorted(
        p
        for p in paths
        if p.relative_to(root).as_posix().startswith("quality/discussion-tui/")
        and p.suffix == ".json"
    )
    if not candidates:
        return [
            {
                "code": "missing-discussion-tui",
                "path": "quality/discussion-tui",
                "message": "no discussion TUI record is declared",
            }
        ]
    findings = []
    for path in candidates[:128]:
        try:
            evaluate_file(root, path.relative_to(root).as_posix())
        except ProjectError as error:
            findings.append(
                {
                    "code": "invalid-discussion-tui",
                    "path": path.relative_to(root).as_posix(),
                    "message": str(error),
                }
            )
    return findings
