# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT
"""Bounded, privacy-safe validation for typed oracle interaction gates."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from awq.project import ProjectError, confined_path
from awq.registry import canonical_bytes

SCHEMA_VERSION = 1
_REQUIRED = {
    "schema_version",
    "gate_type",
    "task",
    "event_refs",
    "context",
    "before",
    "after",
    "formal_spec",
    "user_disposition",
    "privacy_projection",
    "unresolved",
}


def validate(value: Any) -> dict[str, Any]:  # noqa: C901
    """Validate one interaction record without exposing its content."""
    if not isinstance(value, dict) or set(value) != _REQUIRED or value["schema_version"] != 1:
        raise ProjectError("interaction-gate record has unknown or missing fields")
    if value["gate_type"] not in {"clarification", "decision", "guidance", "review"}:
        raise ProjectError("interaction-gate type is invalid")
    task = value["task"]
    if not isinstance(task, dict) or set(task) != {"id", "revision"}:
        raise ProjectError("interaction-gate task context is invalid")
    if (
        not isinstance(task["id"], str)
        or len(task["id"]) != 7
        or not task["id"].startswith("AR-")
        or not task["id"][3:].isdigit()
        or not isinstance(task["revision"], int)
        or isinstance(task["revision"], bool)
        or not 1 <= task["revision"] <= 1_000_000
    ):
        raise ProjectError("interaction-gate task context is invalid")
    refs = value["event_refs"]
    if (
        not isinstance(refs, list)
        or not 1 <= len(refs) <= 32
        or len(set(refs)) != len(refs)
        or any(not isinstance(item, str) or not item.startswith("EV-") for item in refs)
    ):
        raise ProjectError("interaction-gate event references are invalid")
    _context(value["context"])
    _artifacts(value["before"], "before")
    _artifacts(value["after"], "after")
    formal = value["formal_spec"]
    if (
        not isinstance(formal, dict)
        or set(formal) != {"specification_sha256", "result_sha256", "review_sha256", "status"}
        or formal["status"] != "pass"
    ):
        raise ProjectError("interaction-gate formal review must be a complete pass")
    for field in ("specification_sha256", "result_sha256", "review_sha256"):
        _digest(formal[field], field)
    if value["user_disposition"] not in {"accepted", "rejected"}:
        raise ProjectError("interaction-gate user disposition is invalid")
    privacy = value["privacy_projection"]
    if (
        not isinstance(privacy, dict)
        or set(privacy) != {"public_safe", "projection_sha256", "redacted_fields"}
        or privacy["public_safe"] is not True
    ):
        raise ProjectError("interaction-gate privacy projection is not public-safe")
    _digest(privacy["projection_sha256"], "projection_sha256")
    redacted = privacy["redacted_fields"]
    if not isinstance(redacted, list) or len(redacted) > 64 or len(set(redacted)) != len(redacted):
        raise ProjectError("interaction-gate redaction list is invalid")
    if any(not isinstance(item, str) or not item for item in redacted):
        raise ProjectError("interaction-gate redaction list is invalid")
    if value["unresolved"] is not False:
        raise ProjectError("unresolved interaction-gate cannot pass")
    return value


def _digest(value: Any, field: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ProjectError(f"interaction-gate {field} must be a SHA-256 digest")


def _context(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {
        "objective_sha256",
        "constraints_sha256",
        "implications_sha256",
    }:
        raise ProjectError("interaction-gate context is incomplete")
    for field, item in value.items():
        _digest(item, field)


def _artifacts(value: Any, name: str) -> None:
    if not isinstance(value, dict) or set(value) != {"plan_sha256", "design_sha256"}:
        raise ProjectError(f"interaction-gate {name} artifacts are incomplete")
    _digest(value["plan_sha256"], f"{name}_plan_sha256")
    _digest(value["design_sha256"], f"{name}_design_sha256")


def evaluate_file(root: Path, relative: str) -> dict[str, Any]:
    """Validate one confined record and return only its public identity."""
    path = confined_path(root, relative)
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProjectError("interaction-gate record is not valid JSON") from error
    validate(value)
    if canonical_bytes(value) != path.read_bytes():
        raise ProjectError("interaction-gate record is not canonical JSON")
    return {
        "status": "pass",
        "kind": "interaction-gate-evidence",
        "task": value["task"],
        "record_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def check(root: Path, paths: list[Path]) -> list[dict[str, str]]:
    """Check all declared records; an empty declaration fails closed."""
    candidates = sorted(
        path
        for path in paths
        if path.relative_to(root).as_posix().startswith("quality/interaction-gates/")
        and path.suffix == ".json"
    )
    if not candidates:
        return [
            {
                "code": "missing-interaction-gate",
                "path": "quality/interaction-gates",
                "message": "no interaction-gate record is declared",
            }
        ]
    findings: list[dict[str, str]] = []
    for path in candidates[:128]:
        try:
            evaluate_file(root, path.relative_to(root).as_posix())
        except ProjectError as error:
            findings.append(
                {
                    "code": "invalid-interaction-gate",
                    "path": path.relative_to(root).as_posix(),
                    "message": str(error),
                }
            )
    return findings
