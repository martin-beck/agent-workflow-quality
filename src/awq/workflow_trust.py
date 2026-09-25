# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Offline trust-boundary validation for directive and rollback workflows."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from awq.release import ReleaseError

REVISION = re.compile(r"^[0-9a-f]{40}$")
HASH = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){1,8}$")
RUNNER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not TIMESTAMP.fullmatch(value):
        raise ReleaseError("workflow trust timestamp is invalid")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReleaseError("workflow trust timestamp is invalid") from error


def _exact(value: object, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ReleaseError("workflow trust fields are unknown or incomplete")
    return value


def _id(value: object, prefix: str) -> str:
    if not isinstance(value, str) or len(value) > 100 or not IDENTIFIER.fullmatch(value):
        raise ReleaseError("workflow trust identifier is invalid")
    if not value.startswith(prefix + "-"):
        raise ReleaseError("workflow trust identifier prefix is invalid")
    return value


def _revision(value: object) -> str:
    if not isinstance(value, str) or not REVISION.fullmatch(value):
        raise ReleaseError("workflow trust source revision is invalid")
    return value


def _hash(value: object, message: str) -> str:
    if not isinstance(value, str) or not HASH.fullmatch(value):
        raise ReleaseError(message)
    return value


def _runner(value: object) -> str:
    item = _exact(value, {"runner_id", "trust_class", "platform"})
    runner_id = item["runner_id"]
    if not isinstance(runner_id, str) or not RUNNER.fullmatch(runner_id):
        raise ReleaseError("workflow trust runner identity is invalid")
    if item["trust_class"] not in {"trusted-host", "ephemeral"}:
        raise ReleaseError("workflow trust runner class is invalid")
    if item["platform"] not in {"linux", "windows", "macos"}:
        raise ReleaseError("workflow trust runner platform is invalid")
    return runner_id


def validate_directive(value: object, as_of: str) -> dict[str, str]:
    item = _exact(
        value,
        {
            "schema_version",
            "id",
            "source_revision",
            "request_id",
            "actor",
            "action",
            "created_at",
            "expires_at",
            "runner",
            "permission",
            "payload_sha256",
        },
    )
    if item["schema_version"] != 1:
        raise ReleaseError("workflow trust directive version is invalid")
    identifier = _id(item["id"], "DIRECTIVE")
    _revision(item["source_revision"])
    request_id = _id(item["request_id"], "REQUEST")
    if item["actor"] not in {"human", "coordinator"} or item["action"] not in {
        "intake",
        "reopen",
        "rollback",
        "publish-review",
    }:
        raise ReleaseError("workflow trust directive authority is invalid")
    created, expires, now = (
        _timestamp(item["created_at"]),
        _timestamp(item["expires_at"]),
        _timestamp(as_of),
    )
    if created > expires or expires <= now:
        raise ReleaseError("workflow trust directive is expired")
    runner_id = _runner(item["runner"])
    if item["permission"] not in {"review", "approve", "execute"}:
        raise ReleaseError("workflow trust directive permission is invalid")
    _hash(item["payload_sha256"], "workflow trust directive payload digest is invalid")
    return {
        "id": identifier,
        "request_id": request_id,
        "runner_id": runner_id,
        "action": item["action"],
    }


def validate_rollback(value: object, as_of: str) -> dict[str, str]:
    item = _exact(
        value,
        {
            "schema_version",
            "id",
            "source_revision",
            "checkpoint_sha256",
            "requested_by",
            "permission",
            "publication_state",
            "runner",
            "created_at",
        },
    )
    if item["schema_version"] != 1:
        raise ReleaseError("workflow trust rollback version is invalid")
    identifier = _id(item["id"], "ROLLBACK")
    _revision(item["source_revision"])
    if not isinstance(item["requested_by"], str) or not re.fullmatch(
        r"[A-Za-z0-9_.@+-]{1,128}", item["requested_by"]
    ):
        raise ReleaseError("workflow trust rollback requester is invalid")
    if item["permission"] != "operator-approved" or item["publication_state"] not in {
        "not-requested",
        "review-only",
    }:
        raise ReleaseError("workflow trust rollback permission or publication is invalid")
    runner_id = _runner(item["runner"])
    created = _timestamp(item["created_at"])
    if created > _timestamp(as_of):
        raise ReleaseError("workflow trust rollback timestamp is invalid")
    _hash(item["checkpoint_sha256"], "workflow trust checkpoint digest is invalid")
    return {
        "id": identifier,
        "runner_id": runner_id,
        "publication_state": item["publication_state"],
    }


def evaluate(value: object, as_of: str) -> dict[str, Any]:
    item = _exact(value, {"schema_version", "directives", "rollbacks"})
    if (
        item["schema_version"] != 1
        or not isinstance(item["directives"], list)
        or not isinstance(item["rollbacks"], list)
    ):
        raise ReleaseError("workflow trust document is invalid")
    directives = [validate_directive(entry, as_of) for entry in item["directives"]]
    rollbacks = [validate_rollback(entry, as_of) for entry in item["rollbacks"]]
    if len({entry["id"] for entry in directives}) != len(directives) or len(
        {entry["id"] for entry in rollbacks}
    ) != len(rollbacks):
        raise ReleaseError("workflow trust identifiers are reused")
    return {
        "schema_version": 1,
        "directive_ids": sorted(entry["id"] for entry in directives),
        "rollback_ids": sorted(entry["id"] for entry in rollbacks),
        "trusted_runner_count": len({entry["runner_id"] for entry in directives + rollbacks}),
        "publication_authorized": False,
    }
