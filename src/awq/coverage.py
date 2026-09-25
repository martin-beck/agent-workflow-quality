# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Deterministic, content-minimized evidence coverage aggregation."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from awq.project import ProjectError, confined_path, load_json, load_project

ROLES = {"gate-evidence", "publication", "diagnostic", "release"}
STATUSES = {"pass", "fail", "missing", "unavailable"}
EVIDENCE_CLASSES = {
    "mechanical",
    "contract-test",
    "property-or-fuzz",
    "bounded-model",
    "environmental",
}


def _record(value: object, requirements: set[str]) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {
        "task_id",
        "role",
        "requirement",
        "status",
        "evidence_class",
    }:
        raise ProjectError("coverage record has unknown or missing fields")
    item = value
    for key in ("task_id", "role", "requirement", "status", "evidence_class"):
        if not isinstance(item[key], str) or not item[key] or len(item[key]) > 100:
            raise ProjectError("coverage record contains invalid text")
    if item["role"] not in ROLES or item["status"] not in STATUSES:
        raise ProjectError("coverage record role or status is invalid")
    if item["evidence_class"] not in EVIDENCE_CLASSES:
        raise ProjectError("coverage record evidence class is invalid")
    if item["requirement"] not in requirements:
        raise ProjectError("coverage record requirement is not locked")
    return {key: item[key] for key in item}


def evaluate(root: Path, relative: str) -> dict[str, Any]:
    """Aggregate records by task and role while retaining no evidence content."""
    policy, lock = load_project(root)
    del policy
    raw = load_json(confined_path(root, relative))
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema_version", "records"}
        or raw["schema_version"] != 1
    ):
        raise ProjectError("coverage document has unknown or missing fields")
    records = raw["records"]
    if not isinstance(records, list) or len(records) > 4096:
        raise ProjectError("coverage record bound exceeded")
    normalized = [_record(item, set(lock["requirements"])) for item in records]
    identities = [(item["task_id"], item["role"], item["requirement"]) for item in normalized]
    if len(identities) != len(set(identities)):
        raise ProjectError("coverage record identity is reused")
    tasks: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    roles: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for item in normalized:
        tasks[item["task_id"]][item["role"]].append(item["requirement"])
        roles[item["role"]][item["status"]] += 1
    task_output = []
    for task_id in sorted(tasks):
        by_role = tasks[task_id]
        task_output.append(
            {
                "task_id": task_id,
                "roles": [
                    {"role": role, "requirements": sorted(by_role[role])}
                    for role in sorted(by_role)
                ],
            }
        )
    role_output = [
        {
            "role": role,
            "records": sum(roles[role].values()),
            "statuses": {status: roles[role].get(status, 0) for status in sorted(STATUSES)},
        }
        for role in sorted(roles)
    ]
    return {
        "status": "ok",
        "schema_version": 1,
        "records": len(normalized),
        "locked_requirements": len(lock["requirements"]),
        "tasks": task_output,
        "roles": role_output,
    }
