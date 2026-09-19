# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT
"""Small finite policy model for guidance resolution transitions."""

from __future__ import annotations

from typing import Final

STATES: Final = frozenset(
    {
        "pending_clarification",
        "rejected_proposal",
        "user_added_alternative",
        "reconciled",
        "reopened",
    }
)
RESULT_FOR_STATE: Final = {
    "pending_clarification": "clarification",
    "rejected_proposal": "rejection",
    "user_added_alternative": "alternative",
    "reconciled": "reconciliation",
    "reopened": "reopen",
}


def transition(before: str, after: str, result: str, issue: str) -> dict[str, object]:
    """Return a bounded transition and reject unauthorized unresolved outcomes."""
    if before not in STATES or after not in STATES or RESULT_FOR_STATE.get(after) != result:
        raise ValueError("invalid guidance-resolution transition")
    if issue == "no_op" and before != after:
        raise ValueError("no-op transition changed state")
    if issue != "no_op" and before == after:
        raise ValueError("material transition did not change state")
    return {
        "before": before,
        "after": after,
        "result": result,
        "authorization": after == "reconciled" and result == "reconciliation",
    }


def safety_oracle(record: dict[str, object]) -> bool:
    """Check the model invariant: unresolved guidance can never authorize work."""
    return record["authorization"] is False if record["after"] != "reconciled" else True
