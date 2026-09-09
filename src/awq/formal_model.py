# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Finite review/promotion transition system; not a proof of consumer implementations."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, replace
from typing import Any

MODEL = "review-promotion-v1"
MUTATIONS = ("none", "stale-review", "expired-review", "self-review")
ASSUMPTIONS = (
    "atomic-interleaved-actions",
    "bounded-monotonic-clock",
    "bounded-monotonic-revisions",
    "honest-review-records",
    "single-policy-owner",
)
INVARIANTS = ("current-revision", "independent-reviewer", "unexpired-review")
MAX_TRANSITIONS = 200_000


@dataclass(frozen=True)
class State:
    """Finite abstract state; actor zero is the policy owner."""

    revision: int = 0
    tick: int = 0
    reviewed_revision: int = -1
    review_tick: int = -1
    reviewer: int = -1
    pending_revision: int = -1
    pending_tick: int = -1
    pending_reviewer: int = -1
    enforced: bool = False


def violations(state: State, ttl: int) -> list[str]:
    """Independent safety oracle applied to every reachable enforced state."""
    if not state.enforced:
        return []
    result = []
    if state.reviewed_revision != state.revision:
        result.append("current-revision")
    if state.reviewer <= 0:
        result.append("independent-reviewer")
    if not 0 <= state.tick - state.review_tick < ttl:
        result.append("unexpired-review")
    return sorted(result)


def _allows(state: State, ttl: int, mutation: str) -> bool:
    current = state.reviewed_revision == state.revision or mutation == "stale-review"
    independent = state.reviewer > 0 or mutation == "self-review"
    fresh = 0 <= state.tick - state.review_tick < ttl or mutation == "expired-review"
    return state.reviewed_revision >= 0 and current and independent and fresh


def successors(state: State, bounds: dict[str, int], mutation: str) -> Iterator[tuple[str, State]]:
    """Enumerate deterministic action interleavings, including stale pending reviews."""
    if state.revision < bounds["revisions"]:
        yield "edit", replace(state, revision=state.revision + 1, enforced=False)
    if state.tick < bounds["ticks"]:
        yield "tick", replace(state, tick=state.tick + 1, enforced=False)
    if state.pending_revision < 0:
        for actor in range(bounds["actors"]):
            yield (
                "begin-review-" + str(actor),
                replace(
                    state,
                    pending_revision=state.revision,
                    pending_tick=state.tick,
                    pending_reviewer=actor,
                ),
            )
    else:
        yield (
            "finish-review",
            replace(
                state,
                reviewed_revision=state.pending_revision,
                review_tick=state.pending_tick,
                reviewer=state.pending_reviewer,
                pending_revision=-1,
                pending_tick=-1,
                pending_reviewer=-1,
                enforced=False,
            ),
        )
    if not state.enforced and _allows(state, bounds["review_ttl"], mutation):
        yield "enforce", replace(state, enforced=True)


def _trace(parents: dict[State, tuple[State, str] | None], state: State, action: str) -> list[str]:
    actions = [action]
    previous = parents[state]
    while previous is not None:
        state, action = previous
        actions.append(action)
        previous = parents[state]
    return list(reversed(actions))


def explore(bounds: dict[str, int], mutation: str) -> dict[str, Any]:
    """Exhaust all reachable states or return a bounded failure, never a partial proof."""
    initial = State()
    parents: dict[State, tuple[State, str] | None] = {initial: None}
    queue = deque([initial])
    transitions = 0
    while queue:
        state = queue.popleft()
        for action, candidate in successors(state, bounds, mutation):
            transitions += 1
            if transitions > MAX_TRANSITIONS:
                return _result("incomplete", len(parents), transitions - 1, [], [])
            failed = violations(candidate, bounds["review_ttl"])
            if failed:
                return _result(
                    "counterexample",
                    len(parents),
                    transitions,
                    _trace(parents, state, action),
                    failed,
                )
            if candidate not in parents:
                if len(parents) >= bounds["max_states"]:
                    return _result("incomplete", len(parents), transitions, [], [])
                parents[candidate] = (state, action)
                queue.append(candidate)
    return _result(
        "exhausted" if mutation == "none" else "surviving-mutant",
        len(parents),
        transitions,
        [],
        [],
    )


def _result(
    outcome: str, states: int, transitions: int, trace: list[str], failed: list[str]
) -> dict[str, Any]:
    return {
        "status": "pass" if outcome == "exhausted" else "fail",
        "outcome": outcome,
        "states": states,
        "transitions": transitions,
        "counterexample": trace,
        "violated_invariants": failed,
    }
