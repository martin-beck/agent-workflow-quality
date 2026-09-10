# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Deterministic finite lifecycle components; no implementation/composition proof."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Hashable, Iterator
from dataclasses import dataclass, replace
from typing import Any

MODEL = "policy-lifecycle-v1"
ASSUMPTIONS = (
    "atomic-abstract-actions",
    "bounded-logical-time",
    "bounded-monotonic-revisions",
    "honest-distinct-reviewers",
    "independent-components",
    "single-atomic-durable-publication",
    "staging-is-not-publication",
)
MUTATIONS = (
    "none",
    "exception-expiry",
    "stale-renewal",
    "stale-review",
    "review-quorum",
    "stale-evidence",
    "tier-skip",
    "late-rollback",
    "lost-update",
    "torn-publication",
    "restart-uncommitted",
)
MAX_TRANSITIONS = 200_000


def _explore[T: Hashable](
    initial: T,
    successors: Callable[[T], Iterator[tuple[str, T]]],
    violations: Callable[[T, str, T], list[str]],
    cap: int,
) -> dict[str, Any]:
    parents: dict[T, tuple[T, str] | None] = {initial: None}
    queue = deque([initial])
    transitions = 0
    while queue:
        before = queue.popleft()
        for action, after in successors(before):
            if transitions >= MAX_TRANSITIONS:
                return _result("incomplete", len(parents), transitions, [], [])
            transitions += 1
            failed = violations(before, action, after)
            if failed:
                trace = [action]
                previous = parents[before]
                while previous is not None:
                    before, action = previous
                    trace.append(action)
                    previous = parents[before]
                return _result(
                    "counterexample", len(parents), transitions, list(reversed(trace)), failed
                )
            if after not in parents:
                if len(parents) >= cap:
                    return _result("incomplete", len(parents), transitions, [], [])
                parents[after] = (before, action)
                queue.append(after)
    return _result("exhausted", len(parents), transitions, [], [])


def _result(
    outcome: str, states: int, transitions: int, trace: list[str], failed: list[str]
) -> dict[str, Any]:
    return {
        "outcome": outcome,
        "states": states,
        "transitions": transitions,
        "counterexample": trace,
        "violated_invariants": sorted(failed),
    }


@dataclass(frozen=True)
class ExceptionState:
    tick: int = 0
    generation: int = 0
    expiry: int = -1
    review_generation: int = -1
    review_tick: int = -1
    approval_generation: int = -1
    used: bool = False


def exception_steps(
    state: ExceptionState, bounds: dict[str, int], mutation: str
) -> Iterator[tuple[str, ExceptionState]]:
    if state.tick < bounds["ticks"]:
        yield "tick", replace(state, tick=state.tick + 1, used=False)
    yield (
        "review-renewal",
        replace(state, review_generation=state.generation, review_tick=state.tick, used=False),
    )
    if state.generation < bounds["revisions"]:
        yield (
            "revoke",
            replace(
                state,
                generation=state.generation + 1,
                expiry=-1,
                approval_generation=-1,
                used=False,
            ),
        )
        current = state.review_generation == state.generation or mutation == "stale-renewal"
        if state.review_generation >= 0 and current and state.review_tick == state.tick:
            yield (
                "publish-renewal",
                replace(
                    state,
                    generation=state.generation + 1,
                    expiry=state.tick + bounds["ttl"],
                    approval_generation=state.review_generation,
                    review_generation=-1,
                    review_tick=-1,
                    used=False,
                ),
            )
    if state.expiry >= 0 and (state.tick < state.expiry or mutation == "exception-expiry"):
        yield "use-exception", replace(state, used=True)


def exception_violations(before: ExceptionState, action: str, after: ExceptionState) -> list[str]:
    del before, action
    result = []
    if after.used and after.tick >= after.expiry:
        result.append("exception-unexpired")
    if after.expiry >= 0 and after.approval_generation != after.generation - 1:
        result.append("renewal-current-generation")
    return result


@dataclass(frozen=True)
class TierState:
    revision: int = 0
    tick: int = 0
    tier: int = 0
    target: int = 0
    review_a: int = -1
    review_b: int = -1
    evidence_revision: int = -1
    evidence_tick: int = -1


def _tier_ready(state: TierState, bounds: dict[str, int], mutation: str) -> bool:
    votes = sum(
        review >= 0 and (review == state.revision or mutation == "stale-review")
        for review in (state.review_a, state.review_b)
    )
    quorum = votes >= (1 if mutation == "review-quorum" else 2)
    evidence = state.evidence_revision == state.revision and (
        0 <= state.tick - state.evidence_tick < bounds["ttl"] or mutation == "stale-evidence"
    )
    step = state.target <= state.tier + 1 or mutation == "tier-skip"
    return quorum and evidence and step and state.tick < bounds["rollback_deadline"]


def tier_steps(
    state: TierState, bounds: dict[str, int], mutation: str
) -> Iterator[tuple[str, TierState]]:
    if state.tick < bounds["ticks"]:
        yield "tick", replace(state, tick=state.tick + 1)
    if state.revision < bounds["revisions"]:
        for target in range(1, bounds["tiers"] + 1):
            yield (
                "propose-" + str(target),
                replace(state, revision=state.revision + 1, target=target),
            )
    yield "review-a", replace(state, review_a=state.revision)
    yield "review-b", replace(state, review_b=state.revision)
    yield "observe", replace(state, evidence_revision=state.revision, evidence_tick=state.tick)
    if state.target > state.tier and _tier_ready(state, bounds, mutation):
        yield "promote", replace(state, tier=state.target)
    if state.tier and (state.tick < bounds["rollback_deadline"] or mutation == "late-rollback"):
        yield "rollback", replace(state, tier=state.tier - 1)


def tier_violations(
    before: TierState, action: str, after: TierState, bounds: dict[str, int]
) -> list[str]:
    result = []
    if action == "promote":
        if before.review_a != before.revision or before.review_b != before.revision:
            result.append("two-current-reviewers")
        if (
            before.evidence_revision != before.revision
            or not 0 <= before.tick - before.evidence_tick < bounds["ttl"]
        ):
            result.append("current-fresh-evidence")
        if after.tier != before.tier + 1:
            result.append("one-tier-at-a-time")
    if action in ("promote", "rollback") and before.tick >= bounds["rollback_deadline"]:
        result.append("rollback-before-deadline")
    return result


@dataclass(frozen=True)
class PublicationState:
    policy: int = 0
    receipt: int = 0
    base_a: int = -1
    base_b: int = -1
    stage_a: int = 0
    stage_b: int = 0
    crashed: bool = False


def _writer_state(
    state: PublicationState,
    actor: str,
    base: int,
    stage: int,
    policy: int | None = None,
    receipt: int | None = None,
) -> PublicationState:
    return replace(
        state,
        base_a=base if actor == "a" else state.base_a,
        base_b=base if actor == "b" else state.base_b,
        stage_a=stage if actor == "a" else state.stage_a,
        stage_b=stage if actor == "b" else state.stage_b,
        policy=state.policy if policy is None else policy,
        receipt=state.receipt if receipt is None else receipt,
    )


def _writer_steps(
    state: PublicationState, actor: str, revisions: int, mutation: str
) -> Iterator[tuple[str, PublicationState]]:
    base = state.base_a if actor == "a" else state.base_b
    stage = state.stage_a if actor == "a" else state.stage_b
    if base < 0 and state.policy < revisions:
        yield "begin-" + actor, _writer_state(state, actor, state.policy, stage)
    if base >= 0:
        if stage < 2:
            yield "stage-" + actor, _writer_state(state, actor, base, stage + 1)
        elif base == state.policy or mutation == "lost-update":
            yield (
                "commit-" + actor,
                _writer_state(
                    state,
                    actor,
                    -1,
                    0,
                    base + 1,
                    state.receipt if mutation == "torn-publication" else base + 1,
                ),
            )


def publication_steps(
    state: PublicationState, bounds: dict[str, int], mutation: str
) -> Iterator[tuple[str, PublicationState]]:
    if state.crashed:
        policy = state.policy
        if mutation == "restart-uncommitted" and state.stage_a:
            policy = state.base_a + 1
        yield "restart", PublicationState(policy=policy, receipt=state.receipt)
    else:
        yield "crash", replace(state, crashed=True)
        for actor in ("a", "b"):
            yield from _writer_steps(state, actor, bounds["revisions"], mutation)


def publication_violations(
    before: PublicationState, action: str, after: PublicationState
) -> list[str]:
    result = []
    if after.policy != after.receipt:
        result.append("atomic-policy-receipt")
    if action.startswith("commit-") and after.policy != before.policy + 1:
        result.append("publication-compare-and-swap")
    if action in ("crash", "restart") and (
        after.policy != before.policy or after.receipt != before.receipt
    ):
        result.append("recovery-preserves-commit")
    return result


def explore(bounds: dict[str, int], mutation: str) -> dict[str, Any]:
    """Check components independently; passing components are not a composition proof."""
    cap = bounds["max_states"]
    components = {
        "exceptions": _explore(
            ExceptionState(),
            lambda state: exception_steps(state, bounds, mutation),
            exception_violations,
            cap,
        ),
        "publication": _explore(
            PublicationState(),
            lambda state: publication_steps(state, bounds, mutation),
            publication_violations,
            cap,
        ),
        "tiers": _explore(
            TierState(),
            lambda state: tier_steps(state, bounds, mutation),
            lambda before, action, after: tier_violations(before, action, after, bounds),
            cap,
        ),
    }
    outcomes = {item["outcome"] for item in components.values()}
    outcome = (
        "counterexample"
        if "counterexample" in outcomes
        else "incomplete"
        if "incomplete" in outcomes
        else "exhausted"
        if mutation == "none"
        else "surviving-mutant"
    )
    return {
        "status": "pass" if outcome == "exhausted" else "fail",
        "outcome": outcome,
        "components": components,
        "composition": "not-proven",
        "refinement": "not-proven",
    }
