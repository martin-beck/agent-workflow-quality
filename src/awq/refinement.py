# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Bounded, data-only trace correspondence; never an implementation refinement theorem."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any, Never

from awq import formal_model
from awq.project import ProjectError
from awq.registry import canonical_bytes
from awq.trust import read_file

FIELDS = tuple(sorted(asdict(formal_model.State())))
OBLIGATIONS = (
    "bounds",
    "initial-state",
    "invariant-preservation",
    "state-projection",
    "trace-coverage",
    "transition-simulation",
)
ASSUMPTIONS = (
    *formal_model.ASSUMPTIONS,
    "caller-declared-implementation-traces",
    "exact-one-step-projection",
    "reviewed-observation-abstraction",
    "no-hidden-actions-or-state-claim",
)
LIMITATION = (
    "Only supplied finite paired traces are checked. Implementation execution and reviews are "
    "caller-declared, not authenticated or independently collected. No theorem, whole-program "
    "refinement, trace completeness, composition, liveness or universal equivalence is proven. "
    "No candidate code or native gates are executed or changed."
)


def _fail(code: str) -> Never:
    raise ProjectError("refinement contract invalid: " + code)


def _object(value: Any, keys: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        _fail("fields")
    return dict(value)


def _integer(value: Any, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        _fail("bound")
    return int(value)


def _token(value: Any, pattern: str) -> str:
    if not isinstance(value, str) or re.fullmatch(pattern, value, re.ASCII) is None:
        _fail("token")
    return str(value)


def _hash(value: Any) -> str:
    return _token(value, r"[0-9a-f]{64}")


def _array(value: Any, low: int, high: int) -> list[Any]:
    if not isinstance(value, list) or not low <= len(value) <= high:
        _fail("count")
    return list(value)


def _mapping(value: Any, expected: tuple[str, ...], prefix: str) -> dict[str, str]:
    records = _array(value, len(expected), len(expected))
    result = {}
    for raw in records:
        record = _object(raw, ("model", "implementation"))
        name = _token(record["model"], r"[a-z][a-z0-9_-]{0,31}")
        target = _token(record["implementation"], prefix + r"-[0-9]{4}")
        result[name] = target
    if tuple(result) != expected or len(set(result.values())) != len(expected):
        _fail("incomplete-or-duplicate-map")
    return result


def _bounds(value: Any) -> dict[str, int]:
    limits = {"actors": (2, 3), "revisions": (1, 3), "ticks": (1, 6), "review_ttl": (1, 3)}
    raw = _object(value, tuple(limits))
    return {key: _integer(raw[key], *limit) for key, limit in limits.items()}


def _state(value: Any, bounds: dict[str, int]) -> formal_model.State:
    raw = _object(value, FIELDS)
    for key in FIELDS:
        if key == "enforced":
            if type(raw[key]) is not bool:
                _fail("state-boolean")
        else:
            high = (
                bounds["actors"] - 1
                if "reviewer" in key
                else bounds["ticks" if "tick" in key else "revisions"]
            )
            _integer(raw[key], 0 if key in ("tick", "revision") else -1, high)
    return formal_model.State(**raw)


def _review(value: Any, evidence_hash: str) -> None:
    records = _array(value, len(OBLIGATIONS), len(OBLIGATIONS))
    names = []
    for raw in records:
        record = _object(raw, ("id", "owner", "review_sha256", "evidence_sha256"))
        names.append(record["id"])
        _token(record["owner"], r"OWNER-[A-Z0-9]{4,32}")
        _hash(record["review_sha256"])
        if _hash(record["evidence_sha256"]) != evidence_hash:
            _fail("unbound-review")
    if names != list(OBLIGATIONS):
        _fail("incomplete-obligations")


def _projection(
    value: Any, state: formal_model.State, fields: dict[str, str], bounds: dict[str, int]
) -> bool:
    raw = _object(value, tuple(fields.values()))
    projected = _state({key: raw[token] for key, token in fields.items()}, bounds)
    return projected == state


def _action(step: dict[str, Any], actions: dict[str, str]) -> tuple[str, str]:
    action = _token(step["model_action"], r"[a-z][a-z0-9-]{0,31}")
    if action not in actions:
        _fail("unknown-action")
    token = _token(step["implementation_action"], r"ACTION-[0-9]{4}")
    if token not in actions.values():
        _fail("unknown-implementation-action")
    return action, token


def _trace(
    value: Any, fields: dict[str, str], actions: dict[str, str], bounds: dict[str, int]
) -> tuple[str, set[str], set[str], int]:
    record = _object(
        value,
        ("id", "model_initial", "implementation_initial", "steps", "implementation_trace_sha256"),
    )
    identity = _token(record["id"], r"TRACE-[0-9]{4}")
    steps = _array(record["steps"], 1, 64)
    state = _state(record["model_initial"], bounds)
    findings = set()
    seen = set()
    implementation: dict[str, Any] = {"initial": record["implementation_initial"], "steps": []}
    if state != formal_model.State():
        findings.add("initial-state")
    if not _projection(record["implementation_initial"], state, fields, bounds):
        findings.add("state-projection")
    for raw in steps:
        step = _object(
            raw, ("model_action", "implementation_action", "model_state", "implementation_state")
        )
        action, token = _action(step, actions)
        candidate = _state(step["model_state"], bounds)
        if dict(formal_model.successors(state, bounds, "none")).get(action) != candidate:
            findings.add("transition-simulation")
        if actions[action] != token:
            findings.add("action-projection")
        if not _projection(step["implementation_state"], candidate, fields, bounds):
            findings.add("state-projection")
        if formal_model.violations(candidate, bounds["review_ttl"]):
            findings.add("invariant-preservation")
        implementation["steps"].append({"action": token, "state": step["implementation_state"]})
        seen.add(action)
        state = candidate
    if (
        _hash(record["implementation_trace_sha256"])
        != hashlib.sha256(canonical_bytes(implementation)).hexdigest()
    ):
        findings.add("implementation-trace-digest")
    return identity, findings, seen, len(steps)


def evaluate(value: Any) -> dict[str, Any]:
    """Validate complete maps/reviews and replay bounded paired declarations, without execution."""
    contract = _object(
        value,
        (
            "schema_version",
            "kind",
            "model",
            "map_version",
            "model_sha256",
            "implementation_source_sha256",
            "bounds",
            "assumptions",
            "state_map",
            "action_map",
            "obligations",
            "traces",
        ),
    )
    _integer(contract["schema_version"], 1, 1)
    _integer(contract["map_version"], 1, 1)
    if contract["kind"] != "refinement" or contract["model"] != formal_model.MODEL:
        _fail("kind-or-model")
    if contract["assumptions"] != list(ASSUMPTIONS):
        _fail("assumptions")
    source_hash = hashlib.sha256(read_file(Path(formal_model.__file__), 256_000)).hexdigest()
    if _hash(contract["model_sha256"]) != source_hash:
        _fail("model-digest")
    _hash(contract["implementation_source_sha256"])
    bounds = _bounds(contract["bounds"])
    vocabulary = tuple(
        sorted(
            (
                "edit",
                "tick",
                "finish-review",
                "enforce",
                *("begin-review-" + str(actor) for actor in range(bounds["actors"])),
            )
        )
    )
    fields = _mapping(contract["state_map"], FIELDS, "FIELD")
    actions = _mapping(contract["action_map"], vocabulary, "ACTION")
    traces = _array(contract["traces"], 1, 64)
    projection = {key: item for key, item in contract.items() if key != "obligations"}
    _review(contract["obligations"], hashlib.sha256(canonical_bytes(projection)).hexdigest())
    identities = []
    findings: set[str] = set()
    covered: set[str] = set()
    transitions = 0
    for raw in traces:
        identity, failed, seen, count = _trace(raw, fields, actions, bounds)
        identities.append(identity)
        findings.update(failed)
        covered.update(seen)
        transitions += count
    if identities != sorted(set(identities)):
        _fail("trace-order-or-duplicate")
    if covered != set(vocabulary):
        findings.add("trace-coverage")
    return {
        "status": "fail" if findings else "pass",
        "model": formal_model.MODEL,
        "map_version": 1,
        "model_sha256": source_hash,
        "implementation_source_sha256": contract["implementation_source_sha256"],
        "bounds": bounds,
        "assumptions": list(ASSUMPTIONS),
        "obligations": list(OBLIGATIONS),
        "traces": len(traces),
        "transitions": transitions,
        "covered_actions": sorted(covered),
        "findings": sorted(findings),
        "execution": "caller-declared-not-run",
        "refinement": "not-proven",
        "composition": "not-proven",
        "native_gate": "retain",
        "limitation": LIMITATION,
    }
