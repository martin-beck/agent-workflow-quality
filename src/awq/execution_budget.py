# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Bounded execution-budget and process-boundary receipt validation."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Never

from awq import __version__
from awq.project import ProjectError
from awq.registry import canonical_bytes
from awq.release import ReleaseError
from awq.sbom import strict_json
from awq.trust import read_file

MAX_BYTES = 256_000
MAX_VALUE = 10**15
HASH = re.compile(r"[0-9a-f]{64}", re.ASCII)
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}", re.ASCII)
IDENTIFIER = re.compile(r"(?:RECEIPT|RES)-[A-Z0-9]+(?:-[A-Z0-9]+)*", re.ASCII)
DIMENSIONS = {
    "actions": "count",
    "cost": "microunits",
    "cpu": "milliseconds",
    "disk": "bytes",
    "memory": "bytes",
    "output": "bytes",
    "pids": "count",
    "tokens": "count",
    "wall": "milliseconds",
}
CLASSIFICATIONS = ("enforced", "observed", "estimated", "unavailable")
LIMITATION = (
    "Receipt validation checks bounded caller-declared records, not portable containment, billing "
    "reconciliation, benchmark scheduling, host enforcement or trusted-executable behavior."
)


def _fail(code: str) -> Never:
    raise ProjectError("execution receipt invalid: " + code)


def _object(value: Any, keys: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys.split()):
        _fail("fields")
    return dict(value)


def _integer(value: Any, lower: int = 0, upper: int = MAX_VALUE) -> int:
    if type(value) is not int or not lower <= value <= upper:
        _fail("integer")
    return value


def _tool(value: Any) -> dict[str, str]:
    tool = _object(value, "name version sha256")
    if any(
        not isinstance(tool[key], str) or TOKEN.fullmatch(tool[key]) is None
        for key in ("name", "version")
    ):
        _fail("tool")
    if not isinstance(tool["sha256"], str) or HASH.fullmatch(tool["sha256"]) is None:
        _fail("tool")
    return {key: str(tool[key]) for key in ("name", "version", "sha256")}


def _dimension(value: Any) -> dict[str, Any]:
    item = _object(value, "id unit classification limit used measurement")
    identifier = item["id"]
    if (
        not isinstance(identifier, str)
        or identifier not in DIMENSIONS
        or item["unit"] != DIMENSIONS[identifier]
    ):
        _fail("dimension")
    if item["classification"] not in CLASSIFICATIONS:
        _fail("classification")
    if item["classification"] == "unavailable":
        if item["limit"] is not None or item["used"] is not None or item["measurement"] is not None:
            _fail("unavailable-dimension")
    else:
        _integer(item["limit"])
        _integer(item["used"])
        if item["used"] > item["limit"]:
            _fail("budget-exceeded")
        item["measurement"] = _tool(item["measurement"])
    return item


def _reservation_lifecycle(item: dict[str, Any], evaluated_step: int) -> None:
    amount = item["amount"]
    expires = item["expires_step"]
    settled = item["settled"]
    refunded = item["refunded"]
    state = item["state"]
    if settled + refunded > amount:
        _fail("over-settlement")
    if state == "reserved":
        if settled or refunded or item["settlement_step"] is not None or evaluated_step > expires:
            _fail("stale-reservation")
    elif state == "settled":
        if settled != amount or refunded or item["settlement_step"] is None:
            _fail("settlement")
    elif state in ("refunded", "stale"):
        if settled or refunded != amount or item["settlement_step"] is None:
            _fail("refund")
        if state == "stale" and evaluated_step <= expires:
            _fail("stale-reservation")
    else:
        _fail("reservation-state")


def _reservation_effect(item: dict[str, Any]) -> None:
    if item["effect"] == "external":
        if (
            item["effect_step"] is None
            or item["effect_step"] <= item["created_step"]
            or item["state"] != "settled"
        ):
            _fail("reserve-before-effect")
        if item["settlement_step"] < item["effect_step"]:
            _fail("settlement-before-effect")
    elif item["effect_step"] is not None:
        _fail("effect-step")


def _reservation(
    value: Any, dimensions: dict[str, dict[str, Any]], evaluated_step: int
) -> dict[str, Any]:
    item = _object(
        value,
        "id dimension amount state created_step expires_step effect effect_step "
        "settlement_step settled refunded",
    )
    if not isinstance(item["id"], str) or IDENTIFIER.fullmatch(item["id"]) is None:
        _fail("reservation-id")
    if (
        item["dimension"] not in dimensions
        or dimensions[item["dimension"]]["classification"] == "unavailable"
    ):
        _fail("reservation-dimension")
    item["amount"] = _integer(item["amount"], 1)
    created = _integer(item["created_step"])
    expires = _integer(item["expires_step"])
    if expires <= created or item["effect"] not in ("none", "external"):
        _fail("reservation-window")
    for name in ("effect_step", "settlement_step"):
        if item[name] is not None:
            _integer(item[name])
    item["settled"] = _integer(item["settled"])
    item["refunded"] = _integer(item["refunded"])
    _reservation_lifecycle(item, evaluated_step)
    _reservation_effect(item)
    return item


def _termination(value: Any) -> dict[str, Any]:
    termination = _object(value, "deadline_reached term_sent kill_sent descendants orphan_outcome")
    for name in ("deadline_reached", "term_sent", "kill_sent"):
        if type(termination[name]) is not bool:
            _fail("termination")
    if termination["descendants"] not in ("none", "reaped", "surviving", "unknown"):
        _fail("descendants")
    if termination["orphan_outcome"] not in (
        "none",
        "prevented",
        "reaped",
        "surviving",
        "unknown",
    ):
        _fail("orphan")
    return termination


def _process_findings(item: dict[str, Any], termination: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    if termination["deadline_reached"] and not termination["term_sent"]:
        findings.append("term-missing")
    if (
        termination["term_sent"]
        and termination["descendants"] in ("surviving", "unknown")
        and not termination["kill_sent"]
    ):
        findings.append("kill-missing")
    if termination["descendants"] == "surviving":
        findings.append("descendants-survived")
    if termination["orphan_outcome"] == "surviving":
        findings.append("orphan-survived")
    if item["process_scope"] == "none" and termination["deadline_reached"]:
        findings.append("process-boundary-missing")
    if termination["term_sent"] and not termination["deadline_reached"]:
        findings.append("term-without-deadline")
    if termination["kill_sent"] and not termination["term_sent"]:
        findings.append("kill-without-term")
    return findings


def _process(value: Any) -> tuple[dict[str, Any], list[str]]:
    item = _object(value, "argv_sha256 environment process_scope deadline_seconds termination")
    if not isinstance(item["argv_sha256"], str) or HASH.fullmatch(item["argv_sha256"]) is None:
        _fail("argv-digest")
    if item["environment"] not in ("minimal-reviewed", "caller-filtered", "unknown"):
        _fail("environment")
    if item["process_scope"] not in ("new-session", "new-process-group", "none"):
        _fail("process-scope")
    _integer(item["deadline_seconds"], 1, 900)
    termination = _termination(item["termination"])
    return {**item, "termination": termination}, _process_findings(item, termination)


def _sandbox(value: Any) -> dict[str, Any]:
    item = _object(value, "boundary classification outcome tool claim")
    if item["boundary"] not in ("network", "filesystem", "capabilities"):
        _fail("sandbox-boundary")
    if item["classification"] not in ("observed", "unavailable"):
        _fail("unsupported-isolation-claim")
    if item["claim"] != "observation-not-portable-isolation":
        _fail("unsupported-isolation-claim")
    if item["classification"] == "unavailable":
        if item["outcome"] != "unavailable" or item["tool"] is not None:
            _fail("sandbox-unavailable")
    else:
        if item["outcome"] not in ("blocked", "allowed"):
            _fail("sandbox-outcome")
        item["tool"] = _tool(item["tool"])
    return item


def _reservation_balances(
    dimensions: dict[str, dict[str, Any]], reservations: list[dict[str, Any]]
) -> None:
    for identifier, dimension in dimensions.items():
        if dimension["classification"] == "unavailable":
            continue
        matching = [item for item in reservations if item["dimension"] == identifier]
        active = sum(item["amount"] for item in matching if item["state"] == "reserved")
        settled = sum(item["settled"] for item in matching)
        if active > dimension["limit"] - dimension["used"]:
            _fail("reservation-capacity")
        if settled > dimension["used"]:
            _fail("settlement-unaccounted")


def _termination_model() -> tuple[int, int]:
    states = rejected = 0
    for deadline_reached in (False, True):
        for term_sent in (False, True):
            for kill_sent in (False, True):
                states += 1
                if (term_sent and not deadline_reached) or (kill_sent and not term_sent):
                    rejected += 1
    return states, rejected


def bounded_model() -> dict[str, Any]:
    """Exhaust all small reservation and termination outcomes."""
    states = transitions = rejected = 0
    violations: set[str] = set()
    for balance in range(4):
        for amount in range(1, 3):
            states += 1
            for settled, refunded in ((0, 0), (amount, 0), (0, amount)):
                transitions += 1
                if settled and amount > balance:
                    rejected += 1
                    continue
                if settled < 0 or refunded < 0:
                    violations.add("non-negative")
                if settled + refunded > amount:
                    violations.add("conservation")
    termination_states, termination_rejected = _termination_model()
    return {
        "kind": "bounded-reservation-lifecycle",
        "bounds": {
            "max_balance": 3,
            "max_amount": 2,
            "outcomes": 3,
            "termination_booleans": 3,
        },
        "states": states,
        "transitions": transitions,
        "rejected_transitions": rejected,
        "termination_states": termination_states,
        "termination_rejected": termination_rejected,
        "violated_invariants": sorted(violations),
        "outcome": "exhausted" if not violations else "counterexample",
        "limitation": (
            "Finite arithmetic state space only; no implementation refinement or host "
            "enforcement proof."
        ),
    }


def evaluate(value: Any) -> dict[str, Any]:
    """Validate a receipt and return content-minimized lifecycle findings."""
    document = _object(
        value,
        "schema_version receipt_id evaluated_step dimensions reservations process "
        "sandbox limitation",
    )
    if document["schema_version"] != 1:
        _fail("schema-version")
    if (
        not isinstance(document["receipt_id"], str)
        or IDENTIFIER.fullmatch(document["receipt_id"]) is None
    ):
        _fail("receipt-id")
    evaluated_step = _integer(document["evaluated_step"])
    if document["limitation"] != LIMITATION:
        _fail("limitation")
    if not isinstance(document["dimensions"], list) or len(document["dimensions"]) != len(
        DIMENSIONS
    ):
        _fail("dimensions-incomplete")
    dimensions = [_dimension(item) for item in document["dimensions"]]
    identifiers = [item["id"] for item in dimensions]
    if identifiers != sorted(DIMENSIONS):
        _fail("dimensions-order-or-duplicate")
    dimension_map = {item["id"]: item for item in dimensions}
    if not isinstance(document["reservations"], list) or len(document["reservations"]) > 256:
        _fail("reservations")
    reservations = [
        _reservation(item, dimension_map, evaluated_step) for item in document["reservations"]
    ]
    reservation_ids = [item["id"] for item in reservations]
    if reservation_ids != sorted(reservation_ids) or len(reservation_ids) != len(
        set(reservation_ids)
    ):
        _fail("reservation-order-or-duplicate")
    _reservation_balances(dimension_map, reservations)
    process, findings = _process(document["process"])
    if not isinstance(document["sandbox"], list) or len(document["sandbox"]) != 3:
        _fail("sandbox-incomplete")
    sandbox = [_sandbox(item) for item in document["sandbox"]]
    if [item["boundary"] for item in sandbox] != sorted(("network", "filesystem", "capabilities")):
        _fail("sandbox-order-or-duplicate")
    model = bounded_model()
    return {
        "status": "pass" if not findings and model["outcome"] == "exhausted" else "fail",
        "schema_version": 1,
        "awq_version": __version__,
        "receipt_id": document["receipt_id"],
        "receipt_sha256": hashlib.sha256(canonical_bytes(document)).hexdigest(),
        "classifications": {
            name: sum(item["classification"] == name for item in dimensions)
            for name in CLASSIFICATIONS
        },
        "reservations": {
            name: sum(item["state"] == name for item in reservations)
            for name in ("reserved", "settled", "refunded", "stale")
        },
        "process": {
            "environment": process["environment"],
            "process_scope": process["process_scope"],
            "deadline_seconds": process["deadline_seconds"],
            "descendants": process["termination"]["descendants"],
            "orphan_outcome": process["termination"]["orphan_outcome"],
        },
        "sandbox": {item["boundary"]: item["classification"] for item in sandbox},
        "findings": sorted(findings),
        "model": model,
        "limitation": LIMITATION,
    }


def evaluate_file(root: Path, relative: str) -> dict[str, Any]:
    """Read a confined bounded canonical receipt."""
    if (
        not isinstance(relative, str)
        or len(relative) > 200
        or re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_.-]+)*[.]json", relative) is None
        or any(part in (".", "..") for part in relative.split("/"))
        or root.is_symlink()
    ):
        _fail("path")
    try:
        value = strict_json(read_file(root.resolve(strict=True) / relative, MAX_BYTES))
    except (OSError, ValueError, ReleaseError) as error:
        raise ProjectError("execution receipt invalid: unreadable-or-noncanonical") from error
    return evaluate(value)
