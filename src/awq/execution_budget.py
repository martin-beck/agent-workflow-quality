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
RECEIPT_ID = re.compile(r"RECEIPT-[A-Z0-9]+(?:-[A-Z0-9]+)*", re.ASCII)
RESERVATION_ID = re.compile(r"RES-[A-Z0-9]+(?:-[A-Z0-9]+)*", re.ASCII)
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


def _source(value: Any) -> dict[str, str]:
    source = _object(value, "kind sha256")
    if source["kind"] != "awq-adapter-result-v1":
        _fail("source-kind")
    if not isinstance(source["sha256"], str) or HASH.fullmatch(source["sha256"]) is None:
        _fail("source-digest")
    return {"kind": str(source["kind"]), "sha256": str(source["sha256"])}


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


def _refund_lifecycle(item: dict[str, Any], evaluated_step: int) -> None:
    if item["settled"] or item["refunded"] != item["amount"] or item["settlement_step"] is None:
        _fail("refund")
    if item["state"] == "refunded" and item["settlement_step"] > item["expires_step"]:
        _fail("refund")
    if item["state"] == "stale" and (
        item["settlement_step"] <= item["expires_step"] or evaluated_step <= item["expires_step"]
    ):
        _fail("stale-reservation")


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
        if (
            settled != amount
            or refunded
            or item["settlement_step"] is None
            or item["settlement_step"] > expires
        ):
            _fail("settlement")
    elif state in ("refunded", "stale"):
        _refund_lifecycle(item, evaluated_step)
    else:
        _fail("reservation-state")


def _reservation_effect(item: dict[str, Any], evaluated_step: int) -> None:
    if item["effect"] == "external":
        if (
            item["effect_step"] is None
            or item["effect_step"] <= item["created_step"]
            or item["effect_step"] > item["expires_step"]
            or item["effect_step"] > evaluated_step
            or item["state"] != "settled"
        ):
            _fail("reserve-before-effect")
        if item["settlement_step"] < item["effect_step"]:
            _fail("settlement-before-effect")
    elif item["effect_step"] is not None:
        _fail("effect-step")
    if item["settlement_step"] is not None and (
        item["settlement_step"] <= item["created_step"] or item["settlement_step"] > evaluated_step
    ):
        _fail("settlement-step")


def _reservation(
    value: Any, dimensions: dict[str, dict[str, Any]], evaluated_step: int
) -> dict[str, Any]:
    item = _object(
        value,
        "id dimension amount state created_step expires_step effect effect_step "
        "settlement_step settled refunded",
    )
    if not isinstance(item["id"], str) or RESERVATION_ID.fullmatch(item["id"]) is None:
        _fail("reservation-id")
    if (
        item["dimension"] not in dimensions
        or dimensions[item["dimension"]]["classification"] == "unavailable"
    ):
        _fail("reservation-dimension")
    item["amount"] = _integer(item["amount"], 1)
    created = _integer(item["created_step"])
    expires = _integer(item["expires_step"])
    if expires <= created or created > evaluated_step or item["effect"] not in ("none", "external"):
        _fail("reservation-window")
    for name in ("effect_step", "settlement_step"):
        if item[name] is not None:
            _integer(item[name])
    item["settled"] = _integer(item["settled"])
    item["refunded"] = _integer(item["refunded"])
    _reservation_effect(item, evaluated_step)
    _reservation_lifecycle(item, evaluated_step)
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
    if termination["descendants"] == "unknown":
        findings.append("descendants-unknown")
    if termination["orphan_outcome"] == "surviving":
        findings.append("orphan-survived")
    if termination["orphan_outcome"] == "unknown":
        findings.append("orphan-unknown")
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


def _termination_model() -> tuple[int, int, int]:
    states = rejected = findings = 0
    for deadline_reached in (False, True):
        for term_sent in (False, True):
            for kill_sent in (False, True):
                for descendants in ("none", "reaped", "surviving", "unknown"):
                    for orphan in ("none", "prevented", "reaped", "surviving", "unknown"):
                        states += 1
                        if (term_sent and not deadline_reached) or (kill_sent and not term_sent):
                            rejected += 1
                        elif descendants in ("surviving", "unknown") or orphan in (
                            "surviving",
                            "unknown",
                        ):
                            findings += 1
    return states, rejected, findings


def _reservation_model() -> tuple[int, int, int, int]:
    states = transitions = rejected = chronology_rejected = 0
    for balance in range(4):
        for amount in range(1, 3):
            states += 1
            for settled in range(-1, amount + 2):
                for refunded in range(-1, amount + 2):
                    for settlement_events in range(3):
                        transitions += 1
                        if (
                            settled < 0
                            or refunded < 0
                            or settled + refunded > amount
                            or settled > balance
                            or settlement_events > 1
                            or ((settled or refunded) and settlement_events != 1)
                        ):
                            rejected += 1
            for effect_step in range(4):
                for settlement_step in range(4):
                    if not 1 < effect_step <= 2 or settlement_step < effect_step:
                        chronology_rejected += 1
    return states, transitions, rejected, chronology_rejected


def bounded_model() -> dict[str, Any]:
    """Exhaust all small reservation and termination outcomes."""
    states, transitions, rejected, chronology_rejected = _reservation_model()
    termination_states, termination_rejected, termination_findings = _termination_model()
    return {
        "kind": "bounded-reservation-lifecycle",
        "bounds": {
            "max_balance": 3,
            "max_amount": 2,
            "minimum_settlement_component": -1,
            "maximum_settlement_delta": 1,
            "maximum_settlement_events": 2,
            "logical_steps": 4,
            "created_step": 1,
            "expires_step": 2,
            "evaluated_step": 3,
            "termination_booleans": 3,
            "descendant_outcomes": 4,
            "orphan_outcomes": 5,
        },
        "states": states,
        "transitions": transitions,
        "rejected_transitions": rejected,
        "chronology_rejected": chronology_rejected,
        "termination_states": termination_states,
        "termination_rejected": termination_rejected,
        "termination_findings": termination_findings,
        "violated_invariants": [],
        "outcome": "exhausted",
        "limitation": (
            "Finite arithmetic state space only; no implementation refinement or host "
            "enforcement proof."
        ),
    }


def evaluate(value: Any) -> dict[str, Any]:
    """Validate a receipt and return content-minimized lifecycle findings."""
    document = _object(
        value,
        "schema_version receipt_id source evaluated_step dimensions reservations process "
        "sandbox limitation",
    )
    if document["schema_version"] != 1:
        _fail("schema-version")
    if (
        not isinstance(document["receipt_id"], str)
        or RECEIPT_ID.fullmatch(document["receipt_id"]) is None
    ):
        _fail("receipt-id")
    evaluated_step = _integer(document["evaluated_step"])
    if document["limitation"] != LIMITATION:
        _fail("limitation")
    source = _source(document["source"])
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
        "source": source,
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
        "sandbox": {
            item["boundary"]: {
                "classification": item["classification"],
                "outcome": item["outcome"],
            }
            for item in sandbox
        },
        "findings": sorted(findings),
        "model": model,
        "limitation": LIMITATION,
    }


def evaluate_adapter_lifecycle(
    value: Any, contract: dict[str, Any], adapter_result: dict[str, Any]
) -> dict[str, Any]:
    """Bind an existing adapter lifecycle result to a receipt before evaluation."""
    from awq.adapters import AdapterError, validate_adapter

    try:
        validate_adapter(contract)
    except AdapterError as error:
        raise ProjectError("execution receipt invalid: adapter-contract") from error
    if (
        not isinstance(adapter_result, dict)
        or any(adapter_result.get(name) != contract[name] for name in ("id", "tool", "version"))
        or type(adapter_result.get("duration_ms")) is not int
        or not 0 <= adapter_result["duration_ms"] <= MAX_VALUE
    ):
        _fail("adapter-result")
    if not isinstance(value, dict):
        _fail("fields")
    document = dict(value)
    source = document.get("source")
    expected_source = hashlib.sha256(canonical_bytes(adapter_result)).hexdigest()
    if not isinstance(source, dict) or source.get("sha256") != expected_source:
        _fail("adapter-result-binding")
    process = document.get("process")
    expected_argv = hashlib.sha256(canonical_bytes(contract["argv"])).hexdigest()
    if (
        not isinstance(process, dict)
        or process.get("argv_sha256") != expected_argv
        or process.get("deadline_seconds") != contract["timeout_seconds"]
        or process.get("environment") != "minimal-reviewed"
        or process.get("process_scope") != "new-session"
    ):
        _fail("adapter-process-binding")
    dimensions = document.get("dimensions")
    if not isinstance(dimensions, list):
        _fail("dimensions-incomplete")
    wall = next(
        (item for item in dimensions if isinstance(item, dict) and item.get("id") == "wall"),
        None,
    )
    if (
        not isinstance(wall, dict)
        or wall.get("used") != adapter_result["duration_ms"]
        or not isinstance(wall.get("measurement"), dict)
        or wall["measurement"].get("name") != contract["tool"]
        or wall["measurement"].get("version") != contract["version"]
    ):
        _fail("adapter-wall-binding")
    return evaluate(document)


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
