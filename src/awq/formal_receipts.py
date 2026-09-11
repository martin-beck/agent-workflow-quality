# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Strict, bounded formal execution receipts without tool execution or raw output."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Never

from awq.project import ProjectError
from awq.registry import canonical_bytes
from awq.release import ReleaseError
from awq.sbom import strict_json
from awq.trust import read_file

MAX_BYTES = 256_000
MAX_VOCABULARY = 64
MAX_TRACE = 256
HASH = r"[0-9a-f]{64}"
GIT_ID = r"[0-9a-f]{40}"
LIMITATIONS = (
    "Execution is evaluated only within the declared finite bounds.",
    "Counterexample sensitivity is established only for the declared negative model.",
    "Implementation trace correspondence is caller-declared and is not a refinement proof.",
    "Consumer-native gates remain authoritative and are not replaced by this receipt.",
)
NON_CLAIMS = (
    "implementation-refinement",
    "liveness-proof",
    "unbounded-proof",
    "universal-equivalence",
)
PASS_OUTCOMES = {"exhausted", "verified"}
FAIL_OUTCOMES = {"counterexample", "incomplete", "tool-error"}


def _fail(code: str) -> Never:
    raise ProjectError("formal execution receipt invalid: " + code)


def _object(value: Any, keys: tuple[str, ...], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        _fail(label + "-fields")
    return dict(value)


def _token(value: Any, pattern: str, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(pattern, value, re.ASCII) is None:
        _fail(label)
    return value


def _identifier(value: Any, pattern: str, label: str) -> str:
    token = _token(value, pattern, label)
    if len(token) > 100:
        _fail(label)
    return token


def _digest(value: Any, label: str) -> str:
    return _token(value, HASH, label)


def _integer(value: Any, low: int, high: int, label: str) -> int:
    if type(value) is not int or not low <= value <= high:
        _fail(label)
    return value


def _vocabulary(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_VOCABULARY:
        _fail(label + "-count")
    result = [_token(item, r"[a-z][a-z0-9_-]{0,63}", label) for item in value]
    if result != sorted(set(result)):
        _fail(label + "-order-or-duplicate")
    return result


def _source(value: Any) -> dict[str, str]:
    source = _object(value, ("commit", "tree"), "source")
    return {
        "commit": _token(source["commit"], GIT_ID, "source-commit"),
        "tree": _token(source["tree"], GIT_ID, "source-tree"),
    }


def _model(value: Any) -> dict[str, Any]:
    model = _object(
        value,
        ("id", "language", "source_sha256", "config_sha256", "operations", "states"),
        "model",
    )
    language = _token(model["language"], r"(?:alloy|rust-kani|rust-loom|tla-plus)", "language")
    return {
        "id": _identifier(model["id"], r"MODEL-[A-Z0-9]+(?:-[A-Z0-9]+)*", "model-id"),
        "language": language,
        "source_sha256": _digest(model["source_sha256"], "model-source-digest"),
        "config_sha256": _digest(model["config_sha256"], "model-config-digest"),
        "operations": _vocabulary(model["operations"], "operations"),
        "states": _vocabulary(model["states"], "states"),
    }


def _tool(value: Any) -> dict[str, Any]:
    tool = _object(value, ("adapter_id", "name", "version", "executable_sha256"), "tool")
    version = _token(tool["version"], r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,99}", "tool-version")
    if not any(character.isdigit() for character in version):
        _fail("tool-version-floating")
    return {
        "adapter_id": _identifier(
            tool["adapter_id"], r"ADAPTER-[A-Z0-9]+(?:-[A-Z0-9]+)*", "adapter-id"
        ),
        "name": _token(tool["name"], r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}", "tool-name"),
        "version": version,
        "executable_sha256": _digest(tool["executable_sha256"], "tool-digest"),
    }


def _run(value: Any) -> dict[str, Any]:
    run = _object(value, ("id", "attempt", "argv_sha256"), "run")
    return {
        "id": _token(run["id"], r"RUN-[A-Z0-9]{4,32}", "run-id"),
        "attempt": _integer(run["attempt"], 1, 1000, "run-attempt"),
        "argv_sha256": _digest(run["argv_sha256"], "run-argv-digest"),
    }


def _bounds(value: Any) -> dict[str, int]:
    if not isinstance(value, dict) or not 1 <= len(value) <= 32:
        _fail("bounds-count")
    if list(value) != sorted(value):
        _fail("bounds-order")
    result = {}
    for name, raw in value.items():
        key = _token(name, r"[a-z][a-z0-9_-]{0,63}", "bound-name")
        result[key] = _integer(raw, 1, 1_000_000, "bound-value")
    return result


def _result(value: Any) -> dict[str, Any]:
    result = _object(
        value,
        (
            "status",
            "outcome",
            "explored_states",
            "explored_transitions",
            "result_sha256",
            "counterexample_sha256",
        ),
        "result",
    )
    status = _token(result["status"], r"(?:pass|fail)", "result-status")
    outcome = _token(
        result["outcome"],
        r"(?:counterexample|exhausted|incomplete|tool-error|verified)",
        "result-outcome",
    )
    if (status == "pass") != (
        outcome in PASS_OUTCOMES
    ) or outcome not in PASS_OUTCOMES | FAIL_OUTCOMES:
        _fail("result-status-outcome")
    counterexample = result["counterexample_sha256"]
    if outcome == "counterexample":
        _digest(counterexample, "result-counterexample-digest")
    elif counterexample is not None:
        _fail("result-counterexample")
    return {
        "status": status,
        "outcome": outcome,
        "explored_states": _integer(result["explored_states"], 0, 1_000_000, "result-states"),
        "explored_transitions": _integer(
            result["explored_transitions"], 0, 1_000_000, "result-transitions"
        ),
        "result_sha256": _digest(result["result_sha256"], "result-digest"),
        "counterexample_sha256": counterexample,
    }


def _sensitivity(
    value: Any,
    model: dict[str, Any],
    tool: dict[str, Any],
    run: dict[str, Any],
    bounds: dict[str, int],
) -> dict[str, str]:
    sensitivity = _object(
        value,
        (
            "model_sha256",
            "config_sha256",
            "mutation_id",
            "mutation_sha256",
            "tool_sha256",
            "run_sha256",
            "bounds_sha256",
            "expected_outcome",
            "observed_outcome",
            "result_sha256",
            "counterexample_sha256",
        ),
        "sensitivity",
    )
    model_digest = _digest(sensitivity["model_sha256"], "sensitivity-model-digest")
    if model_digest == model["source_sha256"]:
        _fail("sensitivity-negative-model")
    if sensitivity["expected_outcome"] != "counterexample":
        _fail("sensitivity-expectation")
    if sensitivity["observed_outcome"] != "counterexample":
        _fail("sensitivity-outcome")
    for field, expected in (
        ("tool_sha256", hashlib.sha256(canonical_bytes(tool)).hexdigest()),
        ("run_sha256", hashlib.sha256(canonical_bytes(run)).hexdigest()),
        ("bounds_sha256", hashlib.sha256(canonical_bytes(bounds)).hexdigest()),
    ):
        if _digest(sensitivity[field], "sensitivity-" + field) != expected:
            _fail("sensitivity-execution-binding")
    return {
        "model_sha256": model_digest,
        "config_sha256": _digest(sensitivity["config_sha256"], "sensitivity-config-digest"),
        "mutation_id": _identifier(
            sensitivity["mutation_id"],
            r"MUTATION-[A-Z0-9]+(?:-[A-Z0-9]+)*",
            "sensitivity-mutation-id",
        ),
        "mutation_sha256": _digest(sensitivity["mutation_sha256"], "sensitivity-mutation-digest"),
        "tool_sha256": sensitivity["tool_sha256"],
        "run_sha256": sensitivity["run_sha256"],
        "bounds_sha256": sensitivity["bounds_sha256"],
        "expected_outcome": "counterexample",
        "observed_outcome": "counterexample",
        "result_sha256": _digest(sensitivity["result_sha256"], "sensitivity-result-digest"),
        "counterexample_sha256": _digest(
            sensitivity["counterexample_sha256"], "sensitivity-counterexample-digest"
        ),
    }


def _mapping(value: Any, expected: list[str], token_pattern: str, label: str) -> dict[str, str]:
    if not isinstance(value, list) or len(value) != len(expected):
        _fail(label + "-count")
    result: dict[str, str] = {}
    for record in value:
        item = _object(record, ("model", "implementation"), label)
        model_name = _token(item["model"], r"[a-z][a-z0-9_-]{0,63}", label + "-model")
        implementation = _token(item["implementation"], token_pattern, label + "-implementation")
        result[model_name] = implementation
    if list(result) != expected or len(set(result.values())) != len(expected):
        _fail(label + "-incomplete-or-reordered")
    return result


def _correspondence(value: Any, model: dict[str, Any]) -> dict[str, Any]:
    correspondence = _object(
        value,
        (
            "classification",
            "implementation_source_sha256",
            "observation_definition_sha256",
            "operation_map",
            "state_map",
            "trace",
            "trace_sha256",
        ),
        "correspondence",
    )
    if correspondence["classification"] != "bounded-trace-correspondence":
        _fail("correspondence-classification")
    operations = _mapping(
        correspondence["operation_map"], model["operations"], r"OP-[0-9]{4}", "operation-map"
    )
    states = _mapping(correspondence["state_map"], model["states"], r"STATE-[0-9]{4}", "state-map")
    trace = correspondence["trace"]
    if not isinstance(trace, list) or not 1 <= len(trace) <= MAX_TRACE:
        _fail("trace-count")
    for sequence, raw in enumerate(trace):
        event = _object(
            raw,
            (
                "sequence",
                "model_operation",
                "implementation_operation",
                "model_state",
                "implementation_state",
                "observation_sha256",
            ),
            "trace-event",
        )
        if _integer(event["sequence"], 0, MAX_TRACE - 1, "trace-sequence") != sequence:
            _fail("trace-order")
        model_operation = _token(
            event["model_operation"], r"[a-z][a-z0-9_-]{0,63}", "trace-model-operation"
        )
        model_state = _token(event["model_state"], r"[a-z][a-z0-9_-]{0,63}", "trace-model-state")
        if operations.get(model_operation) != event["implementation_operation"]:
            _fail("trace-operation-correspondence")
        if states.get(model_state) != event["implementation_state"]:
            _fail("trace-state-correspondence")
        _digest(event["observation_sha256"], "trace-observation-digest")
    trace_sha256 = _digest(correspondence["trace_sha256"], "trace-digest")
    if trace_sha256 != hashlib.sha256(canonical_bytes(trace)).hexdigest():
        _fail("trace-digest-mismatch")
    return {
        "classification": "bounded-trace-correspondence",
        "implementation_source_sha256": _digest(
            correspondence["implementation_source_sha256"], "implementation-source-digest"
        ),
        "observation_definition_sha256": _digest(
            correspondence["observation_definition_sha256"], "observation-definition-digest"
        ),
        "trace_sha256": trace_sha256,
        "events": len(trace),
    }


def _expectation(value: Any) -> dict[str, Any]:
    expected = _object(
        value,
        ("source", "model", "tool", "run", "bounds", "expected_outcome"),
        "expectation",
    )
    return {
        "source": _source(expected["source"]),
        "model": _model(expected["model"]),
        "tool": _tool(expected["tool"]),
        "run": _run(expected["run"]),
        "bounds": _bounds(expected["bounds"]),
        "expected_outcome": _token(
            expected["expected_outcome"],
            r"(?:counterexample|exhausted|incomplete|tool-error|verified)",
            "expected-outcome",
        ),
    }


def evaluate(value: Any, expected_value: Any) -> dict[str, Any]:
    """Validate a closed receipt and return only bounded identity commitments."""
    receipt = _object(
        value,
        (
            "schema_version",
            "kind",
            "receipt_id",
            "source",
            "model",
            "tool",
            "run",
            "bounds",
            "result",
            "sensitivity",
            "correspondence",
            "non_claims",
            "limitations",
        ),
        "receipt",
    )
    if _integer(receipt["schema_version"], 2, 2, "schema-version") != 2:
        _fail("schema-version")
    if receipt["kind"] != "formal-execution-receipt":
        _fail("kind")
    receipt_id = _token(receipt["receipt_id"], r"FORMAL-RECEIPT-[A-Z0-9]{4,32}", "receipt-id")
    source = _source(receipt["source"])
    model = _model(receipt["model"])
    tool = _tool(receipt["tool"])
    run = _run(receipt["run"])
    bounds = _bounds(receipt["bounds"])
    result = _result(receipt["result"])
    expected = _expectation(expected_value)
    observed_identity = {
        "source": source,
        "model": model,
        "tool": tool,
        "run": run,
        "bounds": bounds,
        "expected_outcome": result["outcome"],
    }
    if observed_identity != expected:
        _fail("trusted-identity-mismatch")
    sensitivity = _sensitivity(receipt["sensitivity"], model, tool, run, bounds)
    correspondence = _correspondence(receipt["correspondence"], model)
    if receipt["non_claims"] != list(NON_CLAIMS):
        _fail("proof-inflation")
    if receipt["limitations"] != list(LIMITATIONS):
        _fail("limitations")
    return {
        "schema_version": 2,
        "kind": "formal-execution-receipt",
        "status": result["status"],
        "receipt_id": receipt_id,
        "receipt_sha256": hashlib.sha256(canonical_bytes(receipt)).hexdigest(),
        "source": source,
        "model": {key: model[key] for key in ("id", "language", "source_sha256", "config_sha256")},
        "tool": tool,
        "run": run,
        "bounds": bounds,
        "outcome": result["outcome"],
        "explored_states": result["explored_states"],
        "explored_transitions": result["explored_transitions"],
        "result_sha256": result["result_sha256"],
        "counterexample_sha256": result["counterexample_sha256"],
        "sensitivity": sensitivity,
        "correspondence": correspondence,
        "non_claims": list(NON_CLAIMS),
        "limitations": list(LIMITATIONS),
        "native_gate": "retain",
    }


def _relative_json(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 200
        or re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_.-]+)*[.]json", value) is None
        or any(part in (".", "..") for part in value.split("/"))
    ):
        _fail("path")
    return value


def evaluate_file(root: Path, relative: str, expected_relative: str) -> dict[str, Any]:
    """Read one receipt plus its trusted expectation below the selected root."""
    receipt_path = _relative_json(relative)
    expectation_path = _relative_json(expected_relative)
    if root.is_symlink():
        _fail("path")
    try:
        resolved_root = root.resolve(strict=True)
        raw = read_file(resolved_root / receipt_path, MAX_BYTES)
        expected_raw = read_file(resolved_root / expectation_path, MAX_BYTES)
        value = strict_json(raw)
        expected = strict_json(expected_raw)
    except (OSError, ValueError, ReleaseError) as error:
        raise ProjectError(
            "formal execution receipt invalid: unreadable-or-noncanonical"
        ) from error
    return evaluate(value, expected)
