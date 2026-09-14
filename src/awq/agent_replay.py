# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Canonical, secret-free synthetic agent-runtime replay evidence."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, NoReturn, cast

from awq import __version__, project
from awq.registry import canonical_bytes
from awq.sbom import strict_json
from awq.trust import read_file

HASH = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+){0,7}$")
IDENTIFIER = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){1,7}$")
VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?$")
EVENT_TYPES = {"request-accepted", "response-frame", "fault", "cancelled", "completed"}
DELIVERY = {"not-applicable", "certain", "uncertain"}
FAULTS = {"connection-reset", "seeded-delay", "truncation"}
LIMITATIONS = (
    "Synthetic replay does not establish live provider compatibility or model quality.",
    "Digest commitments do not retain prompts, responses, credentials, or subprocess output.",
    "Consumer-native gates and live environmental observations remain independently required.",
)
NON_CLAIMS = (
    "live-provider-compatibility",
    "model-quality",
    "provider-equivalence",
    "sandbox-containment",
)


def _fail(code: str) -> NoReturn:
    raise project.ProjectError("agent runtime replay invalid: " + code)


def _object(value: Any, fields: str, code: str = "fields") -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(fields.split()):
        _fail(code)
    return cast(dict[str, Any], value)


def _digest(value: object, code: str = "digest") -> str:
    if not isinstance(value, str) or HASH.fullmatch(value) is None:
        _fail(code)
    return value


def _token(value: object, code: str = "token") -> str:
    if not isinstance(value, str) or len(value) > 80 or TOKEN.fullmatch(value) is None:
        _fail(code)
    return value


def _identifier(value: object, prefix: str, code: str = "identifier") -> str:
    if (
        not isinstance(value, str)
        or len(value) > 100
        or IDENTIFIER.fullmatch(value) is None
        or not value.startswith(prefix + "-")
    ):
        _fail(code)
    return value


def _integer(value: object, low: int, high: int, code: str) -> int:
    if type(value) is not int or not low <= value <= high:
        _fail(code)
    return value


def _version(value: object) -> str:
    if not isinstance(value, str) or len(value) > 100 or VERSION.fullmatch(value) is None:
        _fail("version")
    unstable = {"head", "latest", "main", "master", "nightly", "snapshot"}
    if any(part in unstable for part in re.split(r"[.+-]", value.casefold())):
        _fail("version")
    return value


def _sorted_tokens(value: object, low: int, high: int, code: str) -> list[str]:
    if not isinstance(value, list) or not low <= len(value) <= high:
        _fail(code + "-bound")
    result = [_token(item, code) for item in value]
    if result != sorted(set(result)):
        _fail(code + "-order-or-duplicate")
    return result


def _limits(value: Any) -> dict[str, int]:
    item = _object(
        value,
        "max_bytes max_interactions max_events max_frames max_headers max_retries max_virtual_ms",
        "limits-fields",
    )
    bounds = {
        "max_bytes": (1, 1_000_000),
        "max_interactions": (1, 128),
        "max_events": (1, 1024),
        "max_frames": (0, 1024),
        "max_headers": (0, 64),
        "max_retries": (0, 16),
        "max_virtual_ms": (0, 3_600_000),
    }
    return {name: _integer(item[name], *bound, "limits-bound") for name, bound in bounds.items()}


def _request(value: Any, max_headers: int) -> dict[str, Any]:
    item = _object(value, "method route_id headers body_sha256 match_sha256", "request-fields")
    if item["method"] not in {"DELETE", "GET", "PATCH", "POST", "PUT"}:
        _fail("request-method")
    headers = item["headers"]
    if not isinstance(headers, list) or len(headers) > max_headers:
        _fail("header-bound")
    normalized = []
    for raw in headers:
        header = _object(raw, "name value_sha256", "header-fields")
        normalized.append(
            {
                "name": _token(header["name"], "header-name"),
                "value_sha256": _digest(header["value_sha256"]),
            }
        )
    names = [header["name"] for header in normalized]
    if names != sorted(set(names)):
        _fail("header-order-or-duplicate")
    request = {
        "method": item["method"],
        "route_id": _token(item["route_id"], "route-id"),
        "headers": normalized,
        "body_sha256": _digest(item["body_sha256"]),
        "match_sha256": _digest(item["match_sha256"]),
    }
    matched = {key: request[key] for key in ("method", "route_id", "headers", "body_sha256")}
    if request["match_sha256"] != hashlib.sha256(canonical_bytes(matched)).hexdigest():
        _fail("request-match-binding")
    return request


def _event(
    raw: Any, sequence: int, previous: int, limits: dict[str, int], correlation: str
) -> tuple[dict[str, Any], int, bool, int]:
    event = _object(
        raw,
        "sequence virtual_ms type correlation_id frame_sha256 delivery fault",
        "event-fields",
    )
    if event["sequence"] != sequence:
        _fail("event-sequence")
    virtual = _integer(event["virtual_ms"], 0, limits["max_virtual_ms"], "virtual-time")
    if virtual < previous:
        _fail("event-order")
    if event["type"] not in EVENT_TYPES or event["delivery"] not in DELIVERY:
        _fail("event-type-or-delivery")
    if event["correlation_id"] != correlation:
        _fail("event-correlation")
    frames, uncertain = 0, False
    if event["type"] == "response-frame":
        _digest(event["frame_sha256"], "frame-digest")
        frames = 1
    elif event["frame_sha256"] is not None:
        _fail("unexpected-frame")
    if event["type"] == "fault":
        fault = _object(event["fault"], "kind seed", "fault-fields")
        if fault["kind"] not in FAULTS or event["delivery"] == "not-applicable":
            _fail("fault-delivery")
        _integer(fault["seed"], 0, 2**31 - 1, "fault-seed")
        uncertain = event["delivery"] == "uncertain"
    elif event["fault"] is not None or event["delivery"] == "uncertain":
        _fail("unexpected-fault-or-uncertainty")
    return dict(event), virtual, uncertain, frames


def _events(
    value: Any, limits: dict[str, int], correlation: str
) -> tuple[list[dict[str, Any]], bool, int]:
    if not isinstance(value, list) or not 1 <= len(value) <= limits["max_events"]:
        _fail("event-bound")
    result, previous, frames, uncertain = [], -1, 0, False
    for sequence, raw in enumerate(value, start=1):
        event, previous, is_uncertain, event_frames = _event(
            raw, sequence, previous, limits, correlation
        )
        uncertain |= is_uncertain
        frames += event_frames
        result.append(event)
    if frames > limits["max_frames"]:
        _fail("frame-bound")
    return result, uncertain, frames


def _retry(value: Any) -> dict[str, Any]:
    item = _object(value, "mode retry_of idempotency_proof_sha256", "retry-fields")
    if item["mode"] == "none":
        if item["retry_of"] is not None or item["idempotency_proof_sha256"] is not None:
            _fail("retry-none")
    elif item["mode"] == "consumer-authorized":
        _identifier(item["retry_of"], "INTERACTION", "retry-reference")
        _digest(item["idempotency_proof_sha256"], "idempotency-proof")
    else:
        _fail("retry-mode")
    return dict(item)


def _interactions(value: Any, limits: dict[str, int]) -> tuple[list[dict[str, Any]], int, int, int]:
    if not isinstance(value, list) or not 1 <= len(value) <= limits["max_interactions"]:
        _fail("interaction-bound")
    result: list[dict[str, Any]] = []
    uncertain_matches: dict[str, str] = {}
    matches: set[str] = set()
    event_count = frame_count = retry_count = 0
    for index, raw in enumerate(value, start=1):
        item = _object(raw, "id correlation_id request events retry", "interaction-fields")
        identifier = _identifier(item["id"], "INTERACTION")
        if identifier != f"INTERACTION-{index:04d}":
            _fail("interaction-order")
        correlation = _identifier(item["correlation_id"], "CORRELATION")
        request, retry = _request(item["request"], limits["max_headers"]), _retry(item["retry"])
        if request["match_sha256"] in matches and retry["mode"] == "none":
            _fail("ambiguous-request-match")
        matches.add(request["match_sha256"])
        events, uncertain, frames = _events(item["events"], limits, correlation)
        if retry["mode"] == "consumer-authorized":
            retry_count += 1
            prior_match = uncertain_matches.get(retry["retry_of"])
            if prior_match is None:
                _fail("retry-not-uncertain")
            if prior_match != request["match_sha256"]:
                _fail("retry-request-mismatch")
        if uncertain:
            uncertain_matches[identifier] = request["match_sha256"]
        event_count += len(events)
        frame_count += frames
        result.append({**item, "request": request, "events": events, "retry": retry})
    if (
        retry_count > limits["max_retries"]
        or event_count > limits["max_events"]
        or frame_count > limits["max_frames"]
    ):
        _fail("aggregate-bound")
    return result, event_count, frame_count, retry_count


def _launch(value: Any) -> dict[str, Any]:
    item = _object(
        value,
        "adapter provider model runtime workload source run argv environment prompt_transport "
        "credential_resolver network telemetry adapter_set",
        "launch-fields",
    )
    adapter = _object(item["adapter"], "id version")
    provider = _object(item["provider"], "id endpoint_class")
    model = _object(item["model"], "id settings_sha256")
    runtime = _object(item["runtime"], "name version executable_sha256")
    workload = _object(item["workload"], "id sha256")
    source = _object(item["source"], "commit tree")
    run = _object(item["run"], "id attempt")
    argv = _object(item["argv"], "count sha256")
    environment = _object(item["environment"], "names sha256")
    prompt = _object(item["prompt_transport"], "mode content_sha256")
    resolver = _object(item["credential_resolver"], "id config_sha256")
    network = _object(item["network"], "mode endpoint_count")
    telemetry = _object(item["telemetry"], "mode")
    adapter_set = _object(item["adapter_set"], "requested preserved unsupported")
    _identifier(adapter["id"], "ADAPTER")
    _version(adapter["version"])
    _identifier(provider["id"], "PROVIDER")
    _token(provider["endpoint_class"])
    _identifier(model["id"], "MODEL")
    _digest(model["settings_sha256"])
    _token(runtime["name"])
    _version(runtime["version"])
    _digest(runtime["executable_sha256"])
    _identifier(workload["id"], "WORKLOAD")
    _digest(workload["sha256"])
    for name in ("commit", "tree"):
        if not isinstance(source[name], str) or re.fullmatch(r"[0-9a-f]{40}", source[name]) is None:
            _fail("source-" + name)
    _identifier(run["id"], "RUN")
    _integer(run["attempt"], 1, 1000, "run-attempt")
    _integer(argv["count"], 1, 64, "argv-count")
    _digest(argv["sha256"])
    environment["names"] = _sorted_tokens(environment["names"], 0, 32, "environment-name")
    _digest(environment["sha256"])
    if prompt["mode"] != "digest-only":
        _fail("prompt-transport")
    _digest(prompt["content_sha256"])
    _identifier(resolver["id"], "RESOLVER")
    _digest(resolver["config_sha256"])
    if network != {"mode": "replay-only", "endpoint_count": 0}:
        _fail("network")
    if telemetry != {"mode": "disabled"}:
        _fail("telemetry")
    requested = _sorted_tokens(adapter_set["requested"], 1, 64, "requested-setting")
    preserved = _sorted_tokens(adapter_set["preserved"], 0, 64, "preserved-setting")
    unsupported = _sorted_tokens(adapter_set["unsupported"], 0, 64, "unsupported-setting")
    if preserved != requested or unsupported:
        _fail("adapter-set-not-atomic")
    return dict(item)


def evaluate(value: Any) -> dict[str, Any]:
    """Validate a synthetic cassette and return bounded digest commitments."""
    item = _object(
        value,
        "schema_version kind classification cassette launch consumption limitations non_claims",
        "root-fields",
    )
    if item["schema_version"] != 1 or item["kind"] != "agent-runtime-replay":
        _fail("kind-or-version")
    if item["classification"] != "synthetic-replay":
        _fail("synthetic-promoted-to-live")
    cassette = _object(
        item["cassette"], "id redaction limits normalization interactions", "cassette-fields"
    )
    _identifier(cassette["id"], "CASSETTE")
    redaction = _object(cassette["redaction"], "version stage rules_sha256", "redaction-fields")
    if redaction["version"] != "awq-redaction-v1" or redaction["stage"] != "pre-serialization":
        _fail("redaction-version-or-stage")
    _digest(redaction["rules_sha256"])
    normalization = _object(
        cassette["normalization"], "method headers query body", "normalization-fields"
    )
    if normalization != {
        "method": "uppercase",
        "headers": "lowercase-sorted",
        "query": "canonical-sorted",
        "body": "sha256-only",
    }:
        _fail("normalization")
    limits = _limits(cassette["limits"])
    interactions, events, frames, retries = _interactions(cassette["interactions"], limits)
    launch = _launch(item["launch"])
    consumption = _object(
        item["consumption"],
        "interactions events frames retries unconsumed_frames",
        "consumption-fields",
    )
    expected = {
        "interactions": len(interactions),
        "events": events,
        "frames": frames,
        "retries": retries,
        "unconsumed_frames": 0,
    }
    if consumption != expected:
        _fail("incomplete-consumption")
    if item["limitations"] != list(LIMITATIONS) or item["non_claims"] != list(NON_CLAIMS):
        _fail("claims-or-limitations")
    if len(canonical_bytes(item)) > limits["max_bytes"]:
        _fail("byte-bound")
    return {
        "schema_version": 1,
        "awq_version": __version__,
        "kind": "agent-runtime-replay",
        "classification": "synthetic-replay",
        "status": "pass",
        "cassette_id": cassette["id"],
        "cassette_sha256": hashlib.sha256(canonical_bytes(cassette)).hexdigest(),
        "launch_sha256": hashlib.sha256(canonical_bytes(launch)).hexdigest(),
        "counts": {key: expected[key] for key in ("interactions", "events", "frames", "retries")},
        "redaction_version": redaction["version"],
        "redaction_stage": redaction["stage"],
        "evidence_class": "contract-test",
        "native_gate": "retain",
        "network": "replay-only",
        "telemetry": "disabled",
        "non_claims": list(NON_CLAIMS),
        "limitations": list(LIMITATIONS),
    }


def evaluate_file(root: Path, relative: str) -> dict[str, Any]:
    try:
        value = strict_json(read_file(project.confined_path(root, relative), 1_000_000))
        return evaluate(value)
    except Exception as error:
        raise project.ProjectError(
            "agent runtime replay input is invalid or unavailable"
        ) from error
