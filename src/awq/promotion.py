# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Offline, content-minimized native/shared gate promotion decisions."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Never

from awq.project import ProjectError
from awq.registry import canonical_bytes
from awq.release import ReleaseError
from awq.trust import read_file

MAX_BYTES = 1_000_000
MAX_COUNT = 1_000_000
HASH = r"[0-9a-f]{64}"
OWNER = r"OWNER-[A-Z0-9]{4,32}"
GATE = r"AWQ-[A-Z]+-[0-9]{3}"
STAMP = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
OUTCOMES = ("pass", "fail", "error", "skip")
MATRIX = ("both_pass", "both_fail", "false_positive", "false_negative", "inconclusive")
CATEGORIES = ("configuration", "format", "tool-version", "environment", "policy", "unknown")
REMEDIATIONS = ("align-policy", "repair-adapter", "repair-fixture", "investigate")
TRIGGERS = ("false-negative", "unreviewed-mismatch", "runtime-budget", "flake-budget")
LIMITATION = (
    "Caller-supplied aggregate evidence is not authenticated execution proof. "
    "Hashes bind declared cases and definitions, not their truth or completeness. "
    "Caller-selected time is not trusted clock evidence; automation must supply current UTC "
    "and reject or review stale decisions. Finite corpora and windows do not prove universal "
    "equivalence. Decisions authorize no native gate removal or repository mutation."
)


def _fail(code: str) -> Never:
    raise ProjectError("promotion evidence invalid: " + code)


def _object(value: Any, keys: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys.split()):
        _fail("object-fields")
    return dict(value)


def _integer(value: Any, minimum: int = 0, maximum: int = MAX_COUNT) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail("integer-bound")
    return int(value)


def _token(value: Any, pattern: str) -> str:
    if not isinstance(value, str) or re.fullmatch(pattern, value, flags=re.ASCII) is None:
        _fail("token")
    return str(value)


def _choice(value: Any, choices: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in choices:
        _fail("enumeration")
    return str(value)


def _time(value: Any) -> datetime:
    text = _token(value, STAMP)
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        _fail("timestamp")


def _list(value: Any, maximum: int, minimum: int = 0) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        _fail("list-bound")
    return list(value)


def _ordered(values: list[str]) -> None:
    if values != sorted(set(values)):
        _fail("order-or-duplicate")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate-key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    del value
    _fail("non-finite")


def load(raw: bytes) -> dict[str, Any]:
    """Parse a bounded canonical document without exposing input in errors."""
    if len(raw) > MAX_BYTES:
        _fail("byte-bound")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
        if raw != canonical_bytes(value):
            _fail("noncanonical")
    except (ValueError, UnicodeError, RecursionError):
        _fail("json")
    return _object(value, "schema_version consumer_sha256 source_commit gates")


def _corpus(value: Any) -> tuple[dict[str, int], int, int, bool]:
    counts = dict.fromkeys(MATRIX, 0)
    identifiers = []
    positives = negatives = 0
    oracle_failed = False
    for raw in _list(value, 2000, 1):
        case = _object(raw, "sha256 expected native awq")
        identifiers.append(_token(case["sha256"], HASH))
        expected = _choice(case["expected"], ("pass", "fail"))
        native = _choice(case["native"], OUTCOMES)
        awq = _choice(case["awq"], OUTCOMES)
        positives += expected == "pass"
        negatives += expected == "fail"
        oracle_failed |= native != expected
        if native not in ("pass", "fail") or awq not in ("pass", "fail"):
            counts["inconclusive"] += 1
        elif native == awq:
            counts["both_" + native] += 1
        else:
            counts["false_positive" if native == "pass" else "false_negative"] += 1
    _ordered(identifiers)
    return counts, positives, negatives, oracle_failed


def _observations(value: Any, as_of: datetime) -> tuple[dict[str, int], int, int, int, int]:
    observation = _object(value, "started_at ended_at days")
    started = _time(observation["started_at"])
    ended = _time(observation["ended_at"])
    if not started <= ended <= as_of or ended - started > timedelta(days=366):
        _fail("window")
    totals = dict.fromkeys(MATRIX, 0)
    dates = []
    native_ms = awq_ms = flaky = 0
    for raw in _list(observation["days"], 366, 1):
        day = _object(raw, "date counts native_ms awq_ms flaky_runs")
        stamp = _time(_token(day["date"], r"[0-9]{4}-[0-9]{2}-[0-9]{2}") + "T00:00:00Z")
        if not started.date() <= stamp.date() <= ended.date():
            _fail("day-outside-window")
        dates.append(day["date"])
        counts = _object(day["counts"], " ".join(MATRIX))
        runs = sum(_integer(counts[key]) for key in MATRIX)
        _integer(runs, 1)
        for key in MATRIX:
            totals[key] += counts[key]
        native_ms += _integer(day["native_ms"], 1, 1_000_000_000)
        awq_ms += _integer(day["awq_ms"], 1, 1_000_000_000)
        flaky += _integer(day["flaky_runs"], 0, runs)
    _ordered(dates)
    _integer(sum(totals.values()), 1)
    return totals, len(dates), native_ms, awq_ms, flaky


def _review(value: Any, as_of: datetime, maximum_days: int) -> dict[str, Any]:
    review = _object(value, "owner reviewer created_at expires_at approval_sha256")
    owner = _token(review["owner"], OWNER)
    reviewer = _token(review["reviewer"], OWNER)
    created = _time(review["created_at"])
    expires = _time(review["expires_at"])
    _token(review["approval_sha256"], HASH)
    if owner == reviewer or not created < expires or created > as_of:
        _fail("review")
    if expires - created > timedelta(days=maximum_days):
        _fail("review-duration")
    return review


def _exceptions(value: Any, total: int, as_of: datetime) -> tuple[bool, list[str]]:
    covered = 0
    categories = []
    active = True
    for raw in _list(value, len(CATEGORIES)):
        item = _object(raw, "category count remediation review")
        categories.append(_choice(item["category"], CATEGORIES))
        covered += _integer(item["count"], 1)
        _choice(item["remediation"], REMEDIATIONS)
        review = _review(item["review"], as_of, 30)
        active &= as_of < _time(review["expires_at"])
    _ordered(categories)
    if covered != total:
        active = False
    return active, categories


def _ratio(value: Any) -> tuple[int, int]:
    ratio = _object(value, "numerator denominator")
    return _integer(ratio["numerator"]), _integer(ratio["denominator"], 1)


def _policy(value: Any) -> dict[str, Any]:
    policy = _object(
        value,
        "minimum_days minimum_runs minimum_positive minimum_negative max_age_seconds "
        "runtime_ratio flake_ratio",
    )
    _integer(policy["minimum_days"], 7, 366)
    _integer(policy["minimum_runs"], 20)
    _integer(policy["minimum_positive"], 5, 2000)
    _integer(policy["minimum_negative"], 5, 2000)
    _integer(policy["max_age_seconds"], 1, 604800)
    numerator, denominator = _ratio(policy["runtime_ratio"])
    if not 1 <= numerator <= 10 * denominator:
        _fail("runtime-budget")
    numerator, denominator = _ratio(policy["flake_ratio"])
    if numerator * 20 > denominator:
        _fail("flake-budget")
    return policy


def _rollback(value: Any, as_of: datetime) -> bool:
    rollback = _object(value, "review triggers deadline")
    review = _review(rollback["review"], as_of, 90)
    triggers = [_choice(item, TRIGGERS) for item in _list(rollback["triggers"], 4, 1)]
    _ordered(triggers)
    deadline = _time(rollback["deadline"])
    if "false-negative" not in triggers or deadline > _time(review["expires_at"]):
        _fail("rollback")
    return as_of < deadline and as_of < _time(review["expires_at"])


def _decision(gate: dict[str, Any], as_of: datetime) -> dict[str, Any]:
    policy = _policy(gate["policy"])
    corpus, positives, negatives, oracle_failed = _corpus(gate["cases"])
    live, days, native_ms, awq_ms, flaky = _observations(gate["observation"], as_of)
    counts = {key: corpus[key] + live[key] for key in MATRIX}
    reviewed, categories = _exceptions(
        gate["false_positive_reviews"], counts["false_positive"], as_of
    )
    rollback = _rollback(gate["rollback"], as_of)
    blocking = []
    factors = []
    if counts["false_negative"]:
        blocking.append("false-negative")
    if oracle_failed:
        blocking.append("controlled-native-oracle")
    if not reviewed:
        blocking.append("false-positive-unreviewed-or-expired")
    if counts["false_positive"]:
        factors.append("reviewed-false-positive" if reviewed else "unreviewed-false-positive")
    if not rollback:
        blocking.append("rollback-expired")
    factors.extend(_measurement_factors(gate, policy, live, days, native_ms, awq_ms, flaky, as_of))
    if positives < policy["minimum_positive"] or negatives < policy["minimum_negative"]:
        factors.append("controlled-corpus-insufficient")
    if counts["inconclusive"]:
        factors.append("inconclusive")
    request = _choice(gate["requested"], ("retain", "shadow", "enforce"))
    decision = _select(request, blocking, factors)
    return {
        "gate": gate["id"],
        "decision": decision,
        "native_gate": "retain",
        "requested": request,
        "mismatches": counts,
        "blocking": sorted(blocking),
        "factors": sorted(factors),
        "false_positive_categories": categories,
        "observed_days": days,
        "observed_runs": sum(live.values()),
        "evidence_sha256": hashlib.sha256(canonical_bytes(gate)).hexdigest(),
    }


def _measurement_factors(
    gate: dict[str, Any],
    policy: dict[str, Any],
    live: dict[str, int],
    days: int,
    native_ms: int,
    awq_ms: int,
    flaky: int,
    as_of: datetime,
) -> list[str]:
    factors = []
    runs = sum(live.values())
    if days < policy["minimum_days"] or runs < policy["minimum_runs"]:
        factors.append("observation-insufficient")
    end = _time(gate["observation"]["ended_at"])
    if (as_of - end) // timedelta(seconds=1) > policy["max_age_seconds"]:
        factors.append("observation-stale")
    numerator, denominator = _ratio(policy["runtime_ratio"])
    if awq_ms * denominator > native_ms * numerator:
        factors.append("runtime-budget")
    numerator, denominator = _ratio(policy["flake_ratio"])
    if flaky * denominator > runs * numerator:
        factors.append("flake-budget")
    return factors


def _select(request: str, blocking: list[str], factors: list[str]) -> str:
    if blocking:
        return "block"
    if request != "enforce":
        return request
    if any(item != "reviewed-false-positive" for item in factors):
        return "shadow"
    return "enforce"


def evaluate(document: Any, as_of: str) -> dict[str, Any]:
    """Evaluate declared evidence independently per gate, never remove native gates."""
    value = _object(document, "schema_version consumer_sha256 source_commit gates")
    _integer(value["schema_version"], 1, 1)
    _token(value["consumer_sha256"], HASH)
    _token(value["source_commit"], r"[0-9a-f]{40}")
    instant = _time(as_of)
    results = []
    ids = []
    for raw in _list(value["gates"], 200, 1):
        gate = _object(
            raw,
            "id native_definition_sha256 awq_definition_sha256 requested cases observation "
            "policy false_positive_reviews rollback",
        )
        ids.append(_token(gate["id"], GATE))
        _token(gate["native_definition_sha256"], HASH)
        _token(gate["awq_definition_sha256"], HASH)
        results.append(_decision(gate, instant))
    _ordered(ids)
    return {
        "status": "fail" if any(item["decision"] == "block" for item in results) else "pass",
        "schema_version": 1,
        "as_of": as_of,
        "consumer_sha256": value["consumer_sha256"],
        "source_commit": value["source_commit"],
        "gates": results,
        "limitation": LIMITATION,
    }


def evaluate_file(root: Path, relative: str, as_of: str) -> dict[str, Any]:
    """Read a confined regular evidence file with no symlinks or raw diagnostic output."""
    if (
        not isinstance(relative, str)
        or len(relative) > 200
        or re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_.-]+)*[.]json", relative) is None
        or any(part in (".", "..") for part in relative.split("/"))
    ):
        _fail("evidence-path")
    try:
        raw = read_file(root.resolve(strict=True) / relative, MAX_BYTES)
    except (OSError, ValueError, ReleaseError) as error:
        raise ProjectError("promotion evidence invalid: unreadable-file") from error
    return evaluate(load(raw), as_of)
