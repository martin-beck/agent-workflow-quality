# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Strict bounded formal/refactoring evidence with no runtime execution of candidate code."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Never

from awq import __version__, formal_model
from awq.project import ProjectError
from awq.registry import canonical_bytes
from awq.release import ReleaseError
from awq.sbom import strict_json
from awq.trust import read_file

MAX_BYTES = 256_000
HASH = r"[0-9a-f]{64}"
METHODS = ("characterization", "differential", "mutation", "property")
LIMITATION = (
    "Finite abstract-model exploration is not an implementation refinement proof, liveness proof "
    "or universal equivalence proof. Refactoring records are caller-declared bounded observations, "
    "not authenticated executions. No candidate code, commands, network or native gates are run "
    "or changed. Hashes do not establish the truth, completeness or privacy of evidence."
)


def _fail(code: str) -> Never:
    raise ProjectError("assurance contract invalid: " + code)


def _object(value: Any, keys: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys.split()):
        _fail("fields")
    return dict(value)


def _integer(value: Any, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        _fail("integer-bound")
    return int(value)


def _digest(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(HASH, value, re.ASCII) is None:
        _fail("digest")
    return str(value)


def _identities(value: Any) -> None:
    identities = _object(value, "before_source_sha256 after_source_sha256")
    for item in identities.values():
        _digest(item)
    if identities["before_source_sha256"] == identities["after_source_sha256"]:
        _fail("unchanged-source")


def _model(value: dict[str, Any]) -> dict[str, Any]:
    contract = _object(value, "schema_version kind model mutation bounds assumptions")
    if (
        contract["model"] != formal_model.MODEL
        or contract["mutation"] not in formal_model.MUTATIONS
    ):
        _fail("model-or-mutation")
    if contract["assumptions"] != list(formal_model.ASSUMPTIONS):
        _fail("assumptions")
    bounds = _object(contract["bounds"], "actors revisions ticks review_ttl max_states")
    for key, low, high in (
        ("actors", 2, 3),
        ("revisions", 1, 3),
        ("ticks", 1, 6),
        ("review_ttl", 1, 3),
        ("max_states", 1, 20_000),
    ):
        _integer(bounds[key], low, high)
    result = formal_model.explore(bounds, contract["mutation"])
    return {
        **result,
        "model": formal_model.MODEL,
        "mutation": contract["mutation"],
        "bounds": bounds,
        "assumptions": list(formal_model.ASSUMPTIONS),
        "invariants": list(formal_model.INVARIANTS),
        "refinement": "not-proven",
        "model_sha256": hashlib.sha256(
            read_file(Path(formal_model.__file__), MAX_BYTES)
        ).hexdigest(),
    }


def _record(raw: Any) -> dict[str, Any]:
    record = _object(
        raw,
        "method tool_sha256 cases_sha256 before_result_sha256 after_result_sha256 "
        "cases before_failures after_failures mismatches mutants killed",
    )
    if record["method"] not in METHODS:
        _fail("method")
    for key in ("tool_sha256", "cases_sha256", "before_result_sha256", "after_result_sha256"):
        _digest(record[key])
    count = _integer(record["cases"], 1, 100_000)
    for key in ("before_failures", "after_failures", "mismatches"):
        _integer(record[key], 0, count)
    mutants = _integer(record["mutants"], 0, 10_000)
    _integer(record["killed"], 0, mutants)
    if (record["method"] == "mutation") != (mutants > 0):
        _fail("mutation-count")
    return record


def _refactor(value: dict[str, Any]) -> dict[str, Any]:
    contract = _object(value, "schema_version kind identities scope owner review_sha256 records")
    _identities(contract["identities"])
    if contract["scope"] != "bounded-behavior-agreement":
        _fail("claim")
    if (
        not isinstance(contract["owner"], str)
        or re.fullmatch(r"OWNER-[A-Z0-9]{4,32}", contract["owner"], re.ASCII) is None
    ):
        _fail("owner")
    _digest(contract["review_sha256"])
    if not isinstance(contract["records"], list) or len(contract["records"]) != len(METHODS):
        _fail("records")
    records = [_record(item) for item in contract["records"]]
    if [record["method"] for record in records] != list(METHODS):
        _fail("method-order-or-duplicate")
    findings = []
    for record in records:
        if record["before_failures"] or record["after_failures"]:
            findings.append(record["method"] + ":test-failure")
        if record["mismatches"] or record["before_result_sha256"] != record["after_result_sha256"]:
            findings.append(record["method"] + ":behavior-mismatch")
        if record["killed"] != record["mutants"]:
            findings.append(record["method"] + ":surviving-mutant")
    return {
        "status": "fail" if findings else "pass",
        "scope": contract["scope"],
        "identities": contract["identities"],
        "methods": list(METHODS),
        "findings": sorted(findings),
        "execution": "caller-declared-not-run",
    }


def evaluate(value: Any) -> dict[str, Any]:
    """Validate and evaluate the exact model or refactoring profile."""
    if not isinstance(value, dict):
        _fail("document")
    _integer(value.get("schema_version"), 1, 1)
    kind = value.get("kind")
    if kind not in ("model", "refactor"):
        _fail("kind")
    result = _model(value) if kind == "model" else _refactor(value)
    return {
        **result,
        "schema_version": 1,
        "awq_version": __version__,
        "kind": kind,
        "contract_sha256": hashlib.sha256(canonical_bytes(value)).hexdigest(),
        "limitation": LIMITATION,
    }


def evaluate_file(root: Path, relative: str) -> dict[str, Any]:
    """Read bounded canonical evidence confined beneath a canonical root."""
    if (
        not isinstance(relative, str)
        or len(relative) > 200
        or re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_.-]+)*[.]json", relative) is None
        or any(part in (".", "..") for part in relative.split("/"))
        or root.is_symlink()
    ):
        _fail("path")
    try:
        raw = read_file(root.resolve(strict=True) / relative, MAX_BYTES)
        value = strict_json(raw)
    except (OSError, ValueError, ReleaseError) as error:
        raise ProjectError("assurance contract invalid: unreadable-or-noncanonical") from error
    return evaluate(value)
