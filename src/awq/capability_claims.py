# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Closed, offline validation for evidence-bound capability claims."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from importlib.resources import files
from typing import Any

from awq.project import ProjectError
from awq.registry import canonical_bytes

MATURITY = (
    "planned",
    "foundation",
    "implemented",
    "integrated",
    "environment-verified",
    "unsupported",
    "deprecated",
)
EVIDENCE = ("mechanical", "contract-test", "property-or-fuzz", "bounded-model", "environmental")
SURFACES = ("cli", "python-api", "schema", "release", "native-gate", "documentation")
_ID = re.compile(r"^AWQ-CAP-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_TIME = re.compile(r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


def _fail(code: str) -> None:
    raise ProjectError("capability claims invalid: " + code)


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        _fail("timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail("timestamp")
    if result.tzinfo != UTC:
        _fail("timestamp")
    return result


def _source(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"repository", "commit", "tree"}:
        _fail("source")
    if not all(isinstance(value[k], str) and value[k] for k in value):
        _fail("source")
    if _COMMIT.fullmatch(value["commit"]) is None or _HASH.fullmatch(value["tree"]) is None:
        _fail("source")
    if "/" not in value["repository"] or value["repository"].startswith(("http", "/")):
        _fail("source")
    return dict(value)


def validate_registry(value: Any, *, now: datetime | None = None) -> dict[str, Any]:  # noqa: C901
    """Validate claims and cross-field evidence obligations without executing tools."""
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "claims"}
        or value["schema_version"] != 1
    ):
        _fail("fields")
    claims = value["claims"]
    if not isinstance(claims, list) or not claims or len(claims) > 128:
        _fail("claims")
    now = now or datetime.now(UTC)
    seen: set[str] = set()
    for claim in claims:
        required = {
            "id",
            "maturity",
            "source_scope",
            "supported_surfaces",
            "owner",
            "limitations",
            "review",
            "evidence",
        }
        if not isinstance(claim, dict) or set(claim) != required:
            _fail("claim-fields")
        ident = claim["id"]
        if not isinstance(ident, str) or _ID.fullmatch(ident) is None or ident in seen:
            _fail("claim-id")
        seen.add(ident)
        maturity = claim["maturity"]
        if maturity not in MATURITY:
            _fail("maturity")
        source = _source(claim["source_scope"])
        surfaces = claim["supported_surfaces"]
        if (
            not isinstance(surfaces, list)
            or surfaces != sorted(set(surfaces))
            or not surfaces
            or not set(surfaces) <= set(SURFACES)
        ):
            _fail("surfaces")
        if not isinstance(claim["owner"], str) or not re.fullmatch(
            r"[a-z0-9]+(?:-[a-z0-9]+)*", claim["owner"]
        ):
            _fail("owner")
        limitations = claim["limitations"]
        if (
            not isinstance(limitations, list)
            or not limitations
            or any(not isinstance(x, str) or not 10 <= len(x) <= 300 for x in limitations)
        ):
            _fail("limitations")
        review = claim["review"]
        if (
            not isinstance(review, dict)
            or set(review) != {"id", "reviewed_at", "reviewer"}
            or not re.fullmatch(r"REVIEW-[A-Z0-9-]+", str(review.get("id", "")))
        ):
            _fail("review")
        _timestamp(review.get("reviewed_at"))
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", str(review.get("reviewer", ""))):
            _fail("review")
        evidence = claim["evidence"]
        if not isinstance(evidence, list) or not evidence:
            _fail("evidence")
        for item in evidence:
            if not isinstance(item, dict) or set(item) != {
                "id",
                "class",
                "digest",
                "observed_at",
                "freshness_seconds",
                "source_commit",
            }:
                _fail("evidence-fields")
            if not isinstance(item["id"], str) or not re.fullmatch(
                r"EVIDENCE-[A-Z0-9-]+", item["id"]
            ):
                _fail("evidence-id")
            if (
                item["class"] not in EVIDENCE
                or _HASH.fullmatch(str(item["digest"])) is None
                or _COMMIT.fullmatch(str(item["source_commit"])) is None
            ):
                _fail("evidence-values")
            observed = _timestamp(item["observed_at"])
            if (
                item["source_commit"] != source["commit"]
                or not isinstance(item["freshness_seconds"], int)
                or not 1 <= item["freshness_seconds"] <= 31_536_000
            ):
                _fail("evidence-binding")
            if (now - observed).total_seconds() > item["freshness_seconds"]:
                _fail("stale-evidence")
        if maturity == "environment-verified" and not any(
            x["class"] == "environmental" for x in evidence
        ):
            _fail("environment-evidence")
        if maturity in ("unsupported", "deprecated") and not any(
            any(word in x.casefold() for word in ("rationale", "unsupported", "deprecated"))
            for x in limitations
        ):
            _fail("nonclaim-rationale")
    return dict(value)


def load_registry() -> tuple[dict[str, Any], str]:
    raw = files("awq.data").joinpath("capability_claims.json").read_bytes()
    value = json.loads(raw)
    validate_registry(value)
    return value, hashlib.sha256(canonical_bytes(value)).hexdigest()
