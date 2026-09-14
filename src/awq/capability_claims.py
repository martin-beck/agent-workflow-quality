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
ORIGINS = ("live", "synthetic")
_MATURITY_ORDER = ("planned", "foundation", "implemented", "integrated", "environment-verified")
_ID = re.compile(r"^AWQ-CAP-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_TREE = re.compile(r"^[0-9a-f]{40}$")
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
    if not isinstance(value, dict) or set(value) != {"repository", "path", "commit", "tree"}:
        _fail("source")
    if not all(isinstance(value[k], str) and value[k] for k in value):
        _fail("source")
    if _COMMIT.fullmatch(value["commit"]) is None or _TREE.fullmatch(value["tree"]) is None:
        _fail("source")
    if "/" not in value["repository"] or value["repository"].startswith(("http", "/")):
        _fail("source")
    if (
        not isinstance(value["path"], str)
        or not value["path"]
        or value["path"].startswith(("/", "~"))
        or ".." in value["path"].split("/")
        or "\\" in value["path"]
        or "//" in value["path"]
    ):
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
            "transition",
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
        transition = claim["transition"]
        if (
            not isinstance(transition, dict)
            or set(transition) != {"from", "to", "reviewed"}
            or transition["from"] not in ("none", *MATURITY)
            or transition["to"] != maturity
            or transition["reviewed"] is not True
            or (transition["from"] == maturity and maturity not in ("planned", "foundation"))
            or (
                transition["from"] == "none"
                and maturity not in ("planned", "foundation", "unsupported", "deprecated")
            )
            or (
                transition["from"] in _MATURITY_ORDER
                and maturity in _MATURITY_ORDER
                and _MATURITY_ORDER.index(maturity) != _MATURITY_ORDER.index(transition["from"]) + 1
            )
        ):
            _fail("transition")
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
        if not isinstance(evidence, list) or not evidence or len(evidence) > 32:
            _fail("evidence")
        evidence_ids: set[str] = set()
        for item in evidence:
            if not isinstance(item, dict) or set(item) != {
                "id",
                "class",
                "digest",
                "observed_at",
                "freshness_seconds",
                "source_commit",
                "origin",
            }:
                _fail("evidence-fields")
            if (
                not isinstance(item["id"], str)
                or not re.fullmatch(r"EVIDENCE-[A-Z0-9-]+", item["id"])
                or item["id"] in evidence_ids
            ):
                _fail("evidence-id")
            evidence_ids.add(item["id"])
            if (
                item["class"] not in EVIDENCE
                or _HASH.fullmatch(str(item["digest"])) is None
                or _COMMIT.fullmatch(str(item["source_commit"])) is None
            ):
                _fail("evidence-values")
            if item["origin"] not in ORIGINS or (
                item["origin"] == "synthetic" and maturity not in ("planned", "foundation")
            ):
                _fail("evidence-origin")
            observed = _timestamp(item["observed_at"])
            if (
                item["source_commit"] != source["commit"]
                or isinstance(item["freshness_seconds"], bool)
                or not isinstance(item["freshness_seconds"], int)
                or not 1 <= item["freshness_seconds"] <= 31_536_000
            ):
                _fail("evidence-binding")
            if observed > now:
                _fail("future-evidence")
            if (now - observed).total_seconds() > item["freshness_seconds"]:
                _fail("stale-evidence")
        if maturity == "environment-verified" and not any(
            x["class"] == "environmental" for x in evidence
        ):
            _fail("environment-evidence")
        if maturity == "environment-verified" and "native-gate" not in surfaces:
            _fail("environment-surface")
        if maturity == "integrated" and not {"cli", "python-api"} & set(surfaces):
            _fail("integration-surface")
        if maturity in ("unsupported", "deprecated") and not any(
            any(word in x.casefold() for word in ("rationale", "unsupported", "deprecated"))
            for x in limitations
        ):
            _fail("nonclaim-rationale")
    return dict(value)


def load_registry() -> tuple[dict[str, Any], str]:
    raw = files("awq.data").joinpath("capability_claims.json").read_bytes()

    def reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, val in pairs:
            if key in result:
                raise ProjectError("capability claims invalid: duplicate key")
            result[key] = val
        return result

    value = json.loads(raw, object_pairs_hook=reject_pairs)
    validate_registry(value)
    return value, hashlib.sha256(canonical_bytes(value)).hexdigest()
