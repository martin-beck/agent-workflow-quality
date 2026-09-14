# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT
"""Closed, offline validation for workflow and optional visual evidence claims."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn, cast

from awq.project import ProjectError
from awq.registry import canonical_bytes

_ID = re.compile(r"^AWQ-WF-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_STAGES = (
    "goal",
    "preconditions",
    "automatic-actions",
    "human-decisions",
    "outcomes",
    "failures",
    "recovery",
)
_MATURITY = ("planned", "contract-tested", "environment-verified", "human-reviewed")
_SOURCE_KINDS = ("authored", "generated", "derived", "superseded")


def _fail(code: str) -> NoReturn:
    raise ProjectError("workflow claims invalid: " + code)


def _digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        _fail(code)
    return value


def _strings(value: Any, code: str, *, allow_empty: bool = False) -> list[str]:
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or len(value) > 128
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        _fail(code)
    return cast(list[str], value)


def _timestamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail(code)
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail(code)


def _validate_source_kind(value: dict[str, Any]) -> None:
    derived_from = value["derived_from"]
    generator = value["generator_sha256"]
    if value["kind"] == "authored":
        if derived_from is not None or generator is not None:
            _fail("authored-source")
    elif value["kind"] == "generated":
        if not isinstance(derived_from, str):
            _fail("generated-source")
        _digest(generator, "generator-digest")
    elif value["kind"] == "derived":
        if not isinstance(derived_from, str) or generator is not None:
            _fail("derived-source")
    elif value["claim_ids"] or not isinstance(derived_from, str) or generator is not None:
        _fail("superseded-source")


def _source(value: Any) -> dict[str, Any]:
    required = {
        "path",
        "commit",
        "sha256",
        "kind",
        "claim_ids",
        "derived_from",
        "generator_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        _fail("source")
    if (
        not isinstance(value["path"], str)
        or value["path"].startswith(("/", "~"))
        or ".." in value["path"].split("/")
    ):
        _fail("source")
    if not isinstance(value["commit"], str) or _COMMIT.fullmatch(value["commit"]) is None:
        _fail("source")
    _digest(value["sha256"], "source")
    if value["kind"] not in _SOURCE_KINDS:
        _fail("source-kind")
    _strings(value["claim_ids"], "source-claims", allow_empty=value["kind"] == "superseded")
    _validate_source_kind(value)
    return dict(value)


def validate(value: Any) -> dict[str, Any]:  # noqa: C901
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "claims", "sources", "visual_assets"}
        or value["schema_version"] != 1
    ):
        _fail("fields")
    sources = value["sources"]
    if not isinstance(sources, list) or not sources or len(sources) > 128:
        _fail("sources")
    source_ids: set[str] = set()
    source_values: dict[str, dict[str, Any]] = {}
    for source in sources:
        item = _source(source)
        ident = item.get("path")
        if not isinstance(ident, str) or ident in source_ids:
            _fail("duplicate-source")
        source_ids.add(ident)
        source_values[ident] = item
    for source in source_values.values():
        derived_from = source["derived_from"]
        if derived_from is not None and (
            derived_from not in source_ids or derived_from == source["path"]
        ):
            _fail("source-lineage")
    claims = value["claims"]
    if not isinstance(claims, list) or not claims or len(claims) > 128:
        _fail("claims")
    seen: set[str] = set()
    stages: list[str] = []
    claim_values: dict[str, dict[str, Any]] = {}
    for claim in claims:
        required = {
            "id",
            "stage",
            "maturity",
            "statement",
            "authority",
            "semantic_tests",
            "evidence",
            "limitations",
            "visual_asset_ids",
        }
        if not isinstance(claim, dict) or set(claim) != required:
            _fail("claim-fields")
        if (
            not isinstance(claim["id"], str)
            or _ID.fullmatch(claim["id"]) is None
            or claim["id"] in seen
        ):
            _fail("claim-id")
        seen.add(claim["id"])
        claim_values[claim["id"]] = claim
        if claim["stage"] not in _STAGES or claim["maturity"] not in _MATURITY:
            _fail("claim-values")
        stages.append(claim["stage"])
        if not isinstance(claim["statement"], str) or not 1 <= len(claim["statement"]) <= 300:
            _fail("statement")
        authority = claim["authority"]
        if not isinstance(authority, str) or authority not in source_ids:
            _fail("authority")
        if source_values[authority]["kind"] != "authored":
            _fail("authority-kind")
        tests = claim["semantic_tests"]
        if (
            not isinstance(tests, list)
            or not tests
            or any(not isinstance(x, str) or not x for x in tests)
        ):
            _fail("semantic-tests")
        evidence = claim["evidence"]
        if not isinstance(evidence, list) or not evidence or len(evidence) > 32:
            _fail("evidence")
        for item in evidence:
            if not isinstance(item, dict) or set(item) != {"id", "maturity", "digest", "source"}:
                _fail("evidence-fields")
            if (
                not isinstance(item["id"], str)
                or not item["id"].startswith("EVIDENCE-")
                or item["maturity"] not in _MATURITY
            ):
                _fail("evidence-values")
            _digest(item["digest"], "evidence-digest")
            if item["source"] not in source_ids:
                _fail("evidence-source")
            if claim["maturity"] == "planned" and item["maturity"] not in ("planned",):
                _fail("planned-evidence")
            if _MATURITY.index(item["maturity"]) > _MATURITY.index(claim["maturity"]):
                _fail("evidence-maturity")
        limitations = claim["limitations"]
        if (
            not isinstance(limitations, list)
            or not limitations
            or any(not isinstance(x, str) or len(x) < 10 for x in limitations)
        ):
            _fail("limitations")
        asset_refs = _strings(claim["visual_asset_ids"], "claim-assets", allow_empty=True)
        if claim["maturity"] == "planned" and asset_refs:
            _fail("planned-visual")
    if stages != list(_STAGES):
        _fail("stage-order")
    for source in source_values.values():
        for claim_id in source["claim_ids"]:
            if claim_id not in seen:
                _fail("source-claim")
    for claim_id, claim in claim_values.items():
        authorities = [
            source["path"]
            for source in source_values.values()
            if source["kind"] == "authored" and claim_id in source["claim_ids"]
        ]
        if authorities != [claim["authority"]]:
            _fail("contradictory-authority")
    assets = value["visual_assets"]
    if not isinstance(assets, list) or len(assets) > 128:
        _fail("visual-assets")
    asset_ids: set[str] = set()
    for asset in assets:
        required = {
            "id",
            "path",
            "sha256",
            "width",
            "height",
            "format",
            "accessibility",
            "source",
            "reviewed",
            "claim_id",
            "capture",
            "consumer_dimensions",
            "baseline",
        }
        if not isinstance(asset, dict) or set(asset) != required:
            _fail("asset-fields")
        if (
            not isinstance(asset["id"], str)
            or not asset["id"].startswith("ASSET-")
            or asset["id"] in asset_ids
        ):
            _fail("asset-id")
        asset_ids.add(asset["id"])
        if asset["claim_id"] not in seen:
            _fail("asset-claim")
        if (
            not isinstance(asset["path"], str)
            or asset["path"].startswith(("/", "~"))
            or ".." in asset["path"].split("/")
        ):
            _fail("asset-path")
        _digest(asset["sha256"], "asset-digest")
        if (
            not isinstance(asset["width"], int)
            or isinstance(asset["width"], bool)
            or not 1 <= asset["width"] <= 10000
        ):
            _fail("asset-dimensions")
        if (
            not isinstance(asset["height"], int)
            or isinstance(asset["height"], bool)
            or not 1 <= asset["height"] <= 10000
        ):
            _fail("asset-dimensions")
        if (
            asset["format"] not in ("png", "jpeg", "webp", "svg")
            or not isinstance(asset["accessibility"], str)
            or len(asset["accessibility"]) < 10
            or asset["source"] not in source_ids
            or asset["reviewed"] is not True
        ):
            _fail("asset-values")
        capture = asset["capture"]
        if not isinstance(capture, dict) or set(capture) != {
            "source_revision",
            "current_source_revision",
            "environment_class",
            "captured_at",
            "reviewed_at",
        }:
            _fail("capture-fields")
        if (
            not isinstance(capture["source_revision"], str)
            or _COMMIT.fullmatch(capture["source_revision"]) is None
            or capture["source_revision"] != capture["current_source_revision"]
            or capture["source_revision"] != source_values[asset["source"]]["commit"]
            or capture["environment_class"] not in ("consumer-controlled", "reviewed-lab")
            or _timestamp(capture["captured_at"], "capture-time")
            > _timestamp(capture["reviewed_at"], "review-time")
        ):
            _fail("stale-capture")
        dimensions = asset["consumer_dimensions"]
        if not isinstance(dimensions, dict) or set(dimensions) != {
            "api",
            "abi",
            "form_factor",
            "locale",
            "font_scale",
        }:
            _fail("consumer-dimensions")
        for key in ("api", "abi", "form_factor", "locale", "font_scale"):
            if not isinstance(dimensions[key], str) or not dimensions[key]:
                _fail("consumer-dimensions")
        baseline = asset["baseline"]
        if baseline is not None:
            if not isinstance(baseline, dict) or set(baseline) != {
                "sha256",
                "comparison",
                "matches",
            }:
                _fail("baseline-fields")
            _digest(baseline["sha256"], "baseline-digest")
            expected = baseline["sha256"] == asset["sha256"]
            if baseline["comparison"] != "sha256-equality" or baseline["matches"] is not expected:
                _fail("baseline-comparison")
    referenced_assets = {
        asset_id for claim in claim_values.values() for asset_id in claim["visual_asset_ids"]
    }
    if referenced_assets != asset_ids:
        _fail("orphaned-assets")
    for asset in assets:
        if asset["id"] not in claim_values[asset["claim_id"]]["visual_asset_ids"]:
            _fail("asset-link")
    return dict(value)


def load_registry() -> tuple[dict[str, Any], str]:
    path = Path(__file__).with_name("data") / "workflow_claims.json"
    value = json.loads(path.read_bytes())
    validate(value)
    return value, hashlib.sha256(canonical_bytes(value)).hexdigest()
