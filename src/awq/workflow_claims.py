# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT
"""Closed, offline validation for workflow and optional visual evidence claims."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, cast

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


def _fail(code: str) -> None:
    raise ProjectError("workflow claims invalid: " + code)


def _digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        _fail(code)
    return cast(str, value)


def _source(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"path", "commit", "sha256", "generated"}:
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
    if not isinstance(value["generated"], bool):
        _fail("source")
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
    for source in sources:
        item = _source(source)
        ident = item.get("path")
        if not isinstance(ident, str) or ident in source_ids:
            _fail("duplicate-source")
        source_ids.add(cast(str, ident))
    claims = value["claims"]
    if not isinstance(claims, list) or not claims or len(claims) > 128:
        _fail("claims")
    seen: set[str] = set()
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
        if claim["stage"] not in _STAGES or claim["maturity"] not in _MATURITY:
            _fail("claim-values")
        if not isinstance(claim["statement"], str) or not 1 <= len(claim["statement"]) <= 300:
            _fail("statement")
        authority = claim["authority"]
        if not isinstance(authority, str) or authority not in source_ids:
            _fail("authority")
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
            if claim["maturity"] == "planned" and item["maturity"] not in (
                "planned",
                "contract-tested",
            ):
                _fail("planned-evidence")
        limitations = claim["limitations"]
        if (
            not isinstance(limitations, list)
            or not limitations
            or any(not isinstance(x, str) or len(x) < 10 for x in limitations)
        ):
            _fail("limitations")
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
            or not isinstance(asset["reviewed"], bool)
        ):
            _fail("asset-values")
    return dict(value)


def load_registry() -> tuple[dict[str, Any], str]:
    path = Path(__file__).with_name("data") / "workflow_claims.json"
    value = json.loads(path.read_bytes())
    validate(value)
    return value, hashlib.sha256(canonical_bytes(value)).hexdigest()
