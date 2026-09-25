# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Evidence coverage aggregation contract tests."""

import copy
import json
from pathlib import Path

import pytest

from awq import coverage
from awq.project import ProjectError
from scripts.validate_contracts import validate

ROOT = Path(__file__).resolve().parents[1]


def test_coverage_is_deterministic_and_content_minimized() -> None:
    value = json.loads((ROOT / "fixtures/conforming/evidence-coverage.json").read_text())
    validate(value, "evidence-coverage.schema.json")
    first = coverage.evaluate(ROOT, "fixtures/conforming/evidence-coverage.json")
    second = coverage.evaluate(ROOT, "fixtures/conforming/evidence-coverage.json")
    assert first == second
    assert first["records"] == 3
    assert [item["task_id"] for item in first["tasks"]] == ["AR-1001", "AR-1002"]
    assert first["roles"][0]["role"] == "diagnostic"
    assert "evidence_class" not in json.dumps(first)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["records"][0].update(requirement="AWQ-NOT-LOCKED"),
        lambda value: value["records"][0].update(role="owner"),
        lambda value: value["records"].append(copy.deepcopy(value["records"][0])),
    ],
)
def test_coverage_rejects_unlocked_roles_and_duplicate_identity(mutate) -> None:
    value = json.loads((ROOT / "fixtures/conforming/evidence-coverage.json").read_text())
    mutate(value)
    path = ROOT / "fixtures/conforming/evidence-coverage-hostile.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    try:
        with pytest.raises(ProjectError):
            coverage.evaluate(ROOT, path.relative_to(ROOT).as_posix())
    finally:
        path.unlink()
