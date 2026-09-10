# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Check the bounded baseline and reviewed known-bad counterexample fixtures offline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from awq import assurance, lifecycle_model
from awq.project import ProjectError
from awq.sbom import strict_json
from awq.trust import read_file

ROOT = Path(__file__).resolve().parents[1]


def check(root: Path) -> dict[str, Any]:
    """Require full exploration plus each exact reviewed counterexample."""
    baseline = assurance.evaluate_file(root, "fixtures/conforming/assurance/model.json")
    observed: dict[str, Any] = {
        "model": baseline["model"],
        "baseline": {
            key: baseline[key] for key in ("status", "outcome", "states", "transitions", "bounds")
        },
        "mutations": {},
    }
    for mutation in ("stale-review", "expired-review", "self-review"):
        result = assurance.evaluate_file(
            root, "fixtures/nonconforming/assurance/" + mutation + ".json"
        )
        observed["mutations"][mutation] = {
            key: result[key]
            for key in ("status", "outcome", "counterexample", "violated_invariants")
        }
    expected = strict_json(read_file(root / "formal/counterexamples.json"))
    lifecycle = check_lifecycle(root)
    correspondence = check_refinement(root)
    return {
        "status": "pass"
        if observed == expected
        and lifecycle["status"] == "pass"
        and correspondence["status"] == "pass"
        else "fail",
        "lifecycle": lifecycle,
        "correspondence": correspondence,
        "model": baseline["model"],
        "states": baseline["states"],
        "transitions": baseline["transitions"],
        "known_bad_mutations": 3,
        "refinement": "not-proven",
    }


def check_lifecycle(root: Path) -> dict[str, Any]:
    baseline = assurance.evaluate_file(root, "fixtures/conforming/lifecycle/model.json")
    observed: dict[str, Any] = {
        "model": baseline["model"],
        "bounds": baseline["bounds"],
        "baseline": baseline["components"],
        "mutations": {},
    }
    for mutation in lifecycle_model.MUTATIONS[1:]:
        result = assurance.evaluate_file(
            root, "fixtures/nonconforming/lifecycle/" + mutation + ".json"
        )
        observed["mutations"][mutation] = result["components"]
    expected = strict_json(read_file(root / "formal/lifecycle-counterexamples.json"))
    return {
        "status": "pass" if observed == expected else "fail",
        "components": baseline["components"],
        "known_bad_mutations": 10,
        "composition": "not-proven",
        "refinement": "not-proven",
    }


def check_refinement(root: Path) -> dict[str, Any]:
    """Require reviewed positive correspondence and each hostile rejection."""
    positive = assurance.evaluate_file(root, "fixtures/conforming/refinement/map.json")
    template = assurance.evaluate_file(root, "templates/refinement-map.json")
    bad = assurance.evaluate_file(
        root, "fixtures/nonconforming/refinement/contradictory-trace.json"
    )
    rejected = 0
    for name in ("missing-map", "out-of-bound"):
        try:
            assurance.evaluate_file(root, "fixtures/nonconforming/refinement/" + name + ".json")
        except ProjectError:
            rejected += 1
    passed = (
        positive == template
        and positive["status"] == "pass"
        and positive["traces"] == 4
        and positive["transitions"] == 7
        and bad["status"] == "fail"
        and bad["findings"] == ["state-projection", "transition-simulation"]
        and rejected == 2
    )
    return {
        "status": "pass" if passed else "fail",
        "negative_fixtures": 3,
        "refinement": "not-proven",
        "execution": "caller-declared-not-run",
    }


def main() -> int:
    result = check(ROOT)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
