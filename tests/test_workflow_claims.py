# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT
import copy
import unittest
from collections.abc import Callable
from typing import Any

from awq import workflow_claims
from awq.project import ProjectError


class WorkflowClaimsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value, self.digest = workflow_claims.load_registry()

    def test_valid(self) -> None:
        self.assertEqual(self.value, workflow_claims.validate(copy.deepcopy(self.value)))
        self.assertEqual(self.digest, workflow_claims.load_registry()[1])

    def test_hostile_claims_and_assets_fail_closed(self) -> None:
        mutations: tuple[Callable[[Any], Any], ...] = (
            lambda x: x["claims"][0].update(authority="missing"),
            lambda x: x["claims"][0].update(extra=True),
            lambda x: x["sources"][0].update(path="../private"),
            lambda x: x["claims"][0]["evidence"][0].update(digest="bad"),
            lambda x: x["visual_assets"].append({"id": "ASSET-X"}),
            lambda x: x["claims"].reverse(),
            lambda x: x["claims"][0].update(semantic_tests=[]),
            lambda x: x["claims"][0].update(visual_asset_ids=["ASSET-ORPHAN"]),
            lambda x: x["sources"][1].update(
                kind="authored",
                derived_from=None,
                generator_sha256=None,
                claim_ids=[x["claims"][0]["id"]],
            ),
        )
        for mutation in mutations:
            value = copy.deepcopy(self.value)
            mutation(value)
            with self.assertRaises(ProjectError):
                workflow_claims.validate(value)

    def test_visual_evidence_is_revision_bound_and_deterministic(self) -> None:
        value = copy.deepcopy(self.value)
        asset = value["visual_assets"][0]
        mutations: tuple[Callable[[Any], Any], ...] = (
            lambda x: x.update(accessibility="short"),
            lambda x: x["capture"].update(source_revision="f" * 40),
            lambda x: x["capture"].update(current_source_revision="e" * 40),
            lambda x: x["capture"].update(reviewed_at="2026-01-01T00:00:00Z"),
            lambda x: x["consumer_dimensions"].update(locale=""),
            lambda x: x["baseline"].update(matches=False),
        )
        for mutation in mutations:
            changed = copy.deepcopy(asset)
            mutation(changed)
            value["visual_assets"][0] = changed
            with self.assertRaises(ProjectError):
                workflow_claims.validate(value)

    def test_planned_claim_cannot_use_visual_evidence(self) -> None:
        value = copy.deepcopy(self.value)
        value["claims"][0]["maturity"] = "planned"
        value["claims"][0]["evidence"][0]["maturity"] = "planned"
        value["claims"][0]["visual_asset_ids"] = ["ASSET-WORKFLOW"]
        value["visual_assets"][0]["claim_id"] = value["claims"][0]["id"]
        with self.assertRaisesRegex(ProjectError, "planned-visual"):
            workflow_claims.validate(value)
