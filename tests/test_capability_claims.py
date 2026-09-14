# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

import copy
import unittest
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import awq.capability_claims as capability_claims
from awq.project import ProjectError


class CapabilityClaimsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value, self.digest = capability_claims.load_registry()
        self.now = datetime(2026, 9, 14, tzinfo=UTC)

    def test_registry_is_closed_deterministic_and_evidence_bound(self) -> None:
        self.assertEqual(
            self.value, capability_claims.validate_registry(copy.deepcopy(self.value), now=self.now)
        )
        self.assertEqual(self.digest, capability_claims.load_registry()[1])
        self.assertEqual("implemented", self.value["claims"][0]["maturity"])
        self.assertEqual("environment-verified", self.value["claims"][1]["maturity"])

    def test_maturity_evidence_and_claim_inflation_fail_closed(self) -> None:
        mutations: tuple[Callable[[Any], Any], ...] = (
            lambda x: x["claims"][0].update(extra=True),
            lambda x: x["claims"][1].update(id="AWQ-CAP-CORE"),
            lambda x: x["claims"][1]["evidence"][0].update({"class": "contract-test"}),
            lambda x: x["claims"][0]["evidence"][0].update(source_commit="f" * 40),
            lambda x: x["claims"][0]["evidence"][0].update(observed_at="2020-01-01T00:00:00Z"),
            lambda x: x["claims"][0].update(supported_surfaces=[]),
            lambda x: x["claims"][0]["source_scope"].update(path="../private.json"),
            lambda x: x["claims"][0]["evidence"][0].update(origin="synthetic"),
            lambda x: x["claims"][0]["transition"].update(reviewed=False),
            lambda x: x["claims"][0]["transition"].update({"from": "planned"}),
        )
        for mutate in mutations:
            item = copy.deepcopy(self.value)
            mutate(item)
            with self.assertRaises(ProjectError):
                capability_claims.validate_registry(item, now=self.now)

    def test_incremental_maturity_and_nonclaims_are_explicit(self) -> None:
        planned = self.value["claims"][2]
        self.assertEqual(
            ("none", "planned"), (planned["transition"]["from"], planned["transition"]["to"])
        )
        self.assertEqual("synthetic", planned["evidence"][0]["origin"])
        item = copy.deepcopy(self.value)
        item["claims"][0]["maturity"] = "integrated"
        item["claims"][0]["transition"]["to"] = "integrated"
        item["claims"][0]["supported_surfaces"] = ["documentation"]
        with self.assertRaises(ProjectError):
            capability_claims.validate_registry(item, now=self.now)
