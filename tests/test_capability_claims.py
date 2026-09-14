# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

import copy
import unittest
from datetime import UTC, datetime

from awq import capability_claims
from awq.project import ProjectError


class CapabilityClaimsTests(unittest.TestCase):
    def setUp(self):
        self.value, self.digest = capability_claims.load_registry()
        self.now = datetime(2026, 9, 14, tzinfo=UTC)

    def test_registry_is_closed_deterministic_and_evidence_bound(self):
        self.assertEqual(
            self.value, capability_claims.validate_registry(copy.deepcopy(self.value), now=self.now)
        )
        self.assertEqual(self.digest, capability_claims.load_registry()[1])
        self.assertEqual("implemented", self.value["claims"][0]["maturity"])
        self.assertEqual("environment-verified", self.value["claims"][1]["maturity"])

    def test_maturity_evidence_and_claim_inflation_fail_closed(self):
        for mutate in (
            lambda x: x["claims"][0].update(extra=True),
            lambda x: x["claims"][1].update(id="AWQ-CAP-CORE"),
            lambda x: x["claims"][1]["evidence"][0].update({"class": "contract-test"}),
            lambda x: x["claims"][0]["evidence"][0].update(source_commit="f" * 40),
            lambda x: x["claims"][0]["evidence"][0].update(observed_at="2020-01-01T00:00:00Z"),
            lambda x: x["claims"][0].update(supported_surfaces=[]),
        ):
            item = copy.deepcopy(self.value)
            mutate(item)
            with self.assertRaises(ProjectError):
                capability_claims.validate_registry(item, now=self.now)
