# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Prove every shipped hostile fixture is rejected by its production check."""

from __future__ import annotations

import unittest
from pathlib import Path

from awq import checks
from tests.support import base_policy

ROOT = Path(__file__).resolve().parents[1]
BROKEN = ROOT / "fixtures" / "broken"


class NegativeFixtureTests(unittest.TestCase):
    def test_hostile_fixture_families_fail(self) -> None:
        cases = [
            ("action-pin", checks.action_pins),
            ("action-pin", checks.workflow_policy),
            ("docs", checks.local_links),
            ("json", checks.json_parse),
            ("python", checks.python_syntax),
            ("privacy", checks.privacy_patterns),
            ("rust", checks.rust_lock),
            ("android", checks.gradle_integrity),
            ("formal", checks.formal_claims),
        ]
        for name, function in cases:
            root = BROKEN / name
            paths = sorted(path for path in root.rglob("*") if path.is_file())
            with self.subTest(name=name, function=function.__name__):
                self.assertTrue(function(root, paths, base_policy()))
