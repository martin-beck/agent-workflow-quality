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
        )
        for mutation in mutations:
            value = copy.deepcopy(self.value)
            mutation(value)
            with self.assertRaises(ProjectError):
                workflow_claims.validate(value)
