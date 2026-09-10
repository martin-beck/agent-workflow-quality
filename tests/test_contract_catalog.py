# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Exhaustive public-contract inventory, evolution and hostile-path tests."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import unittest
from typing import Any, cast

from awq import contracts
from awq.cli import main
from awq.registry import canonical_bytes
from scripts import generate_contract_catalog as generator
from scripts.validate_contracts import validate


class ContractCatalogTests(unittest.TestCase):
    def document(self) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(generator.CATALOG.read_bytes()))

    def test_catalog_is_exhaustive_deterministic_and_schema_valid(self) -> None:
        value = self.document()
        validate(value, "contract-catalog.schema.json")
        entries = contracts.validate_catalog(value)
        discovered = {
            f"schemas/{path.name}"
            for path in generator.ROOT.joinpath("schemas").glob("*.schema.json")
        }
        registered = {item["path"] for item in entries.values() if item["kind"] == "json-schema"}
        self.assertEqual(discovered, registered)
        expected_registries = {f"src/awq/data/{name}.json" for name in generator.REGISTRIES}
        structured = {
            item["path"] for item in entries.values() if item["kind"] == "structured-registry"
        }
        self.assertEqual(expected_registries, structured)
        self.assertEqual(value, generator.build_catalog())
        self.assertEqual(canonical_bytes(value), generator.CATALOG.read_bytes())
        self.assertEqual(generator.render(value), generator.DOCUMENT.read_text(encoding="utf-8"))
        generator._verify_evidence(value)

    def test_closed_shapes_duplicates_missing_evidence_and_command_drift(self) -> None:
        good = self.document()
        mutations: list[object] = [None, {**good, "schema_version": 2}, {**good, "contracts": None}]
        unknown = copy.deepcopy(good)
        unknown["unknown"] = True
        mutations.append(unknown)
        entry_unknown = copy.deepcopy(good)
        entry_unknown["contracts"][0]["unknown"] = True
        mutations.append(entry_unknown)
        duplicate_id = copy.deepcopy(good)
        duplicate_id["contracts"][1]["id"] = duplicate_id["contracts"][0]["id"]
        mutations.append(duplicate_id)
        duplicate_path = copy.deepcopy(good)
        duplicate_path["contracts"][1]["path"] = duplicate_path["contracts"][0]["path"]
        mutations.append(duplicate_path)
        unsafe_path = copy.deepcopy(good)
        unsafe_path["contracts"][0]["path"] = "../private"
        mutations.append(unsafe_path)
        classification = copy.deepcopy(good)
        classification["contracts"][0]["kind"] = "claim"
        mutations.append(classification)
        missing = copy.deepcopy(good)
        missing["contracts"][0]["positive_fixtures"] = []
        mutations.append(missing)
        fixture_shape = copy.deepcopy(good)
        fixture_shape["contracts"][0]["positive_fixtures"][0]["unknown"] = True
        mutations.append(fixture_shape)
        fixture_path = copy.deepcopy(good)
        fixture_path["contracts"][0]["positive_fixtures"][0]["path"] = "/private"
        mutations.append(fixture_path)
        fixture_duplicate = copy.deepcopy(good)
        fixture_duplicate["contracts"][0]["positive_fixtures"] *= 2
        mutations.append(fixture_duplicate)
        version = copy.deepcopy(good)
        version["contracts"][0]["version"] = 99
        mutations.append(version)
        command = copy.deepcopy(good)
        command["contracts"][0]["test_argv"] = ["sh", "-c", "tests"]
        mutations.append(command)
        documentation = copy.deepcopy(good)
        documentation["contracts"][0]["documentation"] = "../README.md"
        mutations.append(documentation)
        conformance = copy.deepcopy(good)
        conformance["contracts"][0]["implementation_conformance"] = ""
        mutations.append(conformance)
        shape_claim = copy.deepcopy(good)
        shape_claim["contracts"][0]["assurance"] = "shape"
        shape_claim["contracts"][0]["limitation"] = "This shape proves all behavior completely."
        mutations.append(shape_claim)
        unordered = copy.deepcopy(good)
        unordered["contracts"].reverse()
        mutations.append(unordered)
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(contracts.ContractCatalogError):
                contracts.validate_catalog(value)
        absent = copy.deepcopy(good)
        absent["contracts"][0]["positive_fixtures"][0]["case"] = "test_missing_case"
        with self.assertRaisesRegex(SystemExit, "missing positive_fixtures evidence"):
            generator._verify_evidence(absent)

    def test_baseline_rejects_drift_duplicates_unknowns_and_incompatible_change(self) -> None:
        catalog = self.document()
        baseline = generator.build_baseline(catalog)
        generator.verify_baseline(catalog, baseline)
        compatible = copy.deepcopy(baseline)
        history = compatible["entries"][0]["history"]
        current = copy.deepcopy(history[0])
        history[0]["sha256"] = "f" * 64
        current["classification"] = "compatible"
        current["reason"] = "Reviewed byte-only canonicalization with unchanged semantics."
        history.append(current)
        generator.verify_baseline(catalog, compatible)
        cases = []
        changed_bytes = copy.deepcopy(baseline)
        changed_bytes["entries"][0]["history"][-1]["sha256"] = "0" * 64
        cases.append(changed_bytes)
        changed_semantics = copy.deepcopy(baseline)
        changed_semantics["entries"][0]["history"][-1]["semantic"]["required"] = [
            "new_required_field"
        ]
        cases.append(changed_semantics)
        duplicate = copy.deepcopy(baseline)
        duplicate["entries"][1]["id"] = duplicate["entries"][0]["id"]
        cases.append(duplicate)
        unknown = copy.deepcopy(baseline)
        unknown["entries"][0]["unknown"] = True
        cases.append(unknown)
        unclassified = copy.deepcopy(baseline)
        unclassified["entries"][0]["history"][-1]["classification"] = "incompatible"
        cases.append(unclassified)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                generator.verify_baseline(catalog, value)

    def test_packaged_catalog_cli_is_content_minimized_and_non_claiming(self) -> None:
        entries, digest = contracts.load_contract_catalog()
        self.assertEqual(len(self.document()["contracts"]), len(entries))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(
                0, main(["--root", str(generator.ROOT), "contract-catalog", "--format", "json"])
            )
        result = json.loads(output.getvalue())
        self.assertEqual(digest, result["catalog_sha256"])
        self.assertIn("not semantic execution evidence", result["limitation"])
        self.assertNotIn(str(generator.ROOT), output.getvalue())

    def test_historical_release_contract_remains_registered_and_executable(self) -> None:
        entries = contracts.validate_catalog(self.document())
        release = entries["AWQ-CONTRACT-RELEASE-MANIFEST-V3"]
        self.assertEqual("tests.test_release.ReleaseVerificationTests", release["test_argv"][3])
        self.assertIn(
            "test_manifest_rejects_shapes_unknowns_duplicates_and_noncanonical_bytes",
            {item["case"] for item in release["hostile_fixtures"]},
        )


if __name__ == "__main__":
    unittest.main()
