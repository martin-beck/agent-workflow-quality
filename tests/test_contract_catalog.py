# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Exhaustive public-contract inventory, evolution and hostile-path tests."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

import jsonschema

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
        non_ascii_documentation = copy.deepcopy(good)
        non_ascii_documentation["contracts"][0]["documentation"] = "docs/boom-💥.md"
        mutations.append(non_ascii_documentation)
        short_limitation = copy.deepcopy(good)
        short_limitation["contracts"][0]["limitation"] = "too short"
        mutations.append(short_limitation)
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

    def test_runtime_and_schema_reject_the_same_path_and_limitation_shapes(self) -> None:
        good = self.document()
        candidates = []
        for field, replacement in (
            ("documentation", "docs/boom-💥.md"),
            ("limitation", "too short"),
        ):
            candidate = copy.deepcopy(good)
            candidate["contracts"][0][field] = replacement
            candidates.append(candidate)
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                with self.assertRaises(jsonschema.ValidationError):
                    validate(candidate, "contract-catalog.schema.json")
                with self.assertRaises(contracts.ContractCatalogError):
                    contracts.validate_catalog(candidate)

    def test_evidence_resolves_exact_conformance_and_unittest_classes(self) -> None:
        good = self.document()
        missing_conformance = copy.deepcopy(good)
        missing_conformance["contracts"][0]["implementation_conformance"] = (
            "awq.tests.missing.NoSuchHandler"
        )
        missing_class = copy.deepcopy(good)
        missing_class["contracts"][0]["test_argv"][3] = "tests.test_adapters.NoSuchClass"
        matching_missing_class = copy.deepcopy(good)
        matching_missing_class["contracts"][0]["implementation_conformance"] = (
            "awq.tests.adapters.NoSuchClass"
        )
        matching_missing_class["contracts"][0]["test_argv"][3] = "tests.test_adapters.NoSuchClass"
        for candidate in (missing_conformance, missing_class, matching_missing_class):
            with self.subTest(candidate=candidate), self.assertRaises(SystemExit):
                generator._verify_evidence(candidate)

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
        registry = next(
            item["history"][0]["semantic"]
            for item in baseline["entries"]
            if item["history"][0]["semantic"]["kind"] == "structured-registry"
        )
        registry_update = copy.deepcopy(registry)
        registry_update["canonical_document_sha256"] = "e" * 64
        self.assertTrue(generator._compatible_semantics(registry, registry_update))
        registry_update["keys"].append("new-root-key")
        self.assertFalse(generator._compatible_semantics(registry, registry_update))
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

    def test_semantic_fingerprint_covers_nested_schema_constraints(self) -> None:
        first: dict[str, Any] = {
            "$id": "https://example.invalid/schema.json",
            "type": "object",
            "properties": {"schema_version": {"const": 1}},
        }
        changed = copy.deepcopy(first)
        changed["properties"]["schema_version"]["const"] = 2
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested.schema.json"
            path.write_text(json.dumps(first), encoding="utf-8")
            initial = generator._semantic(path)
            path.write_text(json.dumps(changed), encoding="utf-8")
            self.assertNotEqual(initial, generator._semantic(path))
            path.write_text(json.dumps(first, indent=2), encoding="utf-8")
            self.assertEqual(initial, generator._semantic(path))

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
