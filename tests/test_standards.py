# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Standards catalogue, mapping and generated-document contracts."""

from __future__ import annotations

import copy
import unittest
from unittest import mock

from awq import registry
from awq.registry import RegistryError
from scripts.generate_catalog import render_standards


class StandardsRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.requirements, _, _ = registry.load_registry()
        self.sources, self.mappings, self.digest = registry.load_standards()

    def test_catalogue_is_pinned_complete_and_stable(self) -> None:
        self.assertEqual(
            {
                "COMMONMARK",
                "IETF-RFC8259",
                "NIST-SSDF",
                "OPENSSF-OSPS",
                "POSIX-SHELL",
                "PYTHON-REFERENCE",
                "SLSA",
                "SPDX",
            },
            set(self.sources),
        )
        self.assertEqual(18, len(self.mappings))
        self.assertEqual(64, len(self.digest))
        self.assertEqual(
            set(self.requirements),
            {mapping["requirement"] for mapping in self.mappings.values()},
        )
        self.assertEqual([], registry.standards_drift(self.sources, self.mappings))

    def test_source_shape_versions_controls_and_urls_fail_closed(self) -> None:
        source = copy.deepcopy(next(iter(self.sources.values())))
        invalid = [
            {**source, "extra": True},
            {**source, "edition": "latest"},
            {**source, "edition": "CURRENT"},
            {**source, "source_url": "http://example.invalid"},
            {**source, "controls": []},
            {**source, "controls": [{}]},
            {
                **source,
                "controls": [
                    source["controls"][0],
                    copy.deepcopy(source["controls"][0]),
                ],
            },
            {
                **source,
                "controls": [{**source["controls"][0], "url": "http://example.invalid"}],
            },
        ]
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(RegistryError):
                registry._validated_sources([item])
        with self.assertRaisesRegex(RegistryError, "unique"):
            registry._validated_sources([source, copy.deepcopy(source)])

    def test_mapping_references_editions_and_claims_fail_closed(self) -> None:
        mapping = copy.deepcopy(next(iter(self.mappings.values())))
        invalid = [
            {**mapping, "extra": True},
            {**mapping, "requirement": "AWQ-NOPE-999"},
            {**mapping, "source": "UNKNOWN"},
            {**mapping, "edition": "stale"},
            {**mapping, "control": "removed-control"},
            {**mapping, "relationship": "certifies"},
            {**mapping, "evidence": "proof"},
            {**mapping, "claim": "certified"},
        ]
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(RegistryError):
                registry._validated_mappings([item], self.requirements, self.sources)
        with self.assertRaisesRegex(RegistryError, "unique"):
            registry._validated_mappings(
                [mapping, copy.deepcopy(mapping)], self.requirements, self.sources
            )

    def test_drift_report_is_deterministic_without_weakening_validation(self) -> None:
        mapping = copy.deepcopy(next(iter(self.mappings.values())))
        mapping["edition"] = "superseded"
        drift = registry.standards_drift(self.sources, {mapping["id"]: mapping})
        self.assertEqual(mapping["id"], drift[0]["mapping"])
        self.assertEqual("superseded", drift[0]["mapped_edition"])
        with self.assertRaisesRegex(RegistryError, "stale edition"):
            registry._validated_mappings([mapping], self.requirements, self.sources)

    def test_load_rejects_document_shapes_versions_and_unmapped_requirements(self) -> None:
        valid_source_doc = {"schema_version": 1, "sources": list(self.sources.values())}
        valid_mapping_doc = {"schema_version": 1, "mappings": list(self.mappings.values())}
        cases = [
            ({}, valid_mapping_doc, "control source registry"),
            (valid_source_doc, {}, "standards mapping registry"),
            (
                {**valid_source_doc, "schema_version": 2},
                valid_mapping_doc,
                "unsupported standards",
            ),
            (
                valid_source_doc,
                {**valid_mapping_doc, "schema_version": 2},
                "unsupported standards",
            ),
            (
                valid_source_doc,
                {
                    "schema_version": 1,
                    "mappings": [
                        item
                        for item in self.mappings.values()
                        if item["requirement"] != "AWQ-CORE-001"
                    ],
                },
                "without standards traceability",
            ),
        ]
        for source_doc, mapping_doc, message in cases:
            with (
                self.subTest(message=message),
                mock.patch(
                    "awq.registry.load_registry",
                    return_value=(self.requirements, {}, "0" * 64),
                ),
                mock.patch("awq.registry._read", side_effect=[source_doc, mapping_doc]),
                self.assertRaisesRegex(RegistryError, message),
            ):
                registry.load_standards()

    def test_generated_catalogue_has_profiles_gaps_and_non_claim(self) -> None:
        first = render_standards()
        self.assertEqual(first, render_standards())
        self.assertIn("## Profile matrices", first)
        self.assertIn("## Coverage gaps", first)
        self.assertIn("## Source-version drift", first)
        self.assertIn("alignment only", first)
        self.assertIn("do not assert certification", first)
        self.assertIn("None; every mapping names", first)


if __name__ == "__main__":
    unittest.main()
