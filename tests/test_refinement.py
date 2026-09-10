# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Reviewed paired traces, hostile maps and offline CLI boundaries."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any
from unittest import mock

from awq import assurance, refinement
from awq.cli import main
from awq.project import ProjectError
from awq.registry import canonical_bytes
from scripts.validate_contracts import validate

ROOT = Path(__file__).resolve().parents[1]


def contract() -> dict[str, Any]:
    return dict(json.loads((ROOT / "templates/refinement-map.json").read_bytes()))


def bind(value: dict[str, Any]) -> dict[str, Any]:
    projection = {key: item for key, item in value.items() if key != "obligations"}
    digest = hashlib.sha256(canonical_bytes(projection)).hexdigest()
    for record in value["obligations"]:
        record["evidence_sha256"] = digest
    return value


class RefinementTests(unittest.TestCase):
    def test_positive_complete_mapping_and_explicit_limits(self) -> None:
        value = contract()
        for schema in ("refinement-map.schema.json", "assurance-contract.schema.json"):
            validate(value, schema)
        result = assurance.evaluate(value)
        self.assertEqual(result, assurance.evaluate(copy.deepcopy(value)))
        self.assertEqual("pass", result["status"])
        self.assertEqual((4, 7), (result["traces"], result["transitions"]))
        self.assertEqual([], result["findings"])
        self.assertEqual(list(refinement.OBLIGATIONS), result["obligations"])
        self.assertEqual("not-proven", result["refinement"])
        self.assertEqual("not-proven", result["composition"])
        self.assertEqual("caller-declared-not-run", result["execution"])
        self.assertEqual("retain", result["native_gate"])
        self.assertIn("Only supplied finite paired traces", result["limitation"])
        self.assertNotIn("OWNER-DEMO", json.dumps(result))

    def test_reviewed_hostile_fixtures(self) -> None:
        for name in ("missing-map", "out-of-bound"):
            with self.subTest(name=name), self.assertRaises(ProjectError):
                assurance.evaluate_file(ROOT, "fixtures/nonconforming/refinement/" + name + ".json")
        result = assurance.evaluate_file(
            ROOT, "fixtures/nonconforming/refinement/contradictory-trace.json"
        )
        self.assertEqual("fail", result["status"])
        self.assertEqual(["state-projection", "transition-simulation"], result["findings"])

    def test_closed_shape_version_bounds_and_tokens(self) -> None:
        changes: list[tuple[str, Any]] = [
            ("schema_version", True),
            ("map_version", 2),
            ("kind", "proof"),
            ("model", "policy-lifecycle-v1"),
            ("assumptions", []),
            ("model_sha256", "0" * 64),
            ("implementation_source_sha256", "PRIVATE-MARKER"),
            ("state_map", []),
            ("action_map", []),
            ("traces", []),
            ("traces", {}),
            ("obligations", []),
            ("bounds", {}),
        ]
        for key, replacement in changes:
            value = contract()
            value[key] = replacement
            with self.subTest(key=key), self.assertRaises(ProjectError):
                refinement.evaluate(value)
        for key, replacement in (
            ("actors", 1),
            ("ticks", 7),
            ("review_ttl", 0),
            ("revisions", 4),
            ("actors", 2.0),
            ("ticks", True),
        ):
            value = contract()
            value["bounds"][key] = replacement
            with (
                self.subTest(bound=key),
                mock.patch(
                    "awq.formal_model.successors", side_effect=AssertionError("must not replay")
                ),
                self.assertRaises(ProjectError),
            ):
                refinement.evaluate(bind(value))
        value = contract()
        value["private_path"] = "PRIVATE-MARKER"
        with self.assertRaises(ProjectError) as caught:
            refinement.evaluate(value)
        self.assertNotIn("PRIVATE-MARKER", str(caught.exception))
        with self.assertRaises(ProjectError):
            refinement.evaluate([])

    def test_maps_are_complete_ordered_unique_and_bound_to_reviews(self) -> None:
        for key in ("state_map", "action_map"):
            for mode in ("duplicate-model", "duplicate-target", "reorder", "unknown", "extra"):
                value = contract()
                rows = value[key]
                if mode == "duplicate-model":
                    rows[1]["model"] = rows[0]["model"]
                elif mode == "duplicate-target":
                    rows[1]["implementation"] = rows[0]["implementation"]
                elif mode == "reorder":
                    rows.reverse()
                elif mode == "unknown":
                    rows[0]["model"] = "unknown"
                else:
                    rows[0]["unknown_field"] = "PRIVATE-MARKER"
                with self.subTest(key=key, mode=mode), self.assertRaises(ProjectError):
                    refinement.evaluate(bind(value))
        value = contract()
        value["implementation_source_sha256"] = "c" * 64
        with self.assertRaisesRegex(ProjectError, "unbound-review"):
            refinement.evaluate(value)
        for field, bad in (
            ("id", "unknown"),
            ("owner", "/private/owner"),
            ("review_sha256", "g" * 64),
            ("evidence_sha256", "0" * 64),
        ):
            value = contract()
            value["obligations"][0][field] = bad
            with self.subTest(field=field), self.assertRaises(ProjectError):
                refinement.evaluate(value)

    def test_trace_structure_bounds_types_and_unknowns(self) -> None:
        for field, bad in (
            ("model_action", "unknown"),
            ("implementation_action", "ACTION-9999"),
            ("implementation_state", {}),
            ("model_state", {}),
        ):
            value = contract()
            value["traces"][0]["steps"][0][field] = bad
            with self.subTest(field=field), self.assertRaises(ProjectError):
                refinement.evaluate(bind(value))
        for key, state_bad in (("enforced", 0), ("revision", 2), ("reviewer", 2), ("tick", 3)):
            value = contract()
            value["traces"][0]["steps"][0]["model_state"][key] = state_bad
            with self.subTest(key=key), self.assertRaises(ProjectError):
                refinement.evaluate(bind(value))
        for target in ("traces", "steps"):
            value = contract()
            if target == "traces":
                value["traces"] *= 17
            else:
                value["traces"][0]["steps"] *= 65
            with self.subTest(target=target), self.assertRaises(ProjectError):
                refinement.evaluate(bind(value))
        for mode in ("duplicate", "reversed"):
            value = contract()
            if mode == "duplicate":
                value["traces"][1]["id"] = value["traces"][0]["id"]
            else:
                value["traces"].reverse()
            with self.subTest(mode=mode), self.assertRaises(ProjectError):
                refinement.evaluate(bind(value))

    def test_semantic_mismatches_fail_even_with_matching_review_commitments(self) -> None:
        for mode, finding in (
            ("initial", "initial-state"),
            ("action", "action-projection"),
            ("invariant", "invariant-preservation"),
            ("digest", "implementation-trace-digest"),
            ("coverage", "trace-coverage"),
            ("projection", "state-projection"),
        ):
            value = contract()
            first = value["traces"][0]
            if mode == "initial":
                first["model_initial"]["revision"] = 1
            elif mode == "action":
                first["steps"][0]["implementation_action"] = value["action_map"][0][
                    "implementation"
                ]
            elif mode == "invariant":
                first["steps"][0]["model_state"]["enforced"] = True
            elif mode == "digest":
                first["implementation_trace_sha256"] = "0" * 64
            elif mode == "coverage":
                value["traces"].pop()
            else:
                token = next(
                    row["implementation"]
                    for row in value["state_map"]
                    if row["model"] == "revision"
                )
                first["implementation_initial"][token] = 1
            with self.subTest(mode=mode):
                result = refinement.evaluate(bind(value))
                self.assertEqual("fail", result["status"])
                self.assertIn(finding, result["findings"])

    def test_confined_canonical_bounded_file_and_cli(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "evidence.json"
            path.write_bytes(canonical_bytes(contract()))
            for output_format in ("json", "text"):
                output = io.StringIO()
                with redirect_stdout(output):
                    code = main(
                        [
                            "--root",
                            str(root),
                            "assurance-check",
                            "evidence.json",
                            "--format",
                            output_format,
                        ]
                    )
                self.assertEqual(0, code)
                self.assertIn("not-proven", output.getvalue())
                self.assertNotIn(str(root), output.getvalue())
            for relative in (
                "../evidence.json",
                "/private.json",
                "a/../evidence.json",
                "private\\evidence.json",
                "x" * 201 + ".json",
            ):
                with self.subTest(relative=relative), self.assertRaises(ProjectError):
                    assurance.evaluate_file(root, relative)
            (root / "link.json").symlink_to(path)
            (root / "linked").symlink_to(root, target_is_directory=True)
            for relative in ("link.json", "linked/evidence.json", "missing.json"):
                with self.subTest(relative=relative), self.assertRaises(ProjectError):
                    assurance.evaluate_file(root, relative)
            for raw in (
                b" " + canonical_bytes(contract()),
                b'{"a":1,"a":2}\n',
                b'{"a":NaN}\n',
                b"x" * 256_001,
            ):
                path.write_bytes(raw)
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(
                        1,
                        main(
                            [
                                "--root",
                                str(root),
                                "assurance-check",
                                "evidence.json",
                                "--format",
                                "json",
                            ]
                        ),
                    )
                self.assertEqual("error", json.loads(output.getvalue())["status"])
                self.assertNotIn(str(root), output.getvalue())
            value = contract()
            value["traces"].pop()
            path.write_bytes(canonical_bytes(bind(value)))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    1,
                    main(
                        [
                            "--root",
                            str(root),
                            "assurance-check",
                            "evidence.json",
                            "--format",
                            "json",
                        ]
                    ),
                )


if __name__ == "__main__":
    unittest.main()
