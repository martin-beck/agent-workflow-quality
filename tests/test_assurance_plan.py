# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Consumer assurance-plan schema, runtime and hostile-path tests."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

import jsonschema

from awq import assurance_plan
from awq.cli import main
from awq.project import ProjectError
from awq.registry import canonical_bytes
from awq.release import ReleaseError
from scripts import generate_assurance_plan_docs
from scripts.validate_contracts import validate

ROOT = Path(__file__).resolve().parents[1]


def document(name: str = "agent-relay.json") -> dict[str, Any]:
    path = ROOT / "fixtures/conforming/assurance-plan" / name
    return dict(json.loads(path.read_bytes()))


def observed(value: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(value)
    observations = []
    for index, gate in enumerate(sorted(result["gates"], key=lambda item: item["id"]), start=1):
        correlation = hashlib.sha256(canonical_bytes(gate["correlation"])).hexdigest()
        observations.append(
            {
                "gate": gate["id"],
                "source": "native-environment" if gate["native_mapping"] else "executed",
                "status": "pass",
                "identity": {
                    "schema_version": 1,
                    "correlation_sha256": correlation,
                    "producer_sha256": f"{index:064x}",
                    "tool_sha256": f"{index + 20:064x}",
                    "run_id": f"RUN-ASSURANCE-{index}",
                    "attempt": 1,
                    "evidence_class": gate["evidence_class"],
                    "platform_class": gate["correlation"]["platform_class"],
                    "collected_at": "2026-09-10T23:30:00Z",
                    "freshness": {"max_age_seconds": 7200},
                    "evidence_sha256": f"{index + 40:064x}",
                },
            }
        )
    result["observations"] = observations
    return result


class AssurancePlanTests(unittest.TestCase):
    def test_hostile_fixture_inventory_is_complete_and_bounded(self) -> None:
        value = json.loads(
            (ROOT / "fixtures/nonconforming/assurance-plan/mutations.json").read_bytes()
        )
        self.assertEqual(1, value["schema_version"])
        self.assertEqual(
            {
                "circular-gate-order",
                "duplicate-invariant",
                "missing-ownership",
                "orphaned-domain",
                "overlapping-identifiers",
                "shell-string",
                "stale-observation",
                "unknown-report-contract",
                "unsupported-without-rationale",
            },
            {item["id"] for item in value["mutations"]},
        )
        self.assertLessEqual(len(value["mutations"]), 32)

    def test_representative_inventories_are_closed_deterministic_and_nonexecuting(self) -> None:
        for name in ("agent-relay.json", "agent-systems-benchmark.json"):
            with self.subTest(name=name):
                value = document(name)
                validate(value, "assurance-plan.schema.json")
                with mock.patch(
                    "subprocess.run", side_effect=AssertionError("must not execute")
                ) as run:
                    first = assurance_plan.evaluate(value)
                    second = assurance_plan.evaluate(json.loads(canonical_bytes(value)))
                run.assert_not_called()
                self.assertEqual(first, second)
                self.assertEqual("declared", first["status"])
                self.assertEqual(0, first["coverage"]["observed"])
                self.assertNotIn("argv", json.dumps(first))

    def test_exact_identity_observations_pass_without_exposing_identity(self) -> None:
        value = observed(document())
        validate(value, "assurance-plan.schema.json")
        result = assurance_plan.evaluate(value)
        self.assertEqual("pass", result["status"])
        self.assertEqual(len(value["gates"]), result["coverage"]["observed"])
        rendered = json.dumps(result, sort_keys=True)
        for excluded in ("correlation_sha256", "producer_sha256", "tool_sha256", "run_id"):
            self.assertNotIn(excluded, rendered)
        self.assertTrue(all(item["native_gate"] == "retain" for item in result["gates"]))

    def test_orphans_duplicates_ownership_shell_reports_and_cycles_fail_closed(self) -> None:
        candidates: list[dict[str, Any]] = []
        value = document()
        value["gates"][0]["domains"].remove("DOMAIN-RUST")
        candidates.append(value)
        value = document()
        value["gates"][1]["invariant"] = value["gates"][0]["invariant"]
        candidates.append(value)
        value = document()
        value["gates"][0]["owner"] = ""
        candidates.append(value)
        value = document()
        value["gates"][0]["argv"] = ["sh", "-c", "pytest"]
        candidates.append(value)
        value = document()
        value["gates"][0]["report_contract"] = "AWQ-CONTRACT-UNKNOWN-V1"
        candidates.append(value)
        value = document()
        value["gates"][0]["depends_on"] = [value["gates"][1]["id"]]
        candidates.append(value)
        value = document()
        value["gates"].append(copy.deepcopy(value["gates"][1]))
        candidates.append(value)
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(ProjectError):
                assurance_plan.validate(candidate)

    def test_unsupported_requires_reviewed_rationale_and_exclusive_coverage(self) -> None:
        value = document()
        domain = value["domains"][-1]
        value["gates"][0]["domains"].remove(domain["id"])
        value["unsupported"] = [
            {
                "id": "UNSUPPORTED-RUST",
                "domain": domain["id"],
                "owner": "relay-maintainers",
                "rationale": "The surface is outside this reviewed consumer profile.",
                "review": "REVIEW-RELAY-RUST",
            }
        ]
        self.assertEqual([domain["id"]], assurance_plan.evaluate(value)["unsupported_domains"])
        for field, replacement in (("rationale", "short"), ("review", ""), ("owner", "")):
            hostile = copy.deepcopy(value)
            hostile["unsupported"][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(ProjectError):
                assurance_plan.validate(hostile)
        overlap = copy.deepcopy(value)
        overlap["gates"][0]["domains"].append(domain["id"])
        overlap["gates"][0]["domains"].sort()
        with self.assertRaises(ProjectError):
            assurance_plan.validate(overlap)
        all_unsupported = document()
        all_unsupported["gates"] = []
        all_unsupported["unsupported"] = [
            {
                "id": "UNSUPPORTED-" + item["id"].removeprefix("DOMAIN-"),
                "domain": item["id"],
                "owner": item["owner"],
                "rationale": "This domain is outside the reviewed execution profile.",
                "review": "REVIEW-" + item["id"].removeprefix("DOMAIN-"),
            }
            for item in all_unsupported["domains"]
        ]
        self.assertEqual("declared", assurance_plan.evaluate(all_unsupported)["status"])

    def test_stale_future_wrong_revision_and_identity_bindings_fail_closed(self) -> None:
        paths: list[tuple[list[str | int], Any]] = [
            (["observations", 0, "identity", "collected_at"], "2026-09-01T00:00:00Z"),
            (["observations", 0, "identity", "collected_at"], "2026-09-12T00:00:00Z"),
            (["observations", 0, "identity", "correlation_sha256"], "0" * 64),
            (["observations", 0, "identity", "evidence_class"], "mechanical"),
            (["gates", 0, "correlation", "source_commit"], "0" * 40),
        ]
        for path, replacement in paths:
            value = observed(document())
            target: Any = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(ProjectError):
                assurance_plan.validate(value)

    def test_observation_shape_order_source_and_status_fail_closed(self) -> None:
        candidates: list[dict[str, Any]] = []
        value = observed(document())
        value["observations"][0]["gate"] = "GATE-UNKNOWN"
        candidates.append(value)
        value = observed(document())
        value["observations"].append(copy.deepcopy(value["observations"][0]))
        candidates.append(value)
        value = observed(document())
        value["observations"][0]["source"] = "imported"
        candidates.append(value)
        value = observed(document())
        value["observations"][0]["source"] = "executed"
        candidates.append(value)
        value = observed(document())
        value["observations"][0]["status"] = "unknown"
        candidates.append(value)
        value = observed(document())
        value["observations"].reverse()
        candidates.append(value)
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(ProjectError):
                assurance_plan.validate(candidate)

    def test_runtime_semantic_bounds_fail_closed(self) -> None:
        mutations: list[tuple[list[str | int], Any]] = [
            (["evaluated_at"], "not-a-timestamp"),
            (["evaluated_at"], "2026-02-31T00:00:00Z"),
            (["repository", "id"], "INVALID"),
            (["repository", "source_commit"], "0" * 39),
            (["repository", "tree_state"], "dirty"),
            (["domains", 0, "id"], "BAD-ID"),
            (["domains", 0, "kind"], "unknown"),
            (["domains", 0, "owner"], "Bad Owner"),
            (["gates", 0, "invariant"], "BAD"),
            (["gates", 0, "tier"], "unknown"),
            (["gates", 0, "evidence_class"], "unknown"),
            (["gates", 0, "input_scope"], []),
            (["gates", 0, "depends_on"], "GATE-NOT-A-LIST"),
            (["gates", 0, "depends_on"], ["GATE-NOT-DECLARED"]),
            (["gates", 0, "argv"], ["python", "https://example.invalid/tool"]),
            (["gates", 0, "argv"], ["python", "tool;other"]),
            (["gates", 0, "input_scope"], ["C:/private"]),
            (["gates", 0, "native_mapping"], "bad"),
            (["gates", 0, "correlation", "configuration_sha256"], "0" * 63),
            (["gates", 0, "correlation", "platform_class"], "unknown"),
        ]
        for path, replacement in mutations:
            value = document()
            target: Any = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(ProjectError):
                assurance_plan.validate(value)

    def test_collection_shapes_and_order_are_strict(self) -> None:
        candidates: list[dict[str, Any]] = []
        for field, replacement in (
            ("domains", "not-a-list"),
            ("gates", "not-a-list"),
            ("unsupported", "not-a-list"),
            ("observations", "not-a-list"),
        ):
            value = document()
            value[field] = replacement
            candidates.append(value)
        value = document()
        value["domains"].reverse()
        candidates.append(value)
        value = document()
        value["gates"][0]["domains"].reverse()
        candidates.append(value)
        value = document()
        value["gates"][0]["input_scope"].reverse()
        candidates.append(value)
        value = document()
        value["gates"][0]["depends_on"] = ["GATE-NOT-DECLARED"]
        candidates.append(value)
        value = document("agent-systems-benchmark.json")
        value["gates"][1], value["gates"][2] = value["gates"][2], value["gates"][1]
        candidates.append(value)
        value = document()
        value["gates"][0]["domains"].remove(value["domains"][-1]["id"])
        value["unsupported"] = [
            {
                "id": "UNSUPPORTED-FIRST",
                "domain": value["domains"][-1]["id"],
                "owner": value["domains"][-1]["owner"],
                "rationale": "This domain is outside the reviewed execution profile.",
                "review": "REVIEW-FIRST",
            },
            {
                "id": "UNSUPPORTED-SECOND",
                "domain": value["domains"][-1]["id"],
                "owner": value["domains"][-1]["owner"],
                "rationale": "This duplicate domain declaration must fail closed.",
                "review": "REVIEW-SECOND",
            },
        ]
        candidates.append(value)
        value = document()
        value["gates"][0]["domains"].remove(value["domains"][-1]["id"])
        value["unsupported"] = [
            {
                "id": "UNSUPPORTED-UNKNOWN",
                "domain": "DOMAIN-NOT-DECLARED",
                "owner": "relay-maintainers",
                "rationale": "An undeclared domain cannot be waived by this plan.",
                "review": "REVIEW-UNKNOWN",
            }
        ]
        candidates.append(value)
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(ProjectError):
                assurance_plan.validate(candidate)

    def test_schema_runtime_parity_for_closed_shapes_and_bounds(self) -> None:
        candidates = []
        for path, replacement in (
            (["schema_version"], 2),
            (["domains", 0, "description"], "short"),
            (["gates", 0, "argv"], []),
            (["gates", 0, "argv"], ["python", "https://example.invalid/tool"]),
            (["gates", 0, "argv"], ["python", "tool;other"]),
            (["gates", 0, "input_scope"], ["../private"]),
            (["gates", 0, "input_scope"], ["C:/private"]),
        ):
            value = document()
            target: Any = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = replacement
            candidates.append(value)
        value = document()
        value["unknown"] = True
        candidates.append(value)
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                with self.assertRaises(jsonschema.ValidationError):
                    validate(candidate, "assurance-plan.schema.json")
                with self.assertRaises(ProjectError):
                    assurance_plan.validate(candidate)

    def test_diff_is_deterministic_and_removal_is_weakening(self) -> None:
        base = document()
        head = copy.deepcopy(base)
        removed = head["gates"].pop()
        head["domains"] = [item for item in head["domains"] if item["id"] not in removed["domains"]]
        result = assurance_plan.diff(base, head)
        self.assertEqual("fail", result["status"])
        self.assertEqual(
            [("domains", "removed"), ("gates", "removed")],
            [(item["section"], item["action"]) for item in result["changes"]],
        )
        self.assertNotIn("argv", json.dumps(result))

    def test_diff_addition_change_and_file_wrapper_require_review(self) -> None:
        base = document()
        changed = copy.deepcopy(base)
        changed["domains"][0]["description"] += " Reviewed."
        result = assurance_plan.diff(base, changed)
        self.assertEqual("pass", result["status"])
        self.assertEqual("changed", result["changes"][0]["action"])

        added = copy.deepcopy(base)
        extra = copy.deepcopy(added["domains"][0])
        extra.update(
            {
                "id": "DOMAIN-ADDITIONAL",
                "description": "Additional explicitly reviewed quality surface.",
            }
        )
        added["domains"].append(extra)
        added["domains"].sort(key=lambda item: item["id"])
        added["unsupported"].append(
            {
                "id": "UNSUPPORTED-ADDITIONAL",
                "domain": "DOMAIN-ADDITIONAL",
                "owner": extra["owner"],
                "rationale": "This additional domain has no executable gate yet.",
                "review": "REVIEW-ADDITIONAL",
            }
        )
        self.assertEqual("added", assurance_plan.diff(base, added)["changes"][0]["action"])
        relative = Path("fixtures/conforming/assurance-plan/agent-relay.json")
        self.assertEqual("pass", assurance_plan.diff_files(ROOT, relative, relative)["status"])

    def test_cli_is_confined_and_declarations_never_exit_as_pass(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(
                [
                    "--root",
                    str(ROOT),
                    "assurance-plan-check",
                    "fixtures/conforming/assurance-plan/agent-relay.json",
                    "--format",
                    "json",
                ]
            )
        self.assertEqual(1, code)
        self.assertEqual("declared", json.loads(output.getvalue())["status"])
        output = io.StringIO()
        relative = "fixtures/conforming/assurance-plan/agent-relay.json"
        with contextlib.redirect_stdout(output):
            code = main(
                [
                    "--root",
                    str(ROOT),
                    "assurance-plan-diff",
                    relative,
                    relative,
                    "--format",
                    "json",
                ]
            )
        self.assertEqual(0, code)
        self.assertEqual("pass", json.loads(output.getvalue())["status"])
        for path in ("../outside.json", "/absolute.json", "not-json.txt"):
            with self.subTest(path=path), self.assertRaises(ProjectError):
                assurance_plan.evaluate_file(ROOT, path)

    def test_generated_documentation_is_canonical_and_nonclaiming(self) -> None:
        rendered = generate_assurance_plan_docs.render()
        self.assertEqual(
            rendered, generate_assurance_plan_docs.DOCUMENT.read_text(encoding="utf-8")
        )
        self.assertIn("declarations only", rendered)
        self.assertIn("never `pass`", rendered)
        self.assertNotIn(str(ROOT), rendered)

    def test_duplicate_json_and_private_values_are_rejected_without_echo(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "plan.json"
            path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaises(ReleaseError):
                assurance_plan.evaluate_file(root, "plan.json")
        value = document()
        value["domains"][0]["description"] = "private /" + "home" + "/PRIVATE-MARKER"
        with self.assertRaises(ProjectError) as caught:
            assurance_plan.validate(value)
        self.assertNotIn("PRIVATE-MARKER", str(caught.exception))
        value = document()
        value["gates"][0]["argv"] = ["python3", "C:\\Users\\PRIVATE-MARKER"]
        with self.assertRaises(ProjectError) as caught:
            assurance_plan.validate(value)
        self.assertNotIn("PRIVATE-MARKER", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
