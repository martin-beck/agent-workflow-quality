# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Evidence lineage, publication truth and retention planning contracts."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from awq import evidence_lifecycle as subject
from awq.cli import main
from awq.project import ProjectError
from awq.registry import canonical_bytes
from scripts.validate_contracts import validate

ROOT = Path(__file__).resolve().parents[1]
AS_OF = "2026-09-11T00:00:00Z"


def contract() -> dict[str, Any]:
    return dict(json.loads((ROOT / "fixtures/conforming/evidence-lifecycle.json").read_bytes()))


class EvidenceLifecycleTests(unittest.TestCase):
    def test_complete_contract_is_deterministic_and_non_authorizing(self) -> None:
        value = contract()
        validate(value, "evidence-lifecycle.schema.json")
        result = subject.evaluate(value, AS_OF)
        self.assertEqual(result, subject.evaluate(json.loads(canonical_bytes(value)), AS_OF))
        self.assertEqual("pass", result["status"])
        self.assertEqual("pass", result["quality_status"])
        self.assertEqual("partial", result["publication_status"])
        self.assertEqual(2, result["lineage"]["records"])
        self.assertEqual(1, result["lineage"]["outcomes"]["fail"])
        self.assertEqual(
            ["EVIDENCE-OLD-A", "EVIDENCE-OLD-B"],
            [item["id"] for item in result["retention"]["candidates"]],
        )
        self.assertTrue(result["retention"]["low_watermark_reached"])
        self.assertEqual("not-granted", result["retention"]["authorization"])
        self.assertEqual("dry-run", result["retention"]["mode"])
        self.assertEqual("retain", result["native_gate"])
        rendered = json.dumps(result, sort_keys=True)
        for forbidden in ("artifact_sha256", "source_head", "run_id", "score"):
            self.assertNotIn(forbidden, rendered)

    def test_hash_chain_rejects_mutation_reordering_parent_source_and_attempt_reuse(self) -> None:
        candidates = []
        value = contract()
        value["lineage"][0]["outcome"] = "error"
        candidates.append(value)
        value = contract()
        value["lineage"].reverse()
        candidates.append(value)
        value = contract()
        value["lineage"][1]["parent_sha256"] = "0" * 64
        candidates.append(value)
        value = contract()
        value["lineage"][1]["source_revision"] = "0" * 40
        candidates.append(value)
        value = contract()
        value["lineage"][1]["attempt_id"] = value["lineage"][0]["attempt_id"]
        candidates.append(value)
        for candidate in candidates:
            with (
                self.subTest(candidate=candidates.index(candidate)),
                self.assertRaises(ProjectError),
            ):
                subject.evaluate(candidate, AS_OF)
        hostile = json.loads(
            (ROOT / "fixtures/nonconforming/evidence-lifecycle/broken-parent.json").read_bytes()
        )
        validate(hostile, "evidence-lifecycle.schema.json")
        with self.assertRaises(ProjectError):
            subject.evaluate(hostile, AS_OF)

    def test_validation_outcome_is_distinct_from_score_and_publication(self) -> None:
        value = contract()
        value["lineage"][1]["score"] = -100
        record = value["lineage"][1]
        record["record_sha256"] = subject.digest(
            {key: item for key, item in record.items() if key != "record_sha256"}
        )
        result = subject.evaluate(value, AS_OF)
        self.assertEqual("pass", result["status"])
        self.assertEqual("partial", result["publication_status"])
        value = contract()
        value["publications"][0]["validation_outcome"] = "fail"
        value["publications"][0]["publication_state"] = "failed"
        result = subject.evaluate(value, AS_OF)
        self.assertEqual("fail", result["status"])
        self.assertEqual("fail", result["quality_status"])
        value = contract()
        value["publications"][1]["publication_state"] = "unavailable"
        self.assertEqual("pass", subject.evaluate(value, AS_OF)["status"])

    def test_required_gates_cannot_fail_open_or_publish_without_prerequisites(self) -> None:
        candidates = []
        value = contract()
        value["publications"][0]["continue_on_error"] = True
        candidates.append(value)
        value = contract()
        value["publications"][0]["validation_outcome"] = "fail"
        candidates.append(value)
        value = contract()
        value["publications"][1]["prerequisites"] = ["ARTIFACT-MISSING"]
        candidates.append(value)
        value = contract()
        value["publications"].reverse()
        candidates.append(value)
        for candidate in candidates:
            with self.assertRaises(ProjectError):
                subject.evaluate(candidate, AS_OF)

    def test_retention_order_bounds_hysteresis_and_all_protections(self) -> None:
        expected = subject.evaluate(contract(), AS_OF)["retention"]
        value = contract()
        value["inventory"].reverse()
        self.assertEqual(expected, subject.evaluate(value, AS_OF)["retention"])
        value = contract()
        value["retention_policy"]["maximum_selection_count"] = 1
        limited = subject.evaluate(value, AS_OF)["retention"]
        selected = [item["id"] for item in limited["candidates"]]
        self.assertEqual(["EVIDENCE-OLD-A"], selected)
        self.assertFalse(limited["low_watermark_reached"])
        self.assertEqual(1, len(selected))
        value = contract()
        value["retention_policy"]["high_watermark_bytes"] = 5000
        value["retention_policy"]["low_watermark_bytes"] = 4000
        self.assertEqual([], subject.evaluate(value, AS_OF)["retention"]["candidates"])
        protected = {
            "EVIDENCE-ACTIVE",
            "EVIDENCE-DIAGNOSTIC",
            "EVIDENCE-MAIN",
            "EVIDENCE-PR",
            "EVIDENCE-RELEASE",
            "EVIDENCE-UNKNOWN",
        }
        self.assertTrue(protected.isdisjoint(item["id"] for item in expected["candidates"]))

    def test_closed_fields_bounds_chronology_and_privacy_fail_closed(self) -> None:
        candidates = []
        value = contract()
        value["private_path"] = "/home/example"
        candidates.append(value)
        value = contract()
        value["lineage"][0]["score"] = True
        candidates.append(value)
        value = contract()
        value["retention_policy"]["low_watermark_bytes"] = 4000
        candidates.append(value)
        value = contract()
        value["inventory"][0]["created_at"] = "2026-09-12T00:00:00Z"
        candidates.append(value)
        value = contract()
        value["retention_policy"]["protected_references"]["open_pr_heads"] *= 65
        candidates.append(value)
        for candidate in candidates:
            with self.assertRaises(ProjectError) as caught:
                subject.evaluate(candidate, AS_OF)
            self.assertNotIn("/home/example", str(caught.exception))

    def test_runtime_rejects_hostile_values_beyond_schema_validation(self) -> None:
        candidates = []
        value = contract()
        value["source_revision"] = "not-a-revision"
        candidates.append(value)
        value = contract()
        value["lineage"][0]["id"] = "bad"
        candidates.append(value)
        value = contract()
        value["lineage"][0]["attempt_id"] = "#"
        candidates.append(value)
        value = contract()
        value["lineage"][0]["kind"] = "score"
        candidates.append(value)
        value = contract()
        value["lineage"][0]["evidence_class"] = "transcript"
        candidates.append(value)
        value = contract()
        value["lineage"][1]["observed_at"] = "2026-09-09T00:00:00Z"
        candidates.append(value)
        value = contract()
        value["lineage"][0]["observed_at"] = "2026-02-30T00:00:00Z"
        candidates.append(value)
        value = contract()
        value["lineage"] = []
        candidates.append(value)
        value = contract()
        value["publications"][0]["artifact_sha256"] = "not-a-digest"
        candidates.append(value)
        value = contract()
        value["publications"][0]["requirement"] = "recommended"
        candidates.append(value)
        value = contract()
        value["publications"][0]["publication_state"] = "hidden"
        candidates.append(value)
        value = contract()
        value["publications"][0]["continue_on_error"] = 1
        candidates.append(value)
        value = contract()
        value["publications"][0]["validation_outcome"] = "fail"
        candidates.append(value)
        value = contract()
        value["publications"] *= 65
        candidates.append(value)
        value = contract()
        value["retention_policy"]["minimum_age_seconds"] = -1
        candidates.append(value)
        value = contract()
        value["inventory"] = "not-an-inventory"
        candidates.append(value)
        value = contract()
        value["inventory"][0]["artifact_role"] = "log"
        candidates.append(value)
        value = contract()
        value["inventory"][0]["bytes"] = True
        candidates.append(value)
        value = contract()
        value["inventory"][0]["run_state"] = "queued"
        candidates.append(value)
        value = contract()
        value["inventory"][0]["provenance"] = "trusted"
        candidates.append(value)
        value = contract()
        value["inventory"][1]["id"] = value["inventory"][0]["id"]
        candidates.append(value)
        value = contract()
        value["schema_version"] = True
        candidates.append(value)
        for candidate in candidates:
            with self.assertRaises(ProjectError):
                subject.evaluate(candidate, AS_OF)

    def test_cli_reads_only_confined_bounded_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "contract.json").write_bytes(canonical_bytes(contract()))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(
                    0,
                    main(
                        [
                            "--root",
                            str(root),
                            "evidence-lifecycle-evaluate",
                            "contract.json",
                            "--as-of",
                            AS_OF,
                            "--format",
                            "json",
                        ]
                    ),
                )
            self.assertEqual(
                "not-granted", json.loads(output.getvalue())["retention"]["authorization"]
            )
            before = (root / "contract.json").read_bytes()
            self.assertEqual(before, (root / "contract.json").read_bytes())
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(
                    1,
                    main(
                        [
                            "--root",
                            str(root),
                            "evidence-lifecycle-evaluate",
                            "../contract.json",
                            "--as-of",
                            AS_OF,
                        ]
                    ),
                )


if __name__ == "__main__":
    unittest.main()
