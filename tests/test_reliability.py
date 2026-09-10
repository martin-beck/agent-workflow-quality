# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Synthetic reliability measurements, hostile observations and retention boundaries."""

from __future__ import annotations

import copy
import io
import json
import os
import resource
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from awq import project
from awq import reliability as subject
from awq import reliability_worker as worker
from awq.cli import main
from awq.project import ProjectError
from awq.registry import canonical_bytes
from scripts import reliability_campaign
from scripts.validate_contracts import validate

ROOT = Path(__file__).resolve().parents[1]
AS_OF = "2026-01-01T00:00:00Z"


def evidence() -> dict[str, Any]:
    return dict(
        json.loads((ROOT / "fixtures/conforming/reliability/observation.json").read_bytes())
    )


def budget(profile: str = "pr") -> dict[str, Any]:
    return dict(json.loads((ROOT / ("templates/reliability-" + profile + ".json")).read_bytes()))


def retained(index: int = 0) -> dict[str, Any]:
    return {
        "id": "EVIDENCE-" + str(index),
        "sha256": format(index, "064x"),
        "bytes": 100,
        "created_at": "2025-12-31T00:00:00Z",
        "expires_at": "2026-01-02T00:00:00Z",
        "classification": "aggregate-only",
    }


class ReliabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.scratch = Path(self.temporary.name).resolve()

    def test_real_pr_collection_and_scheduled_repeat_contract(self) -> None:
        result = subject.collect(budget(), self.scratch, AS_OF)
        self.assertEqual("pass", result["status"])
        self.assertEqual(9, len(result["observation"]["runs"]))
        self.assertEqual(12, len(result["timing"]))
        validate(result["observation"], "reliability-budget.schema.json")
        self.assertNotIn(str(self.scratch), json.dumps(result))
        self.assertEqual([], list(self.scratch.iterdir()))
        sample = evidence()["runs"][0]["stages"]
        with mock.patch.object(subject, "_trial", return_value=sample) as trial:
            scheduled = subject.collect(budget("scheduled"), self.scratch, AS_OF)
        self.assertEqual(21, trial.call_count)
        self.assertEqual("pass", scheduled["status"])
        validate(scheduled["observation"], "reliability-budget.schema.json")

    def test_fixed_worker_oracle_normalization_and_git_tracking(self) -> None:
        root = self.scratch / "repository"
        root.mkdir()
        self.assertEqual(19, worker.prepare(root, "small"))
        payloads = list(root.glob("sample-*.json"))
        self.assertEqual(16, len(payloads))
        self.assertEqual({64}, {path.stat().st_size for path in payloads})
        self.assertEqual(
            {"nested": [{"value": 3}]},
            worker.normalize({"duration_ms": 7, "nested": [{"duration_ms": 2, "value": 3}]}),
        )
        with mock.patch.object(time, "perf_counter_ns", side_effect=[100, 125]):
            value = worker.measure(lambda: {"status": "pass", "duration_ms": 99})
        self.assertEqual(25, value["elapsed_ns"])
        self.assertEqual(subject.digest({"status": "pass"}), value["semantic_sha256"])
        for operation in (lambda: {"status": "fail"}, lambda: "x" * 65537):
            with self.assertRaises(ValueError):
                worker.measure(operation)
        with (
            mock.patch.object(project, "tracked_files", return_value=[]),
            self.assertRaisesRegex(ValueError, "tracking"),
        ):
            worker.benchmark("small", self.scratch)
        with (
            mock.patch.object(worker, "canonical_bytes", return_value=b"x"),
            self.assertRaisesRegex(ValueError, "size"),
        ):
            worker.prepare(self.scratch, "small")
        for fixture, scratch in (("unknown", self.scratch), ("small", Path())):
            with self.assertRaises(ValueError):
                worker.benchmark(fixture, scratch)

    def test_threshold_determinism_timeout_truncation_and_age(self) -> None:
        baseline = subject.evaluate(evidence(), AS_OF)
        self.assertEqual("pass", baseline["status"])
        self.assertEqual(baseline, subject.evaluate(copy.deepcopy(evidence()), AS_OF))
        for name in (
            "runtime-regression",
            "timeout",
            "truncation",
            "nondeterministic",
            "retention",
        ):
            value = json.loads(
                (ROOT / ("fixtures/nonconforming/reliability/" + name + ".json")).read_bytes()
            )
            validate(value, "reliability-budget.schema.json")
            self.assertEqual("fail", subject.evaluate(value, AS_OF)["status"], name)
        value = evidence()
        value["runs"][0]["stages"]["checks"]["elapsed_ns"] = 4_000_000_001
        self.assertIn(
            "absolute-runtime-budget", subject.evaluate(value, AS_OF)["timing"][1]["reasons"]
        )
        self.assertTrue(subject.evaluate(evidence(), "2026-01-08T00:00:01Z")["stale"])
        self.assertFalse(subject.evaluate(evidence(), "2026-01-08T00:00:00Z")["stale"])
        with self.assertRaises(ProjectError):
            subject.evaluate(evidence(), "2025-12-31T23:59:59Z")

    def test_extension_repeat_failures_and_disagreement(self) -> None:
        value = evidence()
        item: dict[str, Any] = {
            "id": "GATE-DEMO",
            "source_sha256": "a" * 64,
            "samples": [{"status": "pass", "semantic_sha256": "b" * 64} for _ in range(3)],
        }
        value["extensions"] = [item]
        self.assertEqual("pass", subject.evaluate(value, AS_OF)["status"])
        for status in ("fail", "error", "timeout", "truncated"):
            item["samples"][0]["status"] = status
            result = subject.evaluate(value, AS_OF)
            self.assertEqual("fail", result["status"])
            self.assertTrue(result["extensions"][0]["nondeterministic"])
            self.assertEqual(1, result["extensions"][0]["failures"])
        for sample in item["samples"]:
            sample["status"] = "fail"
        result = subject.evaluate(value, AS_OF)
        self.assertFalse(result["extensions"][0]["nondeterministic"])
        self.assertEqual("fail", result["status"])

    def test_retention_budget_decisions_do_not_delete(self) -> None:
        value = evidence()
        value["retained"] = [retained()]
        self.assertEqual([], subject.evaluate(value, AS_OF)["cleanup"])
        mutations = [
            ("classification", "raw-content", "unreviewed-or-raw-content"),
            ("classification", "unreviewed", "unreviewed-or-raw-content"),
            ("bytes", 65537, "record-size-budget"),
            ("expires_at", "2026-01-08T00:00:01Z", "retention-window-budget"),
            ("expires_at", AS_OF, "expired-evidence"),
        ]
        sentinel = self.scratch / "retained.txt"
        sentinel.write_text("public fixture")
        for field, replacement, reason in mutations:
            value["retained"] = [{**retained(), field: replacement}]
            self.assertEqual(reason, subject.evaluate(value, AS_OF)["cleanup"][0]["reason"])
        for records in (
            [retained(index) for index in range(65)],
            [{**retained(index), "bytes": 65536} for index in range(17)],
        ):
            value["retained"] = records
            self.assertEqual(
                "inventory-budget", subject.evaluate(value, AS_OF)["cleanup"][-1]["reason"]
            )
        self.assertEqual("public fixture", sentinel.read_text())

    def test_closed_shapes_numeric_bounds_and_chronology(self) -> None:
        value: Any
        changes: list[tuple[str, Any]] = [
            ("extra", "PRIVATE"),
            ("schema_version", True),
            ("kind", "proof"),
            ("profile", []),
            ("profile", "unbounded"),
            ("reference_ns", {}),
            ("fixture_set_sha256", "0" * 64),
            ("runs", []),
            ("extensions", [{}] * 17),
            ("retained", [{}] * 129),
            ("observed_at", "2026-02-30T00:00:00Z"),
        ]
        for field, replacement in changes:
            with self.subTest(field=field), self.assertRaises(ProjectError):
                subject.evaluate({**evidence(), field: replacement}, AS_OF)
        for value in (None, [], {}):
            with self.assertRaises(ProjectError):
                subject.request(value)
        for value in (True, 1.0, 0, 2_000_000_001):
            altered = budget()
            altered["reference_ns"]["small"]["checks"] = value
            with self.assertRaises(ProjectError):
                subject.request(altered)
        for stamp in ("yesterday", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00.0Z"):
            with self.assertRaises(ProjectError):
                subject.timestamp(stamp)
        for field, value in (("trial", True), ("trial", 7), ("fixture", "large"), ("stages", {})):
            altered = evidence()
            altered["runs"][0][field] = value
            with self.assertRaises(ProjectError):
                subject.evaluate(altered, AS_OF)
        for field, value in (
            ("elapsed_ns", -1),
            ("elapsed_ns", True),
            ("status", "skipped"),
            ("semantic_sha256", "PRIVATE"),
        ):
            altered = evidence()
            altered["runs"][0]["stages"]["checks"][field] = value
            with self.assertRaises(ProjectError):
                subject.evaluate(altered, AS_OF)

    def test_invalid_extension_and_retention_records(self) -> None:
        value: Any
        extension = {
            "id": "GATE-A",
            "source_sha256": "a" * 64,
            "samples": [{"status": "pass", "semantic_sha256": "b" * 64} for _ in range(3)],
        }
        for field, value in (
            ("id", "../PRIVATE"),
            ("source_sha256", "x"),
            ("samples", []),
            ("samples", [{"status": "unknown", "semantic_sha256": "b" * 64}] * 3),
        ):
            with self.assertRaises(ProjectError):
                subject._extensions([{**extension, field: value}], 3)
        with self.assertRaises(ProjectError):
            subject._extensions([extension, extension], 3)
        for field, value in (
            ("id", "/PRIVATE"),
            ("sha256", "x"),
            ("bytes", 0),
            ("created_at", "2026-01-02T00:00:00Z"),
            ("expires_at", "2025-12-31T00:00:00Z"),
            ("classification", "safe"),
        ):
            with self.assertRaises(ProjectError):
                subject._retained([{**retained(), field: value}], subject.timestamp(AS_OF))
        for second in (retained(), {**retained(1), "sha256": retained()["sha256"]}):
            with self.assertRaises(ProjectError):
                subject._retained([retained(), second], subject.timestamp(AS_OF))

    def test_confined_files_scratch_and_redacted_errors(self) -> None:
        path = self.scratch / "input.json"
        path.write_bytes(canonical_bytes(evidence()))
        self.assertEqual("pass", subject.run_file(self.scratch, "input.json", AS_OF)["status"])
        (self.scratch / "link.json").symlink_to(path)
        for relative in ("../input.json", str(path), "link.json", "missing"):
            with self.assertRaises(ProjectError):
                subject.run_file(self.scratch, relative, AS_OF)
        for raw in (b" " + canonical_bytes(evidence()), b'{"kind":0,"kind":1}\n', b"x" * 256001):
            path.write_bytes(raw)
            with self.assertRaises(ProjectError):
                subject.run_file(self.scratch, "input.json", AS_OF)
        for scratch in (Path(), path):
            with self.assertRaises(ProjectError):
                subject.collect(budget(), scratch, AS_OF)
        path.write_bytes(canonical_bytes(evidence()))
        with (
            mock.patch.object(subject, "evaluate", side_effect=RuntimeError("PRIVATE")),
            self.assertRaisesRegex(
                ProjectError, "^reliability input or execution is invalid or unavailable$"
            ),
        ):
            subject.run_file(self.scratch, "input.json", AS_OF)

    def test_trial_timeout_output_bounds_errors_and_resource_limits(self) -> None:
        for raw, code, expected in (
            (b"x" * 65536, 0, "truncated"),
            (b"{}", 0, "error"),
            (b"", 1, "error"),
        ):
            output = io.BytesIO(raw)
            process = mock.MagicMock()
            process.__enter__.return_value = process
            process.wait.return_value = code
            with (
                mock.patch.object(subprocess, "Popen", return_value=process),
                mock.patch.object(tempfile, "TemporaryFile", return_value=output),
                mock.patch.object(os, "killpg"),
            ):
                self.assertEqual(
                    expected, subject._trial("small", self.scratch)["checks"]["status"]
                )
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.wait.side_effect = [subprocess.TimeoutExpired("worker", 30), 0]
        with (
            mock.patch.object(subprocess, "Popen", return_value=process),
            mock.patch.object(os, "killpg") as kill,
        ):
            self.assertEqual("timeout", subject._trial("small", self.scratch)["checks"]["status"])
            self.assertEqual(2, kill.call_count)
        with mock.patch.object(subprocess, "Popen", side_effect=OSError):
            self.assertEqual("error", subject._trial("small", self.scratch)["checks"]["status"])
        with mock.patch.object(os, "name", "nt"), self.assertRaises(ProjectError):
            subject._trial("small", self.scratch)
        with mock.patch.object(resource, "setrlimit") as limits:
            subject._limits()
        self.assertEqual(2, limits.call_count)

    def test_timeout_kills_real_descendant(self) -> None:
        marker = self.scratch / "descendant.txt"
        child = (
            "import time; from pathlib import Path; time.sleep(2); Path("
            + repr(str(marker))
            + ").write_text('public')"
        )
        program = (
            "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',"
            + repr(child)
            + "]); time.sleep(20)"
        )
        original = subprocess.Popen

        def spawn(_argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
            return original([sys.executable, "-c", program], **kwargs)

        with (
            mock.patch.object(subprocess, "Popen", side_effect=spawn),
            mock.patch.object(subject, "TIMEOUT", 1),
            mock.patch.object(subject, "_limits"),
        ):
            self.assertEqual("timeout", subject._trial("small", self.scratch)["checks"]["status"])
        time.sleep(1.2)
        self.assertFalse(marker.exists())

    def test_cli_script_worker_entrypoints(self) -> None:
        sample = evidence()["runs"][0]["stages"]
        for command, relative in (
            ("reliability-evaluate", "fixtures/conforming/reliability/observation.json"),
            ("reliability-collect", "templates/reliability-pr.json"),
        ):
            args = ["--root", str(ROOT), command, relative, "--as-of", AS_OF, "--format", "json"]
            if command.endswith("collect"):
                args += ["--scratch", str(self.scratch)]
            with (
                mock.patch.object(subject, "_trial", return_value=sample),
                mock.patch.object(sys, "stdout", new_callable=io.StringIO) as output,
            ):
                self.assertEqual(0, main(args))
                self.assertEqual("pass", json.loads(output.getvalue())["status"])
        for returned in ({"status": "pass"}, {"status": "fail"}):
            stream = mock.Mock(buffer=io.BytesIO())
            with (
                mock.patch.object(subject, "run_file", return_value=returned),
                mock.patch.object(sys, "stdout", stream),
            ):
                self.assertEqual(
                    0 if returned["status"] == "pass" else 1,
                    reliability_campaign.main(["--scratch", str(self.scratch), "--as-of", AS_OF]),
                )
        stream = mock.Mock(buffer=io.BytesIO())
        with (
            mock.patch.object(subject, "run_file", side_effect=ProjectError("PRIVATE")),
            mock.patch.object(sys, "stdout", stream),
        ):
            self.assertEqual(
                1, reliability_campaign.main(["--scratch", str(self.scratch), "--as-of", AS_OF])
            )
        self.assertNotIn(b"PRIVATE", stream.buffer.getvalue())
        with (
            mock.patch.object(worker, "benchmark", return_value=sample),
            mock.patch.object(sys, "stdout", stream),
        ):
            self.assertEqual(0, worker.main(["small", str(self.scratch)]))
            self.assertEqual(1, worker.main([]))
            with mock.patch.object(worker, "benchmark", side_effect=ValueError):
                self.assertEqual(1, worker.main(["small", str(self.scratch)]))


if __name__ == "__main__":
    unittest.main()
