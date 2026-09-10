# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Generic structured test-report evidence and hostile fixtures."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import unittest
from types import SimpleNamespace
from typing import Any
from unittest import mock

from awq import test_reports
from awq.cli import main
from scripts.validate_contracts import validate
from tests.support import Repository


def report(name: str, outcomes: tuple[str, ...]) -> str:
    cases = []
    for index, outcome in enumerate(outcomes):
        child = "" if not outcome else f"<{outcome}/>"
        cases.append(f'<testcase name="case-{index}">{child}</testcase>')
    counts = {kind: outcomes.count(kind) for kind in ("failure", "error", "skipped")}
    return (
        f'<testsuite name="{name}" tests="{len(outcomes)}" '
        f'failures="{counts["failure"]}" errors="{counts["error"]}" '
        f'skipped="{counts["skipped"]}">' + "".join(cases) + "</testsuite>"
    )


class TestReportEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = Repository()

    def tearDown(self) -> None:
        self.repository.close()

    def contract(self, producers: list[tuple[str, str, tuple[str, ...]]]) -> dict[str, Any]:
        records = []
        roots = []
        modules = []
        for module, producer, outcomes in producers:
            relative = f"reports/{module}/{producer}.xml"
            self.repository.write(relative, report(f"{module}.{producer}", outcomes))
            roots.append(f"reports/{module}")
            modules.append(module)
            records.append(
                {
                    "module": module,
                    "path": relative,
                    "sha256": hashlib.sha256(
                        (self.repository.root / relative).read_bytes()
                    ).hexdigest(),
                }
            )
        self.repository.commit("reports")
        return {
            "collected_at": "2026-09-10T20:00:00Z",
            "kind": "junit-report-contract",
            "max_age_seconds": 3600,
            "minimum_discovered": 1,
            "minimum_executed": 1,
            "producer": {
                "configuration_sha256": "1" * 64,
                "id": "mixed.junit",
                "version": "1.0.0",
            },
            "report_roots": sorted(set(roots)),
            "reports": sorted(records, key=lambda item: item["path"]),
            "required_modules": sorted(set(modules)),
            "schema_version": 1,
            "skip_policy": "allow",
            "source_revision": self.repository.head(),
        }

    def test_python_jvm_and_mixed_module_reports_prove_execution(self) -> None:
        fixtures: list[list[tuple[str, str, tuple[str, ...]]]] = [
            [("python", "pytest", ("", "skipped"))],
            [("jvm", "gradle", ("", ""))],
            [("jvm", "gradle", ("",)), ("python", "pytest", ("", "skipped"))],
        ]
        for producers in fixtures:
            with self.subTest(producers=producers):
                value = self.contract(producers)
                result = test_reports.evaluate(self.repository.root, value, "2026-09-10T20:30:00Z")
                validate(value, "test-report-evidence.schema.json")
                validate(result, "test-report-evidence.schema.json")
                self.assertEqual("executed-test-report", result["classification"])
                self.assertEqual(len(producers), result["totals"]["reports"])
                self.assertNotIn("case-0", json.dumps(result))
                self.repository.close()
                self.repository = Repository()

    def test_failures_errors_empty_all_skipped_and_count_lies_fail(self) -> None:
        for outcomes, message in (
            (("failure",), "failures"),
            (("error",), "failures"),
            (("skipped",), "floor"),
        ):
            value = self.contract([("module", "runner", outcomes)])
            with (
                self.subTest(outcomes=outcomes),
                self.assertRaisesRegex(test_reports.TestReportError, message),
            ):
                test_reports.evaluate(self.repository.root, value, "2026-09-10T20:30:00Z")
            self.repository.close()
            self.repository = Repository()
        value = self.contract([("module", "runner", ("",))])
        path = self.repository.root / "reports/module/runner.xml"
        path.write_text('<testsuite name="empty" tests="0" failures="0" errors="0" skipped="0"/>')
        value["reports"][0]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(test_reports.TestReportError, "empty suite"):
            test_reports.evaluate(self.repository.root, value, "2026-09-10T20:30:00Z")
        path.write_text(report("lie", ("",)).replace('tests="1"', 'tests="2"'))
        value["reports"][0]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(test_reports.TestReportError, "inconsistent"):
            test_reports.evaluate(self.repository.root, value, "2026-09-10T20:30:00Z")

    def test_exact_set_modules_freshness_revision_paths_and_entities_fail(self) -> None:
        value = self.contract([("module", "runner", ("",))])
        mutations = []
        missing = copy.deepcopy(value)
        missing["required_modules"] = ["missing"]
        mutations.append((missing, "module"))
        stale = copy.deepcopy(value)
        stale["collected_at"] = "2026-09-01T00:00:00Z"
        mutations.append((stale, "stale"))
        wrong = copy.deepcopy(value)
        wrong["source_revision"] = "0" * 40
        mutations.append((wrong, "revision"))
        unsafe = copy.deepcopy(value)
        unsafe["reports"][0]["path"] = "../escape.xml"
        mutations.append((unsafe, "escapes"))
        artifact = copy.deepcopy(value)
        artifact["artifact_available"] = True
        mutations.append((artifact, "unknown"))
        for candidate, message in mutations:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(test_reports.TestReportError, message),
            ):
                test_reports.evaluate(self.repository.root, candidate, "2026-09-10T20:30:00Z")
        self.repository.write("reports/module/orphan.xml", report("orphan", ("",)))
        with self.assertRaisesRegex(test_reports.TestReportError, "unexpected"):
            test_reports.evaluate(self.repository.root, value, "2026-09-10T20:30:00Z")
        orphan = self.repository.root / "reports/module/orphan.xml"
        orphan.unlink()
        path = self.repository.root / "reports/module/runner.xml"
        path.write_text(
            '<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///etc/passwd">]>'
            '<testsuite name="x" tests="1" failures="0" errors="0" skipped="0">'
            '<testcase name="x">&secret;</testcase></testsuite>'
        )
        value["reports"][0]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(test_reports.TestReportError, "forbidden"):
            test_reports.evaluate(self.repository.root, value, "2026-09-10T20:30:00Z")

    def test_skip_policy_duplicate_json_and_cli(self) -> None:
        value = self.contract([("module", "runner", ("", "skipped"))])
        value["skip_policy"] = "forbid"
        with self.assertRaisesRegex(test_reports.TestReportError, "skip policy"):
            test_reports.evaluate(self.repository.root, value, "2026-09-10T20:30:00Z")
        value["skip_policy"] = "allow"
        self.repository.json("observation.json", value)
        self.assertEqual(
            0,
            main(
                [
                    "--root",
                    str(self.repository.root),
                    "test-report-evaluate",
                    "observation.json",
                    "--as-of",
                    "2026-09-10T20:30:00Z",
                    "--format",
                    "json",
                ]
            ),
        )
        (self.repository.root / "duplicate.json").write_text(
            '{"schema_version":1,"schema_version":1}\n'
        )
        with self.assertRaisesRegex(test_reports.TestReportError, "duplicate"):
            test_reports.evaluate_file(
                self.repository.root, "duplicate.json", "2026-09-10T20:30:00Z"
            )

    def test_contract_field_and_parser_boundaries(self) -> None:
        value = self.contract([("module", "runner", ("",))])
        mutations: list[tuple[object, str]] = [([], "unknown or missing")]
        for key, replacement, message in (
            ("schema_version", 2, "version or kind"),
            ("source_revision", "bad", "source revision"),
            ("report_roots", [], "report roots"),
            ("reports", [], "declared reports"),
            ("required_modules", [], "required modules"),
            ("minimum_discovered", 0, "minimum discovered"),
            ("minimum_executed", 0, "minimum executed"),
            ("skip_policy", "sometimes", "skip policy"),
            ("max_age_seconds", 0, "maximum age"),
            ("collected_at", "invalid", "collection time"),
        ):
            mutation = copy.deepcopy(value)
            mutation[key] = replacement
            mutations.append((mutation, message))
        for field, replacement, message in (
            ("id", "*", "producer identifier"),
            ("version", "", "producer version"),
            ("configuration_sha256", "bad", "configuration digest"),
        ):
            mutation = copy.deepcopy(value)
            producer = mutation["producer"]
            assert isinstance(producer, dict)
            producer[field] = replacement
            mutations.append((mutation, message))
        for invalid, message in mutations:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(test_reports.TestReportError, message),
            ):
                test_reports.evaluate(self.repository.root, invalid, "2026-09-10T20:30:00Z")
        path = self.repository.root / "reports/module/runner.xml"
        for content, message in (
            (b"", "byte size"),
            (b"\xff", "not UTF-8"),
            (b"<broken", "malformed"),
            (b"<unknown/>", "root is unsupported"),
            (b"<testsuites/>", "suite count"),
            (
                b'<testsuite tests="1" failures="0" errors="0" skipped="0">'
                b'<testcase name="x"/></testsuite>',
                "suite name",
            ),
            (
                b'<testsuite name="x" tests="-1" failures="0" errors="0" skipped="0">'
                b'<testcase name="x"/></testsuite>',
                "invalid count",
            ),
            (
                b'<testsuite name="x" tests="1" failures="1" errors="1" skipped="0">'
                b'<testcase name="x"><failure/><error/></testcase></testsuite>',
                "contradictory",
            ),
        ):
            path.write_bytes(content)
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(test_reports.TestReportError, message),
            ):
                test_reports.parse_junit_report(path)
        path.write_text(report("valid", ("",)))
        reports = value["reports"]
        assert isinstance(reports, list)
        assert isinstance(reports[0], dict)
        record: dict[str, Any] = reports[0]
        record["sha256"] = "0" * 64
        with self.assertRaisesRegex(test_reports.TestReportError, "digest mismatch"):
            test_reports.summarize_declared_reports(self.repository.root, reports)
        with self.assertRaisesRegex(test_reports.TestReportError, "report count"):
            test_reports.summarize_declared_reports(self.repository.root, [])
        record["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        with (
            mock.patch.object(test_reports, "MAX_REPORT_BYTES", 1),
            self.assertRaisesRegex(test_reports.TestReportError, "bytes exceed"),
        ):
            test_reports.summarize_declared_reports(self.repository.root, reports)
        record["path"] = "reports/module/missing.xml"
        with self.assertRaisesRegex(test_reports.TestReportError, "unavailable"):
            test_reports.summarize_declared_reports(self.repository.root, reports)

    def test_file_contract_rejects_noncanonical_encoding_and_size(self) -> None:
        value = self.contract([("module", "runner", ("",))])
        self.repository.json("contract.json", value)
        path = self.repository.root / "contract.json"
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(test_reports.TestReportError, "not canonical"):
            test_reports.evaluate_file(
                self.repository.root, "contract.json", "2026-09-10T20:30:00Z"
            )
        path.write_bytes(b"\xff")
        with self.assertRaisesRegex(test_reports.TestReportError, "invalid JSON"):
            test_reports.evaluate_file(
                self.repository.root, "contract.json", "2026-09-10T20:30:00Z"
            )
        path.write_bytes(b"")
        with self.assertRaisesRegex(test_reports.TestReportError, "byte size"):
            test_reports.evaluate_file(
                self.repository.root, "contract.json", "2026-09-10T20:30:00Z"
            )
        with self.assertRaisesRegex(test_reports.TestReportError, "source revision"):
            test_reports._git_revision(self.repository.root / "not-a-repository")

    def test_remaining_path_time_structure_and_order_guards(self) -> None:
        for raw_path in ("bad\\path", "/absolute", "."):
            with self.subTest(value=raw_path), self.assertRaises(test_reports.TestReportError):
                test_reports._relative(raw_path)
        with self.assertRaisesRegex(test_reports.TestReportError, "time"):
            test_reports._timestamp("2026-02-29T00:00:00Z", "time")
        with self.assertRaisesRegex(test_reports.TestReportError, "time"):
            test_reports._timestamp("2026-01-01T24:00:00Z", "time")
        with (
            mock.patch.object(
                subprocess,
                "run",
                return_value=SimpleNamespace(stdout=b"\xff", returncode=0),
            ),
            self.assertRaisesRegex(test_reports.TestReportError, "revision"),
        ):
            test_reports._git_revision(self.repository.root)
        value = self.contract([("module", "runner", ("",))])
        path = self.repository.root / "reports/module/runner.xml"
        with (
            mock.patch.object(test_reports, "MAX_XML_DEPTH", 1),
            self.assertRaisesRegex(test_reports.TestReportError, "structural"),
        ):
            test_reports.parse_junit_report(path)
        nested = (
            '<testsuites><testsuite name="outer" tests="2" failures="0" errors="0" skipped="0">'
            + report("one", ("",))
            + report("two", ("",))
            + "</testsuite></testsuites>"
        )
        path.write_text(nested)
        with (
            mock.patch.object(test_reports, "MAX_CASES", 1),
            self.assertRaisesRegex(test_reports.TestReportError, "aggregate"),
        ):
            test_reports.parse_junit_report(path)
        for key, replacement, message in (
            ("report_roots", ["reports/module", "reports"], "not sorted"),
            ("required_modules", ["module", "module"], "not sorted"),
        ):
            mutation = copy.deepcopy(value)
            mutation[key] = replacement
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(test_reports.TestReportError, message),
            ):
                test_reports.evaluate(self.repository.root, mutation, "2026-09-10T20:30:00Z")
        for field, report_replacement, message in (
            ("module", "*", "module"),
            ("sha256", "bad", "digest"),
            ("path", "other/report.xml", "outside"),
        ):
            mutation = copy.deepcopy(value)
            reports = mutation["reports"]
            assert isinstance(reports, list)
            record = reports[0]
            assert isinstance(record, dict)
            record[field] = report_replacement
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(test_reports.TestReportError, message),
            ):
                test_reports.evaluate(self.repository.root, mutation, "2026-09-10T20:30:00Z")
        report_link = self.repository.root / "reports/module/link.xml"
        report_link.symlink_to(path)
        with self.assertRaisesRegex(test_reports.TestReportError, "non-regular"):
            test_reports.evaluate(self.repository.root, value, "2026-09-10T20:30:00Z")


if __name__ == "__main__":
    unittest.main()
