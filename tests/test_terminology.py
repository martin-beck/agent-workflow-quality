# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Consumer terminology registry and lexical checker tests."""

from __future__ import annotations

import json
import unittest
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema

from awq import checks, commands, terminology
from awq.registry import load_registry
from tests.support import Repository, base_exception, base_policy

ROOT = Path(__file__).resolve().parents[1]


def contract() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "default_scope": "normative",
        "formats": [".json", ".md", ".txt"],
        "scope_rules": [
            {"scope": "generated", "paths": ["generated/**"]},
            {"scope": "example", "paths": ["fixtures/**"]},
        ],
        "terms": [
            {
                "id": "TERM-PRIMARY",
                "canonical": "primary",
                "aliases": ["master", "café"],
                "scopes": ["normative"],
                "severity": "error",
                "case_policy": "casefold",
            },
            {
                "id": "TERM-GENERATED",
                "canonical": "worker",
                "aliases": ["slave"],
                "scopes": ["generated"],
                "severity": "advisory",
                "case_policy": "exact",
            },
        ],
        "exceptions": [],
    }


class TerminologyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repository()
        self.repo.json("quality/terminology.json", contract())

    def tearDown(self) -> None:
        self.repo.close()

    def evaluate(self, *names: str) -> tuple[list[dict[str, str]], list[str]]:
        return terminology.evaluate(self.repo.root, [self.repo.root / name for name in names])

    def test_profile_and_canonical_positive_case(self) -> None:
        requirements, profiles, _ = load_registry()
        self.assertEqual(["AWQ-TERM-001"], profiles["terminology"]["requirements"])
        self.assertEqual("terminology-vocabulary", requirements["AWQ-TERM-001"]["command"])
        self.repo.write("README.md", "Use the primary branch.\n")
        self.assertEqual(([], []), self.evaluate("README.md", "quality/terminology.json"))

    def test_opt_in_profile_runs_end_to_end(self) -> None:
        repository = Repository()
        self.addCleanup(repository.close)
        repository.json("quality/terminology.json", contract())
        repository.write("README.md", "Use the primary branch.\n")
        commands.initialize(repository.root, ["terminology"], False)
        repository.commit()
        self.assertEqual("pass", commands.check(repository.root, "pr")["status"])
        repository.write("README.md", "Use the master branch.\n")
        repository.commit()
        result = commands.check(repository.root, "pr")
        self.assertEqual("fail", result["status"])
        self.assertEqual("AWQ-TERM-001", result["requirements"][0]["id"])

    def test_public_schema_accepts_template_and_rejects_unknown_fields(self) -> None:
        schema = json.loads((ROOT / "schemas/terminology-registry.schema.json").read_text())
        template = json.loads((ROOT / "templates/terminology.json").read_text())
        jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(
            template
        )
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate({**template, "unknown": True})

    def test_unicode_casefold_boundaries_and_minimized_finding(self) -> None:
        self.repo.write("README.md", "Use MASTER, CAFE\u0301, and masterful.\n")
        findings, _ = self.evaluate("README.md")
        self.assertEqual(1, len(findings))
        self.assertEqual("terminology-error", findings[0]["code"])
        self.assertEqual("README.md", findings[0]["path"])
        self.assertEqual(
            "TERM-PRIMARY has a forbidden alias in normative scope", findings[0]["message"]
        )
        self.assertNotIn("master", json.dumps(findings).casefold())
        self.assertNotIn("café", json.dumps(findings).casefold())
        requirement = load_registry()[0]["AWQ-TERM-001"]
        exception = base_exception(requirement="AWQ-TERM-001", scope=["README.md"])
        result = checks.run_requirement(
            self.repo.root,
            base_policy(exceptions=[exception]),
            requirement,
            [self.repo.root / "README.md"],
        )
        self.assertEqual("fail", result["status"])
        self.assertEqual([], result["exceptions"])

    def test_markdown_scopes_are_independent(self) -> None:
        document = self.repo.write(
            "guide.md",
            "master is normative\n\n> master is quoted\n\n```text\nmaster is an example\n```\n",
        )
        findings, _ = terminology.evaluate(self.repo.root, [document])
        self.assertEqual(1, len(findings))
        self.assertIn("normative scope", findings[0]["message"])
        value = contract()
        value["terms"][0]["scopes"] = ["quotation", "example"]
        self.repo.json("quality/terminology.json", value)
        findings, _ = terminology.evaluate(self.repo.root, [document])
        self.assertEqual(
            {"quotation", "example"}, {item["message"].split()[-2] for item in findings}
        )

    def test_generated_fixture_json_and_selected_formats(self) -> None:
        generated = self.repo.write("generated/catalog.json", '{"role":"slave"}\n')
        fixture = self.repo.write("fixtures/history.txt", "master\n")
        ignored = self.repo.write("source.py", "master\n")
        findings, _ = terminology.evaluate(self.repo.root, [generated, fixture, ignored])
        self.assertEqual(["terminology-advisory"], [item["code"] for item in findings])
        self.assertEqual("generated/catalog.json", findings[0]["path"])

    def test_advisory_does_not_fail_requirement(self) -> None:
        generated = self.repo.write("generated/catalog.txt", "slave\n")
        requirement = load_registry()[0]["AWQ-TERM-001"]
        result = checks.run_requirement(self.repo.root, base_policy(), requirement, [generated])
        self.assertEqual("pass", result["status"])
        self.assertEqual("terminology-advisory", result["findings"][0]["code"])

    def test_active_exception_is_reported_without_a_finding(self) -> None:
        value = contract()
        value["exceptions"] = [
            {
                "id": "TERM-EX-0001",
                "term": "TERM-PRIMARY",
                "owner": "@example/quality",
                "reason": "Historical name in a migration notice.",
                "paths": ["README.md"],
                "scopes": ["normative"],
                "created_at": "2026-09-01T00:00:00+00:00",
                "expires_at": "2026-09-30T00:00:00+00:00",
                "compensating_evidence": "The replacement is stated beside the historical name.",
                "review_reference": "urn:example:review:TERM-EX-0001",
            }
        ]
        self.repo.json("quality/terminology.json", value)
        document = self.repo.write("README.md", "master\n")
        findings, used = terminology.evaluate(
            self.repo.root, [document], now=datetime(2026, 9, 10, tzinfo=UTC)
        )
        self.assertEqual([], findings)
        self.assertEqual(["TERM-EX-0001"], used)
        value["exceptions"][0]["created_at"] = "2026-09-20T00:00:00+00:00"
        value["exceptions"][0]["expires_at"] = "2026-09-21T00:00:00+00:00"
        self.repo.json("quality/terminology.json", value)
        findings, used = terminology.evaluate(
            self.repo.root, [document], now=datetime(2026, 9, 10, tzinfo=UTC)
        )
        self.assertEqual(1, len(findings))
        self.assertEqual([], used)

    def test_expired_exception_and_overlong_lifetime_fail_closed(self) -> None:
        value = contract()
        exception = {
            "id": "TERM-EX-0001",
            "term": "TERM-PRIMARY",
            "owner": "@example",
            "reason": "Migration notice.",
            "paths": ["README.md"],
            "scopes": ["normative"],
            "created_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2026-04-02T00:00:00+00:00",
            "compensating_evidence": "Reviewed notice.",
            "review_reference": "https://example.invalid/reviews/1",
        }
        value["exceptions"] = [exception]
        with self.assertRaisesRegex(terminology.TerminologyError, "exception-lifetime"):
            terminology.validate(value)
        exception["created_at"] = "2026-09-01T00:00:00+00:00"
        exception["expires_at"] = "2026-09-02T00:00:00+00:00"
        self.repo.json("quality/terminology.json", value)
        document = self.repo.write("README.md", "master\n")
        findings, used = terminology.evaluate(
            self.repo.root, [document], now=datetime(2026, 9, 10, tzinfo=UTC)
        )
        self.assertEqual(1, len(findings))
        self.assertEqual([], used)

    def test_unknown_fields_unsafe_paths_and_duplicates_are_rejected(self) -> None:
        cases = []
        value = contract()
        value["unknown"] = True
        cases.append(value)
        value = contract()
        value["scope_rules"][0]["paths"] = ["../generated/**"]
        cases.append(value)
        value = contract()
        value["terms"].append(deepcopy(value["terms"][0]))
        cases.append(value)
        value = contract()
        value["terms"][1]["aliases"] = ["MASTER"]
        value["terms"][1]["case_policy"] = "casefold"
        cases.append(value)
        value = contract()
        value["terms"][0]["case_policy"] = "exact"
        value["terms"][0]["aliases"] = ["MASTER"]
        value["terms"][1]["case_policy"] = "casefold"
        value["terms"][1]["aliases"] = ["master"]
        cases.append(value)
        value = contract()
        value["terms"][1]["canonical"] = "PRIMARY"
        cases.append(value)
        value = contract()
        value["terms"][1]["canonical"] = "master"
        cases.append(value)
        value = contract()
        value["terms"][0]["case_policy"] = "exact"
        value["terms"][0]["aliases"] = ["MASTER"]
        value["terms"][1]["case_policy"] = "casefold"
        value["terms"][1]["canonical"] = "master"
        value["terms"][1]["aliases"] = ["worker"]
        cases.append(value)
        for invalid in cases:
            with self.subTest(invalid=invalid), self.assertRaises(terminology.TerminologyError):
                terminology.validate(invalid)

    def test_ambiguous_path_scope_and_invalid_contract_are_minimized(self) -> None:
        value = contract()
        value["scope_rules"].append({"scope": "quotation", "paths": ["generated/*.md"]})
        self.repo.json("quality/terminology.json", value)
        document = self.repo.write("generated/readme.md", "master\n")
        finding = checks.terminology_vocabulary(self.repo.root, [document], base_policy())[0]
        self.assertEqual("terminology-contract", finding.code)
        self.assertEqual("terminology contract is invalid", finding.message)
        requirement = load_registry()[0]["AWQ-TERM-001"]
        exception = {
            "id": "EX-0001",
            "kind": "standard",
            "requirement": "AWQ-TERM-001",
            "owner": "@owner",
            "reason": "Attempt to bypass an invalid contract.",
            "scope": ["quality/terminology.json"],
            "created_at": "2026-09-10T00:00:00+00:00",
            "expires_at": "2026-09-11T00:00:00+00:00",
            "compensating_evidence": "Synthetic hostile fixture.",
            "approval": "urn:example:review:EX-0001",
            "renewals": [],
            "revocation": None,
        }
        result = checks.run_requirement(
            self.repo.root, base_policy(exceptions=[exception]), requirement, [document]
        )
        self.assertEqual("fail", result["status"])
        self.assertEqual([], result["exceptions"])

    def test_duplicate_json_keys_and_missing_contract_fail_closed(self) -> None:
        path = self.repo.root / "quality" / "terminology.json"
        path.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")
        with self.assertRaisesRegex(terminology.TerminologyError, "duplicate-json-key"):
            terminology.load(self.repo.root)
        path.unlink()
        finding = checks.terminology_vocabulary(self.repo.root, [], base_policy())[0]
        self.assertEqual("terminology-contract", finding.code)


if __name__ == "__main__":
    unittest.main()
