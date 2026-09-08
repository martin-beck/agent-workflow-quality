"""Policy governance, exception lifecycle, and hosting observation tests."""

from __future__ import annotations

import contextlib
import io
import json
import unittest
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock

import jsonschema

from awq import commands
from awq.cli import main
from awq.project import ProjectError, validate_policy
from tests.support import Repository, base_exception, base_policy


class FakeResponse:
    """Minimal bounded urlopen response."""

    def __init__(self, payload: object | bytes) -> None:
        self.data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, amount: int) -> bytes:
        return self.data[:amount]


def extension() -> dict[str, Any]:
    return {
        "id": "LOCAL-GATE",
        "tier": "pr",
        "argv": ["tool", "check"],
        "timeout_seconds": 30,
        "evidence": "mechanical",
        "limitation": "Checks only the declared files.",
        "remediation": "Repair the finding.",
        "formats": [".x", ".y"],
    }


def policy_with_controls() -> dict[str, Any]:
    return base_policy(
        profiles=["core", "docs"],
        fixture_paths=["fixtures/known"],
        extensions=[extension()],
        exceptions=[base_exception()],
        governance={
            "owners": ["@owner", "@second"],
            "max_standard_days": 30,
            "max_emergency_hours": 24,
        },
    )


class ExceptionLifecycleTests(unittest.TestCase):
    def test_valid_standard_renewal_emergency_and_revocation(self) -> None:
        validate_policy(base_policy(exceptions=[base_exception()]))

        renewed = base_exception(
            created_at="2026-01-01T00:00:00+00:00",
            expires_at="2026-01-20T00:00:00+00:00",
            renewals=[
                {
                    "renewed_at": "2026-01-05T00:00:00+00:00",
                    "previous_expires_at": "2026-01-10T00:00:00+00:00",
                    "expires_at": "2026-01-20T00:00:00+00:00",
                    "owner": "@owner",
                    "reason": "Continue the bounded investigation.",
                    "approval": "urn:awq:renewal:EX-0001:1",
                }
            ],
        )
        validate_policy(base_policy(exceptions=[renewed]))

        revoked = {
            **renewed,
            "revocation": {
                "revoked_at": "2026-01-06T00:00:00+00:00",
                "owner": "@owner",
                "reason": "The underlying defect is fixed.",
                "approval": "https://example.invalid/reviews/1",
            },
        }
        validate_policy(base_policy(exceptions=[revoked]))

        emergency = base_exception(
            kind="emergency",
            created_at="2026-01-01T00:00:00+00:00",
            expires_at="2026-01-01T12:00:00+00:00",
        )
        validate_policy(base_policy(exceptions=[emergency]))

    def test_invalid_lifecycle_records_fail_closed(self) -> None:
        valid_renewal = {
            "renewed_at": "2026-01-05T00:00:00+00:00",
            "previous_expires_at": "2026-01-10T00:00:00+00:00",
            "expires_at": "2026-01-20T00:00:00+00:00",
            "owner": "@owner",
            "reason": "Reviewed continuation.",
            "approval": "urn:awq:renewal:1",
        }
        invalid = [
            base_policy(exceptions=[base_exception(id="bad")]),
            base_policy(exceptions=[base_exception(kind="permanent")]),
            base_policy(exceptions=[base_exception(requirement="AWQ-NOPE-999")]),
            base_policy(exceptions=[base_exception(owner="@orphan")]),
            base_policy(exceptions=[base_exception(reason="")]),
            base_policy(exceptions=[base_exception(scope=["../all"])]),
            base_policy(
                exceptions=[base_exception(approval="https://user:secret@example.invalid/1")]
            ),
            base_policy(exceptions=[base_exception(created_at="2026-01-01")]),
            base_policy(
                exceptions=[
                    base_exception(
                        created_at="2026-01-01T00:00:00+00:00",
                        expires_at="2026-02-15T00:00:00+00:00",
                    )
                ]
            ),
            base_policy(
                exceptions=[
                    base_exception(
                        created_at="2026-01-01T00:00:00+00:00",
                        expires_at="2026-01-20T00:00:00+00:00",
                        renewals=[
                            {
                                **valid_renewal,
                                "renewed_at": "2026-01-12T00:00:00+00:00",
                            }
                        ],
                    )
                ]
            ),
            base_policy(
                exceptions=[
                    base_exception(
                        kind="emergency",
                        created_at="2026-01-01T00:00:00+00:00",
                        expires_at="2026-01-01T12:00:00+00:00",
                        renewals=[valid_renewal],
                    )
                ]
            ),
            base_policy(
                exceptions=[
                    base_exception(
                        created_at="2026-01-01T00:00:00+00:00",
                        expires_at="2026-01-10T00:00:00+00:00",
                        revocation={
                            "revoked_at": "2026-01-11T00:00:00+00:00",
                            "owner": "@owner",
                            "reason": "Too late.",
                            "approval": "urn:awq:revocation:1",
                        },
                    )
                ]
            ),
            base_policy(
                governance={"owners": ["owner"], "max_standard_days": 30, "max_emergency_hours": 24}
            ),
            base_policy(
                governance={
                    "owners": ["@owner"],
                    "max_standard_days": 91,
                    "max_emergency_hours": 24,
                }
            ),
            base_policy(exceptions=[base_exception(), base_exception()]),
            base_policy(governance={}),
            base_policy(
                governance={
                    "owners": ["@owner"],
                    "max_standard_days": 30,
                    "max_emergency_hours": 73,
                }
            ),
            base_policy(fixture_paths=["same", "same"]),
            base_policy(extensions=[extension(), extension()]),
            base_policy(extensions=[{**extension(), "argv": []}]),
            base_policy(extensions=[{**extension(), "timeout_seconds": 0}]),
            base_policy(extensions=[{**extension(), "tier": "never"}]),
            base_policy(extensions=[{**extension(), "limitation": ""}]),
            base_policy(extensions=[{**extension(), "formats": [".X"]}]),
            base_policy(exceptions=[{**base_exception(), "approval": None}]),
            base_policy(exceptions=[{**base_exception(), "created_at": None}]),
            base_policy(exceptions=[{**base_exception(), "created_at": "not-a-time"}]),
            base_policy(exceptions=[{**base_exception(), "renewals": {}}]),
            base_policy(exceptions=[{**base_exception(), "renewals": [{}]}]),
            base_policy(
                exceptions=[
                    base_exception(
                        created_at="2026-01-01T00:00:00+00:00",
                        expires_at="2026-03-01T00:00:00+00:00",
                        renewals=[
                            {
                                **valid_renewal,
                                "expires_at": "2026-03-01T00:00:00+00:00",
                            }
                        ],
                    )
                ]
            ),
            base_policy(
                exceptions=[
                    base_exception(
                        created_at="2026-01-01T00:00:00+00:00",
                        expires_at="2026-01-20T00:00:00+00:00",
                        renewals=[{**valid_renewal, "owner": "@orphan"}],
                    )
                ]
            ),
            base_policy(
                exceptions=[
                    base_exception(
                        created_at="2026-01-01T00:00:00+00:00",
                        expires_at="2026-01-20T00:00:00+00:00",
                        renewals=[{**valid_renewal, "reason": ""}],
                    )
                ]
            ),
            base_policy(
                exceptions=[
                    base_exception(
                        created_at="2026-01-01T00:00:00+00:00",
                        expires_at="2026-01-21T00:00:00+00:00",
                        renewals=[valid_renewal],
                    )
                ]
            ),
            base_policy(exceptions=[{**base_exception(), "revocation": {}}]),
            base_policy(
                exceptions=[
                    {
                        **base_exception(),
                        "revocation": {
                            "revoked_at": datetime.now(UTC).isoformat(),
                            "owner": "@orphan",
                            "reason": "No owner.",
                            "approval": "urn:awq:revocation:1",
                        },
                    }
                ]
            ),
            base_policy(
                exceptions=[
                    {
                        **base_exception(),
                        "revocation": {
                            "revoked_at": datetime.now(UTC).isoformat(),
                            "owner": "@owner",
                            "reason": "",
                            "approval": "urn:awq:revocation:1",
                        },
                    }
                ]
            ),
        ]
        for number, policy in enumerate(invalid):
            with self.subTest(case=number), self.assertRaises(ProjectError):
                validate_policy(policy)

    def test_doctor_retains_but_ignores_revoked_history(self) -> None:
        repo = Repository()
        try:
            commands.initialize(repo.root, ["core"], False)
            policy = json.loads((repo.root / "quality/awq.json").read_text())
            policy["exceptions"] = [
                base_exception(
                    owner="@project-maintainers",
                    created_at="2020-01-01T00:00:00+00:00",
                    expires_at="2020-01-02T00:00:00+00:00",
                    revocation={
                        "revoked_at": "2020-01-01T12:00:00+00:00",
                        "owner": "@project-maintainers",
                        "reason": "Resolved.",
                        "approval": "urn:awq:revocation:EX-0001",
                    },
                )
            ]
            repo.json("quality/awq.json", policy)
            self.assertEqual("pass", commands.doctor(repo.root)["status"])
        finally:
            repo.close()


class SemanticDiffTests(unittest.TestCase):
    def classify(self, old: dict[str, Any], new: dict[str, Any], field: str) -> set[str]:
        changes: list[dict[str, str]] = []
        commands._compare_policy(old, new, changes)
        return {
            item["classification"]
            for item in changes
            if item["field"] == field or item["field"].startswith(field + ".")
        }

    def test_every_policy_weakening_surface_is_classified(self) -> None:
        cases: list[tuple[str, str, Any]] = [
            ("profiles", "profiles", lambda p: p["profiles"].remove("docs")),
            ("unknown", "unknown_formats", lambda p: p.__setitem__("unknown_formats", "advisory")),
            ("fixtures", "fixture_paths", lambda p: p["fixture_paths"].append("fixtures/more")),
            ("owners", "governance.owners", lambda p: p["governance"]["owners"].remove("@second")),
            (
                "standard bound",
                "governance.max_standard_days",
                lambda p: p["governance"].__setitem__("max_standard_days", 31),
            ),
            (
                "emergency bound",
                "governance.max_emergency_hours",
                lambda p: p["governance"].__setitem__("max_emergency_hours", 25),
            ),
            ("extension removed", "extensions.LOCAL-GATE", lambda p: p["extensions"].clear()),
            (
                "format removed",
                "extensions.LOCAL-GATE.formats",
                lambda p: p["extensions"][0]["formats"].remove(".y"),
            ),
            (
                "later tier",
                "extensions.LOCAL-GATE.tier",
                lambda p: p["extensions"][0].__setitem__("tier", "scheduled"),
            ),
            (
                "command",
                "extensions.LOCAL-GATE.argv",
                lambda p: p["extensions"][0].__setitem__("argv", ["other"]),
            ),
            (
                "evidence",
                "extensions.LOCAL-GATE.evidence",
                lambda p: p["extensions"][0].__setitem__("evidence", "environmental"),
            ),
            (
                "limitation",
                "extensions.LOCAL-GATE.limitation",
                lambda p: p["extensions"][0].__setitem__("limitation", "Changed."),
            ),
            (
                "deadline",
                "extensions.LOCAL-GATE.timeout_seconds",
                lambda p: p["extensions"][0].__setitem__("timeout_seconds", 1),
            ),
            (
                "scope",
                "exceptions.EX-0001.scope",
                lambda p: p["exceptions"][0]["scope"].append("*"),
            ),
            (
                "silent expiry",
                "exceptions.EX-0001.expires_at",
                lambda p: p["exceptions"][0].__setitem__("expires_at", "2030-01-01T00:00:00+00:00"),
            ),
            (
                "kind",
                "exceptions.EX-0001.kind",
                lambda p: p["exceptions"][0].__setitem__("kind", "emergency"),
            ),
            (
                "requirement",
                "exceptions.EX-0001.requirement",
                lambda p: p["exceptions"][0].__setitem__("requirement", "AWQ-CORE-002"),
            ),
            (
                "exception owner",
                "exceptions.EX-0001.owner",
                lambda p: p["exceptions"][0].__setitem__("owner", "@second"),
            ),
            (
                "reason",
                "exceptions.EX-0001.reason",
                lambda p: p["exceptions"][0].__setitem__("reason", "Changed."),
            ),
            (
                "created",
                "exceptions.EX-0001.created_at",
                lambda p: p["exceptions"][0].__setitem__("created_at", "2026-01-01T00:00:00+00:00"),
            ),
            (
                "compensation",
                "exceptions.EX-0001.compensating_evidence",
                lambda p: p["exceptions"][0].__setitem__("compensating_evidence", "Changed."),
            ),
            (
                "approval",
                "exceptions.EX-0001.approval",
                lambda p: p["exceptions"][0].__setitem__("approval", "urn:changed"),
            ),
            (
                "history",
                "exceptions.EX-0001.renewals",
                lambda p: p["exceptions"][0].__setitem__("renewals", [{"tampered": True}]),
            ),
            ("record removal", "exceptions.EX-0001", lambda p: p["exceptions"].clear()),
        ]
        for name, field, mutate in cases:
            old = policy_with_controls()
            new = deepcopy(old)
            mutate(new)
            with self.subTest(surface=name):
                self.assertIn("weakening", self.classify(old, new, field))

    def test_strengthening_review_and_lifecycle_classification(self) -> None:
        old = policy_with_controls()

        longer_timeout = deepcopy(old)
        longer_timeout["extensions"][0]["timeout_seconds"] = 60
        self.assertEqual(
            {"strengthening"},
            self.classify(old, longer_timeout, "extensions.LOCAL-GATE.timeout_seconds"),
        )

        remediation = deepcopy(old)
        remediation["extensions"][0]["remediation"] = "Use the documented repair."
        self.assertEqual(
            {"review"}, self.classify(old, remediation, "extensions.LOCAL-GATE.remediation")
        )

        renewal = deepcopy(old)
        previous = old["exceptions"][0]["expires_at"]
        extended = (datetime.fromisoformat(previous) + timedelta(days=1)).isoformat()
        renewal["exceptions"][0]["expires_at"] = extended
        renewal["exceptions"][0]["renewals"] = [
            {
                "renewed_at": datetime.now(UTC).isoformat(),
                "previous_expires_at": previous,
                "expires_at": extended,
                "owner": "@owner",
                "reason": "Reviewed.",
                "approval": "urn:awq:renewal:EX-0001:1",
            }
        ]
        self.assertEqual({"review"}, self.classify(old, renewal, "exceptions.EX-0001.expires_at"))
        self.assertNotIn("weakening", self.classify(old, renewal, "exceptions.EX-0001.renewals"))

        revoked = deepcopy(old)
        revoked["exceptions"][0]["revocation"] = {
            "revoked_at": datetime.now(UTC).isoformat(),
            "owner": "@owner",
            "reason": "Resolved.",
            "approval": "urn:awq:revocation:EX-0001",
        }
        self.assertEqual(
            {"strengthening"}, self.classify(old, revoked, "exceptions.EX-0001.revocation")
        )
        self.assertEqual(
            {"weakening"}, self.classify(revoked, old, "exceptions.EX-0001.revocation")
        )

        added = deepcopy(old)
        added["exceptions"].append(base_exception(id="EX-0002"))
        self.assertEqual({"review"}, self.classify(old, added, "exceptions.EX-0002"))

    def test_strengthening_additions_and_lock_fields_are_classified(self) -> None:
        old = policy_with_controls()
        new = deepcopy(old)
        new["profiles"].append("schemas")
        new["fixture_paths"].clear()
        new["governance"]["owners"].append("@third")
        new["governance"]["max_standard_days"] = 20
        new["extensions"][0]["formats"].append(".z")
        new["extensions"][0]["tier"] = "local"
        new["exceptions"][0]["expires_at"] = (
            datetime.fromisoformat(old["exceptions"][0]["expires_at"]) - timedelta(hours=1)
        ).isoformat()
        changes: list[dict[str, str]] = []
        commands._compare_policy(old, new, changes)
        self.assertNotIn("weakening", {item["classification"] for item in changes})
        self.assertIn("strengthening", {item["classification"] for item in changes})

        without_extension = deepcopy(old)
        without_extension["extensions"] = []
        changes = []
        commands._compare_policy(without_extension, old, changes)
        self.assertIn(
            "strengthening",
            {
                item["classification"]
                for item in changes
                if item["field"] == "extensions.LOCAL-GATE"
            },
        )

        lock = {
            "schema_version": 1,
            "awq_version": "0.1.0",
            "registry_sha256": "0" * 64,
            "profiles": ["core", "docs"],
            "requirements": ["AWQ-CORE-001", "AWQ-DOC-001"],
        }
        changed_lock = {
            **lock,
            "schema_version": 2,
            "awq_version": "0.2.0",
            "registry_sha256": "1" * 64,
            "profiles": ["core"],
            "requirements": ["AWQ-CORE-001"],
        }
        changes = []
        commands._compare_lock(lock, changed_lock, changes)
        self.assertEqual({"weakening", "review"}, {item["classification"] for item in changes})

    def test_legacy_policy_migration_is_explicit_and_bounded(self) -> None:
        current = base_policy()
        version_two = deepcopy(current)
        version_two.pop("adapters")
        version_two["schema_version"] = 2
        normalized = commands._policy_v3(version_two, current)
        self.assertEqual(3, normalized["schema_version"])
        self.assertEqual([], normalized["adapters"])
        self.assertIs(current, commands._policy_v3(current, current))

        version_one = deepcopy(version_two)
        version_one.pop("governance")
        version_one["schema_version"] = 1
        normalized = commands._policy_v3(version_one, current)
        self.assertEqual(current["governance"], normalized["governance"])
        version_one["exceptions"] = [base_exception()]
        with self.assertRaises(ProjectError):
            commands._policy_v3(version_one, current)

    def test_doctor_flags_exception_for_inactive_requirement(self) -> None:
        repo = Repository()
        try:
            commands.initialize(repo.root, ["core"], False)
            policy = json.loads((repo.root / "quality/awq.json").read_text())
            policy["exceptions"] = [
                base_exception(
                    requirement="AWQ-DOC-001",
                    owner="@project-maintainers",
                )
            ]
            repo.json("quality/awq.json", policy)
            findings = commands.doctor(repo.root)["findings"]
            self.assertEqual(
                ["unknown-exception-requirement"],
                [item["code"] for item in findings],
            )
        finally:
            repo.close()

    def test_governance_suggestions_are_deterministic_and_offline(self) -> None:
        repo = Repository()
        try:
            commands.initialize(repo.root, ["core"], False)
            first = commands.governance(repo.root)
            second = commands.governance(repo.root)
            self.assertEqual(first, second)
            self.assertEqual("ok", first["status"])
            self.assertIn("offline", first["limitation"])
            self.assertEqual(
                [
                    "/quality/",
                    "/schemas/",
                    "/src/awq/data/",
                    "/.github/workflows/",
                    "/.github/CODEOWNERS",
                ],
                [item["pattern"] for item in first["codeowners_suggestions"]],
            )
        finally:
            repo.close()


class HostingObservationTests(unittest.TestCase):
    def test_detailed_rulesets_are_environmental_and_schema_valid(self) -> None:
        summaries = [{"id": 7}, {"id": True}, "ignored"]
        detail = {
            "id": 7,
            "name": "Protected main",
            "target": "branch",
            "enforcement": "active",
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
            "rules": [
                {"type": "pull_request"},
                {
                    "type": "required_status_checks",
                    "parameters": {"required_status_checks": [{"context": "verify"}]},
                },
                {"type": 3},
                "ignored",
            ],
        }
        opener = mock.Mock(
            side_effect=[
                FakeResponse({"default_branch": "main"}),
                FakeResponse(summaries),
                FakeResponse(detail),
            ]
        )
        with (
            mock.patch("awq.commands.urlopen", opener),
            mock.patch.dict("os.environ", {"GITHUB_TOKEN": "secret-token"}),
        ):
            result = commands.hosting_observation("owner/repository")
        self.assertEqual("pass", result["status"])
        self.assertEqual("environmental", result["evidence"])
        self.assertEqual("main", result["default_branch"])
        self.assertTrue(result["rulesets"][0]["applies_to_default_branch"])
        self.assertEqual(["verify"], result["rulesets"][0]["required_status_checks"])
        self.assertTrue(result["network"])
        self.assertIn("not offline proof", result["limitation"])
        datetime.fromisoformat(result["observed_at"])
        self.assertNotIn("secret-token", json.dumps(result))
        request = opener.call_args_list[0].args[0]
        self.assertEqual("Bearer secret-token", request.get_header("Authorization"))
        schema = json.loads(
            (
                Path(__file__).resolve().parents[1] / "schemas/hosting-observation.schema.json"
            ).read_text()
        )
        jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(
            result
        )

    def test_missing_rules_and_cli_failure(self) -> None:
        responses = [
            FakeResponse({"default_branch": "main"}),
            FakeResponse([]),
        ]
        with mock.patch("awq.commands.urlopen", side_effect=responses):
            result = commands.hosting_observation("owner/repository")
        self.assertEqual("fail", result["status"])
        self.assertEqual(
            {"pull_request", "required_status_checks"},
            {item["rule"] for item in result["findings"]},
        )
        output = io.StringIO()
        with (
            mock.patch(
                "awq.commands.urlopen",
                side_effect=[
                    FakeResponse({"default_branch": "main"}),
                    FakeResponse([]),
                ],
            ),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(
                1,
                main(
                    [
                        "hosting-observe",
                        "--repository",
                        "owner/repository",
                        "--format",
                        "json",
                    ]
                ),
            )
        self.assertEqual("fail", json.loads(output.getvalue())["status"])

    def test_network_shape_and_size_fail_closed(self) -> None:
        with self.assertRaises(ProjectError):
            commands.hosting_observation("not-a-repository")
        failures: list[object] = [
            FakeResponse({}),
            OSError("network"),
            FakeResponse(b"x" * 1_000_001),
        ]
        for failure in failures:
            effect = failure if isinstance(failure, OSError) else None
            with self.subTest(failure=type(failure).__name__):
                patcher = (
                    mock.patch("awq.commands.urlopen", side_effect=effect)
                    if effect
                    else mock.patch("awq.commands.urlopen", return_value=failure)
                )
                with patcher, self.assertRaises(ProjectError):
                    commands.hosting_observation("owner/repository")
        with (
            mock.patch(
                "awq.commands.urlopen",
                side_effect=[
                    FakeResponse({"default_branch": "main"}),
                    FakeResponse([{"id": 1}]),
                    FakeResponse([]),
                ],
            ),
            self.assertRaises(ProjectError),
        ):
            commands.hosting_observation("owner/repository")
        with (
            mock.patch(
                "awq.commands.urlopen",
                side_effect=[
                    FakeResponse({"default_branch": "main"}),
                    FakeResponse([{"id": number} for number in range(11)]),
                ],
            ),
            self.assertRaises(ProjectError),
        ):
            commands.hosting_observation("owner/repository")

    def test_non_default_or_excluded_rules_do_not_pass(self) -> None:
        base = {
            "id": 1,
            "name": "Wrong branch",
            "target": "branch",
            "enforcement": "active",
            "rules": [
                {"type": "pull_request"},
                {
                    "type": "required_status_checks",
                    "parameters": {"required_status_checks": [{"context": "verify"}]},
                },
            ],
        }
        for conditions in (
            {},
            {"ref_name": {"include": ["refs/heads/develop"], "exclude": []}},
            {"ref_name": {"include": [{"bad": "shape"}], "exclude": []}},
            {
                "ref_name": {
                    "include": ["~DEFAULT_BRANCH"],
                    "exclude": ["~DEFAULT_BRANCH"],
                }
            },
        ):
            detail = {**base, "conditions": conditions}
            with mock.patch(
                "awq.commands.urlopen",
                side_effect=[
                    FakeResponse({"default_branch": "main"}),
                    FakeResponse([{"id": 1}]),
                    FakeResponse(detail),
                ],
            ):
                result = commands.hosting_observation("owner/repository")
            self.assertEqual("fail", result["status"])

        malformed = {
            **base,
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
            "rules": None,
        }
        with mock.patch(
            "awq.commands.urlopen",
            side_effect=[
                FakeResponse({"default_branch": "main"}),
                FakeResponse([{"id": 1}]),
                FakeResponse(malformed),
            ],
        ):
            self.assertEqual("fail", commands.hosting_observation("owner/repository")["status"])


if __name__ == "__main__":
    unittest.main()
