# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Real signature, policy rotation, provenance and atomic update contract tests."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import subprocess
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any
from unittest import mock

from awq import candidate, provenance, trust, verified_update
from awq.cli import main as cli_main
from awq.project import load_project
from awq.registry import canonical_bytes
from awq.release import (
    ReleaseError,
    registry_digests,
    source_identity,
    validate_manifest,
    verify_release,
)
from scripts.validate_contracts import validate
from tests.release_support import SignedRelease


class AuthenticatedUpdateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = SignedRelease()
        self.addCleanup(self.fixture.close)

    def update(self, dry_run: bool = True) -> dict[str, object]:
        fixture = self.fixture
        return verified_update.update(
            fixture.consumer, fixture.version, dry_run, *fixture.arguments()
        )

    def test_complete_real_bootstrap_dry_run_and_atomic_lock_only_update(self) -> None:
        fixture = self.fixture
        before = fixture.consumer_bytes()
        result = self.update()
        self.assertEqual(before, fixture.consumer_bytes())
        self.assertFalse(result["committed"])
        self.assertTrue(result["lock_diff"])
        self.assertEqual("pass", verified_update.verify(*fixture.arguments())["status"])
        structural = verify_release(fixture.manifest_path, fixture.source)
        self.assertEqual(3, structural["schema_version"])
        self.assertEqual("not-checked", structural["authentication"])
        validate(fixture.policy, "release-trust-policy.schema.json")
        validate(fixture.manifest, "release-manifest.schema.json")
        document = json.loads(
            (fixture.bundle / fixture.manifest["provenance"]["name"]).read_bytes()
        )
        validate(document, "release-provenance.schema.json")
        written = self.update(False)
        self.assertTrue(written["committed"])
        self.assertEqual(result["lock_diff"], written["lock_diff"])
        after = fixture.consumer_bytes()
        changed = [name for name in before if before[name] != after[name]]
        self.assertEqual(["quality/awq.lock.json"], changed)
        self.assertEqual(set(before), set(after))
        _, lock = load_project(fixture.consumer)
        validate(lock, "lock.schema.json")
        self.assertEqual(fixture.policy, lock["receipt"]["trust_policy"])
        self.assertEqual(fixture.tag_object, lock["receipt"]["tag_object"])
        with self.assertRaisesRegex(ReleaseError, "rollback or replay"):
            self.update(False)
        self.assertEqual(after, fixture.consumer_bytes())

    def test_same_principal_add_then_retire_rotation_uses_stored_old_authority(self) -> None:
        fixture = self.fixture
        self.update(False)
        old = deepcopy(fixture.policy)
        added = fixture.policy_value([0, 1], old)
        fixture.build("0.16.2", added, 0)
        self.update(False)
        retired = fixture.policy_value([1], added)
        fixture.build("0.16.3", retired, 1)
        self.update(False)
        _, lock = load_project(fixture.consumer)
        self.assertEqual(3, lock["receipt"]["policy_generation"])
        self.assertEqual(retired, lock["receipt"]["trust_policy"])
        self.assertEqual(fixture.roots[1]["fingerprint"], lock["receipt"]["signer_fingerprint"])

    def test_candidate_only_signer_cannot_self_bootstrap_rotation(self) -> None:
        fixture = self.fixture
        self.update(False)
        before = fixture.consumer_bytes()
        added = fixture.policy_value([0, 1], fixture.policy)
        fixture.build("0.16.2", added, 1)
        with self.assertRaisesRegex(ReleaseError, "not authorized"):
            self.update(False)
        self.assertEqual(before, fixture.consumer_bytes())

    def test_missing_unknown_tampered_expired_and_revoked_trust_fail_unchanged(self) -> None:
        fixture = self.fixture
        before = fixture.consumer_bytes()
        original = deepcopy(fixture.policy)
        changes: list[dict[str, Any]] = [
            {"repository": "https://example.invalid/other"},
            {"unexpected": True},
            {"roots": []},
            {"roots": [fixture.roots[1]]},
            {"generation": 2, "previous_policy_sha256": "0" * 64},
            {"roots": [{**fixture.roots[0], "valid_until": "2021-01-01T00:00:00Z"}]},
            {"retired": [fixture.roots[0]["fingerprint"]]},
        ]
        for changed in changes:
            with self.subTest(changed=changed):
                fixture.policy_path.write_bytes(canonical_bytes({**original, **changed}))
                with self.assertRaises(ReleaseError):
                    self.update(False)
                self.assertEqual(before, fixture.consumer_bytes())
        fixture.policy_path.unlink()
        with self.assertRaises(ReleaseError):
            self.update(False)
        self.assertEqual(before, fixture.consumer_bytes())

    def test_exact_tag_object_type_target_name_and_signature_are_required(self) -> None:
        fixture = self.fixture
        before = fixture.consumer_bytes()
        manifest, policy, source, tag, oid = fixture.arguments()
        for reference, pinned in [
            ("main", oid),
            (tag, "main"),
            (tag, "0" * 40),
            (tag, fixture.manifest["source"]["commit"]),
        ]:
            with self.subTest(reference=reference, pinned=pinned), self.assertRaises(ReleaseError):
                verified_update.update(
                    fixture.consumer,
                    fixture.version,
                    False,
                    manifest,
                    policy,
                    source,
                    reference,
                    pinned,
                )
        original = fixture.manifest_path.read_bytes()
        fixture.manifest_path.write_bytes(
            original.replace(b'"schema_version":3', b'"schema_version":2')
        )
        with self.assertRaises(ReleaseError):
            self.update(False)
        fixture.manifest_path.write_bytes(original)
        signature = fixture.manifest_path.with_name(fixture.manifest_path.name + ".sig")
        signature.write_bytes(b"untrusted signature\n")
        with self.assertRaisesRegex(ReleaseError, "not authorized"):
            self.update(False)
        self.assertEqual(before, fixture.consumer_bytes())

    def test_candidate_consumed_bytes_must_match_authenticated_bindings(self) -> None:
        fixture = self.fixture
        expected = registry_digests(fixture.source)
        lock = candidate.candidate_lock(fixture.source, fixture.version, ["core"], expected)
        self.assertEqual(["core"], lock["profiles"])
        path = fixture.source / "src/awq/data/requirements.json"
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        with self.assertRaisesRegex(ReleaseError, "bytes differ"):
            candidate.candidate_lock(fixture.source, fixture.version, ["core"], expected)
        path.write_bytes(original)
        requirement = json.loads(original)
        requirement["requirements"][0]["id"] = "not-a-contract-id"
        path.write_bytes(canonical_bytes(requirement))
        with self.assertRaisesRegex(ReleaseError, "identity"):
            candidate.candidate_lock(
                fixture.source, fixture.version, ["core"], registry_digests(fixture.source)
            )

    def test_cli_requires_complete_evidence_and_emits_authenticated_exact_diff(self) -> None:
        fixture = self.fixture
        arguments = [
            "--root",
            str(fixture.consumer),
            "update",
            "--to",
            fixture.version,
            "--manifest",
            str(fixture.manifest_path),
            "--trust-policy",
            str(fixture.policy_path),
            "--source",
            str(fixture.source),
            "--tag",
            "refs/tags/v" + fixture.version,
            "--tag-object",
            fixture.tag_object,
            "--dry-run",
            "--format",
            "json",
        ]
        before = fixture.consumer_bytes()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(0, cli_main(arguments))
        result = json.loads(output.getvalue())
        self.assertFalse(result["committed"])
        self.assertTrue(result["lock_diff"])
        self.assertNotIn(str(fixture.root), output.getvalue())
        self.assertEqual(before, fixture.consumer_bytes())
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli_main(["update", "--to", fixture.version, "--dry-run"])

    def test_precommit_failures_unchanged_and_postcommit_fsync_honestly_reported(self) -> None:
        fixture = self.fixture
        before = fixture.consumer_bytes()
        with (
            mock.patch("awq.verified_update.os.fsync", side_effect=OSError("synthetic")),
            self.assertRaises(ReleaseError),
        ):
            self.update(False)
        self.assertEqual(before, fixture.consumer_bytes())
        with mock.patch("awq.verified_update.os.fsync", side_effect=[None, OSError("synthetic")]):
            result = self.update(False)
        self.assertTrue(result["committed"])
        self.assertEqual("unconfirmed", result["durability"])
        self.assertNotEqual(
            before["quality/awq.lock.json"], fixture.consumer_bytes()["quality/awq.lock.json"]
        )
        self.assertFalse(list((fixture.consumer / "quality").glob(".awq-update-*")))

    def test_provenance_exact_canonical_subject_source_material_and_workflow_profile(self) -> None:
        fixture = self.fixture
        manifest = fixture.manifest
        path = fixture.bundle / manifest["provenance"]["name"]
        raw = path.read_bytes()
        document = json.loads(raw)
        self.assertEqual(
            [
                {"name": item["name"], "digest": {"sha256": item["sha256"]}}
                for item in manifest["artifacts"]
            ],
            document["subject"],
        )
        mutants = []
        value = deepcopy(document)
        value["subject"].pop()
        mutants.append(value)
        value = deepcopy(document)
        value["predicate"]["buildDefinition"]["externalParameters"]["source"]["commit"] = "0" * 40
        mutants.append(value)
        value = deepcopy(document)
        value["predicate"]["buildDefinition"]["externalParameters"]["workflow"]["commit"] = "main"
        mutants.append(value)
        value = deepcopy(document)
        value["predicate"]["buildDefinition"]["resolvedDependencies"].pop()
        mutants.append(value)
        value = deepcopy(document)
        value["extra"] = "private-marker-awq-test"
        mutants.append(value)
        for mutated in [*[canonical_bytes(item) for item in mutants], raw + b"\n"]:
            with self.subTest(mutated=mutated[:30]):
                path.write_bytes(mutated)
                manifest["provenance"]["size"] = len(mutated)
                manifest["provenance"]["sha256"] = hashlib.sha256(mutated).hexdigest()
                with self.assertRaises(ReleaseError):
                    provenance.verify(fixture.bundle, manifest, fixture.source)
        materials = provenance.source_materials(fixture.source)
        materials[provenance.WORKFLOW] = b"steps:\n  - uses: actions/checkout@main\n"
        with self.assertRaisesRegex(ReleaseError, "mutable"):
            provenance.generate(manifest, materials)
        with self.assertRaises(ReleaseError):
            provenance.generate(manifest, {})
        with self.assertRaises(ReleaseError):
            provenance.add(fixture.source, fixture.bundle, manifest, "latest")
        malformed = deepcopy(manifest)
        malformed["artifacts"].append({"kind": "signature"})
        with self.assertRaises(ReleaseError):
            validate_manifest(malformed)

    def test_manual_tag_verification_uses_external_signers_without_config_persistence(self) -> None:
        fixture = self.fixture
        before = fixture.git("config", "--local", "--list")
        allowed = fixture.root / "reviewed-allowed-signers"
        root = fixture.roots[0]
        allowed.write_text(root["principal"] + " " + root["public_key"] + "\n")
        self.assertEqual(root["fingerprint"], trust.fingerprint(root["public_key"]))
        fixture.git(
            "-c", "gpg.ssh.allowedSignersFile=" + str(allowed), "verify-tag", fixture.tag_object
        )
        self.assertEqual(before, fixture.git("config", "--local", "--list"))

    def test_same_authorized_principal_but_different_manifest_and_tag_keys_fail(self) -> None:
        fixture = self.fixture
        policy = fixture.policy_value([0, 1])
        fixture.build("0.16.2", policy, 1)
        fixture.sign(0)
        before = fixture.consumer_bytes()
        with self.assertRaisesRegex(ReleaseError, "verification failed"):
            self.update(False)
        self.assertEqual(before, fixture.consumer_bytes())

    def test_candidate_local_policy_is_never_a_bootstrap_trust_anchor(self) -> None:
        fixture = self.fixture
        local = fixture.source / "config/allowed_signers"
        local.write_bytes(canonical_bytes(fixture.policy))
        before = fixture.consumer_bytes()
        manifest, _, source, tag, oid = fixture.arguments()
        with self.assertRaisesRegex(ReleaseError, "independently provisioned"):
            verified_update.update(
                fixture.consumer, fixture.version, False, manifest, local, source, tag, oid
            )
        self.assertEqual(before, fixture.consumer_bytes())

    def test_source_identity_ignores_checkout_clean_filters_and_rejects_raw_changes(self) -> None:
        fixture = self.fixture
        source = fixture.source
        marker = fixture.root / "filter-executed"
        # The filter would run even during status on a stat-dirty checkout.
        attributes = source / ".gitattributes"
        attributes.write_text("*.json filter=hostile\n")
        # Stage attributes only; do not ask Git to filter candidate JSON.
        fixture.git("add", ".gitattributes")
        fixture.git("commit", "-qm", "Synthetic hostile checkout configuration")
        fixture.git("config", "filter.hostile.clean", "touch " + str(marker))
        fixture.git("config", "filter.hostile.required", "true")
        self.assertFalse(marker.exists())
        path = source / "src/awq/data/requirements.json"
        raw = path.read_bytes()
        path.write_bytes(raw)
        source_identity(source)
        self.assertFalse(marker.exists())
        path.write_bytes(raw + b" ")
        with self.assertRaisesRegex(ReleaseError, "tracked changes"):
            source_identity(source)
        self.assertFalse(marker.exists())
        path.write_bytes(raw)
        path.chmod(0o755)
        with self.assertRaisesRegex(ReleaseError, "tracked changes"):
            source_identity(source)
        path.chmod(0o644)
        path.unlink()
        path.symlink_to(fixture.policy_path)
        with self.assertRaises(ReleaseError):
            source_identity(source)
        path.unlink()
        path.write_bytes(raw)
        self.assertFalse(marker.exists())

    def test_staged_change_and_untracked_noise_have_distinct_identity_results(self) -> None:
        fixture = self.fixture
        source = fixture.source
        expected = source_identity(source)
        (source / "untracked.txt").write_text("untracked noise\n")
        self.assertEqual(expected, source_identity(source))
        path = source / "src/awq/__init__.py"
        original = path.read_bytes()
        path.write_bytes(b"not executed\n")
        fixture.git("add", "src/awq/__init__.py")
        path.write_bytes(original)
        with self.assertRaisesRegex(ReleaseError, "index"):
            source_identity(source)


class TrustBoundaryTests(unittest.TestCase):
    fixture: SignedRelease

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = SignedRelease()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture.close()

    def test_policy_and_receipt_reject_unknown_types_bounds_and_conflicts(self) -> None:
        fixture = self.fixture
        good = fixture.policy
        cases: list[object] = [
            None,
            {},
            {**good, "schema_version": True},
            {**good, "generation": True},
            {**good, "generation": 1001},
            {**good, "previous_policy_sha256": "0" * 64},
            {**good, "roots": good["roots"] * 2},
            {**good, "retired": ["bad"]},
            {**good, "roots": [{**good["roots"][0], "principal": "bad,principal"}]},
            {**good, "roots": [{**good["roots"][0], "fingerprint": "SHA256:bad"}]},
            {**good, "roots": [{**good["roots"][0], "valid_after": "2091-01-01T00:00:00Z"}]},
            {**good, "roots": [{**good["roots"][0], "valid_until": "2090-99-99T00:00:00Z"}]},
        ]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ReleaseError):
                trust.validate_policy(value)
        for value in [None, "ssh-rsa bad", "ssh-ed25519 bad", "ssh-ed25519 AAAA"]:
            with self.subTest(value=value), self.assertRaises(ReleaseError):
                trust.fingerprint(value)
        _, receipt = verified_update.authenticated_release(*fixture.arguments())
        for key in receipt:
            value = deepcopy(receipt)
            value.pop(key)
            with self.subTest(key=key), self.assertRaises(ReleaseError):
                trust.validate_receipt(value)
        for key, value in [
            ("policy_generation", True),
            ("signer", "\n"),
            ("signer_fingerprint", "bad"),
            ("tag_ref", "main"),
            ("source_commit", "main"),
            ("manifest_sha256", "bad"),
            ("policy_sha256", "0" * 64),
        ]:
            changed = {**receipt, key: value}
            with self.subTest(key=key), self.assertRaises(ReleaseError):
                trust.validate_receipt(changed)

    def test_rotation_rejects_generation_conflict_lost_overlap_and_key_reuse(self) -> None:
        fixture = self.fixture
        old = fixture.policy
        signer = fixture.roots[0]
        good = fixture.policy_value([0, 1], old)
        trust.transition(old, good, signer)
        for value in [
            {**good, "generation": 3},
            {**good, "previous_policy_sha256": "0" * 64},
            fixture.policy_value([1], old),
            fixture.policy_value([0], old),
            {
                **good,
                "roots": [
                    {**item, "valid_until": "2080-01-01T00:00:00Z"} for item in good["roots"]
                ],
            },
        ]:
            with self.subTest(value=value), self.assertRaises(ReleaseError):
                trust.transition(old, value, signer)
        with self.assertRaises(ReleaseError):
            trust.transition(old, old, fixture.roots[1])

    def test_external_canonical_inputs_and_platform_boundary(self) -> None:
        fixture = self.fixture
        with self.assertRaises(ReleaseError):
            trust.load_policy(fixture.policy_path, (fixture.root,))
        with self.assertRaises(ReleaseError):
            trust.read_file(Path("relative"))
        link = fixture.root / "policy-link"
        link.symlink_to(fixture.policy_path)
        try:
            with self.assertRaises(ReleaseError):
                trust.read_file(link)
        finally:
            link.unlink()
        with self.assertRaises(ReleaseError):
            trust.read_file(fixture.policy_path, 1)
        with mock.patch("awq.trust.os.name", "nt"), self.assertRaises(ReleaseError):
            trust.run(["/usr/bin/true"])
        with mock.patch("awq.verified_update.os.name", "nt"), self.assertRaises(ReleaseError):
            verified_update.update(fixture.consumer, fixture.version, True, *fixture.arguments())
        for value in ["main", "v0.16.0", "01.1.0", "1.2", True, "1.2.3.4"]:
            with self.subTest(value=value), self.assertRaises(ReleaseError):
                verified_update.version_tuple(value)

    def test_bounded_verifier_status_output_timeout_and_unavailable(self) -> None:
        self.assertEqual(b"ok\n", trust.run(["/usr/bin/printf", "%s\n", "ok"]))
        with self.assertRaises(ReleaseError):
            trust.run(["/usr/bin/false"])
        with self.assertRaises(ReleaseError):
            trust.run(["/nonexistent/awq-verifier"])
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.pid = 123
        process.wait.side_effect = [subprocess.TimeoutExpired("bounded", 30), -9]
        with (
            mock.patch("subprocess.Popen", return_value=process),
            mock.patch("os.killpg") as kill,
            self.assertRaisesRegex(ReleaseError, "deadline"),
        ):
            trust.run(["/usr/bin/true"])
        kill.assert_called_once()
        with self.assertRaises(ReleaseError):
            trust.verify_signature(b"x", b"x" * 8193, self.fixture.roots[0], "awq-release")


if __name__ == "__main__":
    unittest.main()
