# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Fail-closed boundaries for authenticated candidate data and provenance readers."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tarfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock

from awq import candidate, provenance, trust, verified_update
from awq.project import load_project, validate_lock
from awq.registry import canonical_bytes
from awq.release import REGISTRY_PATHS, ReleaseError, _tracked_source, registry_digests
from tests.release_support import SignedRelease


class ReleaseBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = SignedRelease()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture.close()

    fixture: SignedRelease

    def test_candidate_unknown_duplicate_nonfinite_and_structurally_invalid_records(self) -> None:
        fixture = self.fixture
        source = fixture.source
        documents = {
            name: (source / relative).read_bytes() for name, relative in REGISTRY_PATHS.items()
        }
        cases: list[tuple[str, object]] = [
            ("requirements", {}),
            ("requirements", []),
            ("requirements", {"schema_version": True, "requirements": []}),
            ("requirements", {"schema_version": 1, "requirements": []}),
        ]
        requirements = json.loads(documents["requirements"])
        for field, value in [
            ("extra", "unknown"),
            ("title", []),
            ("tier", "unknown"),
            ("severity", "unknown"),
            ("network", 1),
            ("profiles", ["unknown"]),
            ("profiles", [True]),
            ("standards", []),
        ]:
            mutated = deepcopy(requirements)
            mutated["requirements"][0][field] = value
            cases.append(("requirements", mutated))
        duplicated = deepcopy(requirements)
        duplicated["requirements"].append(deepcopy(duplicated["requirements"][0]))
        cases.append(("requirements", duplicated))
        profiles = json.loads(documents["profiles"])
        for field, value in [
            ("extra", True),
            ("name", "bad/name"),
            ("description", ""),
            ("requirements", ["unknown"]),
            ("requirements", [["nested"]]),
        ]:
            mutated = deepcopy(profiles)
            mutated["profiles"][0][field] = value
            cases.append(("profiles", mutated))
        mismatched = deepcopy(profiles)
        mismatched["profiles"][1]["requirements"].append(requirements["requirements"][0]["id"])
        cases.append(("profiles", mismatched))
        cases.extend(
            [
                ("adapter_catalog", {}),
                ("adapter_catalog", {"schema_version": True, "families": []}),
                ("adapter_catalog", {"schema_version": 1, "families": []}),
            ]
        )
        cases.extend([("standards_sources", {}), ("standards_mappings", {})])
        bad_mapping = json.loads(documents["standards_mappings"])
        bad_mapping["mappings"][0]["source"] = "unknown"
        cases.append(("standards_mappings", bad_mapping))
        for name, changed in cases:
            path = source / REGISTRY_PATHS[name]
            try:
                path.write_bytes(canonical_bytes(changed))
                with self.subTest(name=name, changed=changed), self.assertRaises(ReleaseError):
                    candidate.candidate_lock(
                        source, fixture.version, ["core"], registry_digests(source)
                    )
            finally:
                path.write_bytes(documents[name])
        path = source / REGISTRY_PATHS["requirements"]
        for raw in [b'{"a":1,"a":2}', b'{"a":NaN}', b"{", b"\xff", b"[]"]:
            try:
                path.write_bytes(raw)
                with self.subTest(raw=raw), self.assertRaises(ReleaseError):
                    candidate.document(path)
            finally:
                path.write_bytes(documents["requirements"])
        for selected in [[], ["not-present"], ["core", "core"]]:
            with self.subTest(selected=selected), self.assertRaises(ReleaseError):
                candidate.candidate_lock(
                    source, fixture.version, selected, registry_digests(source)
                )
        with self.assertRaises(ReleaseError):
            candidate.candidate_lock(source, fixture.version, ["core"], {})

    def test_provenance_readers_reject_missing_oversized_duplicate_and_invalid_archives(
        self,
    ) -> None:
        fixture = self.fixture
        manifest = fixture.manifest
        materials = provenance.source_materials(fixture.source)
        with mock.patch("awq.provenance.MAX_TOTAL", 1), self.assertRaises(ReleaseError):
            provenance.source_materials(fixture.source)
        materials[provenance.WORKFLOW] = b"\xff"
        with self.assertRaises(ReleaseError):
            provenance.generate(manifest, materials)
        scratch = fixture.root / "hostile.tar.gz"
        scratch.write_bytes(b"not tar")
        with self.assertRaises(ReleaseError):
            provenance.archive_materials(scratch, fixture.version)
        for names in [[], ["uv.lock", "uv.lock"]]:
            with tarfile.open(scratch, "w:gz") as archive:
                for name in names:
                    raw = (fixture.source / name).read_bytes()
                    member = tarfile.TarInfo(f"agent_workflow_quality-{fixture.version}/" + name)
                    member.size = len(raw)
                    archive.addfile(member, io.BytesIO(raw))
            with self.subTest(names=names), self.assertRaises(ReleaseError):
                provenance.archive_materials(scratch, fixture.version)
        record = next(item for item in manifest["artifacts"] if item["kind"] == "sdist")
        with mock.patch("awq.provenance.MAX_BYTES", 1), self.assertRaises(ReleaseError):
            provenance.archive_materials(fixture.bundle / record["name"], fixture.version)
        fake = mock.MagicMock()
        fake.__enter__.return_value = fake
        member = tarfile.TarInfo(f"agent_workflow_quality-{fixture.version}/uv.lock")
        fake.__iter__.side_effect = lambda: iter([member])
        fake.extractfile.return_value = None
        with mock.patch("tarfile.open", return_value=fake), self.assertRaises(ReleaseError):
            provenance.archive_materials(scratch, fixture.version)
        fake.extractfile.return_value = io.BytesIO(b"x" * 20)
        with (
            mock.patch("tarfile.open", return_value=fake),
            mock.patch("awq.provenance.MAX_BYTES", 10),
            self.assertRaises(ReleaseError),
        ):
            provenance.archive_materials(scratch, fixture.version)
        fake.__iter__.side_effect = lambda: (tarfile.TarInfo("unrelated") for _ in range(10001))
        with mock.patch("tarfile.open", return_value=fake), self.assertRaises(ReleaseError):
            provenance.archive_materials(scratch, fixture.version)
        scratch.unlink()

    def test_provenance_identity_and_source_mismatch_are_not_repaired(self) -> None:
        fixture = self.fixture
        changed = deepcopy(fixture.manifest)
        changed["provenance"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ReleaseError, "identity"):
            provenance.verify(fixture.bundle, changed, fixture.source)
        materials = provenance.source_materials(fixture.source)
        materials["LICENSE"] += b"changed"
        with (
            mock.patch("awq.provenance.source_materials", return_value=materials),
            self.assertRaisesRegex(ReleaseError, "materials differ"),
        ):
            provenance.verify(fixture.bundle, fixture.manifest, fixture.source)

    def test_update_failures_after_authentication_preserve_bytes(self) -> None:
        fixture = self.fixture
        before = fixture.consumer_bytes()
        manifest = deepcopy(fixture.manifest)
        receipt = verified_update.authenticated_release(*fixture.arguments())[1]
        manifest["version"] = "0.24.9"
        with (
            mock.patch(
                "awq.verified_update.authenticated_release", return_value=(manifest, receipt)
            ),
            self.assertRaisesRegex(ReleaseError, "exact update target"),
        ):
            verified_update.update(fixture.consumer, fixture.version, False, *fixture.arguments())
        policy_path = fixture.consumer / "quality/awq.json"
        lock_path = fixture.consumer / "quality/awq.lock.json"
        with self.assertRaisesRegex(ReleaseError, "changed"):
            verified_update._replace(
                lock_path, b"not the original", b"new", policy_path, policy_path.read_bytes()
            )
        with (
            mock.patch("pathlib.Path.replace", side_effect=OSError("redacted")),
            self.assertRaisesRegex(ReleaseError, "before publication"),
        ):
            verified_update.update(fixture.consumer, fixture.version, False, *fixture.arguments())
        with (
            mock.patch("fcntl.flock", side_effect=BlockingIOError),
            self.assertRaisesRegex(ReleaseError, "another verified update"),
        ):
            verified_update.update(fixture.consumer, fixture.version, False, *fixture.arguments())
        self.assertEqual(before, fixture.consumer_bytes())
        with self.assertRaises(ReleaseError):
            verified_update._directory(Path("relative"))
        with self.assertRaises(ReleaseError):
            verified_update._directory(fixture.root / "missing")
        wrong = deepcopy(fixture.manifest)
        wrong["schema_version"] = 2
        wrong.pop("provenance")
        wrong.pop("trust_policy_sha256")
        with (
            mock.patch("awq.verified_update.validate_manifest", return_value=wrong),
            self.assertRaisesRegex(ReleaseError, "v3"),
        ):
            verified_update.authenticated_release(*fixture.arguments())
        wrong = deepcopy(fixture.manifest)
        wrong["trust_policy_sha256"] = "0" * 64
        with (
            mock.patch("awq.verified_update.validate_manifest", return_value=wrong),
            self.assertRaisesRegex(ReleaseError, "bind"),
        ):
            verified_update.authenticated_release(*fixture.arguments())

    def test_trust_tag_receipt_timestamp_and_resource_guards(self) -> None:
        fixture = self.fixture
        for raw in [
            b"unsigned tag\n",
            b"-----BEGIN SSH SIGNATURE-----\n" * 2,
            b"wrong target\n-----BEGIN SSH SIGNATURE-----\ninvalid\n",
        ]:
            with (
                mock.patch("awq.trust.git", side_effect=[fixture.tag_object.encode(), raw]),
                self.assertRaises(ReleaseError),
            ):
                trust.verify_tag(
                    fixture.source,
                    "refs/tags/v" + fixture.version,
                    fixture.tag_object,
                    fixture.manifest,
                    fixture.roots[0],
                )
        with self.assertRaises(ReleaseError):
            trust._timestamp("not a timestamp")
        with self.assertRaises(ReleaseError):
            trust._root({})
        receipt = verified_update.authenticated_release(*fixture.arguments())[1]
        receipt["signer_fingerprint"] = fixture.roots[2]["fingerprint"]
        with self.assertRaises(ReleaseError):
            trust.validate_receipt(receipt)
        import resource

        with mock.patch("resource.setrlimit") as limit:
            trust._limits()
        self.assertEqual(
            [resource.RLIMIT_FSIZE, resource.RLIMIT_CPU],
            [call.args[0] for call in limit.call_args_list],
        )

    def test_git_verifier_disables_lazy_fetch_transports_and_ambient_credentials(self) -> None:
        fixture = self.fixture
        with mock.patch("subprocess.Popen", wraps=subprocess.Popen) as spawn:
            trust.git(fixture.source, "rev-parse", "HEAD")
        environment = spawn.call_args.kwargs["env"]
        self.assertEqual("1", environment["GIT_NO_LAZY_FETCH"])
        self.assertEqual("", environment["GIT_ALLOW_PROTOCOL"])
        self.assertEqual("0", environment["GIT_OPTIONAL_LOCKS"])
        self.assertNotIn("SSH_AUTH_SOCK", environment)
        self.assertNotIn("HTTPS_PROXY", environment)
        marker = fixture.root / "transport-must-not-execute"
        with self.assertRaises(ReleaseError):
            trust.git(
                fixture.source,
                "-c",
                "protocol.ext.allow=always",
                "ls-remote",
                "ext::/usr/bin/touch " + str(marker),
            )
        self.assertFalse(marker.exists())
        before = fixture.consumer_bytes()
        with (
            mock.patch("awq.verified_update.os.open", side_effect=OSError("private path")),
            self.assertRaisesRegex(ReleaseError, "directory is unavailable"),
        ):
            verified_update.update(fixture.consumer, fixture.version, False, *fixture.arguments())
        self.assertEqual(before, fixture.consumer_bytes())

    def test_raw_git_source_member_index_path_and_size_guards(self) -> None:
        fixture = self.fixture
        root = fixture.source
        raw = (root / "LICENSE").read_bytes()
        oid = (
            hashlib.sha1(f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False)
            .hexdigest()
            .encode()
        )
        good = b"100644 blob " + oid + b"\tLICENSE\0"
        cases = [
            b"",
            b"not terminated",
            b"120000 blob " + oid + b"\tLICENSE\0",
            b"160000 commit " + oid + b"\tLICENSE\0",
            b"malformed\0",
            b"100644 blob " + oid + b"\t../LICENSE\0",
            b"100644 blob " + oid + b"\t\xff\0",
        ]
        for raw_tree in cases:
            with (
                self.subTest(raw_tree=raw_tree),
                mock.patch("awq.trust.git", return_value=raw_tree),
                self.assertRaises(ReleaseError),
            ):
                _tracked_source(root)
        with (
            mock.patch("awq.trust.git", return_value=good),
            mock.patch("awq.release.MAX_TOTAL_BYTES", 1),
            self.assertRaises(ReleaseError),
        ):
            _tracked_source(root)
        with (
            mock.patch("awq.trust.git", return_value=good),
            mock.patch("awq.release.MAX_MEMBERS", 0),
            self.assertRaises(ReleaseError),
        ):
            _tracked_source(root)
        _, lock = load_project(fixture.consumer)
        for key, value in [("awq_version", False), ("registry_sha256", "bad"), ("profiles", [[]])]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_lock({**lock, key: value})


if __name__ == "__main__":
    unittest.main()
