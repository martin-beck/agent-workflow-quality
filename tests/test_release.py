# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Canonical release-manifest and offline bundle verification tests."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile
from copy import deepcopy
from pathlib import Path
from unittest import mock

from awq.cli import main
from awq.release import (
    BUILD_CONSTRAINTS_PATH,
    BUILD_CONSTRAINTS_SHA256,
    REGISTRY_PATHS,
    REQUIRED_SCHEMAS,
    SBOM_SCHEMA_ASSETS,
    ReleaseError,
    canonical_bytes,
    inspect_archive,
    load_manifest,
    make_manifest,
    registry_digests,
    sha256_file,
    source_identity,
    validate_manifest,
    verify_release,
)
from tests.support import Repository, packaged_schema_bytes


class ReleaseVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.version = "0.13.0"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def wheel(
        self,
        *,
        version: str | None = None,
        timestamp: tuple[int, int, int, int, int, int] = (2026, 9, 9, 5, 15, 26),
        mode: int | None = None,
        private: bool = False,
    ) -> Path:
        observed = version or self.version
        path = self.root / f"agent_workflow_quality-{self.version}-py3-none-any.whl"
        metadata = f"Name: agent-workflow-quality\nVersion: {observed}\n".encode()

        def write(archive: zipfile.ZipFile, name: str, content: bytes) -> None:
            item = zipfile.ZipInfo(name, date_time=timestamp)
            item.create_system = 3
            item.external_attr = (
                mode if mode is not None else (0o644 if ".dist-info/" in name else 0o100644)
            ) << 16
            item.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(item, content)

        with zipfile.ZipFile(path, mode="w") as archive:
            write(
                archive,
                f"agent_workflow_quality-{observed}.dist-info/METADATA",
                metadata,
            )
            for schema in sorted(REQUIRED_SCHEMAS):
                write(archive, f"awq/schemas/{schema}", packaged_schema_bytes(schema))
            write(archive, "awq/data/adapter_catalog.json", b"{}\n")
            if private:
                write(archive, "awq/private.txt", b"/home/" + b"alice/project")
        return path

    def sdist(
        self,
        *,
        version: str | None = None,
        mtime: int = 1_788_930_927,
        mode: int = 0o644,
    ) -> Path:
        observed = version or self.version
        path = self.root / f"agent_workflow_quality-{self.version}.tar.gz"
        prefix = f"agent_workflow_quality-{self.version}"
        members = {
            f"{prefix}/pyproject.toml": (
                f'[project]\nname = "agent-workflow-quality"\nversion = "{observed}"\n'
            ).encode(),
            f"{prefix}/src/awq/data/adapter_catalog.json": b"{}\n",
            **{
                f"{prefix}/schemas/{name}": packaged_schema_bytes(name) for name in REQUIRED_SCHEMAS
            },
        }
        with tarfile.open(path, mode="w:gz") as archive:
            for name, content in members.items():
                item = tarfile.TarInfo(name)
                item.size = len(content)
                item.mtime = mtime
                item.mode = mode
                archive.addfile(item, io.BytesIO(content))
        return path

    def manifest_value(
        self,
        *,
        wheel_version: str | None = None,
        sdist_version: str | None = None,
        wheel_timestamp: tuple[int, int, int, int, int, int] = (2026, 9, 9, 5, 15, 26),
        wheel_mode: int | None = None,
        sdist_mtime: int = 1_788_930_927,
        sdist_mode: int = 0o644,
        private: bool = False,
    ) -> dict[str, object]:
        wheel = self.wheel(
            version=wheel_version,
            timestamp=wheel_timestamp,
            mode=wheel_mode,
            private=private,
        )
        sdist = self.sdist(
            version=sdist_version,
            mtime=sdist_mtime,
            mode=sdist_mode,
        )
        artifacts = [
            {
                "name": item.name,
                "kind": kind,
                "media_type": media,
                "size": item.stat().st_size,
                "sha256": sha256_file(item),
            }
            for item, kind, media in (
                (wheel, "wheel", "application/zip"),
                (sdist, "sdist", "application/gzip"),
            )
        ]
        return make_manifest(
            version=self.version,
            source={
                "repository": "https://github.com/martin-beck/agent-workflow-quality",
                "commit": "a" * 40,
                "tree": "b" * 40,
                "source_date_epoch": 1_788_930_927,
            },
            builder={
                "recipe": "awq-release-v1",
                "python_version": "3.13.15",
                "uv_version": "0.12.8",
                "hatchling_version": "1.27.0",
                "host": "linux-x86_64",
                "build_constraints_sha256": BUILD_CONSTRAINTS_SHA256,
            },
            registries=dict.fromkeys(REGISTRY_PATHS, "c" * 64),
            artifacts=artifacts,
        )

    def write_manifest(self, value: object) -> Path:
        path = self.root / f"agent_workflow_quality-{self.version}.release.json"
        path.write_bytes(canonical_bytes(value))
        return path

    def test_complete_bundle_verifies_and_reports_only_public_bindings(self) -> None:
        value = self.manifest_value()
        path = self.write_manifest(value)
        result = verify_release(path)
        self.assertEqual(
            {
                "artifacts",
                "authentication",
                "manifest_sha256",
                "schema_version",
                "source_commit",
                "status",
                "version",
            },
            set(result),
        )
        self.assertEqual("pass", result["status"])
        self.assertEqual(1, result["schema_version"])
        self.assertEqual(self.version, result["version"])
        self.assertEqual("a" * 40, result["source_commit"])
        self.assertEqual(2, len(result["artifacts"]))
        self.assertEqual(sha256_file(path), result["manifest_sha256"])
        self.assertEqual(value, load_manifest(path))

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(
                0,
                main(
                    [
                        "--root",
                        str(self.root),
                        "release-verify",
                        str(path),
                        "--format",
                        "json",
                    ]
                ),
            )
        self.assertEqual("a" * 40, json.loads(output.getvalue())["source_commit"])
        self.assertEqual(1, json.loads(output.getvalue())["schema_version"])

    def test_manifest_rejects_shapes_unknowns_duplicates_and_noncanonical_bytes(self) -> None:
        baseline = self.manifest_value()
        mutations: list[dict[str, object]] = []
        for name, value in (
            ("schema_version", True),
            ("package", "other"),
            ("version", "v0.13"),
        ):
            changed = deepcopy(baseline)
            changed[name] = value
            mutations.append(changed)
        changed = deepcopy(baseline)
        changed["unknown"] = True
        mutations.append(changed)
        changed = deepcopy(baseline)
        source = changed["source"]
        assert isinstance(source, dict)
        source["repository"] = "https://example.invalid/project"
        mutations.append(changed)
        changed = deepcopy(baseline)
        builder = changed["builder"]
        assert isinstance(builder, dict)
        builder["host"] = "private-host"
        mutations.append(changed)
        changed = deepcopy(baseline)
        registries = changed["registries"]
        assert isinstance(registries, dict)
        registries["profiles"] = "bad"
        mutations.append(changed)
        changed = deepcopy(baseline)
        artifacts = changed["artifacts"]
        assert isinstance(artifacts, list)
        changed["artifacts"] = list(reversed(artifacts))
        mutations.append(changed)
        changed = deepcopy(baseline)
        artifacts = changed["artifacts"]
        assert isinstance(artifacts, list)
        duplicate = deepcopy(artifacts[0])
        duplicate["name"] = "different.whl"
        artifacts.append(duplicate)
        artifacts.sort(key=lambda item: str(item["name"]))
        mutations.append(changed)
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ReleaseError):
                validate_manifest(mutation)

        path = self.write_manifest(baseline)
        path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
        with self.assertRaisesRegex(ReleaseError, "canonical"):
            load_manifest(path)
        path.write_bytes(b'{"schema_version":1,"schema_version":1}\n')
        with self.assertRaisesRegex(ReleaseError, "duplicate"):
            load_manifest(path)
        path.write_bytes(b"\xff")
        with self.assertRaisesRegex(ReleaseError, "strict JSON"):
            load_manifest(path)

    def test_bundle_rejects_changed_undeclared_symlink_and_version_skew(self) -> None:
        path = self.write_manifest(self.manifest_value())
        wheel = self.root / f"agent_workflow_quality-{self.version}-py3-none-any.whl"
        wheel.write_bytes(wheel.read_bytes() + b"changed")
        with self.assertRaisesRegex(ReleaseError, "does not match"):
            verify_release(path)

        self.root.joinpath("extra").write_text("extra", encoding="utf-8")
        path = self.write_manifest(self.manifest_value())
        with self.assertRaisesRegex(ReleaseError, "undeclared"):
            verify_release(path)
        self.root.joinpath("extra").unlink()

        path = self.write_manifest(self.manifest_value(wheel_version="9.9.9"))
        with self.assertRaisesRegex(ReleaseError, "wrong package version"):
            verify_release(path)
        path = self.write_manifest(self.manifest_value(sdist_version="9.9.9"))
        with self.assertRaisesRegex(ReleaseError, "wrong package version"):
            verify_release(path)

        path = self.write_manifest(self.manifest_value())
        wheel.unlink()
        try:
            wheel.symlink_to(path.name)
        except OSError:
            self.skipTest("symlinks are unavailable")
        with self.assertRaisesRegex(ReleaseError, "does not match"):
            verify_release(path)

    def test_bundle_rejects_noncanonical_metadata_and_private_content(self) -> None:
        mutations = (
            {"wheel_timestamp": (2026, 9, 9, 5, 15, 28)},
            {"wheel_mode": 0o100755},
            {"sdist_mtime": 1_788_930_928},
            {"sdist_mode": 0o600},
            {"private": True},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                path = self.write_manifest(self.manifest_value(**mutation))
                with self.assertRaisesRegex(ReleaseError, "archive verification"):
                    verify_release(path)

    def test_source_and_registry_bindings_are_checked_without_untracked_noise(self) -> None:
        repository = Repository()
        try:
            for relative in REGISTRY_PATHS.values():
                repository.write(relative, "{}\n")
            repository.write(
                BUILD_CONSTRAINTS_PATH,
                (Path(__file__).parents[1] / BUILD_CONSTRAINTS_PATH).read_bytes(),
            )
            repository.write("README.md", "release fixture\n")
            repository.commit()
            identity = source_identity(repository.root)
            epoch = identity["source_date_epoch"]
            assert isinstance(epoch, int)
            observed = time.gmtime(epoch)
            wheel_timestamp = (
                observed.tm_year,
                observed.tm_mon,
                observed.tm_mday,
                observed.tm_hour,
                observed.tm_min,
                observed.tm_sec - observed.tm_sec % 2,
            )
            value = self.manifest_value(
                wheel_timestamp=wheel_timestamp,
                sdist_mtime=epoch,
            )
            value["source"] = identity
            value["registries"] = registry_digests(repository.root)
            path = self.write_manifest(value)
            repository.write("UNTRACKED.txt", "ignored source noise\n")
            self.assertEqual("pass", verify_release(path, repository.root)["status"])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(
                    0,
                    main(
                        [
                            "--root",
                            str(repository.root),
                            "release-verify",
                            str(path),
                            "--source",
                            "--format",
                            "json",
                        ]
                    ),
                )
            self.assertEqual("pass", json.loads(output.getvalue())["status"])
            self.assertEqual(1, json.loads(output.getvalue())["schema_version"])

            source_mismatch = deepcopy(value)
            source = source_mismatch["source"]
            assert isinstance(source, dict)
            source["commit"] = "d" * 40
            path = self.write_manifest(source_mismatch)
            with self.assertRaisesRegex(ReleaseError, "source identity does not match"):
                verify_release(path, repository.root)

            registry_mismatch = deepcopy(value)
            registries = registry_mismatch["registries"]
            assert isinstance(registries, dict)
            registries["profiles"] = "d" * 64
            path = self.write_manifest(registry_mismatch)
            with self.assertRaisesRegex(ReleaseError, "registry bindings do not match"):
                verify_release(path, repository.root)

            path = self.write_manifest(value)
            repository.write("README.md", "changed\n")
            with self.assertRaisesRegex(ReleaseError, "tracked changes"):
                verify_release(path, repository.root)
        finally:
            repository.close()

    def test_manifest_and_source_primitives_fail_closed(self) -> None:
        with self.assertRaises(ReleaseError):
            validate_manifest([])
        with self.assertRaises(ReleaseError):
            make_manifest(
                version="bad",
                source={},
                builder={},
                registries={},
                artifacts=[],
            )
        missing = self.root / "missing.json"
        with self.assertRaisesRegex(ReleaseError, "unavailable"):
            load_manifest(missing)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(
                1,
                main(
                    [
                        "--root",
                        str(self.root),
                        "release-verify",
                        str(missing),
                        "--format",
                        "json",
                    ]
                ),
            )
        self.assertEqual("error", json.loads(output.getvalue())["status"])
        target = self.root / "target"
        target.write_text("{}\n", encoding="utf-8")
        link = self.root / "link.json"
        try:
            link.symlink_to(target.name)
        except OSError:
            self.skipTest("symlinks are unavailable")
        with self.assertRaisesRegex(ReleaseError, "unavailable"):
            load_manifest(link)

    def test_git_failures_are_normalized(self) -> None:
        repository = Repository()
        try:
            repository.write("README.md", "fixture\n")
            repository.commit()
            nested = repository.root / "nested"
            nested.mkdir()
            with self.assertRaisesRegex(ReleaseError, "worktree root"):
                source_identity(nested)
            with (
                mock.patch(
                    "awq.trust.git", side_effect=ReleaseError("source Git identity is unavailable")
                ),
                self.assertRaisesRegex(ReleaseError, "unavailable"),
            ):
                source_identity(repository.root)
        finally:
            repository.close()

    def test_historical_v013_bundle_retains_its_original_schema_contract(self) -> None:
        with mock.patch.object(
            sys.modules[__name__], "REQUIRED_SCHEMAS", REQUIRED_SCHEMAS - SBOM_SCHEMA_ASSETS
        ):
            value = self.manifest_value()
        path = self.write_manifest(value)
        result = verify_release(path)
        self.assertEqual("pass", result["status"])
        self.assertEqual(1, result["schema_version"])
        artifacts = value["artifacts"]
        assert isinstance(artifacts, list)
        for artifact in artifacts:
            findings = inspect_archive(self.root / artifact["name"])
            self.assertEqual(2, len(findings))
            for name in SBOM_SCHEMA_ASSETS:
                self.assertTrue(any(name in finding for finding in findings))


def subprocess_result(returncode: int, output: bytes) -> subprocess.CompletedProcess[bytes]:
    """Create a narrowly shaped subprocess result for a failure test."""
    return subprocess.CompletedProcess(args=("/usr/bin/git",), returncode=returncode, stdout=output)


if __name__ == "__main__":
    unittest.main()
