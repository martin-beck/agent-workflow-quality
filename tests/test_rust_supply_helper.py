# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Hostile and success tests for the pinned Rust supply helper."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypedDict
from unittest import mock

import awq.rust_supply_helper as helper


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


class LockedPackage(TypedDict):
    checksum: str
    name: str
    source: str
    version: str


class RegistryPackage(LockedPackage):
    yanked: bool


class RegistrySnapshot(TypedDict):
    cargo_lock_sha256: str
    expires_at: str
    generated_at: str
    packages: list[RegistryPackage]
    schema_version: int


class RustSupplyHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_json(self, relative: str, value: object) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(canonical(value), encoding="utf-8")
        return path

    def lock(self) -> tuple[Path, LockedPackage]:
        package: LockedPackage = {
            "checksum": "a" * 64,
            "name": "alpha",
            "source": helper.REGISTRY_SOURCE,
            "version": "1.2.3",
        }
        lock = self.root / "Cargo.lock"
        lock.write_text(
            "# generated\nversion = 4\n\n[[package]]\n"
            'name = "alpha"\nversion = "1.2.3"\n'
            f'source = "{helper.REGISTRY_SOURCE}"\nchecksum = "{"a" * 64}"\n',
            encoding="utf-8",
        )
        return lock, package

    def snapshot(self) -> RegistrySnapshot:
        lock, package = self.lock()
        now = datetime.now(UTC).replace(microsecond=0)
        return {
            "cargo_lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
            "expires_at": timestamp(now + timedelta(days=1)),
            "generated_at": timestamp(now - timedelta(minutes=1)),
            "packages": [
                {
                    "checksum": package["checksum"],
                    "name": package["name"],
                    "source": package["source"],
                    "version": package["version"],
                    "yanked": False,
                }
            ],
            "schema_version": 1,
        }

    def test_canonical_json_rejects_duplicates_noncanonical_and_symlinks(self) -> None:
        path = self.write_json("quality/value.json", {"schema_version": 1})
        value, digest = helper._read_json(self.root, "quality/value.json")
        self.assertEqual({"schema_version": 1}, value)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

        path.write_text('{"schema_version": 1}\n', encoding="utf-8")
        with self.assertRaisesRegex(helper.RustSupplyError, "not canonical"):
            helper._read_json(self.root, "quality/value.json")
        path.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")
        with self.assertRaisesRegex(helper.RustSupplyError, "duplicate"):
            helper._read_json(self.root, "quality/value.json")
        path.unlink()
        target = self.write_json("target.json", {"schema_version": 1})
        path.symlink_to(target)
        with self.assertRaisesRegex(helper.RustSupplyError, "unavailable"):
            helper._read_json(self.root, "quality/value.json")

    def test_confined_inputs_timestamps_and_scratch_fail_closed(self) -> None:
        for relative in ("", "/absolute", "../escape", "nested\\escape", "nested/../escape"):
            with (
                self.subTest(relative=relative),
                self.assertRaisesRegex(helper.RustSupplyError, "unsafe"),
            ):
                helper._confined_file(self.root, relative)

        oversized = self.root / "oversized"
        oversized.write_bytes(b"xx")
        with self.assertRaisesRegex(helper.RustSupplyError, "size bound"):
            helper._confined_file(self.root, "oversized", 1)

        invalid_json = self.root / "invalid.json"
        invalid_json.write_bytes(b"\xff")
        with self.assertRaisesRegex(helper.RustSupplyError, "invalid"):
            helper._read_json(self.root, "invalid.json")
        invalid_json.write_text("{", encoding="utf-8")
        with self.assertRaisesRegex(helper.RustSupplyError, "invalid"):
            helper._read_json(self.root, "invalid.json")

        for value in (None, "2026-09-08T00:00:00+00:00", "not-a-timeZ"):
            with (
                self.subTest(timestamp=value),
                self.assertRaisesRegex(helper.RustSupplyError, "timestamp"),
            ):
                helper._timestamp(value)

        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(helper._temporary_parent())
        with mock.patch.dict(os.environ, {"TMPDIR": str(self.root)}, clear=True):
            self.assertEqual(self.root, helper._temporary_parent())
        with (
            mock.patch.dict(os.environ, {"TMPDIR": "relative"}, clear=True),
            self.assertRaisesRegex(helper.RustSupplyError, "temporary"),
        ):
            helper._temporary_parent()

        rust_prefix = self.root / "rust"
        scratch = self.root / "scratch"
        rust_prefix.mkdir()
        scratch.mkdir()
        with self.assertRaisesRegex(helper.RustSupplyError, "Cargo home"):
            helper._environment(rust_prefix, scratch)
        cargo_home = rust_prefix / "runtime-cargo"
        cargo_home.mkdir()
        (cargo_home / "credentials.toml").write_text("fixture-private", encoding="utf-8")
        with self.assertRaisesRegex(helper.RustSupplyError, "unsafe"):
            helper._environment(rust_prefix, scratch)

    def test_tree_project_lock_and_policy_shapes_fail_closed(self) -> None:
        empty = self.root / "empty"
        empty.mkdir()
        with self.assertRaisesRegex(helper.RustSupplyError, "empty"):
            helper._bounded_tree_files(empty)
        with self.assertRaisesRegex(helper.RustSupplyError, "traversal"):
            helper._walk_error(OSError("fixture-private-traversal"))

        tree = self.root / "tree"
        target = tree / "target"
        target.mkdir(parents=True)
        (target / "entry").write_text("x", encoding="utf-8")
        (tree / "linked").symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(helper.RustSupplyError, "symlink"):
            helper._bounded_tree_files(tree)
        (tree / "linked").unlink()
        with (
            mock.patch.object(helper, "MAX_TREE_ENTRIES", 0),
            self.assertRaisesRegex(helper.RustSupplyError, "safety bound"),
        ):
            helper._bounded_tree_files(tree)

        manifest = {
            "advisory_db": {
                "expires_at": timestamp(datetime.now(UTC) + timedelta(days=1)),
            }
        }
        database = self.root / "advisory-db"
        database.mkdir()
        with (
            mock.patch.object(helper, "_prefix", return_value=self.root),
            mock.patch.object(helper, "_tree_sha256", return_value=helper.ADVISORY_TREE_SHA256),
        ):
            self.assertEqual(database, helper._verify_advisory_database(manifest))

        (self.root / "rust-toolchain.toml").write_text(
            '[toolchain]\nchannel = "stable"\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(helper.RustSupplyError, "toolchain"):
            helper._verify_rust_project(self.root)
        (self.root / "rust-toolchain.toml").write_text(
            '[toolchain]\nchannel = "1.93.0"\nprofile = "minimal"\n'
            'components = ["clippy", "rustfmt"]\n',
            encoding="utf-8",
        )
        (self.root / "Cargo.toml").write_text("[package]\nname='fixture'\n", encoding="utf-8")
        (self.root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        (self.root / ".cargo").mkdir()
        (self.root / ".cargo/config.toml").write_text("[net]\noffline=true\n", encoding="utf-8")
        helper._verify_rust_project(self.root)

        malformed_locks = (
            "version = 4\n",
            'version = 4\npackage = ["bad"]\n',
            (
                f'version = 4\n[[package]]\nname="alpha"\nversion="1.0.0"\n'
                f'source="{helper.REGISTRY_SOURCE}"\n'
            ),
            (
                f'version = 4\n[[package]]\nname="alpha"\nversion="1.0.0"\n'
                f'source="{helper.REGISTRY_SOURCE}"\nchecksum="bad"\n'
            ),
            (
                f'version = 4\n[[package]]\nname="alpha"\nversion="2.0.0"\n'
                f'source="{helper.REGISTRY_SOURCE}"\nchecksum="{"a" * 64}"\n'
                f'[[package]]\nname="alpha"\nversion="1.0.0"\n'
                f'source="{helper.REGISTRY_SOURCE}"\nchecksum="{"b" * 64}"\n'
            ),
        )
        for number, content in enumerate(malformed_locks):
            with self.subTest(lock_case=number), self.assertRaises(helper.RustSupplyError):
                helper._registry_packages_from_content(content.encode())

        snapshot: dict[str, object] = dict(self.snapshot())
        del snapshot["packages"]
        self.write_json("quality/rust-registry-snapshot.json", snapshot)
        with self.assertRaisesRegex(helper.RustSupplyError, "snapshot is invalid"):
            helper._registry_snapshot(self.root)
        self.write_json("quality/rust-advisory-policy.json", {"schema_version": 1})
        with self.assertRaisesRegex(helper.RustSupplyError, "policy is invalid"):
            helper._advisory_policy(self.root)

    def test_registry_snapshot_binds_lock_versions_checksums_yanks_and_time(self) -> None:
        snapshot = self.snapshot()
        path = self.write_json("quality/rust-registry-snapshot.json", snapshot)
        identifier, digest = helper._registry_snapshot(self.root)
        self.assertEqual(
            f"cargo-lock:{snapshot['cargo_lock_sha256'][:16]}",
            identifier,
        )
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

        rejected: list[dict[str, object]] = [
            {**snapshot, "cargo_lock_sha256": "0" * 64},
            {
                **snapshot,
                "packages": [{**snapshot["packages"][0], "yanked": True}],
            },
            {
                **snapshot,
                "generated_at": timestamp(datetime.now(UTC) + timedelta(days=1)),
            },
            {
                **snapshot,
                "generated_at": timestamp(datetime.now(UTC) - timedelta(days=91)),
            },
            {**snapshot, "schema_version": True},
        ]
        for number, value in enumerate(rejected):
            with self.subTest(case=number):
                self.write_json("quality/rust-registry-snapshot.json", value)
                with self.assertRaises(helper.RustSupplyError):
                    helper._registry_snapshot(self.root)

    def test_advisory_policy_and_semver_descriptor_are_exact(self) -> None:
        self.write_json(
            "quality/rust-advisory-policy.json",
            {"ignored_advisories": ["RUSTSEC-2020-0001"], "schema_version": 1},
        )
        self.assertEqual(["RUSTSEC-2020-0001"], helper._advisory_policy(self.root))
        self.write_json(
            "quality/rust-advisory-policy.json",
            {
                "ignored_advisories": ["RUSTSEC-2020-0001", "RUSTSEC-2020-0001"],
                "schema_version": 1,
            },
        )
        with self.assertRaises(helper.RustSupplyError):
            helper._advisory_policy(self.root)

        baseline = self.root / "quality/rust-semver-baseline.json"
        baseline.write_text('{"format_version":43,"index":{}}\n', encoding="utf-8")
        digest = hashlib.sha256(baseline.read_bytes()).hexdigest()
        descriptor = {
            "baseline_id": "v1.2.3",
            "baseline_path": "quality/rust-semver-baseline.json",
            "baseline_sha256": digest,
            "cargo_semver_checks": "0.50.0",
            "crate_name": "example_crate",
            "feature_policy": "default-features",
            "package": "example-package",
            "release_type": "minor",
            "rust": "1.93.0",
            "schema_version": 1,
            "target": helper.HOST_TARGET,
        }
        self.write_json("quality/rust-semver-baseline.lock.json", descriptor)
        observed = helper._semver_baseline(self.root)
        self.assertEqual(
            (baseline, "v1.2.3", digest, "minor", "example-package", "example_crate"),
            observed,
        )

        updates: tuple[dict[str, object], ...] = (
            {"baseline_sha256": "0" * 64},
            {"release_type": []},
            {"feature_policy": "heuristic"},
            {"schema_version": True},
        )
        for update in updates:
            with self.subTest(update=update):
                self.write_json(
                    "quality/rust-semver-baseline.lock.json",
                    {**descriptor, **update},
                )
                with self.assertRaises(helper.RustSupplyError):
                    helper._semver_baseline(self.root)

    def test_advisory_tree_digest_is_deterministic_and_rejects_unsafe_entries(self) -> None:
        tree = self.root / "tree"
        (tree / "z").mkdir(parents=True)
        (tree / "z/b").write_bytes(b"two")
        (tree / "a").write_bytes(b"one")
        first = helper._tree_sha256(tree)
        (tree / "a").unlink()
        (tree / "a").write_bytes(b"one")
        self.assertEqual(first, helper._tree_sha256(tree))

        target = self.root / "outside"
        target.write_bytes(b"private")
        (tree / "link").symlink_to(target)
        with self.assertRaisesRegex(helper.RustSupplyError, "unsafe|symlink"):
            helper._tree_sha256(tree)
        (tree / "link").unlink()

        fifo = tree / "pipe"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(helper.RustSupplyError, "unsafe"):
            helper._tree_sha256(tree)
        fifo.unlink()

        with (
            mock.patch.object(helper, "MAX_TREE_FILES", 1),
            self.assertRaisesRegex(helper.RustSupplyError, "safety bound"),
        ):
            helper._tree_sha256(tree)

    def test_advisory_database_expiry_missing_tree_and_integrity_fail_closed(self) -> None:
        now = datetime.now(UTC).replace(microsecond=0)
        manifest = {
            "advisory_db": {
                "expires_at": timestamp(now + timedelta(days=1)),
            }
        }
        with (
            mock.patch.object(helper, "_prefix", return_value=self.root),
            self.assertRaisesRegex(helper.RustSupplyError, "unavailable"),
        ):
            helper._verify_advisory_database(manifest)

        manifest["advisory_db"]["expires_at"] = timestamp(now - timedelta(days=1))
        with (
            mock.patch.object(helper, "_prefix", return_value=self.root),
            self.assertRaisesRegex(helper.RustSupplyError, "expired"),
        ):
            helper._verify_advisory_database(manifest)

        database = self.root / "advisory-db"
        database.mkdir()
        (database / "advisory.md").write_text("fixture-secret-advisory-db", encoding="utf-8")
        manifest["advisory_db"]["expires_at"] = timestamp(now + timedelta(days=1))
        with (
            mock.patch.object(helper, "_prefix", return_value=self.root),
            self.assertRaisesRegex(helper.RustSupplyError, "integrity"),
        ):
            helper._verify_advisory_database(manifest)

    def test_environment_is_isolated_and_policy_argv_is_frozen(self) -> None:
        rust_prefix = self.root / "rust"
        cargo_home = rust_prefix / "runtime-cargo"
        tool_bin = rust_prefix / (
            f"rustup/toolchains/{helper.RUST_VERSION}-{helper.HOST_TARGET}/bin"
        )
        cargo_home.mkdir(parents=True)
        tool_bin.mkdir(parents=True)
        for name in ("cargo", "rustc", "rustdoc"):
            path = tool_bin / name
            path.write_bytes(b"tool")
            path.chmod(0o755)
        scratch = self.root / "scratch"
        scratch.mkdir()
        environment = helper._environment(rust_prefix, scratch)
        self.assertEqual("true", environment["CARGO_NET_OFFLINE"])
        self.assertEqual("1", environment["RUSTC_BOOTSTRAP"])
        self.assertEqual(
            set(environment),
            {
                "CARGO",
                "CARGO_HOME",
                "CARGO_NET_OFFLINE",
                "CARGO_TARGET_DIR",
                "CARGO_TERM_COLOR",
                "HOME",
                "LANG",
                "LC_ALL",
                "NO_COLOR",
                "PATH",
                "RUSTC",
                "RUSTC_BOOTSTRAP",
                "RUSTDOC",
                "TMPDIR",
                "XDG_CACHE_HOME",
            },
        )
        self.assertNotIn("SSH_AUTH_SOCK", environment)

        (self.root / "deny.toml").write_text("[licenses]\n", encoding="utf-8")
        with (
            mock.patch.object(
                helper,
                "_registry_snapshot",
                return_value=("cargo-lock:abc", "a" * 64),
            ),
            mock.patch.object(helper, "_tool", return_value=Path("/reviewed/cargo-deny")),
            mock.patch.object(helper, "_invoke") as invoke,
            mock.patch.object(helper, "_binding") as binding,
        ):
            helper._policy(self.root, rust_prefix)
        argv = invoke.call_args.args[1]
        self.assertEqual("/reviewed/cargo-deny", argv[0])
        self.assertIn("--frozen", argv)
        self.assertEqual(["bans", "licenses", "sources"], argv[-3:])
        binding.assert_called_once_with("registry-snapshot", "cargo-lock:abc", "a" * 64)

    def test_installation_manifest_tools_and_process_boundaries_are_pinned(self) -> None:
        rust_prefix = self.root / "rust"
        rust_prefix.mkdir()
        manifest: dict[str, Any] = {
            "advisory_db": {
                "archive_sha256": (
                    "ff54ebd7becdaa59efe2d54e516d8c1e10e7c2fb20c8d3241a20889c5000f3eb"
                ),
                "commit": helper.ADVISORY_COMMIT,
                "expires_at": helper.ADVISORY_EXPIRES_AT,
                "snapshot_at": "2026-09-08T09:58:15Z",
                "tree_sha256": helper.ADVISORY_TREE_SHA256,
            },
            "rust_tools_prefix": str(rust_prefix),
            "schema_version": 1,
            "tools": helper.TOOL_METADATA,
        }
        self.write_json("manifest.json", manifest)
        with mock.patch.object(helper, "_prefix", return_value=self.root):
            self.assertEqual(manifest, helper._manifest())
        self.write_json("manifest.json", {**manifest, "schema_version": True})
        with (
            mock.patch.object(helper, "_prefix", return_value=self.root),
            self.assertRaisesRegex(helper.RustSupplyError, "unreviewed"),
        ):
            helper._manifest()

        self.assertEqual(rust_prefix, helper._rust_prefix(manifest))
        with self.assertRaisesRegex(helper.RustSupplyError, "invalid"):
            helper._rust_prefix({**manifest, "rust_tools_prefix": 7})

        supply = self.root / "bin/cargo-deny"
        supply.parent.mkdir()
        supply.write_bytes(b"reviewed supply tool")
        supply.chmod(0o755)
        digest = hashlib.sha256(supply.read_bytes()).hexdigest()
        with (
            mock.patch.object(helper, "_prefix", return_value=self.root),
            mock.patch.dict(helper.TOOL_METADATA["cargo-deny"], {"binary_sha256": digest}),
        ):
            self.assertEqual(supply, helper._tool("cargo-deny"))
            supply.write_bytes(b"changed")
            with self.assertRaisesRegex(helper.RustSupplyError, "integrity"):
                helper._tool("cargo-deny")
        with self.assertRaisesRegex(helper.RustSupplyError, "unavailable"):
            helper._tool("unknown")

        tool_bin = rust_prefix / (
            f"rustup/toolchains/{helper.RUST_VERSION}-{helper.HOST_TARGET}/bin"
        )
        tool_bin.mkdir(parents=True)
        for name in ("cargo", "rustc", "rustdoc"):
            path = tool_bin / name
            path.write_bytes(b"tool")
            path.chmod(0o755)
        self.assertEqual(tool_bin / "cargo", helper._rust_tool(rust_prefix, "cargo"))
        with self.assertRaisesRegex(helper.RustSupplyError, "unavailable"):
            helper._rust_tool(rust_prefix, "rustfmt")

        success = subprocess.CompletedProcess(["tool"], 0, "expected\n", "")
        failure = subprocess.CompletedProcess(["tool"], 1, "", "private diagnostic")
        with mock.patch.object(subprocess, "run", return_value=success):
            helper._probe(["tool"], "expected", {})
        with (
            mock.patch.object(subprocess, "run", return_value=failure),
            self.assertRaisesRegex(helper.RustSupplyError, "version mismatch"),
        ):
            helper._probe(["tool"], "expected", {})

        wrapper = rust_prefix / "bin/awq-rust-check"
        wrapper.parent.mkdir()
        wrapper.write_bytes(b"wrapper")
        wrapper.chmod(0o755)
        with (
            mock.patch.object(helper, "_tool", return_value=Path("/reviewed/supply")),
            mock.patch.object(helper, "_probe") as probe,
            mock.patch.object(
                helper, "_rust_tool", return_value=Path("/reviewed/rust")
            ) as rust_tool,
        ):
            helper._verify_installation(manifest, rust_prefix)
        self.assertEqual(4, probe.call_count)
        self.assertEqual(
            ["cargo", "rustc", "rustdoc"], [call.args[1] for call in rust_tool.call_args_list]
        )
        rejected = {
            **manifest,
            "advisory_db": {**manifest["advisory_db"], "tree_sha256": "0" * 64},
        }
        with (
            mock.patch.object(helper, "_tool", return_value=Path("/reviewed/supply")),
            mock.patch.object(helper, "_probe"),
            mock.patch.object(helper, "_rust_tool", return_value=Path("/reviewed/rust")),
            self.assertRaisesRegex(helper.RustSupplyError, "unreviewed"),
        ):
            helper._verify_installation(rejected, rust_prefix)

        with mock.patch.object(
            subprocess,
            "run",
            return_value=subprocess.CompletedProcess(["tool"], 0),
        ):
            helper._run_command(self.root, ["tool"], {})
        with (
            mock.patch.object(
                subprocess,
                "run",
                return_value=subprocess.CompletedProcess(["tool"], 1),
            ),
            self.assertRaisesRegex(helper.RustSupplyError, "rejected"),
        ):
            helper._run_command(self.root, ["tool"], {})
        with (
            mock.patch.object(
                helper, "_environment", return_value={"isolated": "yes"}
            ) as environment,
            mock.patch.object(helper, "_run_command") as run_command,
        ):
            helper._invoke(self.root, ["tool"], rust_prefix)
        environment.assert_called_once()
        run_command.assert_called_once_with(self.root, ["tool"], {"isolated": "yes"})
        with mock.patch("builtins.print") as output:
            helper._binding("advisory-db", "rustsec:reviewed", "a" * 64)
        document = json.loads(output.call_args.args[0])
        self.assertEqual("rustsec:reviewed", document["bindings"][0]["id"])

    def test_audit_and_semver_orchestration_are_exact(self) -> None:
        rust_prefix = self.root / "rust"
        rust_prefix.mkdir()
        database = self.root / "advisory-db"
        database.mkdir()
        manifest = {"advisory_db": {"expires_at": helper.ADVISORY_EXPIRES_AT}}
        with (
            mock.patch.object(helper, "_verify_advisory_database", return_value=database),
            mock.patch.object(
                helper,
                "_advisory_policy",
                return_value=["RUSTSEC-2020-0001", "RUSTSEC-2021-0002"],
            ),
            mock.patch.object(helper, "_tool", return_value=Path("/reviewed/cargo-audit")),
            mock.patch.object(helper, "_invoke") as invoke,
            mock.patch.object(helper, "_binding") as binding,
        ):
            helper._audit(self.root, manifest, rust_prefix)
        audit_argv = invoke.call_args.args[1]
        self.assertEqual("/reviewed/cargo-audit", audit_argv[0])
        self.assertIn("--no-fetch", audit_argv)
        self.assertIn("--no-yanked", audit_argv)
        self.assertEqual(
            ["--ignore", "RUSTSEC-2020-0001", "--ignore", "RUSTSEC-2021-0002"],
            audit_argv[-4:],
        )
        binding.assert_called_once_with(
            "advisory-db",
            f"rustsec:{helper.ADVISORY_COMMIT}",
            helper.ADVISORY_TREE_SHA256,
        )

        baseline = self.write_json(
            "quality/rust-semver-baseline.json",
            {"format_version": 43, "index": {}},
        )
        digest = hashlib.sha256(baseline.read_bytes()).hexdigest()

        def environment(_prefix: Path, scratch: Path) -> dict[str, str]:
            return {"CARGO_TARGET_DIR": str(scratch / "target")}

        def rust_tool(_prefix: Path, name: str) -> Path:
            return Path(f"/reviewed/{name}")

        def run_command(_root: Path, argv: list[str], env: dict[str, str]) -> None:
            if argv[1] == "rustdoc":
                current = (
                    Path(env["CARGO_TARGET_DIR"]) / helper.HOST_TARGET / "doc/example_crate.json"
                )
                current.parent.mkdir(parents=True)
                current.write_text('{"format_version":43,"index":{}}\n', encoding="utf-8")

        with (
            mock.patch.object(
                helper,
                "_semver_baseline",
                return_value=(
                    baseline,
                    "v1.2.3",
                    digest,
                    "minor",
                    "example-package",
                    "example_crate",
                ),
            ),
            mock.patch.object(helper, "_environment", side_effect=environment),
            mock.patch.object(helper, "_rust_tool", side_effect=rust_tool),
            mock.patch.object(helper, "_tool", return_value=Path("/reviewed/cargo-semver-checks")),
            mock.patch.object(helper, "_run_command", side_effect=run_command) as runner,
            mock.patch.object(helper, "_binding") as semver_binding,
        ):
            helper._semver(self.root, rust_prefix)
        self.assertEqual(2, runner.call_count)
        rustdoc_argv = runner.call_args_list[0].args[1]
        semver_argv = runner.call_args_list[1].args[1]
        self.assertEqual("/reviewed/cargo", rustdoc_argv[0])
        self.assertIn("--offline", rustdoc_argv)
        self.assertEqual("/reviewed/cargo-semver-checks", semver_argv[0])
        self.assertIn(str(baseline), semver_argv)
        self.assertIn("minor", semver_argv)
        semver_binding.assert_called_once_with("semver-baseline", "v1.2.3", digest)

    def test_semver_rejects_invalid_current_rustdoc(self) -> None:
        baseline = self.write_json(
            "quality/rust-semver-baseline.json",
            {"format_version": 43, "index": {}},
        )
        digest = hashlib.sha256(baseline.read_bytes()).hexdigest()
        rust_prefix = self.root / "rust"
        rust_prefix.mkdir()

        def environment(_prefix: Path, scratch: Path) -> dict[str, str]:
            return {"CARGO_TARGET_DIR": str(scratch / "target")}

        def rust_tool(_prefix: Path, name: str) -> Path:
            return Path(f"/reviewed/{name}")

        for content in ("{", "[]\n"):
            calls = 0

            def run_command(
                _root: Path,
                argv: list[str],
                env: dict[str, str],
                payload: str = content,
            ) -> None:
                nonlocal calls
                calls += 1
                if argv[1] == "rustdoc":
                    current = (
                        Path(env["CARGO_TARGET_DIR"])
                        / helper.HOST_TARGET
                        / "doc/example_crate.json"
                    )
                    current.parent.mkdir(parents=True)
                    current.write_text(payload, encoding="utf-8")

            with (
                self.subTest(content=content),
                mock.patch.object(
                    helper,
                    "_semver_baseline",
                    return_value=(
                        baseline,
                        "v1.2.3",
                        digest,
                        "minor",
                        "example-package",
                        "example_crate",
                    ),
                ),
                mock.patch.object(helper, "_environment", side_effect=environment),
                mock.patch.object(helper, "_rust_tool", side_effect=rust_tool),
                mock.patch.object(helper, "_run_command", side_effect=run_command),
                mock.patch.object(helper, "_binding") as binding,
                self.assertRaisesRegex(helper.RustSupplyError, "current API"),
            ):
                helper._semver(self.root, rust_prefix)
            self.assertEqual(1, calls)
            binding.assert_not_called()

    def test_main_routes_modes_and_minimizes_failures(self) -> None:
        manifest: dict[str, object] = {}
        rust_prefix = self.root / "rust"
        with (
            mock.patch.object(helper, "_manifest", return_value=manifest),
            mock.patch.object(helper, "_rust_prefix", return_value=rust_prefix),
            mock.patch.object(helper, "_verify_installation"),
            mock.patch.object(helper, "_verify_rust_project"),
            mock.patch.object(helper, "_policy") as policy,
            mock.patch.object(helper, "_audit") as audit,
            mock.patch.object(helper, "_semver") as semver,
            mock.patch("builtins.print") as output,
        ):
            self.assertEqual(0, helper.main(["--version"]))
            output.assert_called_once_with(helper.VERSION_OUTPUT)
            output.reset_mock()
            for mode in ("policy", "audit", "semver"):
                with self.subTest(mode=mode):
                    self.assertEqual(0, helper.main([mode]))
            policy.assert_called_once_with(Path.cwd().resolve(), rust_prefix)
            audit.assert_called_once_with(Path.cwd().resolve(), manifest, rust_prefix)
            semver.assert_called_once_with(Path.cwd().resolve(), rust_prefix)
            self.assertEqual(1, helper.main(["unsupported"]))
            self.assertEqual(
                "awq-rust-supply-check: validation failed",
                output.call_args.args[0],
            )
            self.assertNotIn("unsupported", str(output.call_args))

        with (
            mock.patch.object(helper, "_manifest", side_effect=OSError("fixture-private-path")),
            mock.patch("builtins.print") as output,
        ):
            self.assertEqual(1, helper.main(["audit"]))
        self.assertEqual("awq-rust-supply-check: validation failed", output.call_args.args[0])
        self.assertNotIn("fixture-private-path", str(output.call_args))


if __name__ == "__main__":
    unittest.main()
