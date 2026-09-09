# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Edge-path tests for the advanced Rust helper."""

from __future__ import annotations

import hashlib
import json
import resource
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import awq.rust_advanced_helper as helper


class RustAdvancedHelperEdgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        fixture = Path("fixtures/conforming/rust-advanced/quality/rust-advanced.json")
        self.config = json.loads(fixture.read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_tool_and_toolchain_paths_reject_integrity_drift(self) -> None:
        prefix = self.root / "prefix"
        (prefix / "bin").mkdir(parents=True)
        tool = prefix / "bin/cargo-fuzz"
        tool.write_bytes(b"tool")
        tool.chmod(0o755)
        toolchain = (
            prefix / "rustup/toolchains" / f"{helper.STABLE_TOOLCHAIN}-{helper.HOST_TARGET}" / "bin"
        )
        toolchain.mkdir(parents=True)
        cargo = toolchain / "cargo"
        cargo.write_bytes(b"cargo")
        cargo.chmod(0o755)
        with (
            mock.patch.object(helper, "_prefix", return_value=prefix),
            mock.patch.dict(
                helper.TOOL_METADATA,
                {"cargo-fuzz": {"binary_sha256": hashlib.sha256(b"tool").hexdigest()}},
            ),
        ):
            self.assertEqual(tool, helper._tool("cargo-fuzz"))
            self.assertEqual(cargo, helper._rust_tool(helper.STABLE_TOOLCHAIN, "cargo"))
            with self.assertRaisesRegex(helper.RustAdvancedError, "unavailable"):
                helper._tool("unknown")
            with self.assertRaisesRegex(helper.RustAdvancedError, "unavailable"):
                helper._rust_tool(helper.STABLE_TOOLCHAIN, "unknown")
            tool.write_bytes(b"drift")
            with self.assertRaisesRegex(helper.RustAdvancedError, "integrity"):
                helper._tool("cargo-fuzz")
            cargo.unlink()
            with self.assertRaisesRegex(helper.RustAdvancedError, "unavailable"):
                helper._rust_tool(helper.STABLE_TOOLCHAIN, "cargo")

    def test_manifest_and_installation_verification(self) -> None:
        manifest = {
            "schema_version": 1,
            "toolchains": helper.TOOLCHAIN_METADATA,
            "tools": helper.TOOL_METADATA,
        }
        (self.root / "manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        with mock.patch.object(helper, "_prefix", return_value=self.root):
            helper._manifest()
        manifest["schema_version"] = True
        (self.root / "manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        with (
            mock.patch.object(helper, "_prefix", return_value=self.root),
            self.assertRaisesRegex(helper.RustAdvancedError, "unreviewed"),
        ):
            helper._manifest()

        def rust_tool(channel: str, name: str) -> Path:
            path = self.root / f"{channel}-{name}"
            path.write_text("x", encoding="utf-8")
            return path

        with (
            mock.patch.object(helper, "_manifest"),
            mock.patch.object(helper, "_tool", side_effect=lambda name: self.root / name),
            mock.patch.object(helper, "_rust_tool", side_effect=rust_tool),
            mock.patch.object(helper, "_probe"),
            mock.patch.object(helper, "_runtime_cargo"),
            mock.patch.object(helper, "_prefix", return_value=self.root),
        ):
            hashes = self.root / "rustup/update-hashes"
            hashes.mkdir(parents=True)
            for key, channel in (
                ("stable", helper.STABLE_TOOLCHAIN),
                ("nightly", helper.NIGHTLY_TOOLCHAIN),
            ):
                (hashes / f"{channel}-{helper.HOST_TARGET}").write_text(
                    str(helper.TOOLCHAIN_METADATA[key]["manifest_sha256"])[:20],
                    encoding="ascii",
                )
            helper._verify_installation()
            (hashes / f"{helper.NIGHTLY_TOOLCHAIN}-{helper.HOST_TARGET}").write_text(
                "drift", encoding="ascii"
            )
            with self.assertRaisesRegex(helper.RustAdvancedError, "manifest mismatch"):
                helper._verify_installation()

    def test_git_clean_and_tracked_contracts(self) -> None:
        completed: subprocess.CompletedProcess[str] = subprocess.CompletedProcess([], 0)
        with mock.patch.object(subprocess, "run", return_value=completed):
            self.assertEqual(0, helper._git(self.root, "status"))
            helper._require_clean(self.root)
            helper._require_tracked(self.root, ["Cargo.lock"])
        with mock.patch.object(helper, "_git", return_value=1):
            with self.assertRaisesRegex(helper.RustAdvancedError, "not clean"):
                helper._require_clean(self.root)
            with self.assertRaisesRegex(helper.RustAdvancedError, "not tracked"):
                helper._require_tracked(self.root, ["Cargo.lock"])

    def test_deadline_and_binding_bounds(self) -> None:
        with (
            mock.patch.object(time, "monotonic", return_value=10.0),
            self.assertRaisesRegex(helper.RustAdvancedError, "deadline"),
        ):
            helper._remaining_timeout(10.0)
        with mock.patch.object(time, "monotonic", return_value=9.0):
            self.assertEqual(1.0, helper._remaining_timeout(10.0))
        binding = helper._binding("kind", "x" * 300, "a" * 64)
        self.assertEqual(199, len(binding["id"]))
        with mock.patch.object(resource, "setrlimit") as limit:
            helper._limit_process(self.config["resources"], address_space=False)
        self.assertEqual(3, limit.call_count)

    def test_coverage_report_rejects_tool_failure_and_bad_counts(self) -> None:
        scratch = self.root / "scratch"
        scratch.mkdir()
        with (
            mock.patch.object(helper, "_tool", return_value=Path("/tool")),
            mock.patch.object(helper, "_environment", return_value={}),
            mock.patch.object(helper, "_run", return_value=1),
            self.assertRaisesRegex(helper.RustAdvancedError, "rejected"),
        ):
            helper._coverage_result(self.root, self.config, "a" * 64, scratch)

        reports = [
            {"type": "llvm.coverage.json.export", "version": "1", "data": []},
            {
                "type": "wrong",
                "version": "1",
                "data": [{"totals": {"lines": {"count": 1, "covered": 1}}}],
            },
            {
                "type": "llvm.coverage.json.export",
                "version": "1",
                "data": [{"totals": {"lines": {"count": True, "covered": 1}}}],
            },
            {
                "type": "llvm.coverage.json.export",
                "version": "1",
                "data": [{"totals": {"lines": {"count": 10, "covered": 1}}}],
            },
        ]
        for number, report in enumerate(reports):
            with self.subTest(case=number):
                case_scratch = self.root / f"scratch-{number}"
                case_scratch.mkdir()

                def run(
                    argv: list[str],
                    *_args: object,
                    tested_report: object = report,
                    **_kwargs: object,
                ) -> int:
                    Path(argv[argv.index("--output-path") + 1]).write_text(
                        json.dumps(tested_report), encoding="utf-8"
                    )
                    return 0

                with (
                    mock.patch.object(helper, "_tool", return_value=Path("/tool")),
                    mock.patch.object(helper, "_environment", return_value={}),
                    mock.patch.object(helper, "_run", side_effect=run),
                    self.assertRaises(helper.RustAdvancedError),
                ):
                    helper._coverage_result(self.root, self.config, "a" * 64, case_scratch)

    def test_mutation_report_selection_and_success(self) -> None:
        policy = self.config["mutation"]
        output = self.root / "mutation"
        report_path = output / "mutants.out/outcomes.json"
        report_path.parent.mkdir(parents=True)
        mutant = {
            "file": policy["files"][0],
            "genre": policy["genres"][0],
            "name": "src/lib.rs:2:14: replace > with == in classify",
            "package": policy["packages"][0],
        }
        base = {
            "cargo_mutants_version": "27.1.0",
            "caught": 1,
            "missed": 0,
            "timeout": 0,
            "unviable": 0,
            "total_mutants": 1,
            "outcomes": [{"scenario": {"Mutant": mutant}}],
        }
        invalid = [
            {**base, "cargo_mutants_version": "0"},
            {**base, "caught": True},
            {**base, "total_mutants": 2},
            {**base, "outcomes": ["bad"]},
            {**base, "outcomes": [{"scenario": {"Mutant": {**mutant, "file": "other.rs"}}}]},
        ]
        for number, report in enumerate(invalid):
            report_path.write_text(json.dumps(report), encoding="utf-8")
            with self.subTest(case=number), self.assertRaises(helper.RustAdvancedError):
                helper._mutation_report(output, policy)

        scratch = self.root / "success"
        scratch.mkdir()

        def run(*_args: object, **_kwargs: object) -> int:
            target = scratch / "mutation/mutants.out/outcomes.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(base), encoding="utf-8")
            return 0

        with (
            mock.patch.object(helper, "_tool", return_value=Path("/tool")),
            mock.patch.object(helper, "_environment", return_value={}),
            mock.patch.object(helper, "_run", side_effect=run),
        ):
            bindings = helper._mutation_result(self.root, self.config, "b" * 64, scratch)
        self.assertEqual(
            ["mutation-outcome", "mutation-plan"],
            [binding["kind"] for binding in bindings],
        )

    def test_execute_dispatches_fuzz_mutation_and_rejects_unknown(self) -> None:
        (self.root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        for mode, function in (
            ("fuzz", "_fuzz_result"),
            ("mutation", "_mutation_result"),
        ):
            with (
                self.subTest(mode=mode),
                mock.patch.object(helper, "_require_clean"),
                mock.patch.object(helper, "_require_tracked"),
                mock.patch.object(helper, "_temporary_parent", return_value=self.root),
                mock.patch.object(helper, function, return_value=[]) as invoked,
            ):
                self.assertEqual([], helper._execute(self.root, mode, self.config, "c" * 64))
                invoked.assert_called_once()
        with (
            mock.patch.object(helper, "_require_clean"),
            mock.patch.object(helper, "_require_tracked"),
            mock.patch.object(helper, "_temporary_parent", return_value=self.root),
            self.assertRaisesRegex(helper.RustAdvancedError, "unsupported"),
        ):
            helper._execute(self.root, "unknown", self.config, "c" * 64)

    def test_main_success_is_canonical_and_invalid_invocation_is_redacted(self) -> None:
        bindings = [{"kind": "coverage-policy", "id": "reviewed", "sha256": "a" * 64}]
        stdout = mock.Mock()
        stdout.buffer = mock.Mock()
        with (
            mock.patch.object(helper, "_verify_installation"),
            mock.patch.object(helper, "_configuration", return_value=(self.config, "a" * 64)),
            mock.patch.object(helper, "_verify_project"),
            mock.patch.object(helper, "_execute", return_value=bindings),
            mock.patch.object(sys, "stdout", stdout),
            mock.patch.object(Path, "cwd", return_value=self.root),
        ):
            self.assertEqual(0, helper.main(["coverage"]))
        expected = helper._canonical_bytes(
            {"bindings": bindings, "schema_version": 1, "status": "pass"}
        )
        stdout.buffer.write.assert_called_once_with(expected)
        with mock.patch.object(helper, "_verify_installation"):
            self.assertEqual(1, helper.main([]))


if __name__ == "__main__":
    unittest.main()
