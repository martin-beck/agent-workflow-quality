# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Hostile and success tests for bounded advanced Rust evidence."""

from __future__ import annotations

import hashlib
import json
import os
import resource
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import awq.rust_advanced_helper as helper


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


class RustAdvancedHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        fixture = Path("fixtures/conforming/rust-advanced/quality/rust-advanced.json")
        self.policy = json.loads(fixture.read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, content: str | bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def write_json(self, relative: str, value: object) -> Path:
        return self.write(relative, canonical(value))

    def test_confined_canonical_json_is_strict(self) -> None:
        path = self.write_json("quality/value.json", {"schema_version": 1})
        value, digest = helper._read_json(self.root, "quality/value.json")
        self.assertEqual({"schema_version": 1}, value)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        for relative in ("", "/absolute", "../escape", "nested\\escape", "."):
            with (
                self.subTest(relative=relative),
                self.assertRaisesRegex(helper.RustAdvancedError, "unsafe"),
            ):
                helper._confined_file(self.root, relative)
        path.write_text('{"x":1,"x":2}\n', encoding="utf-8")
        with self.assertRaisesRegex(helper.RustAdvancedError, "duplicate"):
            helper._read_json(self.root, "quality/value.json")
        path.write_text('{"schema_version": 1}\n', encoding="utf-8")
        with self.assertRaisesRegex(helper.RustAdvancedError, "canonical"):
            helper._read_json(self.root, "quality/value.json")
        path.write_bytes(b"\xff")
        with self.assertRaisesRegex(helper.RustAdvancedError, "invalid"):
            helper._read_json(self.root, "quality/value.json")
        path.write_bytes(b"xx")
        with self.assertRaisesRegex(helper.RustAdvancedError, "size bound"):
            helper._confined_file(self.root, "quality/value.json", 1)
        path.unlink()
        target = self.write_json("target.json", {})
        path.symlink_to(target)
        with self.assertRaisesRegex(helper.RustAdvancedError, "unavailable"):
            helper._confined_file(self.root, "quality/value.json")

    def test_policy_validation_accepts_exact_contract_and_rejects_drift(self) -> None:
        self.write_json("quality/rust-advanced.json", self.policy)
        value, digest = helper._configuration(self.root)
        self.assertEqual(self.policy, value)
        self.assertEqual(64, len(digest))
        invalid: list[tuple[str, object]] = [
            ("schema_version", True),
            ("resources", {"memory_mib": 4096}),
            ("coverage", {**self.policy["coverage"], "line_floor": 0}),
            ("coverage", {**self.policy["coverage"], "all_targets": False}),
            ("fuzz", {**self.policy["fuzz"], "toolchain": "nightly"}),
            ("fuzz", {**self.policy["fuzz"], "runs": 0}),
            ("fuzz", {**self.policy["fuzz"], "random_seed": 0}),
            ("fuzz", {**self.policy["fuzz"], "random_seed": 4_294_967_296}),
            ("mutation", {**self.policy["mutation"], "include_re": "["}),
            ("mutation", {**self.policy["mutation"], "genres": ["Unknown"]}),
        ]
        for number, (key, replacement) in enumerate(invalid):
            tested = dict(self.policy)
            tested[key] = replacement
            with self.subTest(case=number):
                self.write_json("quality/rust-advanced.json", tested)
                with self.assertRaises(helper.RustAdvancedError):
                    helper._configuration(self.root)
        for random_seed in (1, 4_294_967_295):
            validated = helper._fuzz({**self.policy["fuzz"], "random_seed": random_seed})
            self.assertEqual(random_seed, validated["random_seed"])

    def test_collection_validators_reject_order_duplicates_and_shapes(self) -> None:
        with self.assertRaisesRegex(helper.RustAdvancedError, "outside"):
            helper._integer(True, 1, 2, "number")
        for value in ([], ["b", "a"], ["a", "a"], ["bad value"]):
            with self.subTest(strings=value), self.assertRaises(helper.RustAdvancedError):
                helper._strings(value, helper.IDENTIFIER, maximum=3, label="items")
        target = self.policy["fuzz"]["targets"][0]
        for targets in (
            [],
            [target, target],
            [{"name": "bad name", "seeds": target["seeds"]}],
            [{"name": target["name"], "seeds": []}],
            [{"name": target["name"], "seeds": [{"path": "../x", "sha256": "0" * 64}]}],
        ):
            with self.subTest(targets=targets), self.assertRaises(helper.RustAdvancedError):
                helper._fuzz_targets(targets)
        mutation = self.policy["mutation"]
        for replacement in ([], ["Cargo.toml"], ["../src/lib.rs"]):
            with self.subTest(files=replacement), self.assertRaises(helper.RustAdvancedError):
                helper._mutation({**mutation, "files": replacement})
        with self.assertRaises(helper.RustAdvancedError):
            helper._mutation({**mutation, "expected_caught": mutation["max_mutants"] + 1})

    def test_project_declarations_and_temporary_parent_are_exact(self) -> None:
        stable = (
            '[toolchain]\nchannel = "1.93.0"\nprofile = "minimal"\n'
            'components = ["clippy", "rustfmt"]\n'
        )
        nightly = (
            '[toolchain]\nchannel = "nightly-2026-09-01"\nprofile = "minimal"\n'
            'components = ["rust-src"]\n'
        )
        for relative, content in {
            "rust-toolchain.toml": stable,
            "Cargo.toml": "[package]\nname='fixture'\n",
            "Cargo.lock": "version = 4\n",
            ".cargo/config.toml": "[net]\noffline=true\n",
            "fuzz/rust-toolchain.toml": nightly,
            "fuzz/Cargo.toml": "[package]\nname='fuzz'\n",
            "fuzz/Cargo.lock": "version = 4\n",
            "fuzz/fuzz_targets/classify.rs": "fn main() {}\n",
        }.items():
            self.write(relative, content)
        helper._verify_project(self.root, "coverage", self.policy)
        helper._verify_project(self.root, "fuzz", self.policy)
        self.write("rust-toolchain.toml", stable.replace("1.93.0", "stable"))
        with self.assertRaisesRegex(helper.RustAdvancedError, "stable contract"):
            helper._verify_project(self.root, "coverage", self.policy)
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(helper._temporary_parent())
        with mock.patch.dict(os.environ, {"TMPDIR": str(self.root)}, clear=True):
            self.assertEqual(self.root, helper._temporary_parent())
        with (
            mock.patch.dict(os.environ, {"TMPDIR": "relative"}, clear=True),
            self.assertRaisesRegex(helper.RustAdvancedError, "temporary"),
        ):
            helper._temporary_parent()

    def test_installation_paths_environment_and_probes_fail_closed(self) -> None:
        prefix = self.root / "prefix"
        toolchain = (
            prefix / "rustup/toolchains" / f"{helper.STABLE_TOOLCHAIN}-{helper.HOST_TARGET}" / "bin"
        )
        toolchain.mkdir(parents=True)
        runtime = prefix / "runtime-cargo"
        runtime.mkdir()
        for name in ("cargo", "rustc", "rustdoc"):
            path = toolchain / name
            path.write_text("#!/bin/sh\n", encoding="utf-8")
            path.chmod(0o755)
        with mock.patch.object(helper, "_prefix", return_value=prefix):
            self.assertEqual(
                toolchain / "cargo", helper._rust_tool(helper.STABLE_TOOLCHAIN, "cargo")
            )
            self.assertEqual(runtime, helper._runtime_cargo())
            scratch = self.root / "scratch"
            scratch.mkdir()
            environment = helper._environment(helper.STABLE_TOOLCHAIN, scratch)
            self.assertEqual("1", environment["CARGO_BUILD_JOBS"])
            self.assertEqual("true", environment["CARGO_NET_OFFLINE"])
            self.assertNotIn("HOME", environment)
            with self.assertRaisesRegex(helper.RustAdvancedError, "unavailable"):
                helper._rust_tool("stable", "cargo")
            (runtime / "credentials.toml").write_text("secret", encoding="utf-8")
            with self.assertRaisesRegex(helper.RustAdvancedError, "unsafe"):
                helper._runtime_cargo()
        success = subprocess.CompletedProcess([], 0, "reviewed\n", "")
        failure = subprocess.CompletedProcess([], 1, "", "private")
        with mock.patch.object(subprocess, "run", return_value=success):
            helper._probe(["/reviewed"], "reviewed")
        with (
            mock.patch.object(subprocess, "run", return_value=failure),
            self.assertRaisesRegex(helper.RustAdvancedError, "version"),
        ):
            helper._probe(["/reviewed"], "reviewed")

    def test_process_limits_success_and_timeout_kill_the_group(self) -> None:
        resources = self.policy["resources"]
        with mock.patch.object(resource, "setrlimit") as limit:
            helper._limit_process(resources, address_space=True)
        self.assertEqual(4, limit.call_count)
        process = mock.Mock(pid=42)
        process.wait.return_value = 0
        with mock.patch.object(subprocess, "Popen", return_value=process):
            self.assertEqual(0, helper._run(["/tool"], self.root, {}, 1, resources))
        process.wait.side_effect = [subprocess.TimeoutExpired("tool", 1), 0]
        with (
            mock.patch.object(subprocess, "Popen", return_value=process),
            mock.patch.object(helper, "_terminate_tree") as terminate,
            self.assertRaisesRegex(helper.RustAdvancedError, "deadline"),
        ):
            helper._run(["/tool"], self.root, {}, 1, resources, address_space=False)
        terminate.assert_called_once_with(process)

    def test_coverage_result_binds_only_reviewed_summary(self) -> None:
        scratch = self.root / "scratch"
        scratch.mkdir()

        def run(argv: list[str], *_args: object, **_kwargs: object) -> int:
            output = Path(argv[argv.index("--output-path") + 1])
            output.write_text(
                json.dumps(
                    {
                        "type": "llvm.coverage.json.export",
                        "version": "2.0.1",
                        "data": [{"totals": {"lines": {"count": 5, "covered": 5}}}],
                    }
                ),
                encoding="utf-8",
            )
            return 0

        with (
            mock.patch.object(helper, "_tool", return_value=Path("/tool")),
            mock.patch.object(helper, "_environment", return_value={}),
            mock.patch.object(helper, "_run", side_effect=run),
        ):
            bindings = helper._coverage_result(self.root, self.policy, "a" * 64, scratch)
        self.assertEqual("coverage-policy", bindings[0]["kind"])
        (scratch / "coverage.json").write_text("{}", encoding="utf-8")
        with (
            mock.patch.object(helper, "_tool", return_value=Path("/tool")),
            mock.patch.object(helper, "_environment", return_value={}),
            mock.patch.object(helper, "_run", return_value=0),
            self.assertRaisesRegex(helper.RustAdvancedError, "invalid"),
        ):
            helper._coverage_result(self.root, self.policy, "a" * 64, scratch)

    def test_corpus_and_fuzz_execution_are_digest_bounded(self) -> None:
        seed = self.write("fuzz/corpus/classify/seed", b"x\n")
        policy = self.policy["fuzz"]
        policy["targets"][0]["seeds"][0]["sha256"] = hashlib.sha256(seed.read_bytes()).hexdigest()
        scratch = self.root / "copy"
        scratch.mkdir()
        with mock.patch.object(helper, "_require_tracked") as tracked:
            corpus, digest, count = helper._copy_corpus(self.root, policy, scratch)
        self.assertEqual((1, 64), (count, len(digest)))
        self.assertEqual(b"x\n", (corpus / "classify/seed-0000").read_bytes())
        tracked.assert_called_once()
        seed.write_bytes(b"changed")
        bad_copy = self.root / "bad-copy"
        bad_copy.mkdir()
        with self.assertRaisesRegex(helper.RustAdvancedError, "integrity"):
            helper._copy_corpus(self.root, policy, bad_copy)

        seed.write_bytes(b"x\n")
        run_scratch = self.root / "run"
        run_scratch.mkdir()
        environment = {"CARGO_TARGET_DIR": str(run_scratch / "target")}
        calls: list[tuple[list[str], bool]] = []

        def run(argv: list[str], *_args: object, **kwargs: object) -> int:
            calls.append((argv, bool(kwargs.get("address_space", True))))
            if "build" in argv:
                executable = (
                    Path(environment["CARGO_TARGET_DIR"]) / helper.HOST_TARGET / "release/classify"
                )
                executable.parent.mkdir(parents=True)
                executable.write_text("#!/bin/sh\n", encoding="utf-8")
                executable.chmod(0o755)
            return 0

        with (
            mock.patch.object(helper, "_require_tracked"),
            mock.patch.object(helper, "_tool", return_value=Path("/tool")),
            mock.patch.object(helper, "_environment", return_value=environment),
            mock.patch.object(helper, "_run", side_effect=run),
        ):
            bindings = helper._fuzz_result(self.root, self.policy, "b" * 64, run_scratch)
        self.assertEqual([True, False], [item[1] for item in calls])
        self.assertEqual(["fuzz-corpus", "fuzz-plan"], [item["kind"] for item in bindings])

    def test_mutation_report_and_result_reject_survivors(self) -> None:
        policy = self.policy["mutation"]
        output = self.root / "output"
        report_path = output / "mutants.out/outcomes.json"
        report_path.parent.mkdir(parents=True)
        outcome = {
            "scenario": {
                "Mutant": {
                    "file": policy["files"][0],
                    "genre": policy["genres"][0],
                    "name": "src/lib.rs:2:14: replace > with == in classify",
                    "package": policy["packages"][0],
                }
            }
        }
        report = {
            "cargo_mutants_version": "27.1.0",
            "caught": 1,
            "missed": 0,
            "timeout": 0,
            "unviable": 0,
            "total_mutants": 1,
            "outcomes": [outcome],
        }
        report_path.write_text(json.dumps(report), encoding="utf-8")
        self.assertEqual((1, 0, 0, 0), helper._mutation_report(output, policy))
        report["missed"] = 1
        report["caught"] = 0
        report_path.write_text(json.dumps(report), encoding="utf-8")
        scratch = self.root / "mutation-run"
        scratch.mkdir()

        def run(*_args: object, **_kwargs: object) -> int:
            target = scratch / "mutation/mutants.out/outcomes.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(report), encoding="utf-8")
            return 0

        with (
            mock.patch.object(helper, "_tool", return_value=Path("/tool")),
            mock.patch.object(helper, "_environment", return_value={}),
            mock.patch.object(helper, "_run", side_effect=run),
            self.assertRaisesRegex(helper.RustAdvancedError, "not all caught"),
        ):
            helper._mutation_result(self.root, self.policy, "c" * 64, scratch)

    def test_execute_preserves_lock_and_main_redacts_failures(self) -> None:
        lock = self.write("Cargo.lock", "version = 4\n")
        with (
            mock.patch.object(helper, "_require_clean"),
            mock.patch.object(helper, "_require_tracked"),
            mock.patch.object(helper, "_coverage_result", return_value=[]),
            mock.patch.object(helper, "_temporary_parent", return_value=self.root),
        ):
            self.assertEqual([], helper._execute(self.root, "coverage", self.policy, "d" * 64))

        def change_lock(*_args: object) -> list[dict[str, str]]:
            lock.write_text("changed\n", encoding="utf-8")
            return []

        with (
            mock.patch.object(helper, "_require_clean"),
            mock.patch.object(helper, "_require_tracked"),
            mock.patch.object(helper, "_coverage_result", side_effect=change_lock),
            mock.patch.object(helper, "_temporary_parent", return_value=self.root),
            self.assertRaisesRegex(helper.RustAdvancedError, "Cargo.lock changed"),
        ):
            helper._execute(self.root, "coverage", self.policy, "d" * 64)
        with mock.patch.object(helper, "_verify_installation", side_effect=OSError("private")):
            self.assertEqual(1, helper.main(["coverage"]))
        with mock.patch.object(helper, "_verify_installation"):
            self.assertEqual(0, helper.main(["--version"]))


if __name__ == "__main__":
    unittest.main()
