# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Failure-path coverage for advanced Rust evidence."""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import awq.rust_advanced_helper as helper


class RustAdvancedHelperFailureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.config = json.loads(
            Path("fixtures/conforming/rust-advanced/quality/rust-advanced.json").read_text()
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_missing_paths_and_policy_shapes_fail_closed(self) -> None:
        self.assertTrue(helper._prefix().is_dir())
        with mock.patch.object(helper, "_prefix", return_value=self.root):
            with self.assertRaisesRegex(helper.RustAdvancedError, "toolchain"):
                helper._toolchain_bin(helper.STABLE_TOOLCHAIN)
            with self.assertRaisesRegex(helper.RustAdvancedError, "Cargo home"):
                helper._runtime_cargo()
        for function, value in (
            (helper._coverage, {}),
            (helper._fuzz, {}),
            (helper._mutation, {}),
            (helper._fuzz_targets, [{"name": "x"}]),
        ):
            with (
                self.subTest(function=function.__name__),
                self.assertRaises(helper.RustAdvancedError),
            ):
                function(value)
        target = self.config["fuzz"]["targets"][0]
        seed = target["seeds"][0]
        second = {"name": "alpha", "seeds": [{**seed, "path": "fuzz/corpus/alpha/seed"}]}
        first = {"name": "zeta", "seeds": [{**seed, "path": "fuzz/corpus/zeta/seed"}]}
        with self.assertRaisesRegex(helper.RustAdvancedError, "targets are not ordered"):
            helper._fuzz_targets([first, second])
        unsorted_seeds = [
            {**seed, "path": f"fuzz/corpus/{target['name']}/z"},
            {**seed, "path": f"fuzz/corpus/{target['name']}/a"},
        ]
        with self.assertRaisesRegex(helper.RustAdvancedError, "seeds are not ordered"):
            helper._fuzz_targets([{**target, "seeds": unsorted_seeds}])
        mutation = self.config["mutation"]
        with self.assertRaisesRegex(helper.RustAdvancedError, "filters"):
            helper._mutation({**mutation, "exclude_re": [1]})
        with self.assertRaisesRegex(helper.RustAdvancedError, "unsafe"):
            helper._mutation({**mutation, "include_re": "^(.+)+$"})
        with self.assertRaisesRegex(helper.RustAdvancedError, "filter is invalid"):
            helper._mutation({**mutation, "include_re": "^[.$"})

    def test_fuzz_build_executable_and_runtime_failures(self) -> None:
        seed = self.root / "fuzz/corpus/classify/seed.txt"
        seed.parent.mkdir(parents=True)
        seed.write_bytes(b"x\n")
        self.config["fuzz"]["targets"][0]["seeds"][0]["sha256"] = hashlib.sha256(
            seed.read_bytes()
        ).hexdigest()

        for failure in ("build", "executable", "runtime"):
            scratch = self.root / failure
            scratch.mkdir()
            environment = {"CARGO_TARGET_DIR": str(scratch / "target")}
            calls = 0

            def run(
                _argv: list[str],
                *_args: object,
                case: str = failure,
                target_root: Path = Path(environment["CARGO_TARGET_DIR"]),
                **_kwargs: object,
            ) -> int:
                nonlocal calls
                calls += 1
                if calls == 1 and case == "build":
                    return 1
                if calls == 1 and case != "executable":
                    executable = target_root / helper.HOST_TARGET / "release/classify"
                    executable.parent.mkdir(parents=True)
                    executable.write_text("#!/bin/sh\n")
                    executable.chmod(0o755)
                return int(calls == 2 and case == "runtime")

            with (
                self.subTest(failure=failure),
                mock.patch.object(helper, "_require_tracked"),
                mock.patch.object(helper, "_tool", return_value=Path("/tool")),
                mock.patch.object(helper, "_environment", return_value=environment),
                mock.patch.object(helper, "_run", side_effect=run),
                self.assertRaises(helper.RustAdvancedError),
            ):
                helper._fuzz_result(self.root, self.config, "a" * 64, scratch)

    def test_corpus_and_mutation_report_limits(self) -> None:
        seed = self.root / "fuzz/corpus/classify/seed.txt"
        seed.parent.mkdir(parents=True)
        seed.write_bytes(b"xx")
        policy = self.config["fuzz"]
        policy["targets"][0]["seeds"][0]["sha256"] = hashlib.sha256(b"xx").hexdigest()
        scratch = self.root / "corpus"
        scratch.mkdir()
        with (
            mock.patch.object(helper, "MAX_CORPUS_BYTES", 1),
            self.assertRaisesRegex(helper.RustAdvancedError, "corpus"),
        ):
            helper._copy_corpus(self.root, policy, scratch)

        mutation = self.config["mutation"]
        output = self.root / "report"
        with self.assertRaisesRegex(helper.RustAdvancedError, "unavailable"):
            helper._mutation_report(output, mutation)
        path = output / "mutants.out/outcomes.json"
        path.parent.mkdir(parents=True)
        path.write_text("{}")
        with self.assertRaisesRegex(helper.RustAdvancedError, "invalid"):
            helper._mutation_report(output, mutation)

        base = {
            "cargo_mutants_version": "27.1.0",
            "caught": 1,
            "missed": 0,
            "timeout": 0,
            "unviable": 0,
            "total_mutants": 1,
        }
        for outcomes, message in (
            ([{"scenario": {"Mutant": "bad"}}], "outcome is invalid"),
            ([], "count is invalid"),
        ):
            path.write_text(json.dumps({**base, "outcomes": outcomes}))
            with (
                self.subTest(outcomes=outcomes),
                self.assertRaisesRegex(helper.RustAdvancedError, message),
            ):
                helper._mutation_report(output, mutation)

    def test_real_timeout_terminates_descendant(self) -> None:
        pid_file = self.root / "child.pid"
        source = (
            "import pathlib,subprocess,time;"
            "child=subprocess.Popen(['/usr/bin/sleep','30']);"
            f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid));"
            "time.sleep(30)"
        )
        with self.assertRaisesRegex(helper.RustAdvancedError, "deadline"):
            helper._run(
                ["/usr/bin/python3", "-c", source],
                self.root,
                {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
                1,
                self.config["resources"],
                address_space=False,
            )
        child_pid = int(pid_file.read_text())
        process_stat = Path(f"/proc/{child_pid}/stat")
        for _ in range(100):
            if not process_stat.exists() or ") Z " in process_stat.read_text():
                break
            time.sleep(0.01)
        self.assertTrue(not process_stat.exists() or ") Z " in process_stat.read_text())

    def test_fuzz_toolchain_declaration_is_exact(self) -> None:
        stable = (
            '[toolchain]\nchannel = "1.93.0"\nprofile = "minimal"\n'
            'components = ["clippy", "rustfmt"]\n'
        )
        files = {
            "rust-toolchain.toml": stable,
            "Cargo.toml": "[package]\nname='x'\n",
            "Cargo.lock": "version=4\n",
            ".cargo/config.toml": "[net]\noffline=true\n",
            "fuzz/rust-toolchain.toml": stable,
        }
        for relative, content in files.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        with self.assertRaisesRegex(helper.RustAdvancedError, "fuzz toolchain"):
            helper._verify_project(self.root, "fuzz", self.config)


if __name__ == "__main__":
    unittest.main()
