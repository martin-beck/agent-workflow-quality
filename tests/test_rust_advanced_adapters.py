# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Executable contracts for bounded advanced Rust evidence adapters."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from awq import adapters
from scripts.validate_contracts import validate
from tests.support import Repository

ADVANCED_IDS = [
    "ADAPTER-RUST-COVERAGE",
    "ADAPTER-RUST-FUZZ",
    "ADAPTER-RUST-MUTATION",
]
BINDING_KINDS = {
    "ADAPTER-RUST-COVERAGE": ["coverage-policy"],
    "ADAPTER-RUST-FUZZ": ["fuzz-corpus", "fuzz-plan"],
    "ADAPTER-RUST-MUTATION": ["mutation-outcome", "mutation-plan"],
}


class RustAdvancedAdapterExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        families, _ = adapters.load_adapter_catalog()
        self.contracts: dict[str, dict[str, Any]] = {
            item["id"]: item for item in families["rust"]["contracts"] if item["id"] in ADVANCED_IDS
        }
        self.repositories: list[Repository] = []
        wrapper = shutil.which("awq-rust-advanced-check")
        if wrapper is None:
            raise RuntimeError("pinned advanced Rust wrapper is unavailable")
        self.wrapper = Path(wrapper).resolve()

    def tearDown(self) -> None:
        for repository in self.repositories:
            repository.close()

    def fixture(self) -> Repository:
        repository = Repository()
        self.repositories.append(repository)
        fixture = Path("fixtures/conforming/rust-advanced")
        for source in sorted(path for path in fixture.rglob("*") if path.is_file()):
            repository.write(source.relative_to(fixture).as_posix(), source.read_bytes())
        repository.commit()
        return repository

    def environment(self, channel: str, scratch: Path) -> dict[str, str]:
        toolchain = (
            self.wrapper.parent.parent
            / "rustup/toolchains"
            / f"{channel}-x86_64-unknown-linux-gnu/bin"
        )
        temporary = scratch / "tmp"
        target = scratch / "target"
        temporary.mkdir()
        target.mkdir()
        return {
            "PATH": f"{toolchain}:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NO_COLOR": "1",
            "CARGO": str(toolchain / "cargo"),
            "CARGO_HOME": str(self.wrapper.parent.parent / "runtime-cargo"),
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": str(target),
            "CARGO_TERM_COLOR": "never",
            "RUSTC": str(toolchain / "rustc"),
            "RUSTDOC": str(toolchain / "rustdoc"),
            "RUSTUP_AUTO_INSTALL": "0",
            "RUSTUP_TOOLCHAIN": channel,
            "TMPDIR": str(temporary),
        }

    def native(self, root: Path, identifier: str) -> bool:  # noqa: C901
        policy = json.loads((root / "quality/rust-advanced.json").read_text())
        with tempfile.TemporaryDirectory(
            prefix="awq-rust-advanced-native-", dir=os.environ.get("TMPDIR")
        ) as name:
            scratch = Path(name)
            if identifier == "ADAPTER-RUST-COVERAGE":
                environment = self.environment("1.93.0", scratch)
                output = scratch / "coverage.json"
                coverage = policy["coverage"]
                argv = [
                    str(self.wrapper.parent / "cargo-llvm-cov"),
                    "llvm-cov",
                    "--json",
                    "--summary-only",
                    "--output-path",
                    str(output),
                    "--fail-under-lines",
                    str(coverage["line_floor"]),
                    "--locked",
                    "--offline",
                    "--all-targets",
                ]
                for package in coverage["packages"]:
                    argv.extend(["--package", package])
                completed = subprocess.run(
                    argv,
                    cwd=root,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=self.contracts[identifier]["timeout_seconds"],
                    check=False,
                )
                return completed.returncode == 0 and output.is_file()

            if identifier == "ADAPTER-RUST-FUZZ":
                fuzz = policy["fuzz"]
                environment = self.environment(fuzz["toolchain"], scratch)
                environment["CARGO_BUILD_JOBS"] = "1"
                corpus = scratch / "corpus"
                artifacts = scratch / "artifacts"
                corpus.mkdir()
                artifacts.mkdir()
                for target in fuzz["targets"]:
                    target_corpus = corpus / target["name"]
                    target_corpus.mkdir()
                    for number, seed in enumerate(target["seeds"]):
                        source_seed = root / seed["path"]
                        if not source_seed.is_file():
                            return False
                        (target_corpus / f"seed-{number:04d}").write_bytes(source_seed.read_bytes())
                    build = subprocess.run(
                        [
                            str(self.wrapper.parent / "cargo-fuzz"),
                            "fuzz",
                            "build",
                            target["name"],
                            "--fuzz-dir",
                            str(root / fuzz["fuzz_dir"]),
                            "--sanitizer",
                            fuzz["sanitizer"],
                            "--target",
                            fuzz["target"],
                            "--target-dir",
                            environment["CARGO_TARGET_DIR"],
                        ],
                        cwd=root,
                        env=environment,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=self.contracts[identifier]["timeout_seconds"],
                        check=False,
                    )
                    executable = (
                        Path(environment["CARGO_TARGET_DIR"])
                        / fuzz["target"]
                        / "release"
                        / target["name"]
                    )
                    if build.returncode or not executable.is_file():
                        return False
                    runtime = dict(environment)
                    runtime["ASAN_OPTIONS"] = "detect_odr_violation=0"
                    run = subprocess.run(
                        [
                            str(executable),
                            f"-runs={fuzz['runs']}",
                            f"-max_len={fuzz['max_length']}",
                            f"-max_total_time={fuzz['max_total_time_seconds']}",
                            f"-timeout={fuzz['input_timeout_seconds']}",
                            f"-seed={fuzz['random_seed']}",
                            f"-rss_limit_mb={policy['resources']['memory_mib']}",
                            f"-malloc_limit_mb={policy['resources']['memory_mib']}",
                            f"-artifact_prefix={artifacts}/",
                            str(target_corpus),
                        ],
                        cwd=root,
                        env=runtime,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=self.contracts[identifier]["timeout_seconds"],
                        check=False,
                    )
                    if run.returncode:
                        return False
                return True

            mutation = policy["mutation"]
            environment = self.environment("1.93.0", scratch)
            output = scratch / "mutation"
            output.mkdir()
            argv = [
                str(self.wrapper.parent / "cargo-mutants"),
                "mutants",
                "--baseline",
                "run",
                "--jobs",
                "1",
                "--timeout",
                str(mutation["test_timeout_seconds"]),
                "--build-timeout",
                str(mutation["build_timeout_seconds"]),
                "--output",
                str(output),
                "--re",
                mutation["include_re"],
                "--colors",
                "never",
                "--no-shuffle",
                "--no-times",
                "-C=--offline",
                "-C=--locked",
            ]
            for package in mutation["packages"]:
                argv.extend(["--package", package])
            for target_file in mutation["files"]:
                argv.extend(["--file", target_file])
            for expression in mutation["exclude_re"]:
                argv.extend(["--exclude-re", expression])
            completed = subprocess.run(
                argv,
                cwd=root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.contracts[identifier]["timeout_seconds"],
                check=False,
            )
            report_path = output / "mutants.out/outcomes.json"
            if completed.returncode or not report_path.is_file():
                return False
            report = json.loads(report_path.read_text())
            return bool(
                report.get("caught") == mutation["expected_caught"]
                and report.get("missed") == 0
                and report.get("timeout") == 0
                and report.get("unviable") == 0
            )

    def assert_negative(
        self, repository: Repository, identifier: str, forbidden: tuple[str, ...]
    ) -> None:
        self.assertFalse(self.native(repository.root, identifier))
        result = adapters.run_adapter(repository.root, self.contracts[identifier])
        self.assertEqual("fail", result["status"])
        self.assertEqual("adapter-failed", result["findings"][0]["code"])
        self.assertNotIn("bindings", result)
        serialized = json.dumps(result)
        for value in (str(repository.root), *forbidden):
            self.assertNotIn(value, serialized)
        validate(result, "adapter-result.schema.json")

    def test_catalog_contracts_are_explicit_bounded_and_schema_valid(self) -> None:
        self.assertEqual(ADVANCED_IDS, sorted(self.contracts))
        expected_tiers = {
            "ADAPTER-RUST-COVERAGE": "pr",
            "ADAPTER-RUST-FUZZ": "scheduled",
            "ADAPTER-RUST-MUTATION": "trusted-host",
        }
        for identifier in ADVANCED_IDS:
            contract = self.contracts[identifier]
            self.assertEqual("awq-rust-advanced-check", contract["tool"])
            self.assertEqual("1.0.0", contract["version"])
            self.assertEqual("awq-bindings-v1", contract["result_protocol"])
            self.assertEqual("explicit", contract["input_mode"])
            self.assertEqual(900, contract["timeout_seconds"])
            self.assertEqual(expected_tiers[identifier], contract["tier"])
            self.assertNotIn("install", " ".join(contract["argv"]))
            validate(contract, "adapter-contract.schema.json")

    def test_every_contract_matches_native_success_and_bindings(self) -> None:
        repository = self.fixture()
        for identifier in ADVANCED_IDS:
            with self.subTest(identifier=identifier):
                self.assertTrue(self.native(repository.root, identifier))
                result = adapters.run_adapter(repository.root, self.contracts[identifier])
                self.assertEqual("pass", result["status"])
                self.assertEqual(
                    BINDING_KINDS[identifier],
                    [binding["kind"] for binding in result["bindings"]],
                )
                validate(result, "adapter-result.schema.json")
        self.assertEqual(
            "",
            subprocess.check_output(
                ["git", "-C", str(repository.root), "status", "--porcelain=v1"],
                text=True,
            ),
        )

    def test_coverage_floor_failure_matches_native_and_redacts_source(self) -> None:
        repository = self.fixture()
        private_marker = "fixture_private_uncovered_74a1"
        repository.write(
            "src/lib.rs",
            (repository.root / "src/lib.rs").read_text()
            + f"\npub fn {private_marker}() -> bool {{ true }}\n",
        )
        repository.commit("uncovered function")
        self.assert_negative(repository, "ADAPTER-RUST-COVERAGE", (private_marker,))

    def test_crashing_seed_failure_matches_native_and_redacts_target(self) -> None:
        repository = self.fixture()
        private_marker = "fixture-private-fuzz-crash-629c"
        repository.write(
            "fuzz/fuzz_targets/classify.rs",
            "#![no_main]\nuse libfuzzer_sys::fuzz_target;\n"
            "fuzz_target!(|data: &[u8]| {\n"
            f'    if data == b"x\\n" {{ panic!("{private_marker}"); }}\n'
            "});\n",
        )
        repository.commit("crashing seed")
        self.assert_negative(repository, "ADAPTER-RUST-FUZZ", (private_marker,))

    def test_surviving_mutant_failure_matches_native_and_redacts_source(self) -> None:
        repository = self.fixture()
        source = (repository.root / "src/lib.rs").read_text()
        private_marker = "fixture_private_survivor_a931"
        source = source.replace(
            "    #[test] fn positive() { assert_eq!(classify(1), 2); }\n",
            f"    // {private_marker}\n",
        )
        repository.write("src/lib.rs", source)
        repository.commit("surviving mutant")
        self.assert_negative(repository, "ADAPTER-RUST-MUTATION", (private_marker,))

    def test_missing_fuzz_target_fails_before_execution(self) -> None:
        repository = self.fixture()
        target = repository.root / "fuzz/fuzz_targets/classify.rs"
        target.unlink()
        repository.commit("missing target")
        self.assert_negative(repository, "ADAPTER-RUST-FUZZ", ("classify.rs",))


if __name__ == "__main__":
    unittest.main()
