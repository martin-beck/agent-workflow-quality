# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Independent native-oracle and fail-closed tests for bounded Python refactoring."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any
from unittest import mock

from awq import adapters, refactor
from awq import refactor_worker as worker
from awq.cli import main
from awq.project import ProjectError
from awq.registry import canonical_bytes
from scripts import install_refactor_tools as installer
from scripts.validate_contracts import validate

ROOT = Path(__file__).resolve().parents[1]
PYTHON = Path(sys.executable).resolve()
FIXTURE = ROOT / "fixtures/conforming/refactoring"


class RefactorTests(unittest.TestCase):
    temporary: tempfile.TemporaryDirectory[str]
    base: Path
    prefix: Path
    python_hash: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temporary.name)
        cls.prefix = cls.base / "tools"
        cls.python_hash = hashlib.sha256(PYTHON.read_bytes()).hexdigest()
        installer.install(cls.prefix, PYTHON, cls.python_hash)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        shutil.copytree(FIXTURE, self.root, dirs_exist_ok=True)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def policy(self) -> dict[str, Any]:
        return dict(json.loads((self.root / "quality/python-refactor.json").read_bytes()))

    def write(self, value: dict[str, Any]) -> None:
        (self.root / "quality/python-refactor.json").write_bytes(canonical_bytes(value))

    def collect(self) -> dict[str, Any]:
        return refactor.collect(self.root, "quality/python-refactor.json", self.prefix)

    def native(self, filename: str, cases: list[int]) -> list[int]:
        # Independent trusted-fixture oracle: compile the whole native function, not worker AST.
        program = (self.root / filename).read_text() + (
            "\nimport json\nprint(json.dumps([transform(x) for x in " + repr(cases) + "]))\n"
        )
        result = subprocess.run(
            [str(PYTHON), "-I", "-S", "-B", "-c", program],
            cwd="/",
            env={"LANG": "C.UTF-8"},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=3,
            check=True,
        )
        return list(json.loads(result.stdout))

    def test_four_methods_match_independent_native_observations(self) -> None:
        value = self.policy()
        validate(value, "python-refactor.schema.json")
        inputs = [case["input"] for case in value["cases"]]
        expected = [case["expected"] for case in value["cases"]]
        before = self.native("before.py", inputs)
        after = self.native("after.py", inputs)
        self.assertEqual(expected, before)
        self.assertEqual(expected, after)
        self.assertNotEqual(expected, self.native("mutant.py", inputs))
        result = self.collect()
        self.assertEqual("pass", result["status"])
        self.assertEqual(list(refactor.METHODS), [record["method"] for record in result["records"]])
        for record in result["records"]:
            self.assertEqual(
                hashlib.sha256(canonical_bytes(before)).hexdigest(), record["before_result_sha256"]
            )
            self.assertEqual(0, record["mismatches"])
        self.assertEqual((1, 1), (result["records"][2]["mutants"], result["records"][2]["killed"]))
        self.assertEqual("bounded-native-observation", result["execution"])
        self.assertEqual("retain", result["native_gate"])
        serialized = json.dumps(result)
        for private in (str(self.root), str(self.prefix), "OWNER-DEMO", "before.py", "return x"):
            self.assertNotIn(private, serialized)
        self.assertEqual(result, self.collect())

    def test_native_mismatch_property_survivor_and_error_fixtures(self) -> None:
        for name, finding in (
            ("mismatch", "differential:behavior-mismatch"),
            ("survivor", "mutation:surviving-mutant"),
            ("property", "property:test-failure"),
        ):
            value = json.loads(
                (ROOT / "fixtures/nonconforming/refactoring" / (name + ".json")).read_bytes()
            )
            validate(value, "python-refactor.schema.json")
            self.write(value)
            result = self.collect()
            with self.subTest(name=name):
                self.assertEqual("fail", result["status"])
                self.assertIn(finding, result["findings"])
                inputs = [case["input"] for case in value["cases"]]
                if name == "survivor":
                    self.assertEqual(
                        self.native("before.py", inputs), self.native("survivor.py", inputs)
                    )
                elif name == "mismatch":
                    self.assertNotEqual(
                        self.native("before.py", inputs), self.native("mismatch.py", inputs)
                    )
                else:
                    native = self.native("property-after.py", inputs)
                    self.assertNotEqual(-native[0], native[-1])
        self.write(
            json.loads((ROOT / "fixtures/nonconforming/refactoring/error.json").read_bytes())
        )
        with self.assertRaisesRegex(ProjectError, "execution-or-output"):
            self.collect()
        with self.assertRaises(subprocess.CalledProcessError):
            self.native("error.py", [-1, 0, 1])

    def test_installed_wrapper_and_cli_have_exact_pins(self) -> None:
        executable = self.prefix / "bin/awq-refactor-check"
        version = subprocess.run(
            [str(executable), "--version"],
            capture_output=True,
            timeout=10,
            check=True,
            env={"LANG": "C.UTF-8"},
        )
        self.assertEqual(refactor.VERSION_OUTPUT + "\n", version.stdout.decode())
        result = subprocess.run(
            [str(executable), "collect"],
            cwd=self.root,
            capture_output=True,
            timeout=30,
            env={"LANG": "C.UTF-8"},
        )
        self.assertEqual(0, result.returncode)
        document = json.loads(result.stdout)
        self.assertEqual("refactor-evidence", document["bindings"][0]["kind"])
        for output_format in ("json", "text"):
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(
                    0,
                    main(
                        [
                            "--root",
                            str(self.root),
                            "refactor-collect",
                            "quality/python-refactor.json",
                            "--tools",
                            str(self.prefix),
                            "--format",
                            output_format,
                        ]
                    ),
                )
            self.assertNotIn(str(self.root), output.getvalue())
        families, _ = adapters.load_adapter_catalog()
        self.assertEqual(1, len(families["python-refactoring"]["contracts"]))

    def test_policy_unknowns_bounds_digests_paths_and_unsupported_fail_before_process(self) -> None:
        original = self.policy()
        changes: list[tuple[str, Any]] = [
            ("profile", "rust"),
            ("schema_version", True),
            ("tool_version", "latest"),
            ("python_version", "3.13.15"),
            ("owner", "PRIVATE-MARKER"),
            ("properties", []),
            ("mutants", []),
            ("mutants", {}),
            ("cases", []),
            ("review_sha256", "g" * 64),
            ("unknown", "PRIVATE-MARKER"),
        ]
        with mock.patch("awq.refactor._process", side_effect=AssertionError("no execution")):
            for key, replacement in changes:
                value = copy.deepcopy(original)
                value[key] = replacement
                self.write(value)
                with self.subTest(key=key), self.assertRaises((ProjectError, ValueError)):
                    self.collect()
            for mode in (
                "hash",
                "path",
                "duplicate",
                "unchanged",
                "case-type",
                "case-domain",
                "case-bound",
            ):
                value = copy.deepcopy(original)
                if mode == "hash":
                    value["before"]["sha256"] = "0" * 64
                elif mode == "path":
                    value["before"]["path"] = "../PRIVATE-MARKER.py"
                elif mode == "duplicate":
                    value["mutants"] *= 2
                elif mode == "unchanged":
                    value["after"] = value["before"]
                elif mode == "case-type":
                    value["cases"][0]["input"] = True
                elif mode == "case-domain":
                    value["cases"].pop()
                else:
                    value["cases"][0]["expected"] = 1_000_001
                self.write(value)
                with self.subTest(mode=mode), self.assertRaises((ProjectError, ValueError)):
                    self.collect()
        self.write(original)
        with mock.patch("awq.refactor.sys.platform", "win32"), self.assertRaises(ProjectError):
            self.collect()
        with (
            mock.patch("awq.refactor.platform.machine", return_value="aarch64"),
            self.assertRaises(ProjectError),
        ):
            self.collect()

    def test_unsafe_source_symlinks_canonical_input_and_redaction(self) -> None:
        value = self.policy()
        payload = b'def transform(x):\n    return __import__("os").getenv("PRIVATE-MARKER")\n'
        (self.root / "before.py").write_bytes(payload)
        value["before"]["sha256"] = hashlib.sha256(payload).hexdigest()
        self.write(value)
        with self.assertRaises(ProjectError) as caught:
            self.collect()
        self.assertNotIn("PRIVATE-MARKER", str(caught.exception))
        (self.root / "before.py").unlink()
        (self.root / "before.py").symlink_to(self.root / "after.py")
        with self.assertRaises((ProjectError, ValueError)):
            self.collect()
        path = self.root / "quality/python-refactor.json"
        for raw in (b" " + canonical_bytes(value), b'{"x":1,"x":2}\n', b"x" * 100001):
            path.write_bytes(raw)
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(
                    1,
                    main(
                        [
                            "--root",
                            str(self.root),
                            "refactor-collect",
                            "quality/python-refactor.json",
                            "--tools",
                            str(self.prefix),
                            "--format",
                            "json",
                        ]
                    ),
                )
            self.assertNotIn(str(self.root), output.getvalue())

    def test_execution_timeout_and_protocol_errors_are_not_killed_mutants(self) -> None:
        process = mock.Mock()
        process.pid = 123
        process.communicate.side_effect = [subprocess.TimeoutExpired("worker", 3), (b"", b"")]
        with (
            mock.patch("awq.refactor.subprocess.Popen", return_value=process),
            mock.patch("os.killpg") as kill,
        ):
            with self.assertRaisesRegex(ProjectError, "timeout"):
                refactor._process(["/reviewed/python"], b"{}")
            kill.assert_called_once_with(123, 9)
        for raw in (b'{"values":[]}\n', b'{"values":[true]}\n', b'{"values":[1000001]}\n'):
            with (
                mock.patch("awq.refactor._process", return_value=raw),
                self.assertRaises(ProjectError),
            ):
                refactor._execute(PYTHON, Path("/worker"), "def transform(x): return x", [0])
        process.communicate.side_effect = None
        process.communicate.return_value = (b"x" * 8193, b"")
        process.returncode = 0
        with (
            mock.patch("awq.refactor.subprocess.Popen", return_value=process),
            self.assertRaises(ProjectError),
        ):
            refactor._process(["/reviewed/python"], b"{}")

    def test_offline_install_is_atomic_and_existing_or_wrong_tools_fail(self) -> None:
        with self.assertRaises(ProjectError):
            installer.install(self.prefix, PYTHON, self.python_hash)
        dangling = self.base / "dangling"
        dangling.symlink_to(self.base / "missing")
        with self.assertRaises(ProjectError):
            installer.install(dangling, PYTHON, self.python_hash)
        target = self.base / "wrong"
        with self.assertRaises(ProjectError):
            installer.install(target, PYTHON, "0" * 64)
        self.assertFalse(target.exists())
        with (
            mock.patch("awq.refactor.toolchain", side_effect=ProjectError("probe")),
            self.assertRaises(ProjectError),
        ):
            installer.install(target, PYTHON, self.python_hash)
        self.assertFalse(target.exists())
        copied = self.root / "tools"
        shutil.copytree(self.prefix, copied)
        (copied / "lib/awq/refactor_worker.py").write_text("PRIVATE-MARKER")
        with self.assertRaisesRegex(ProjectError, "tool-digest"):
            refactor.toolchain(copied)

    def test_tool_manifest_rejects_skew_malformed_omitted_and_unsafe_identities(self) -> None:
        original = json.loads((self.prefix / "tool.json").read_bytes())
        for key, bad in (
            ("schema_version", True),
            ("tool_version", "latest"),
            ("python_version", "3.13.15"),
            ("python", 1),
            ("python", "relative/python"),
            ("python_sha256", "0" * 64),
            ("files", []),
            ("files", {}),
        ):
            value = copy.deepcopy(original)
            value[key] = bad
            with (
                self.subTest(key=key),
                mock.patch("awq.refactor.strict_json", return_value=value),
                self.assertRaises(ProjectError),
            ):
                refactor.toolchain(self.prefix)
        link = self.root / "python-link"
        link.symlink_to(PYTHON)
        value = copy.deepcopy(original)
        value["python"] = str(link)
        with (
            mock.patch("awq.refactor.strict_json", return_value=value),
            self.assertRaises(ProjectError),
        ):
            refactor.toolchain(self.prefix)
        with self.assertRaises(ProjectError):
            refactor.toolchain(Path("relative"))
        with (
            mock.patch("awq.refactor._process", return_value=b"Python 3.12.13\n"),
            self.assertRaisesRegex(ProjectError, "interpreter-version"),
        ):
            refactor.toolchain(self.prefix)
        with (
            mock.patch("awq.refactor_worker.__file__", str(self.root / "before.py")),
            self.assertRaisesRegex(ProjectError, "worker-version"),
        ):
            refactor.toolchain(self.prefix)
        records = original["files"]
        for items in (
            [{"path": "outside.py", "sha256": "0" * 64}],
            [*records[:-1], records[0]],
            [row for row in records if row["path"] != "lib/awq/refactor_worker.py"],
        ):
            with self.assertRaises(ProjectError):
                refactor._files(self.prefix, items)
        data = b"x" * 5_000_000
        oversized = [
            {"path": "lib/awq/" + name + ".py", "sha256": hashlib.sha256(data).hexdigest()}
            for name in ("a", "b", "c")
        ]
        with (
            mock.patch("awq.refactor.read_file", return_value=data),
            self.assertRaisesRegex(ProjectError, "tool-byte-bound"),
        ):
            refactor._files(self.prefix, oversized)

    def test_resource_limits_entrypoints_and_shared_adapter_protocol(self) -> None:
        with mock.patch("resource.setrlimit") as limits:
            refactor._limits()
        self.assertEqual(4, limits.call_count)
        with (
            mock.patch("awq.refactor.__file__", str(self.prefix / "lib/awq/refactor.py")),
            mock.patch("awq.refactor.Path.cwd", return_value=self.root),
        ):
            for arguments, expected in ((["--version"], 0), (["collect"], 0), ([], 1)):
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(expected, refactor.adapter_main(arguments))
                self.assertNotIn(str(self.root), output.getvalue())
            with (
                mock.patch("awq.refactor.collect", return_value={"status": "fail"}),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(1, refactor.adapter_main(["collect"]))
            with (
                mock.patch("sys.argv", ["awq-refactor-check", "bad"]),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(1, refactor.adapter_main())
        families, _ = adapters.load_adapter_catalog()
        contract = families["python-refactoring"]["contracts"][0]
        with mock.patch(
            "awq.adapters.shutil.which", return_value=str(self.prefix / "bin/awq-refactor-check")
        ):
            result = adapters.run_adapter(self.root, contract)
        self.assertEqual("pass", result["status"])
        self.assertEqual("refactor-evidence", result["bindings"][0]["kind"])

    def test_remaining_source_domain_root_and_policy_rejections(self) -> None:
        value = self.policy()
        (self.root / "copy.py").write_bytes((self.root / "mutant.py").read_bytes())
        value["mutants"].append({"path": "copy.py", "sha256": value["mutants"][0]["sha256"]})
        self.write(value)
        with self.assertRaisesRegex(ProjectError, "duplicate-mutant"):
            self.collect()
        with self.assertRaisesRegex(ProjectError, "source-suffix"):
            refactor._source(self.root, {"path": "source.json", "sha256": "0" * 64})
        with self.assertRaisesRegex(ProjectError, "policy-suffix"):
            refactor._policy(self.root, "policy.py")
        with self.assertRaisesRegex(ProjectError, "root"):
            refactor.collect(Path("relative"), "quality/python-refactor.json", self.prefix)
        with self.assertRaises(ProjectError) as caught:
            refactor.collect(
                self.root / "PRIVATE-MARKER", "quality/python-refactor.json", self.prefix
            )
        self.assertNotIn("PRIVATE-MARKER", str(caught.exception))
        for bad in ("/private.py", "a/../private.py", "x" * 161, None):
            with self.assertRaises(ProjectError):
                refactor._relative(bad)
        with self.assertRaises(ProjectError):
            refactor._object([], "field")

    def test_installer_cli_publish_failure_and_bounds(self) -> None:
        arguments = [
            "--prefix",
            str(self.base / "cli-install"),
            "--python",
            str(PYTHON),
            "--python-sha256",
            self.python_hash,
        ]
        with mock.patch("scripts.install_refactor_tools.install"), redirect_stdout(io.StringIO()):
            self.assertEqual(0, installer.main(arguments))
        with (
            mock.patch(
                "scripts.install_refactor_tools.install", side_effect=ProjectError("private")
            ),
            redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(1, installer.main(arguments))
        self.assertNotIn("private", output.getvalue())
        with (
            mock.patch("scripts.install_refactor_tools.ctypes.CDLL", return_value=object()),
            self.assertRaises(ProjectError),
        ):
            installer._publish(self.root, self.root / "target")
        library = mock.Mock()
        library.renameat2.return_value = 1
        with (
            mock.patch("scripts.install_refactor_tools.ctypes.CDLL", return_value=library),
            self.assertRaises(ProjectError),
        ):
            installer._publish(self.root, self.root / "target")
        with (
            mock.patch("scripts.install_refactor_tools.Path.rglob", return_value=[]),
            self.assertRaises(ProjectError),
        ):
            installer.install(self.base / "empty", PYTHON, self.python_hash)


class WorkerTests(unittest.TestCase):
    def test_native_arithmetic_subset_and_closed_ast(self) -> None:
        self.assertEqual([-2, 0, 2], worker.execute("def transform(x): return 2*x", [-1, 0, 1]))
        self.assertEqual(
            [1, 0, 1], worker.execute("def transform(x): return -x if x < 0 else x", [-1, 0, 1])
        )
        for source in (
            "",
            "import os",
            "def other(x): return x",
            "def transform(y): return y",
            "def transform(x=0): return x",
            "def transform(x): return abs(x)",
            "def transform(x): return x.real",
            "def transform(x): return [x]",
            "def transform(x): return y",
            "def transform(x): return True",
            "def transform(x): return 10001",
            "def transform(x): return x**2",
            "def transform(x): return " + "+".join(["x"] * 129),
        ):
            with self.subTest(source=source), self.assertRaises((ValueError, SyntaxError)):
                worker.validate_source(source)
        for source, cases in (
            ("def transform(x): return x == 0", [0]),
            ("def transform(x): return 10000*10000", [0]),
            ("def transform(x): return x", [True]),
            ("def transform(x): return x", []),
        ):
            with self.assertRaises(ValueError):
                worker.execute(source, list(cases))

    def test_worker_main_fixed_output_and_errors(self) -> None:
        good = {"source": "def transform(x): return x+x", "cases": [-1, 0, 1]}
        for raw, code in (
            (canonical_bytes(good), 0),
            (b"{}", 1),
            (b"x" * 16385, 1),
            (b'{"cases":[0],"source":"def transform(x): return x//0"}', 1),
        ):
            stream = mock.Mock(buffer=io.BytesIO(raw))
            with mock.patch("sys.stdin", stream), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(code, worker.main())
            self.assertNotIn("transform", output.getvalue())
        with mock.patch("sys.version", "0.0.0"), redirect_stdout(io.StringIO()):
            self.assertEqual(1, worker.main())


if __name__ == "__main__":
    unittest.main()
