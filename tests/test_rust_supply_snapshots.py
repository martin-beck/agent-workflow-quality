# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Tests for bounded Rust registry and semver snapshot generation."""

from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

import awq.rust_supply_helper as helper
from scripts import snapshot_rust_registry as registry
from scripts import snapshot_rust_semver as semver


class Response(io.BytesIO):
    def __init__(self, content: bytes, url: str) -> None:
        super().__init__(content)
        self.url = url

    def geturl(self) -> str:
        return self.url


class RustRegistrySnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        (self.root / "quality").mkdir()
        (self.root / "Cargo.lock").write_text(
            "# generated\nversion = 4\n\n[[package]]\n"
            'name = "alpha"\nversion = "1.2.3"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            f'checksum = "{"a" * 64}"\n',
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_sparse_index_paths_are_exact(self) -> None:
        self.assertEqual("1/a", registry._index_path("A"))
        self.assertEqual("2/ab", registry._index_path("ab"))
        self.assertEqual("3/a/abc", registry._index_path("abc"))
        self.assertEqual("se/rd/serde", registry._index_path("Serde"))
        with self.assertRaises(registry.RegistrySnapshotError):
            registry._index_path("../crate")

    def test_index_read_is_same_host_bounded_and_strict(self) -> None:
        entry = {
            "name": "alpha",
            "vers": "1.2.3",
            "cksum": "a" * 64,
            "yanked": False,
        }
        content = (json.dumps(entry) + "\n").encode()
        with mock.patch.object(
            registry,
            "urlopen",
            return_value=Response(content, "https://index.crates.io/al/ph/alpha"),
        ):
            self.assertEqual([entry], registry._crate_versions("alpha"))

        cases = [
            (
                Response(content, "https://example.invalid/alpha"),
                "redirected",
                1_000,
            ),
            (
                Response(b'{"name":"a","name":"b"}\n', "https://index.crates.io/a"),
                "duplicate",
                1_000,
            ),
            (
                Response(b"x" * 100, "https://index.crates.io/a"),
                "size bound",
                10,
            ),
        ]
        for number, (response, message, maximum) in enumerate(cases):
            with (
                self.subTest(case=number),
                mock.patch.object(registry, "MAX_INDEX_BYTES", maximum),
                mock.patch.object(registry, "urlopen", return_value=response),
                self.assertRaisesRegex(registry.RegistrySnapshotError, message),
            ):
                registry._crate_versions("alpha")

    def test_generation_binds_exact_lock_and_observed_yank_state(self) -> None:
        versions: list[dict[str, Any]] = [
            {
                "name": "alpha",
                "vers": "1.2.3",
                "cksum": "a" * 64,
                "yanked": False,
            }
        ]
        output = self.root / "quality/rust-registry-snapshot.json"
        with mock.patch.object(registry, "_crate_versions", return_value=versions) as lookup:
            document = registry.generate(self.root, output, 30)
        lookup.assert_called_once_with("alpha")
        self.assertEqual(False, document["packages"][0]["yanked"])
        self.assertEqual(
            hashlib.sha256((self.root / "Cargo.lock").read_bytes()).hexdigest(),
            document["cargo_lock_sha256"],
        )
        self.assertEqual(
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
            output.read_text(encoding="utf-8"),
        )

        versions[0]["cksum"] = "b" * 64
        original = output.read_bytes()
        with (
            mock.patch.object(registry, "_crate_versions", return_value=versions),
            self.assertRaisesRegex(registry.RegistrySnapshotError, "does not match"),
        ):
            registry.generate(self.root, output, 30)
        self.assertEqual(original, output.read_bytes())

    def test_output_and_validity_bounds_fail_closed(self) -> None:
        outside = self.root / "missing/snapshot.json"
        with (
            mock.patch.object(
                registry,
                "_crate_versions",
                side_effect=AssertionError("unexpected registry acquisition"),
            ) as lookup,
            self.assertRaisesRegex(registry.RegistrySnapshotError, "unsafe"),
        ):
            registry.generate(self.root, outside, 30)
        lookup.assert_not_called()
        for days in (0, 91):
            with (
                self.subTest(days=days),
                mock.patch.object(
                    registry,
                    "_crate_versions",
                    side_effect=AssertionError("unexpected registry acquisition"),
                ) as lookup,
                self.assertRaises(registry.RegistrySnapshotError),
            ):
                registry.generate(self.root, self.root / "quality/snapshot.json", days)
            lookup.assert_not_called()


class RustSemverSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        (self.root / "quality").mkdir()
        self.rust = self.root / "rust"
        self.rust.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_generation_runs_pinned_default_feature_rustdoc_and_publishes_last(self) -> None:
        invocations: list[list[str]] = []

        def run_command(
            root: Path,
            argv: list[str],
            environment: dict[str, str],
        ) -> None:
            self.assertEqual(self.root, root)
            invocations.append(argv)
            target = Path(environment["CARGO_TARGET_DIR"])
            rustdoc = target / "x86_64-unknown-linux-gnu/doc/example_crate.json"
            rustdoc.parent.mkdir(parents=True)
            rustdoc.write_text('{"format_version":43,"index":{}}\n', encoding="utf-8")

        def environment(_rust: Path, scratch: Path) -> dict[str, str]:
            target = scratch / "target"
            target.mkdir()
            return {"CARGO_TARGET_DIR": str(target)}

        with (
            mock.patch.object(helper, "_verify_rust_project"),
            mock.patch.object(semver, "_verify_wrapper", return_value=self.rust),
            mock.patch.object(helper, "_environment", side_effect=environment),
            mock.patch.object(
                helper,
                "_rust_tool",
                return_value=Path("/reviewed/cargo"),
            ),
            mock.patch.object(helper, "_run_command", side_effect=run_command),
        ):
            descriptor = semver.generate(
                self.root,
                self.rust,
                "example-package",
                "example_crate",
                "v1.2.3",
                "minor",
            )
        self.assertEqual(1, len(invocations))
        argv = invocations[0]
        self.assertEqual(["/reviewed/cargo", "rustdoc", "--locked", "--offline"], argv[:4])
        self.assertIn("--package", argv)
        self.assertNotIn("--all-features", argv)
        self.assertNotIn("--no-default-features", argv)
        baseline = self.root / "quality/rust-semver-baseline.json"
        lock = self.root / "quality/rust-semver-baseline.lock.json"
        self.assertTrue(baseline.is_file())
        self.assertEqual(
            hashlib.sha256(baseline.read_bytes()).hexdigest(),
            descriptor["baseline_sha256"],
        )
        self.assertEqual(descriptor, json.loads(lock.read_text(encoding="utf-8")))
        self.assertEqual("example-package", descriptor["package"])
        self.assertEqual("example_crate", descriptor["crate_name"])

    def test_invalid_identity_and_rustdoc_fail_before_publication(self) -> None:
        for package, crate, identifier in (
            ("../bad", "example", "v1"),
            ("example", "../bad", "v1"),
            ("example", "example", "../bad"),
        ):
            with (
                self.subTest(package=package, crate=crate, identifier=identifier),
                self.assertRaises(semver.SemverSnapshotError),
            ):
                semver.generate(
                    self.root,
                    self.rust,
                    package,
                    crate,
                    identifier,
                    "minor",
                )
        invalid = self.root / "invalid.json"
        invalid.write_text('{"not":"rustdoc"}\n', encoding="utf-8")
        with self.assertRaisesRegex(semver.SemverSnapshotError, "not rustdoc"):
            semver._read_rustdoc(invalid)


if __name__ == "__main__":
    unittest.main()
