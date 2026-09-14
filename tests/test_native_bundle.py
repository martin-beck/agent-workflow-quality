# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Positive and hostile native package assurance contract tests."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Any

from awq import native_bundle
from awq.cli import main
from awq.project import ProjectError
from awq.registry import canonical_bytes
from scripts.validate_contracts import validate

EPOCH = 1_800_000_000
TARGET = "x86_64-unknown-linux-gnu"


class NativeBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.document = self._document()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _archive(
        self, name: str, files: list[tuple[str, bytes, int]]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        path = self.root / name
        with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT) as archive:
            for member_name, content, mode in files:
                member = tarfile.TarInfo(member_name)
                member.size = len(content)
                member.mode = mode
                member.mtime = EPOCH
                member.uid = member.gid = 0
                member.uname = member.gname = ""
                archive.addfile(member, io.BytesIO(content))
        raw = path.read_bytes()
        inventory = []
        for member_name, content, mode in files:
            kind = (
                "executable"
                if mode & 0o111
                else ("license" if "LICENSE" in member_name else "data")
            )
            elf = None
            if kind == "executable":
                elf = {
                    "architecture": "x86-64",
                    "class": "elf64",
                    "dynamic_dependencies": ["libc.so.6"],
                    "executable_stack": False,
                    "features": ["pie"],
                    "hardening": ["nx", "pie", "relro"],
                    "machine": "advanced-micro-devices-x86-64",
                    "max_alignment": 4096,
                    "nm_sha256": "b" * 64,
                    "observation_sha256": "c" * 64,
                    "readelf_sha256": "a" * 64,
                    "strings": [],
                    "symbols": ["main"],
                    "text_relocations": False,
                }
            inventory.append(
                {
                    "elf": elf,
                    "kind": kind,
                    "license_id": "LICENSE-MIT",
                    "mode": mode,
                    "path": member_name,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size": len(content),
                    "target": TARGET,
                }
            )
        return (
            {
                "format": "tar-gzip",
                "path": name,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            },
            inventory,
        )

    def _document(self) -> dict[str, Any]:
        packages = []
        signatures = []
        rebuild = []
        for identifier, kind, name, files in (
            (
                "PACKAGE-NATIVE",
                "native-package",
                "native.tar.gz",
                [("LICENSE", b"MIT\n", 0o644), ("bin/tool", b"ELF fixture\n", 0o755)],
            ),
            (
                "PACKAGE-RUNTIME",
                "runtime-bundle",
                "runtime.tar.gz",
                [("LICENSE", b"MIT\n", 0o644), ("share/runtime.dat", b"runtime\n", 0o644)],
            ),
        ):
            archive, inventory = self._archive(name, files)
            packages.append(
                {
                    "archive": archive,
                    "id": identifier,
                    "inventory": inventory,
                    "kind": kind,
                    "normalized_timestamp": EPOCH,
                    "notices": ["LICENSE"],
                }
            )
            signature_path = self.root / (name + ".sig")
            signature_path.write_bytes(("signature-" + identifier + "\n").encode())
            signature = signature_path.read_bytes()
            signatures.append(
                {
                    "artifact_sha256": archive["sha256"],
                    "package_id": identifier,
                    "path": signature_path.name,
                    "sha256": hashlib.sha256(signature).hexdigest(),
                    "signer_id": "SIGNER-RELEASE",
                    "signer_policy_sha256": "d" * 64,
                    "size": len(signature),
                }
            )
            rebuild.append(
                {
                    "first_sha256": archive["sha256"],
                    "manifest_sha256": hashlib.sha256(canonical_bytes(inventory)).hexdigest(),
                    "package_id": identifier,
                    "second_sha256": archive["sha256"],
                }
            )
        return {
            "elf_policy": {
                "allowed_dynamic_dependencies": ["libc.so.6"],
                "architectures": ["x86-64"],
                "classes": ["elf64"],
                "forbidden_features": ["rpath"],
                "forbidden_strings": ["private-marker"],
                "machines": ["advanced-micro-devices-x86-64"],
                "max_alignment": 4096,
                "max_size": 1048576,
                "required_hardening": ["nx", "pie", "relro"],
                "required_symbols": ["main"],
            },
            "kind": "native-bundle-assurance",
            "limitations": list(native_bundle.LIMITATIONS),
            "non_claims": list(native_bundle.NON_CLAIMS),
            "packages": packages,
            "rebuild": rebuild,
            "schema_version": 1,
            "signatures": signatures,
            "signer_policy": {"id": "SIGNER-RELEASE", "sha256": "d" * 64},
            "source": {
                "archive_sha256": "e" * 64,
                "commit": "1" * 40,
                "repository": "https://github.com/example/reviewed-source",
                "tree": "2" * 40,
            },
            "target": TARGET,
            "toolchain": {"id": "TOOLCHAIN-GNU", "sha256": "f" * 64, "version": "2.45.1"},
        }

    def test_native_package_and_runtime_bundle_are_complete_and_deterministic(self) -> None:
        validate(self.document, "native-bundle-assurance.schema.json")
        first = native_bundle.evaluate(self.root, self.document)
        second = native_bundle.evaluate(self.root, copy.deepcopy(self.document))
        self.assertEqual(first, second)
        self.assertEqual(
            ("pass", 2, 4), (first["status"], first["package_count"], first["file_count"])
        )
        rendered = json.dumps(first, sort_keys=True)
        self.assertNotIn(str(self.root), rendered)
        self.assertNotIn("bin/tool", rendered)
        runtime_only = copy.deepcopy(self.document)
        runtime_only["elf_policy"] = None
        runtime_only["packages"] = runtime_only["packages"][1:]
        runtime_only["signatures"] = runtime_only["signatures"][1:]
        runtime_only["rebuild"] = runtime_only["rebuild"][1:]
        self.assertEqual(1, native_bundle.evaluate(self.root, runtime_only)["package_count"])

    def test_abi_dependency_hardening_symbol_target_and_size_fail_closed(self) -> None:
        cases: tuple[tuple[str, object], ...] = (
            ("architecture", "aarch64"),
            ("dynamic_dependencies", ["libprivate.so"]),
            ("hardening", ["nx"]),
            ("symbols", []),
            ("max_alignment", 8192),
        )
        for field, replacement in cases:
            value = copy.deepcopy(self.document)
            value["packages"][0]["inventory"][1]["elf"][field] = replacement
            with self.subTest(field=field), self.assertRaises(ProjectError):
                native_bundle.evaluate(self.root, value)
        value = copy.deepcopy(self.document)
        value["packages"][0]["inventory"][1]["target"] = "aarch64-unknown-linux-gnu"
        with self.assertRaises(ProjectError):
            native_bundle.evaluate(self.root, value)

    def test_inventory_signature_rebuild_and_archive_safety_fail_closed(self) -> None:
        mutations = []
        missing = copy.deepcopy(self.document)
        missing["packages"][0]["inventory"].pop()
        mutations.append(missing)
        signature = copy.deepcopy(self.document)
        signature["signatures"][0]["artifact_sha256"] = "0" * 64
        mutations.append(signature)
        rebuild = copy.deepcopy(self.document)
        rebuild["rebuild"][0]["second_sha256"] = "0" * 64
        mutations.append(rebuild)
        license_missing = copy.deepcopy(self.document)
        license_missing["packages"][0]["notices"] = []
        mutations.append(license_missing)
        for number, value in enumerate(mutations):
            with self.subTest(case=number), self.assertRaises(ProjectError):
                native_bundle.evaluate(self.root, value)

        unsafe, _ = self._archive("unsafe.tar.gz", [("../escape", b"x", 0o644)])
        value = copy.deepcopy(self.document)
        value["packages"][0]["archive"] = unsafe
        with self.assertRaises(ProjectError):
            native_bundle.evaluate(self.root, value)

    def test_unknown_fields_cli_and_content_minimized_failure(self) -> None:
        value = copy.deepcopy(self.document)
        value["private_path"] = "/private/host"
        with self.assertRaises(ProjectError):
            native_bundle.evaluate(self.root, value)
        path = self.root / "contract.json"
        path.write_bytes(canonical_bytes(self.document))
        self.assertEqual(
            0,
            main(
                [
                    "--root",
                    str(self.root),
                    "native-bundle-evaluate",
                    "contract.json",
                    "--format",
                    "json",
                ]
            ),
        )


if __name__ == "__main__":
    unittest.main()
