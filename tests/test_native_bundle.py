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
import time
import unittest
import zipfile
from pathlib import Path
from typing import Any, cast
from unittest import mock

from awq import native_bundle
from awq.cli import main
from awq.project import ProjectError
from awq.registry import canonical_bytes
from awq.release import MAX_MEMBERS
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
                    "readelf_tool": {
                        "id": "TOOL-READELF",
                        "version": "2.45.1",
                        "sha256": "d" * 64,
                        "output_sha256": "a" * 64,
                    },
                    "nm_tool": {
                        "id": "TOOL-NM",
                        "version": "2.45.1",
                        "sha256": "e" * 64,
                        "output_sha256": "b" * 64,
                    },
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
        for entry in inventory:
            if entry["elf"] is not None:
                elf = cast(dict[str, Any], entry["elf"])
                observed = dict(elf)
                observed.pop("observation_sha256")
                observed["artifact_sha256"] = entry["sha256"]
                observed["size"] = entry["size"]
                elf["observation_sha256"] = hashlib.sha256(canonical_bytes(observed)).hexdigest()

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
        validate(self.document, "native-bundle-assurance-v2.schema.json")
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

    def test_elf_observation_binding_rejects_arbitrary_digest(self) -> None:
        value = copy.deepcopy(self.document)
        value["packages"][0]["inventory"][1]["elf"]["machine"] = "other-machine"
        with self.assertRaises(ProjectError):
            native_bundle.evaluate(self.root, value)

    def test_elf_tool_identity_and_pinned_output_fail_closed(self) -> None:
        value = copy.deepcopy(self.document)
        value["packages"][0]["inventory"][1]["elf"]["readelf_tool"]["version"] = "latest"
        with self.assertRaises(ProjectError):
            native_bundle.evaluate(self.root, value)
        value = copy.deepcopy(self.document)
        value["packages"][0]["inventory"][1]["elf"]["nm_tool"]["output_sha256"] = "bad"
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

    def test_primitive_contract_helpers_reject_untrusted_shapes(self) -> None:
        invalid: tuple[tuple[Any, tuple[Any, ...]], ...] = (
            (native_bundle._object, ([], "field", "object")),
            (native_bundle._digest, ("not-a-digest",)),
            (native_bundle._identifier, ("TOOL", "TOOL", "identifier")),
            (native_bundle._integer, (True, 0, 2, "integer")),
            (native_bundle._path, ("", "path")),
            (native_bundle._path, ("a\\b", "path")),
            (
                native_bundle._sorted_strings,
                ("not-a-list", native_bundle.TOKEN, 0, 2, "strings"),
            ),
            (native_bundle._sorted_strings, (["BAD!"], native_bundle.TOKEN, 0, 2, "strings")),
            (native_bundle._sorted_strings, (["b", "a"], native_bundle.TOKEN, 0, 2, "strings")),
        )
        for function, arguments in invalid:
            with (
                self.subTest(function=function.__name__, arguments=arguments),
                self.assertRaises(ProjectError),
            ):
                function(*arguments)
        self.assertEqual("a/b", native_bundle._path("a/b", "path"))
        self.assertEqual(
            ["a", "b"],
            native_bundle._sorted_strings(["a", "b"], native_bundle.TOKEN, 1, 2, "strings"),
        )

    def test_archive_formats_and_regular_file_boundaries_are_fail_closed(self) -> None:
        with self.assertRaises(ProjectError):
            native_bundle._archive_members(self.root / "missing", "tar-gzip", EPOCH)
        with self.assertRaises(ProjectError):
            native_bundle._archive_members(self.root / "missing", "unknown", EPOCH)
        bad_tar = self.root / "bad.tar.gz"
        with tarfile.open(bad_tar, "w:gz") as archive:
            member = tarfile.TarInfo("file")
            member.size = 1
            member.mtime = EPOCH + 1
            archive.addfile(member, io.BytesIO(b"x"))
        with self.assertRaises(ProjectError):
            native_bundle._archive_members(bad_tar, "tar-gzip", EPOCH)
        link_tar = self.root / "link.tar.gz"
        with tarfile.open(link_tar, "w:gz") as archive:
            member = tarfile.TarInfo("link")
            member.type = tarfile.SYMTYPE
            member.linkname = "target"
            archive.addfile(member)
        with self.assertRaises(ProjectError):
            native_bundle._archive_members(link_tar, "tar-gzip", EPOCH)

        zip_path = self.root / "bundle.zip"
        stamp = time.gmtime(EPOCH)
        info = zipfile.ZipInfo(
            "data",
            (
                stamp.tm_year,
                stamp.tm_mon,
                stamp.tm_mday,
                stamp.tm_hour,
                stamp.tm_min,
                stamp.tm_sec - stamp.tm_sec % 2,
            ),
        )
        info.external_attr = 0o644 << 16
        with zipfile.ZipFile(zip_path, "w") as zip_archive:
            zip_archive.writestr(info, b"data")
        members = native_bundle._archive_members(zip_path, "zip", EPOCH)
        self.assertEqual("data", members[0]["path"])
        bad_zip = self.root / "bad.zip"
        bad_info = zipfile.ZipInfo("data", info.date_time)
        bad_info.comment = b"metadata"
        with zipfile.ZipFile(bad_zip, "w") as zip_archive:
            zip_archive.writestr(bad_info, b"data")
        with self.assertRaises(ProjectError):
            native_bundle._archive_members(bad_zip, "zip", EPOCH)

        regular = self.root / "regular"
        regular.write_bytes(b"x")
        with self.assertRaises(ProjectError):
            native_bundle._regular(self.root, "regular", "0" * 64, 1)
        with self.assertRaises(ProjectError):
            native_bundle._regular(self.root, "missing", "0" * 64, 1)

        with mock.patch("awq.native_bundle.tarfile.open") as tar_open:
            archive = tar_open.return_value.__enter__.return_value
            archive.getmembers.return_value = [mock.Mock()] * (MAX_MEMBERS + 1)
            with self.assertRaises(ProjectError):
                native_bundle._archive_members(self.root / "unused", "tar-gzip", EPOCH)
        with mock.patch("awq.native_bundle.zipfile.ZipFile") as zip_open:
            archive = zip_open.return_value.__enter__.return_value
            archive.infolist.return_value = [mock.Mock()] * (MAX_MEMBERS + 1)
            with self.assertRaises(ProjectError):
                native_bundle._archive_members(self.root / "unused", "zip", EPOCH)

        member = mock.Mock()
        member.isfile.return_value = True
        member.issym.return_value = False
        member.islnk.return_value = False
        member.mtime = EPOCH
        member.uid = member.gid = 0
        member.uname = member.gname = ""
        member.pax_headers = {}
        member.size = 1
        member.name = "file"
        with mock.patch("awq.native_bundle.tarfile.open") as tar_open:
            archive = tar_open.return_value.__enter__.return_value
            archive.getmembers.return_value = [member]
            archive.extractfile.return_value = None
            with self.assertRaises(ProjectError):
                native_bundle._archive_members(self.root / "unused", "tar-gzip", EPOCH)
        with mock.patch("awq.native_bundle.tarfile.open") as tar_open:
            archive = tar_open.return_value.__enter__.return_value
            archive.getmembers.return_value = [member]
            archive.extractfile.return_value.read.return_value = b"x"
            member.size = 2
            with self.assertRaises(ProjectError):
                native_bundle._archive_members(self.root / "unused", "tar-gzip", EPOCH)
        with mock.patch("awq.native_bundle.tarfile.open") as tar_open:
            archive = tar_open.return_value.__enter__.return_value
            archive.getmembers.return_value = [member]
            private = b"-----BEGIN PRIVATE KEY-----"
            member.size = len(private)
            archive.extractfile.return_value.read.return_value = private
            with self.assertRaises(ProjectError):
                native_bundle._archive_members(self.root / "unused", "tar-gzip", EPOCH)
        duplicate = mock.Mock()
        duplicate.isfile.return_value = True
        duplicate.issym.return_value = False
        duplicate.islnk.return_value = False
        duplicate.mtime = EPOCH
        duplicate.uid = duplicate.gid = 0
        duplicate.uname = duplicate.gname = ""
        duplicate.pax_headers = {}
        duplicate.size = 1
        duplicate.name = "same"
        with mock.patch("awq.native_bundle.tarfile.open") as tar_open:
            archive = tar_open.return_value.__enter__.return_value
            archive.getmembers.return_value = [duplicate, duplicate]
            archive.extractfile.return_value.read.return_value = b"x"
            with self.assertRaises(ProjectError):
                native_bundle._archive_members(self.root / "unused", "tar-gzip", EPOCH)
        directory = zipfile.ZipInfo("directory/")
        directory.external_attr = 0
        with mock.patch("awq.native_bundle.zipfile.ZipFile") as zip_open:
            archive = zip_open.return_value.__enter__.return_value
            archive.infolist.return_value = [directory]
            with self.assertRaises(ProjectError):
                native_bundle._archive_members(self.root / "unused", "zip", EPOCH)

    def test_native_bundle_rejects_each_remaining_contract_boundary(self) -> None:
        mutations: list[tuple[str, dict[str, Any]]] = []
        for field, replacement in (("schema_version", 2), ("kind", "other")):
            value = copy.deepcopy(self.document)
            value[field] = replacement
            mutations.append((field, value))
        value = copy.deepcopy(self.document)
        value["source"]["repository"] = "https://example.invalid/source"
        mutations.append(("repository", value))
        for field in ("commit", "tree"):
            value = copy.deepcopy(self.document)
            value["source"][field] = "x"
            mutations.append((field, value))
        value = copy.deepcopy(self.document)
        value["toolchain"]["version"] = "bad version"
        mutations.append(("toolchain-version", value))
        value = copy.deepcopy(self.document)
        value["target"] = "bad"
        mutations.append(("target", value))
        value = copy.deepcopy(self.document)
        value["packages"] = []
        mutations.append(("packages", value))
        value = copy.deepcopy(self.document)
        value["packages"][0]["kind"] = "other"
        mutations.append(("package-kind", value))
        value = copy.deepcopy(self.document)
        value["packages"][0]["inventory"] = []
        mutations.append(("inventory", value))
        value = copy.deepcopy(self.document)
        value["packages"][0]["inventory"][0]["kind"] = "other"
        mutations.append(("classification", value))
        value = copy.deepcopy(self.document)
        value["packages"][0]["inventory"][0]["license_id"] = "BAD"
        mutations.append(("license", value))
        value = copy.deepcopy(self.document)
        value["packages"][0]["inventory"][0]["kind"] = "executable"
        mutations.append(("elf-required", value))
        value = copy.deepcopy(self.document)
        value["packages"][0]["inventory"][1]["elf"] = None
        mutations.append(("elf-forbidden", value))
        value = copy.deepcopy(self.document)
        value["packages"][0]["notices"] = ["missing"]
        mutations.append(("notice", value))
        value = copy.deepcopy(self.document)
        value["signatures"] = []
        mutations.append(("signatures", value))
        value = copy.deepcopy(self.document)
        value["signatures"][0]["signer_id"] = "SIGNER-OTHER"
        mutations.append(("signature-binding", value))
        value = copy.deepcopy(self.document)
        value["rebuild"] = []
        mutations.append(("rebuild", value))
        value = copy.deepcopy(self.document)
        value["rebuild"][0]["package_id"] = "PACKAGE-OTHER"
        mutations.append(("rebuild-coverage", value))
        value = copy.deepcopy(self.document)
        value["limitations"] = []
        mutations.append(("claims", value))
        value = copy.deepcopy(self.document)
        value["packages"][0]["inventory"][1]["elf"]["readelf_sha256"] = "b" * 64
        mutations.append(("elf-output-binding", value))
        value = copy.deepcopy(self.document)
        value["packages"][0]["inventory"][1]["elf"]["readelf_tool"]["version"] = "bad version"
        mutations.append(("elf-tool-version", value))
        value = copy.deepcopy(self.document)
        value["elf_policy"] = None
        mutations.append(("elf-policy-required", value))
        value = copy.deepcopy(self.document)
        value["packages"][1]["id"] = value["packages"][0]["id"]
        mutations.append(("package-duplicate", value))
        value = copy.deepcopy(self.document)
        value["signatures"][1] = copy.deepcopy(value["signatures"][0])
        mutations.append(("signature-order", value))
        value = copy.deepcopy(self.document)
        value["rebuild"][1] = copy.deepcopy(value["rebuild"][0])
        mutations.append(("rebuild-order", value))
        for name, value in mutations:
            with self.subTest(name=name), self.assertRaises(ProjectError):
                native_bundle.evaluate(self.root, value)

    def test_evaluate_file_rejects_noncanonical_and_invalid_json(self) -> None:
        path = self.root / "input.json"
        path.write_bytes(json.dumps(self.document).encode())
        with (
            mock.patch.object(native_bundle, "strict_json", return_value=self.document),
            self.assertRaises(ProjectError),
        ):
            native_bundle.evaluate_file(self.root, "input.json")
        path.write_bytes(b'{"kind": "native-bundle-assurance"}')
        with self.assertRaises(ProjectError):
            native_bundle.evaluate_file(self.root, "input.json")
        path.write_bytes(b"not-json")
        with self.assertRaises(ProjectError):
            native_bundle.evaluate_file(self.root, "input.json")
        with self.assertRaises(ProjectError):
            native_bundle.evaluate_file(self.root, "missing.json")


if __name__ == "__main__":
    unittest.main()
