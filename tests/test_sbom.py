# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Positive and hostile tests for the exact SPDX release graph profile."""

from __future__ import annotations

import contextlib
import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

import jsonschema

from awq import provenance, sbom
from awq.cli import main as cli_main
from awq.release import (
    BUILD_CONSTRAINTS_PATH,
    REQUIRED_SCHEMAS,
    ReleaseError,
    canonical_bytes,
    validate_manifest,
    verify_release,
)
from scripts import build_release
from tests.support import packaged_schema_bytes

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/conforming/release-sbom"


class SbomTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inputs = sbom.source_inputs(ROOT)
        self.manifest = json.loads((FIXTURE / "manifest.json").read_bytes())

    def document(self) -> dict[str, Any]:
        return sbom.generate(self.inputs, self.manifest)

    def test_official_schema_and_exact_regeneration(self) -> None:
        document = self.document()
        raw = canonical_bytes(document)
        self.assertEqual(raw, (FIXTURE / "document.spdx.json").read_bytes())
        self.assertEqual(raw, canonical_bytes(self.document()))
        sbom.verify(raw, self.inputs, self.manifest)
        schema = sbom.schema_document(self.inputs[sbom.SCHEMA_PATH])
        jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(
            document
        )
        validate_manifest(self.manifest)

    def test_inventory_scopes_origins_hashes_and_zero_runtime_are_explicit(self) -> None:
        nodes = self.document()["@graph"]
        packages = {node["name"]: node for node in nodes if node["type"] == "software_Package"}
        self.assertEqual(31, len(packages))
        self.assertEqual("0.25.0", packages["agent-workflow-quality"]["software_packageVersion"])
        self.assertTrue(
            packages["arrow"]["software_downloadLocation"].startswith(
                "https://files.pythonhosted.org/packages/"
            )
        )
        targets = [
            node["scope"]
            for node in nodes
            if node["type"] == "LifecycleScopedRelationship"
            and node["to"] == [packages["pathspec"]["spdxId"]]
        ]
        self.assertEqual(["build", "development"], targets)
        runtime = [
            node
            for node in nodes
            if node["type"] == "LifecycleScopedRelationship" and node["scope"] == "runtime"
        ]
        self.assertEqual(1, len(runtime))
        self.assertEqual(["https://spdx.org/rdf/3.0.1/terms/Core/NoneElement"], runtime[0]["to"])
        self.assertFalse(any("suppliedBy" in node for node in packages.values()))
        self.assertTrue(
            any(node.get("name") == "uv.lock" and "verifiedUsing" in node for node in nodes)
        )

    def test_hostile_graph_mutations_fail(self) -> None:
        original = self.document()
        variants = []
        value = deepcopy(original)
        value["unknown"] = True
        variants.append(value)
        value = deepcopy(original)
        value["@context"] = "https://example.invalid/context"
        variants.append(value)
        value = deepcopy(original)
        value["@graph"].pop()
        variants.append(value)
        value = deepcopy(original)
        value["@graph"].append(value["@graph"][0])
        variants.append(value)
        value = deepcopy(original)
        next(node for node in value["@graph"] if node["type"] == "LifecycleScopedRelationship")[
            "scope"
        ] = "runtime"
        variants.append(value)
        value = deepcopy(original)
        next(
            node for node in value["@graph"] if node["type"] == "simplelicensing_LicenseExpression"
        )["simplelicensing_licenseExpression"] = "GPL-3.0-or-later"
        variants.append(value)
        value = deepcopy(original)
        next(node for node in value["@graph"] if node["type"] == "software_Package")["private"] = (
            "/private/fixture"
        )
        variants.append(value)
        for variant in variants:
            with self.subTest(variant=variants.index(variant)), self.assertRaises(ReleaseError):
                sbom.verify(canonical_bytes(variant), self.inputs, self.manifest)

    def test_canonical_json_bounds_duplicates_and_constants_fail(self) -> None:
        for raw in (
            b"{}",
            b'{"x":1,"x":2}\n',
            b'{"x":NaN}\n',
            b"\xff",
            b"{",
            b"[" * 2000,
            b"x" * (sbom.MAX_BYTES + 1),
        ):
            with self.subTest(size=len(raw)), self.assertRaises(ReleaseError):
                sbom.strict_json(raw)
        self.assertEqual({}, sbom.strict_json(b"{}\n"))

    def test_source_manifest_binding_skew_fails(self) -> None:
        for key in ("lock_sha256", "source_license_sha256", "license_inventory_sha256"):
            manifest = deepcopy(self.manifest)
            manifest["sbom"][key] = "0" * 64
            with self.subTest(key=key), self.assertRaises(ReleaseError):
                sbom.verify(canonical_bytes(self.document()), self.inputs, manifest)
        for key, value in (
            ("schema_sha256", "0" * 64),
            ("spec_version", "3.0.0"),
            ("profile", "unknown"),
        ):
            manifest = deepcopy(self.manifest)
            manifest["sbom"][key] = value
            with self.subTest(key=key), self.assertRaises(ReleaseError):
                validate_manifest(manifest)
        manifest = deepcopy(self.manifest)
        manifest["artifacts"] = [item for item in manifest["artifacts"] if item["kind"] != "sbom"]
        with self.assertRaises(ReleaseError):
            validate_manifest(manifest)

    def test_invalid_license_inventory_fails(self) -> None:
        original = sbom.strict_json(self.inputs[sbom.LICENSE_PATH])
        variants: list[Any] = [
            [],
            {},
            {**original, "unknown": True},
            {**original, "schema_version": True},
            {**original, "packages": []},
        ]
        for key, value in (
            ("license", "not-a-license"),
            ("scopes", ["runtime"]),
            ("version", "999"),
            ("unknown", True),
        ):
            variant = deepcopy(original)
            variant["packages"][1][key] = value
            variants.append(variant)
        for variant in variants:
            inputs = {**self.inputs, sbom.LICENSE_PATH: canonical_bytes(variant)}
            with self.subTest(variant=str(variant)[:80]), self.assertRaises(ReleaseError):
                sbom.generate(inputs, self.manifest)

    def test_runtime_lock_origin_and_version_skew_fail(self) -> None:
        original = self.inputs["uv.lock"]
        for old, new in (
            (b'url = "https://files.pythonhosted.org/', b'url = "https://example.invalid/'),
            (b'registry = "https://pypi.org/simple"', b'registry = "http://pypi.org/simple"'),
            (b'name = "arrow"', b'name = "../arrow"'),
            (b'version = "1.4.0"', b'version = "not-a-version"'),
            (b'version = "0.25.0"', b'version = "0.13.0"'),
            (b"sha256:", b"md5:"),
        ):
            self.assertIn(old, original)
            inputs = {**self.inputs, "uv.lock": original.replace(old, new)}
            with self.subTest(old=old), self.assertRaises(ReleaseError):
                sbom.generate(inputs, self.manifest)
        inputs = {
            **self.inputs,
            "pyproject.toml": self.inputs["pyproject.toml"].replace(
                b"dependencies = []", b'dependencies = ["fixture"]'
            ),
        }
        with self.assertRaises(ReleaseError):
            sbom.generate(inputs, self.manifest)
        package: dict[str, Any]
        for package in (
            {},
            {"sdist": {}},
            {"sdist": {"url": "https://files.pythonhosted.org/packages/../x", "size": 1}},
            {"sdist": {"url": "https://files.pythonhosted.org/packages/x", "size": True}},
        ):
            with self.subTest(package=package), self.assertRaises(ReleaseError):
                sbom._locked_origin(package)

    def test_input_bounds_missing_toml_constraints_and_private_content(self) -> None:
        variants = [
            {},
            {**self.inputs, "unknown": b"x"},
            {**self.inputs, "uv.lock": b"x" * (sbom.MAX_BYTES + 1)},
            {**self.inputs, "uv.lock": b"["},
            {**self.inputs, "uv.lock": b"\xff"},
            {**self.inputs, "uv.lock": b"package=[]\n"},
            {**self.inputs, BUILD_CONSTRAINTS_PATH: b"bad"},
        ]
        for inputs in variants:
            with self.subTest(keys=list(inputs)), self.assertRaises(ReleaseError):
                sbom.generate(inputs, self.manifest)
        with mock.patch("awq.sbom.MAX_BYTES", 2000), self.assertRaises(ReleaseError):
            sbom.generate(self.inputs, self.manifest)
        manifest = deepcopy(self.manifest)
        manifest["source"]["repository"] = "/home/" + "fixture/path"
        with self.assertRaises(ReleaseError):
            sbom.generate(self.inputs, manifest)

    def test_schema_corruption_and_wrong_container_fail(self) -> None:
        for raw in (b"", b"not zip"):
            with self.assertRaises(ReleaseError):
                sbom.schema_document(raw)
        for name, content in (
            ("wrong.json", b"{}"),
            ("spdx-json-schema.json", b"{}"),
            ("spdx-json-schema.json", b"x" * (sbom.MAX_BYTES + 1)),
        ):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr(name, content)
            with self.subTest(name=name), self.assertRaises(ReleaseError):
                sbom.schema_document(stream.getvalue())

    def test_regular_source_and_archive_inputs_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ReleaseError):
                sbom.source_inputs(root)
            path = root / "source.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                for name, raw in self.inputs.items():
                    member = tarfile.TarInfo("agent_workflow_quality-0.25.0/" + name)
                    member.size = len(raw)
                    archive.addfile(member, io.BytesIO(raw))
            self.assertEqual(self.inputs, sbom.archive_inputs(path, "0.25.0"))
            with self.assertRaises(ReleaseError):
                sbom.archive_inputs(path, "0.13.0")
            with mock.patch("awq.sbom.MAX_BYTES", 1), self.assertRaises(ReleaseError):
                sbom.archive_inputs(path, "0.25.0")
            path.write_bytes(b"invalid")
            with self.assertRaises(ReleaseError):
                sbom.archive_inputs(path, "0.25.0")

    def test_builder_stages_sbom_and_manifest_without_publishing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            base = deepcopy(self.manifest)
            base["schema_version"] = 1
            base.pop("sbom")
            base["artifacts"] = [item for item in base["artifacts"] if item["kind"] != "sbom"]
            result = build_release._add_sbom(ROOT, stage, base)
            self.assertEqual(2, result["schema_version"])
            validate_manifest(result)
            records = [item for item in result["artifacts"] if item["kind"] == "sbom"]
            self.assertEqual(1, len(records))
            raw = (stage / records[0]["name"]).read_bytes()
            sbom.verify(raw, self.inputs, result)
            self.assertEqual(sbom.digest(raw), records[0]["sha256"])

    def test_complete_offline_bundle_and_rehashed_hostile_sbom(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            manifest = deepcopy(self.manifest)
            epoch = manifest["source"]["source_date_epoch"]
            files = {**self.inputs, **provenance.source_materials(ROOT)}
            for data_name in ("compatibility.json", "agent_recipes.json"):
                files["src/awq/data/" + data_name] = (
                    ROOT / "src/awq/data" / data_name
                ).read_bytes()
            for name in REQUIRED_SCHEMAS:
                files.setdefault("schemas/" + name, packaged_schema_bytes(name))
            for artifact in manifest["artifacts"]:
                if artifact["kind"] == "sbom":
                    continue
                path = stage / artifact["name"]
                if artifact["kind"] == "sdist":
                    with tarfile.open(path, "w:gz") as archive:
                        for name, raw in files.items():
                            member = tarfile.TarInfo("agent_workflow_quality-0.25.0/" + name)
                            member.size = len(raw)
                            member.mtime = epoch
                            member.mode = 0o644
                            archive.addfile(member, io.BytesIO(raw))
                else:
                    self.write_wheel(path, epoch)
                artifact["size"] = path.stat().st_size
                artifact["sha256"] = sbom.digest(path.read_bytes())
            base = deepcopy(manifest)
            base["artifacts"] = [item for item in base["artifacts"] if item["kind"] != "sbom"]
            manifest = build_release._add_sbom(ROOT, stage, base)
            manifest = provenance.add(ROOT, stage, manifest, "0" * 64)
            manifest_path = stage / "agent_workflow_quality-0.25.0.release.json"
            manifest_path.write_bytes(canonical_bytes(manifest))
            result = verify_release(manifest_path)
            self.assertEqual("pass", result["status"])
            self.assertEqual(3, result["schema_version"])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(
                    0,
                    cli_main(
                        [
                            "--root",
                            str(stage),
                            "release-verify",
                            str(manifest_path),
                            "--format",
                            "json",
                        ]
                    ),
                )
            self.assertEqual(result, json.loads(output.getvalue()))
            self.assertEqual(3, json.loads(output.getvalue())["schema_version"])
            item = next(item for item in manifest["artifacts"] if item["kind"] == "sbom")
            hostile = json.loads((stage / item["name"]).read_bytes())
            hostile["@graph"].pop()
            raw = canonical_bytes(hostile)
            (stage / item["name"]).write_bytes(raw)
            item["size"], item["sha256"] = len(raw), sbom.digest(raw)
            manifest_path.write_bytes(canonical_bytes(manifest))
            with self.assertRaisesRegex(ReleaseError, "SBOM"):
                verify_release(manifest_path)
            manifest["schema_version"] = 1
            manifest.pop("sbom")
            manifest.pop("provenance")
            manifest.pop("trust_policy_sha256")
            manifest_path.write_bytes(canonical_bytes(manifest))
            with self.assertRaisesRegex(ReleaseError, "requires an SPDX"):
                verify_release(manifest_path)

    @staticmethod
    def write_wheel(path: Path, epoch: int) -> None:
        instant = datetime.fromtimestamp(epoch, UTC)
        timestamp = (
            instant.year,
            instant.month,
            instant.day,
            instant.hour,
            instant.minute,
            instant.second - instant.second % 2,
        )
        entries = {f"awq/schemas/{name}": packaged_schema_bytes(name) for name in REQUIRED_SCHEMAS}
        entries["awq/data/adapter_catalog.json"] = b"{}\n"
        entries["awq/data/compatibility.json"] = b"{}\n"
        entries["awq/data/agent_recipes.json"] = b"{}\n"
        entries["agent_workflow_quality-0.25.0.dist-info/METADATA"] = (
            b"Name: agent-workflow-quality\nVersion: 0.25.0\n"
        )
        with zipfile.ZipFile(path, "w") as archive:
            for name, raw in entries.items():
                member = zipfile.ZipInfo(name, timestamp)
                member.create_system = 3
                member.external_attr = (0o644 if ".dist-info/" in name else 0o100644) << 16
                member.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(member, raw)


if __name__ == "__main__":
    unittest.main()
