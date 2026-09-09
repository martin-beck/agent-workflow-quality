# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Deterministic SPDX 3.0.1 release graph with an exact offline semantic profile."""

from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
import tomllib
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from awq.release import (
    BUILD_CONSTRAINTS_PATH,
    BUILD_CONSTRAINTS_SHA256,
    PRIVATE_CONTENT,
    ReleaseError,
    canonical_bytes,
)

SPEC = "3.0.1"
PROFILE = "awq-spdx-v1"
CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
SCHEMA_SHA256 = "582c64e809d5b3ef9bd0c4de13a32391b47b0284a3e8d199569fb96f649234b1"
SCHEMA_PATH = "schemas/spdx-3.0.1.schema.zip"
LICENSE_PATH = "config/release-licenses.json"
INPUT_PATHS = (
    "pyproject.toml",
    "uv.lock",
    BUILD_CONSTRAINTS_PATH,
    LICENSE_PATH,
    "LICENSE",
    SCHEMA_PATH,
)
MAX_BYTES = 2_000_000
MAX_PACKAGES = 100
PACKAGE_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
PACKAGE_VERSION = re.compile(r"[0-9][A-Za-z0-9.+!-]{0,79}")
DIGEST = re.compile(r"[0-9a-f]{64}")
LICENSES = frozenset(
    {
        "MIT",
        "Apache-2.0",
        "MPL-2.0",
        "BSD-3-Clause",
        "ISC",
        "GPL-3.0-or-later",
        "PSF-2.0",
        "Apache-2.0 OR BSD-3-Clause",
        "Apache-2.0 OR BSD-2-Clause",
    }
)
REPOSITORY = "https://github.com/martin-beck/agent-workflow-quality"
LIMITATION = (
    "Locked development and build inputs are not shipped runtime dependencies. "
    "Separately acquired adapter tools, operating systems and Python distributions are external. "
    "License expressions are reviewed inventory, not legal advice or a license compliance verdict."
)


def digest(raw: bytes) -> str:
    """Hash bounded input bytes without machine-specific data."""
    return hashlib.sha256(raw).hexdigest()


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReleaseError("SBOM input contains duplicate keys")
        value[key] = item
    return value


def _constant(value: str) -> None:
    del value
    raise ReleaseError("SBOM input contains a non-finite constant")


def strict_json(raw: bytes) -> Any:
    """Load only bounded, canonical, duplicate-free JSON."""
    if len(raw) > MAX_BYTES:
        raise ReleaseError("SBOM input exceeds its bound")
    try:
        value = json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
        if canonical_bytes(value) != raw:
            raise ReleaseError("SBOM input is noncanonical")
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ReleaseError("SBOM input is not canonical strict JSON") from error
    return value


def schema_document(raw: bytes) -> dict[str, Any]:
    """Verify exact official bytes inside the immutable single-entry schema container."""
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            if len(members) != 1 or members[0].filename != "spdx-json-schema.json":
                raise ReleaseError("SPDX schema container is invalid")
            if members[0].file_size > MAX_BYTES:
                raise ReleaseError("SPDX schema exceeds its bound")
            schema = archive.read(members[0])
        if digest(schema) != SCHEMA_SHA256:
            raise ReleaseError("SPDX schema digest differs")
        value = json.loads(schema)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        raise ReleaseError("SPDX schema is invalid") from error
    if not isinstance(value, dict):
        raise ReleaseError("SPDX schema must be an object")
    return value


def source_inputs(root: Path) -> dict[str, bytes]:
    """Read an exact set of regular, bounded source files."""
    result = {}
    for name in INPUT_PATHS:
        path = root / name
        if path.is_symlink() or not path.is_file() or path.resolve() != path:
            raise ReleaseError("SBOM source input is unavailable")
        if path.stat().st_size > MAX_BYTES:
            raise ReleaseError("SBOM source input exceeds its bound")
        result[name] = path.read_bytes()
    return result


def archive_inputs(path: Path, version: str) -> dict[str, bytes]:
    """Read inventory inputs from a previously verified bounded source distribution."""
    names = {f"agent_workflow_quality-{version}/{name}": name for name in INPUT_PATHS}
    result = {}
    try:
        with tarfile.open(path, "r:gz") as archive:
            for count, member in enumerate(archive, 1):
                if count > 10_000:
                    raise ReleaseError("SBOM source archive exceeds its bound")
                if member.name not in names:
                    continue
                name = names[member.name]
                if name in result or not member.isfile() or member.size > MAX_BYTES:
                    raise ReleaseError("SBOM source member is invalid")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ReleaseError("SBOM source member is unavailable")
                with stream:
                    result[name] = stream.read(MAX_BYTES + 1)
    except (OSError, tarfile.TarError) as error:
        raise ReleaseError("SBOM source archive is invalid") from error
    if set(result) != set(INPUT_PATHS):
        raise ReleaseError("SBOM source inventory is incomplete")
    return result


def _toml(raw: bytes) -> dict[str, Any]:
    try:
        return tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ReleaseError("SBOM TOML input is invalid") from error


def _constraints(raw: bytes) -> dict[str, tuple[str, list[str]]]:
    if digest(raw) != BUILD_CONSTRAINTS_SHA256:
        raise ReleaseError("SBOM build constraints differ from the reviewed closure")
    result: dict[str, tuple[str, list[str]]] = {}
    current = ""
    for line in raw.decode("ascii").splitlines():
        package = re.fullmatch(r"([a-z0-9-]+)==([0-9.]+) \\", line)
        checksum = re.fullmatch(r"    --hash=sha256:([0-9a-f]{64})(?: \\)?", line)
        if package:
            current = package[1]
            result[current] = (package[2], [])
        elif checksum:
            result[current][1].append(checksum[1])
    return result


def _locked_packages(inputs: dict[str, bytes], version: str) -> dict[str, dict[str, Any]]:
    lock = _toml(inputs["uv.lock"])
    project = _toml(inputs["pyproject.toml"])["project"]
    if (
        not isinstance(project, dict)
        or project.get("name") != "agent-workflow-quality"
        or project.get("dependencies") != []
        or project.get("version") != version
    ):
        raise ReleaseError("SBOM zero-runtime or package version claim differs")
    locked = lock.get("package")
    if not isinstance(locked, list) or not 1 <= len(locked) <= MAX_PACKAGES:
        raise ReleaseError("SBOM lock package set is invalid")
    expected: dict[str, dict[str, Any]] = {}
    for package in locked:
        name, package_version = package["name"], package["version"]
        if not PACKAGE_NAME.fullmatch(name) or not PACKAGE_VERSION.fullmatch(package_version):
            raise ReleaseError("SBOM lock identity is invalid")
        if name in expected:
            raise ReleaseError("SBOM lock identity is duplicated")
        root = name == "agent-workflow-quality"
        if root and (
            package_version != version
            or package.get("dependencies")
            or package.get("source") != {"editable": "."}
        ):
            raise ReleaseError("SBOM runtime lock disagrees")
        if not root and package.get("source") != {"registry": "https://pypi.org/simple"}:
            raise ReleaseError("SBOM package origin is not the reviewed registry")
        expected[name] = {
            "name": name,
            "version": package_version,
            "scopes": ["runtime"] if root else ["development"],
        }
    return expected


def _merge_build(expected: dict[str, dict[str, Any]], raw: bytes) -> None:
    for name, (package_version, _) in _constraints(raw).items():
        if name in expected:
            if expected[name]["version"] != package_version:
                raise ReleaseError("SBOM build and development versions disagree")
            expected[name]["scopes"].insert(0, "build")
        else:
            expected[name] = {"name": name, "version": package_version, "scopes": ["build"]}


def _licenses(expected: dict[str, dict[str, Any]], raw: bytes) -> list[dict[str, Any]]:
    inventory = strict_json(raw)
    if not isinstance(inventory, dict) or set(inventory) != {"schema_version", "packages"}:
        raise ReleaseError("SBOM license inventory shape is invalid")
    if type(inventory["schema_version"]) is not int or inventory["schema_version"] != 1:
        raise ReleaseError("SBOM license inventory version is invalid")
    packages = inventory["packages"]
    if not isinstance(packages, list) or len(packages) != len(expected):
        raise ReleaseError("SBOM license inventory omits or adds a package")
    for item, name in zip(packages, sorted(expected), strict=True):
        if not isinstance(item, dict) or set(item) != {"name", "version", "scopes", "license"}:
            raise ReleaseError("SBOM license record has unknown or missing fields")
        if {k: item[k] for k in ("name", "version", "scopes")} != expected[name]:
            raise ReleaseError("SBOM license identity or scope differs")
        if not isinstance(item["license"], str) or item["license"] not in LICENSES:
            raise ReleaseError("SBOM license expression is not reviewed")
    return packages


def _packages(inputs: dict[str, bytes], version: str) -> list[dict[str, Any]]:
    expected = _locked_packages(inputs, version)
    _merge_build(expected, inputs[BUILD_CONSTRAINTS_PATH])
    return _licenses(expected, inputs[LICENSE_PATH])


class _Graph:
    def __init__(self, namespace: str, created: str) -> None:
        self.namespace = namespace
        self.creation = namespace + "/creation"
        self.nodes: list[dict[str, Any]] = [
            {
                "@id": self.creation,
                "type": "CreationInfo",
                "created": created,
                "createdBy": [namespace + "/creator"],
                "specVersion": SPEC,
            }
        ]
        self.relations = 0
        self.node("creator", "SoftwareAgent", name="Agent Workflow Quality SBOM generator")

    def node(self, key: str, kind: str, **fields: Any) -> str:
        identifier = self.namespace + "/" + key
        self.nodes.append(
            {"spdxId": identifier, "type": kind, "creationInfo": self.creation, **fields}
        )
        return identifier

    def relationship(
        self, source: str, kind: str, targets: list[str], scope: str | None = None
    ) -> None:
        fields: dict[str, Any] = {"from": source, "relationshipType": kind, "to": targets}
        node_kind = "Relationship"
        if scope is not None:
            fields["scope"] = scope
            node_kind = "LifecycleScopedRelationship"
        self.node(f"relationship-{self.relations:04}", node_kind, **fields)
        self.relations += 1

    def file(self, key: str, name: str, checksum: str, size: int | None = None) -> str:
        if not DIGEST.fullmatch(checksum):
            raise ReleaseError("SBOM file checksum is invalid")
        fields: dict[str, Any] = {
            "name": name,
            "software_fileKind": "file",
            "verifiedUsing": [{"type": "Hash", "algorithm": "sha256", "hashValue": checksum}],
        }
        if size is not None:
            fields["comment"] = canonical_bytes({"size": size}).decode().strip()
        return self.node(key, "software_File", **fields)


def _package_graph(
    graph: _Graph, packages: list[dict[str, Any]], inputs: dict[str, bytes], source: dict[str, Any]
) -> str:
    root_id = graph.namespace + "/package-agent-workflow-quality"
    locked = {p["name"]: p for p in _toml(inputs["uv.lock"])["package"]}
    constraints = _constraints(inputs[BUILD_CONSTRAINTS_PATH])
    for package in packages:
        name, version = package["name"], package["version"]
        fields: dict[str, Any] = {
            "name": name,
            "software_packageVersion": version,
            "software_packageUrl": f"pkg:pypi/{name}@{version}",
            "software_homePage": REPOSITORY
            if name == "agent-workflow-quality"
            else f"https://pypi.org/project/{name}/{version}/",
        }
        if name in locked and name != "agent-workflow-quality":
            fields["software_downloadLocation"] = _locked_origin(locked[name])
        if name == "agent-workflow-quality":
            fields["software_sourceInfo"] = canonical_bytes(source).decode().strip()
        identifier = graph.node("package-" + name, "software_Package", **fields)
        license_id = graph.node(
            "license-" + name,
            "simplelicensing_LicenseExpression",
            simplelicensing_licenseExpression=package["license"],
        )
        graph.relationship(identifier, "hasDeclaredLicense", [license_id])
        if name != "agent-workflow-quality":
            for scope in package["scopes"]:
                graph.relationship(root_id, "dependsOn", [identifier], scope)
        _package_archives(graph, identifier, name, locked.get(name), constraints.get(name))
    graph.relationship(
        root_id, "dependsOn", ["https://spdx.org/rdf/3.0.1/terms/Core/NoneElement"], "runtime"
    )
    return root_id


def _locked_origin(package: dict[str, Any]) -> str:
    item = package.get("sdist")
    if not isinstance(item, dict):
        raise ReleaseError("SBOM locked source origin is absent")
    location = item.get("url")
    if (
        not isinstance(location, str)
        or re.fullmatch(
            r"https://files[.]pythonhosted[.]org/packages/[A-Za-z0-9._/-]{1,500}", location
        )
        is None
    ):
        raise ReleaseError("SBOM locked source origin is invalid")
    if ".." in location.split("/") or "//" in location.removeprefix("https://"):
        raise ReleaseError("SBOM locked source origin is noncanonical")
    if type(item.get("size")) is not int or not 1 <= item["size"] <= 1_000_000_000:
        raise ReleaseError("SBOM locked source size is invalid")
    return location


def _package_archives(
    graph: _Graph,
    identifier: str,
    name: str,
    locked: dict[str, Any] | None,
    constraint: tuple[str, list[str]] | None,
) -> None:
    if locked is not None and name != "agent-workflow-quality":
        item = locked.get("sdist")
        if not isinstance(item, dict) or not isinstance(item.get("hash"), str):
            raise ReleaseError("SBOM locked source archive checksum is absent")
        checksum = item["hash"].removeprefix("sha256:")
        if not item["hash"].startswith("sha256:"):
            raise ReleaseError("SBOM locked source archive checksum is invalid")
        target = graph.file("locked-" + name, name + "-locked-sdist", checksum, item["size"])
        graph.relationship(identifier, "hasDistributionArtifact", [target])
    if constraint is not None:
        for index, checksum in enumerate(sorted(constraint[1])):
            target = graph.file(f"build-{name}-{index}", name + "-allowed-build-archive", checksum)
            graph.relationship(identifier, "hasDistributionArtifact", [target])


def metadata(inputs: dict[str, bytes]) -> dict[str, str]:
    """Return manifest-level bindings for the fixed SPDX profile."""
    return {
        "profile": PROFILE,
        "spec_version": SPEC,
        "schema_sha256": SCHEMA_SHA256,
        "lock_sha256": digest(inputs["uv.lock"]),
        "license_inventory_sha256": digest(inputs[LICENSE_PATH]),
        "source_license_sha256": digest(inputs["LICENSE"]),
    }


def _generate(inputs: dict[str, bytes], manifest: dict[str, Any]) -> dict[str, Any]:
    if set(inputs) != set(INPUT_PATHS) or any(len(raw) > MAX_BYTES for raw in inputs.values()):
        raise ReleaseError("SBOM input set or bounds differ")
    schema_document(inputs[SCHEMA_PATH])
    packages = _packages(inputs, manifest["version"])
    namespace = REPOSITORY + "/spdx/" + manifest["source"]["commit"] + "/" + manifest["version"]
    created = datetime.fromtimestamp(manifest["source"]["source_date_epoch"], UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    graph = _Graph(namespace, created)
    root_id = _package_graph(graph, packages, inputs, manifest["source"])
    for index, (name, raw) in enumerate(sorted(inputs.items())):
        target = graph.file(f"input-{index}", name, digest(raw), len(raw))
        graph.relationship(root_id, "hasInput", [target])
    for artifact in manifest["artifacts"]:
        if artifact["kind"] not in {"wheel", "sdist"}:
            continue
        target = graph.file(
            "artifact-" + artifact["kind"], artifact["name"], artifact["sha256"], artifact["size"]
        )
        graph.relationship(root_id, "hasDistributionArtifact", [target])
    sbom_id = graph.node(
        "sbom",
        "software_Sbom",
        name="AWQ release inventory",
        rootElement=[root_id],
        software_sbomType=["build", "source"],
        description=LIMITATION,
    )
    graph.relationship(sbom_id, "describes", [root_id])
    graph.node(
        "document",
        "SpdxDocument",
        name="AWQ SPDX 3.0.1 release",
        dataLicense="https://spdx.org/licenses/CC0-1.0",
        profileConformance=["core", "simpleLicensing", "software"],
        rootElement=[sbom_id],
        element=sorted(node["spdxId"] for node in graph.nodes if "spdxId" in node),
        comment=canonical_bytes(
            {
                "profile": PROFILE,
                "runtime_dependencies": 0,
                "source": manifest["source"],
                **metadata(inputs),
            }
        )
        .decode()
        .strip(),
    )
    return {
        "@context": CONTEXT,
        "@graph": sorted(graph.nodes, key=lambda node: node.get("spdxId", node.get("@id", ""))),
    }


def generate(inputs: dict[str, bytes], manifest: dict[str, Any]) -> dict[str, Any]:
    """Generate the exact standards-shaped graph from reviewed source and lock inputs."""
    try:
        result = _generate(inputs, manifest)
        raw = canonical_bytes(result)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as error:
        raise ReleaseError("SBOM inventory or release input is invalid") from error
    if len(raw) > MAX_BYTES or any(pattern.search(raw) for pattern in PRIVATE_CONTENT):
        raise ReleaseError("SBOM exceeds bounds or contains private data")
    return result


def verify(raw: bytes, inputs: dict[str, bytes], manifest: dict[str, Any]) -> None:
    """Reject any deviation from the bounded, closed AWQ semantic SPDX profile."""
    observed = strict_json(raw)
    expected = generate(inputs, manifest)
    if observed != expected or raw != canonical_bytes(expected):
        raise ReleaseError("SBOM graph, license, identity or relationship differs")
    if manifest.get("sbom") != metadata(inputs):
        raise ReleaseError("SBOM manifest bindings differ")
