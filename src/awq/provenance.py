# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Deterministic in-toto/SLSA-compatible evidence, not a SLSA-level assertion."""

from __future__ import annotations

import hashlib
import re
import tarfile
from pathlib import Path
from typing import Any

from awq.registry import canonical_bytes
from awq.release import REGISTRY_PATHS, ReleaseError
from awq.sbom import strict_json
from awq.trust import read_file

REPOSITORY = "https://github.com/martin-beck/agent-workflow-quality"
WORKFLOW = ".github/workflows/release-attestation.yml"
MATERIAL_PATHS = tuple(
    sorted(
        {
            *REGISTRY_PATHS.values(),
            "uv.lock",
            "pyproject.toml",
            "LICENSE",
            "config/release-build-constraints.txt",
            "config/release-licenses.json",
            "scripts/build_release.py",
            "src/awq/provenance.py",
            "src/awq/release.py",
            "src/awq/sbom.py",
            "schemas/release-manifest.schema.json",
            "schemas/release-provenance.schema.json",
            "schemas/release-trust-policy.schema.json",
            "schemas/release-license-inventory.schema.json",
            "schemas/spdx-3.0.1.schema.zip",
            WORKFLOW,
            "docs/PROVENANCE.md",
        }
    )
)
MAX_BYTES = 1_000_000
MAX_TOTAL = 10_000_000
MEDIA = "application/vnd.in-toto+json"


def source_materials(source: Path) -> dict[str, bytes]:
    """Load only reviewed material paths; never execute candidate source."""
    result = {name: read_file(source / name, MAX_BYTES) for name in MATERIAL_PATHS}
    if sum(map(len, result.values())) > MAX_TOTAL:
        raise ReleaseError("provenance materials exceed their aggregate bound")
    return result


def archive_materials(path: Path, version: str) -> dict[str, bytes]:
    """Read the same finite materials directly from the already-checked sdist."""
    result: dict[str, bytes] = {}
    prefix = f"agent_workflow_quality-{version}/"
    try:
        with tarfile.open(path, "r:gz") as archive:
            for index, member in enumerate(archive):
                if index >= 10_000:
                    raise ReleaseError("provenance archive exceeds its member bound")
                name = member.name.removeprefix(prefix)
                if member.name == prefix + name and name in MATERIAL_PATHS:
                    if name in result or not member.isfile() or member.size > MAX_BYTES:
                        raise ReleaseError("provenance material is duplicated or unsafe")
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ReleaseError("provenance material is unavailable")
                    with stream:
                        result[name] = stream.read(MAX_BYTES + 1)
                    if len(result[name]) > MAX_BYTES:
                        raise ReleaseError("provenance material exceeds its byte bound")
    except (OSError, tarfile.TarError) as error:
        raise ReleaseError("provenance materials are unavailable") from error
    if set(result) != set(MATERIAL_PATHS) or sum(map(len, result.values())) > MAX_TOTAL:
        raise ReleaseError("provenance material set is incomplete or too large")
    return result


def _workflow(raw: bytes) -> None:
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise ReleaseError("provenance workflow is not UTF-8") from error
    uses = re.findall(r"^\s*-?\s*uses:\s*(\S+)", text, re.MULTILINE)
    if not uses or any(
        not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[a-f0-9]{40}", value) for value in uses
    ):
        raise ReleaseError("provenance workflow has missing or mutable action references")


def generate(manifest: dict[str, Any], materials: dict[str, bytes]) -> dict[str, Any]:
    """Bind all payload subjects and the manifest projection without a digest cycle."""
    if set(materials) != set(MATERIAL_PATHS):
        raise ReleaseError("provenance material set differs from its profile")
    _workflow(materials[WORKFLOW])
    projection = {key: value for key, value in manifest.items() if key != "provenance"}
    source = manifest["source"]
    documentation = REPOSITORY + "/blob/" + source["commit"] + "/docs/PROVENANCE.md"
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"name": item["name"], "digest": {"sha256": item["sha256"]}}
            for item in manifest["artifacts"]
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": documentation + "#build-type",
                "externalParameters": {
                    "source": source,
                    "version": manifest["version"],
                    "manifest_projection_sha256": hashlib.sha256(
                        canonical_bytes(projection)
                    ).hexdigest(),
                    "trust_policy_sha256": manifest["trust_policy_sha256"],
                    "workflow": {
                        "path": WORKFLOW,
                        "commit": source["commit"],
                        "sha256": hashlib.sha256(materials[WORKFLOW]).hexdigest(),
                    },
                },
                "resolvedDependencies": [
                    {
                        "uri": REPOSITORY + "/commit/" + source["commit"],
                        "digest": {"gitCommit": source["commit"], "gitTree": source["tree"]},
                    },
                    *[
                        {
                            "uri": REPOSITORY + "/blob/" + source["commit"] + "/" + name,
                            "digest": {"sha256": hashlib.sha256(materials[name]).hexdigest()},
                        }
                        for name in MATERIAL_PATHS
                    ],
                ],
            },
            "runDetails": {
                "builder": {
                    "id": documentation + "#builder-identity",
                    "version": manifest["builder"],
                }
            },
        },
    }


def add(source: Path, stage: Path, manifest: dict[str, Any], policy_sha256: str) -> dict[str, Any]:
    """Add unsigned deterministic provenance; an external operator signs the final manifest."""
    if not re.fullmatch(r"[a-f0-9]{64}", policy_sha256):
        raise ReleaseError("release requires an explicit reviewed trust-policy digest")
    result = {**manifest, "schema_version": 3, "trust_policy_sha256": policy_sha256}
    raw = canonical_bytes(generate(result, source_materials(source)))
    name = f"agent_workflow_quality-{manifest['version']}.provenance.json"
    (stage / name).write_bytes(raw)
    (stage / name).chmod(0o644)
    result["provenance"] = {
        "name": name,
        "media_type": MEDIA,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    return result


def verify(bundle: Path, manifest: dict[str, Any], source: Path | None) -> None:
    """Reject unknown, altered or missing provenance fields by exact deterministic regeneration."""
    descriptor = manifest["provenance"]
    raw = read_file(bundle / descriptor["name"], MAX_BYTES)
    if len(raw) != descriptor["size"] or hashlib.sha256(raw).hexdigest() != descriptor["sha256"]:
        raise ReleaseError("provenance identity differs from the manifest")
    sdist = next(item for item in manifest["artifacts"] if item["kind"] == "sdist")
    materials = archive_materials(bundle / sdist["name"], manifest["version"])
    if source is not None and source_materials(source) != materials:
        raise ReleaseError("provenance materials differ from the checked source")
    if strict_json(raw) != generate(manifest, materials):
        raise ReleaseError("provenance statement differs from the exact release profile")
