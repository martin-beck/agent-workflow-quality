# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Regenerate the public, synthetic SPDX contract fixture without network access."""

from __future__ import annotations

import argparse
import tomllib
from pathlib import Path

from awq.release import BUILD_CONSTRAINTS_SHA256, canonical_bytes, make_manifest, registry_digests
from awq.sbom import REPOSITORY, digest, generate, metadata, source_inputs

ROOT = Path(__file__).resolve().parents[1]


def render() -> dict[str, bytes]:
    inputs = source_inputs(ROOT)
    version = tomllib.loads(inputs["pyproject.toml"].decode())["project"]["version"]
    manifest = make_manifest(
        version=version,
        source={
            "repository": REPOSITORY,
            "commit": "a" * 40,
            "tree": "b" * 40,
            "source_date_epoch": 1788937200,
        },
        builder={
            "recipe": "awq-release-v1",
            "python_version": "3.13.15",
            "uv_version": "0.12.8",
            "hatchling_version": "1.27.0",
            "host": "linux-x86_64",
            "build_constraints_sha256": BUILD_CONSTRAINTS_SHA256,
        },
        registries=registry_digests(ROOT),
        artifacts=[
            {
                "name": f"agent_workflow_quality-{version}-py3-none-any.whl",
                "kind": "wheel",
                "media_type": "application/zip",
                "size": 1,
                "sha256": "1" * 64,
            },
            {
                "name": f"agent_workflow_quality-{version}.tar.gz",
                "kind": "sdist",
                "media_type": "application/gzip",
                "size": 1,
                "sha256": "2" * 64,
            },
        ],
    )
    raw = canonical_bytes(generate(inputs, manifest))
    manifest["schema_version"] = 2
    manifest["sbom"] = metadata(inputs)
    manifest["artifacts"].append(
        {
            "name": f"agent_workflow_quality-{version}.spdx.json",
            "kind": "sbom",
            "media_type": "application/spdx+json",
            "size": len(raw),
            "sha256": digest(raw),
        }
    )
    manifest["artifacts"].sort(key=lambda item: item["name"])
    return {"document.spdx.json": raw, "manifest.json": canonical_bytes(manifest)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for name, raw in render().items():
        path = ROOT / "fixtures/conforming/release-sbom" / name
        if args.check:
            if path.read_bytes() != raw:
                raise SystemExit("SPDX fixture generation differs")
        else:
            path.write_bytes(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
