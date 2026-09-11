# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Public synthetic releases with ephemeral SSH keys and real Git tag objects."""

from __future__ import annotations

import io
import json
import subprocess
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

from awq import commands, provenance, sbom, trust
from awq.release import (
    ARTIFACT_MEDIA,
    BUILD_CONSTRAINTS_SHA256,
    REQUIRED_SCHEMAS,
    canonical_bytes,
    make_manifest,
    registry_digests,
    source_identity,
)
from scripts.build_release import _add_sbom

ROOT = Path(__file__).resolve().parents[1]
EPOCH = 1788937200


class SignedRelease:
    """Own all mutable fixture state in one external temporary directory."""

    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="awq-auth-tests-")
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.consumer = self.root / "consumer"
        self.source.mkdir()
        self.consumer.mkdir()
        self.keys: list[Path] = []
        self.roots: list[dict[str, Any]] = []
        for index in range(3):
            key = self.root / f"key-{index}"
            self.command(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
            public = " ".join(key.with_suffix(".pub").read_text().split()[:2])
            self.keys.append(key)
            self.roots.append(
                {
                    "principal": "awq-test@example.invalid",
                    "public_key": public,
                    "fingerprint": trust.fingerprint(public),
                    "valid_after": "2020-01-01T00:00:00Z",
                    "valid_until": "2090-01-01T00:00:00Z",
                }
            )
        self.policy = self.policy_value([0])
        self.policy_path = self.root / "trust-policy.json"
        self.policy_path.write_bytes(canonical_bytes(self.policy))
        names = (
            set(provenance.MATERIAL_PATHS)
            | set(sbom.INPUT_PATHS)
            | {"schemas/" + name for name in REQUIRED_SCHEMAS}
            | {
                "src/awq/data/contract_catalog.json",
                "src/awq/data/compatibility.json",
                "src/awq/data/agent_recipes.json",
            }
        )
        for name in names:
            target = self.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes())
        # Executing candidate source is forbidden, even when its bytes are authenticated.
        marker = self.source / "src/awq/__init__.py"
        marker.write_text('raise RuntimeError("candidate code must never execute")\n')
        self.git("init", "-q")
        self.git("config", "user.name", "AWQ synthetic test")
        self.git("config", "user.email", "awq-test@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        commands.initialize(self.consumer, ["core"], False)
        self.version = ""
        self.bundle = self.root / "unset"
        self.manifest_path = self.bundle / "unset"
        self.manifest: dict[str, Any] = {}
        self.tag_object = ""
        self.build("0.31.1", self.policy, 0)

    def close(self) -> None:
        self.temporary.cleanup()

    def command(self, argv: list[str]) -> bytes:
        environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.root),
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_AUTHOR_DATE": f"{EPOCH} +0000",
            "GIT_COMMITTER_DATE": f"{EPOCH} +0000",
        }
        return subprocess.run(
            argv,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=30,
        ).stdout

    def git(self, *arguments: str) -> bytes:
        return self.command(["/usr/bin/git", "-C", str(self.source), *arguments])

    def policy_value(
        self, indices: list[int], previous: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        before = set() if previous is None else {item["fingerprint"] for item in previous["roots"]}
        roots = sorted(
            [self.roots[index].copy() for index in indices], key=lambda item: item["fingerprint"]
        )
        removed = before - {item["fingerprint"] for item in roots}
        return {
            "repository": provenance.REPOSITORY,
            "schema_version": 1,
            "generation": 1 if previous is None else previous["generation"] + 1,
            "previous_policy_sha256": None if previous is None else trust.digest(previous),
            "roots": roots,
            "retired": sorted((set() if previous is None else set(previous["retired"])) | removed),
        }

    def _version(self, version: str) -> None:
        for name in ("pyproject.toml", "uv.lock"):
            path = self.source / name
            path.write_text(
                path.read_text().replace(
                    'version = "' + (self.version or "0.31.0") + '"',
                    'version = "' + version + '"',
                    1,
                )
            )
        path = self.source / "config/release-licenses.json"
        inventory = json.loads(path.read_bytes())
        for item in inventory["packages"]:
            if item["name"] == "agent-workflow-quality":
                item["version"] = version
        path.write_bytes(canonical_bytes(inventory))

    def _wheel(self, path: Path, epoch: int) -> None:
        instant = time.gmtime(epoch)
        timestamp = (
            instant.tm_year,
            instant.tm_mon,
            instant.tm_mday,
            instant.tm_hour,
            instant.tm_min,
            instant.tm_sec - instant.tm_sec % 2,
        )
        entries = {
            "awq/schemas/" + name: (self.source / "schemas" / name).read_bytes()
            for name in REQUIRED_SCHEMAS
        }
        entries["awq/data/adapter_catalog.json"] = (
            self.source / "src/awq/data/adapter_catalog.json"
        ).read_bytes()
        for data_name in ("contract_catalog.json", "compatibility.json", "agent_recipes.json"):
            entries["awq/data/" + data_name] = (
                self.source / "src/awq/data" / data_name
            ).read_bytes()
        entries[f"agent_workflow_quality-{self.version}.dist-info/METADATA"] = (
            f"Name: agent-workflow-quality\nVersion: {self.version}\n"
        ).encode()
        with zipfile.ZipFile(path, "w") as archive:
            for name, raw in entries.items():
                member = zipfile.ZipInfo(name, timestamp)
                member.create_system = 3
                member.external_attr = (0o644 if ".dist-info/" in name else 0o100644) << 16
                member.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(member, raw)

    def build(self, version: str, policy: dict[str, Any], signer: int) -> None:
        self._version(version)
        self.version = version
        self.policy = policy
        self.policy_path.write_bytes(canonical_bytes(policy))
        self.git("add", ".")
        self.git("commit", "-qm", "Synthetic release " + version)
        self.git(
            "-c",
            "gpg.format=ssh",
            "-c",
            "user.signingKey=" + str(self.keys[signer]),
            "tag",
            "-s",
            "-a",
            "v" + version,
            "-m",
            "Synthetic release " + version,
        )
        self.tag_object = self.git("rev-parse", "refs/tags/v" + version).decode().strip()
        identity = source_identity(self.source)
        self.bundle = self.root / ("bundle-" + version)
        self.bundle.mkdir()
        records = []
        for kind, name in {
            "wheel": f"agent_workflow_quality-{version}-py3-none-any.whl",
            "sdist": f"agent_workflow_quality-{version}.tar.gz",
        }.items():
            path = self.bundle / name
            if kind == "wheel":
                self._wheel(path, EPOCH)
            else:
                with tarfile.open(path, "w:gz") as archive:
                    for source in sorted(self.source.rglob("*")):
                        if ".git" in source.parts or not source.is_file():
                            continue
                        raw = source.read_bytes()
                        member = tarfile.TarInfo(
                            f"agent_workflow_quality-{version}/"
                            + source.relative_to(self.source).as_posix()
                        )
                        member.size, member.mtime, member.mode = len(raw), EPOCH, 0o644
                        archive.addfile(member, io.BytesIO(raw))
            records.append(
                {
                    "kind": kind,
                    "name": name,
                    "media_type": ARTIFACT_MEDIA[kind],
                    "sha256": sbom.digest(path.read_bytes()),
                    "size": path.stat().st_size,
                }
            )
        base = make_manifest(
            version=version,
            source=identity,
            registries=registry_digests(self.source),
            builder={
                "recipe": "awq-release-v1",
                "python_version": "3.13.15",
                "uv_version": "0.12.8",
                "hatchling_version": "1.27.0",
                "host": "linux-x86_64",
                "build_constraints_sha256": BUILD_CONSTRAINTS_SHA256,
            },
            artifacts=records,
        )
        base = _add_sbom(self.source, self.bundle, base)
        self.manifest = provenance.add(self.source, self.bundle, base, trust.digest(policy))
        self.manifest_path = self.bundle / f"agent_workflow_quality-{version}.release.json"
        self.sign(signer)

    def sign(self, signer: int = 0) -> None:
        self.manifest_path.write_bytes(canonical_bytes(self.manifest))
        self.manifest_path.with_name(self.manifest_path.name + ".sig").unlink(missing_ok=True)
        self.command(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(self.keys[signer]),
                "-n",
                "awq-release",
                str(self.manifest_path),
            ]
        )

    def arguments(self) -> tuple[Path, Path, Path, str, str]:
        return (
            self.manifest_path,
            self.policy_path,
            self.source,
            "refs/tags/v" + self.version,
            self.tag_object,
        )

    def consumer_bytes(self) -> dict[str, bytes]:
        return {
            path.relative_to(self.consumer).as_posix(): path.read_bytes()
            for path in self.consumer.rglob("*")
            if path.is_file()
        }
