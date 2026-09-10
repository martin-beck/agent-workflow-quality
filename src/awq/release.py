# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Canonical, bounded, offline verification for AWQ release bundles."""

from __future__ import annotations

import hashlib
import json
import re
import stat
import tarfile
import time
import tomllib
import zipfile
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from typing import Any

MAX_MANIFEST_BYTES = 256_000
MAX_MEMBERS = 10_000
MAX_MEMBER_BYTES = 5_000_000
MAX_TOTAL_BYTES = 50_000_000
MAX_ARTIFACTS = 16
DENIED_PARTS = frozenset({".git", ".venv", "__pycache__"})
REQUIRED_SCHEMAS = frozenset(
    {
        "adapter-catalog.schema.json",
        "adapter-contract.schema.json",
        "adapter-result.schema.json",
        "release-manifest.schema.json",
        "release-license-inventory.schema.json",
        "spdx-3.0.1.schema.zip",
    }
)
PROVENANCE_SCHEMA_ASSETS = {"release-provenance.schema.json", "release-trust-policy.schema.json"}
PROMOTION_SCHEMA_ASSETS = {"consumer-equivalence.schema.json"}
NATIVE_MAPPING_SCHEMA_ASSETS = {
    "evidence-identity.schema.json",
    "native-gate-mapping.schema.json",
}
FORMAL_SCHEMA_ASSETS = {"assurance-contract.schema.json"}
LIFECYCLE_SCHEMA_ASSETS = {"lifecycle-model.schema.json"}
REFINEMENT_SCHEMA_ASSETS = {"refinement-map.schema.json"}
PYTHON_REFACTOR_SCHEMA_ASSETS = {"python-refactor.schema.json"}
ADVERSARIAL_SCHEMA_ASSETS = {"adversarial-campaign.schema.json"}
RELIABILITY_SCHEMA_ASSETS = {"reliability-budget.schema.json"}
ONBOARDING_SCHEMA_ASSETS = {"onboarding.schema.json"}
TEST_REPORT_SCHEMA_ASSETS = {"test-report-evidence.schema.json"}
ONBOARDING_DATA_ASSETS = {"compatibility.json", "agent_recipes.json"}
CONTRACT_CATALOG_SCHEMA_ASSETS = {"contract-catalog.schema.json"}
CONTRACT_CATALOG_DATA_ASSETS = {"contract_catalog.json"}
REQUIRED_SCHEMAS |= (
    PROVENANCE_SCHEMA_ASSETS
    | PROMOTION_SCHEMA_ASSETS
    | NATIVE_MAPPING_SCHEMA_ASSETS
    | FORMAL_SCHEMA_ASSETS
    | LIFECYCLE_SCHEMA_ASSETS
    | REFINEMENT_SCHEMA_ASSETS
    | PYTHON_REFACTOR_SCHEMA_ASSETS
    | ADVERSARIAL_SCHEMA_ASSETS
    | RELIABILITY_SCHEMA_ASSETS
    | ONBOARDING_SCHEMA_ASSETS
    | CONTRACT_CATALOG_SCHEMA_ASSETS
    | TEST_REPORT_SCHEMA_ASSETS
)
SBOM_SCHEMA_ASSETS = frozenset(
    {
        "release-license-inventory.schema.json",
        "spdx-3.0.1.schema.zip",
    }
)
REQUIRED_DATA = frozenset({"adapter_catalog.json"}) | CONTRACT_CATALOG_DATA_ASSETS
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_ID = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
TOOL_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,99}$")
ARTIFACT_MEDIA = {
    "wheel": "application/zip",
    "sdist": "application/gzip",
    "sbom": "application/spdx+json",
    "provenance": "application/vnd.in-toto+json",
    "signature": "application/octet-stream",
}
REGISTRY_PATHS = {
    "adapter_catalog": "src/awq/data/adapter_catalog.json",
    "profiles": "src/awq/data/profiles.json",
    "requirements": "src/awq/data/requirements.json",
    "standards_mappings": "src/awq/data/requirement_mappings.json",
    "standards_sources": "src/awq/data/control_sources.json",
}
BUILD_CONSTRAINTS_PATH = "config/release-build-constraints.txt"
BUILD_CONSTRAINTS_SHA256 = "7fe13ad650e7b707d2f37acf736b95a3950cc05a9660808dd3958016878fa7ac"
PRIVATE_CONTENT = (
    re.compile(rb"-----BEGIN [A-Z ]{0,32}PRIVATE KEY-----"),
    re.compile(rb"(?<![A-Za-z0-9_])/home/[A-Za-z0-9._-]{1,64}/"),
    re.compile(rb"(?<![A-Za-z0-9_])/Users/[A-Za-z0-9._-]{1,64}/"),
    re.compile(rb"(?i:[A-Z]:[\\/]+Users[\\/]+[A-Za-z0-9._-]{1,64}[\\/])"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"gh[opusr]_[A-Za-z0-9]{20,}"),
)
ArchiveMember = tuple[str, bytes | None, list[str]]


class DistributionError(ValueError):
    """A distribution archive is malformed or outside review bounds."""


class ReleaseError(ValueError):
    """A release bundle or manifest violates the stable contract."""


def sha256_file(path: Path) -> str:
    """Return a bounded-memory SHA-256 digest for one regular file."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_bytes(value: object) -> bytes:
    """Serialize a JSON-compatible value using the AWQ canonical form."""
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _checked_name(name: str) -> tuple[PurePosixPath, list[str]]:
    path = PurePosixPath(name)
    issues: list[str] = []
    if (
        not name
        or "\0" in name
        or "\\" in name
        or ".." in path.parts
        or re.match(r"^[A-Za-z]:", name)
        or name != path.as_posix()
    ):
        issues.append(f"{name}: unsafe archive path")
    if DENIED_PARTS.intersection(path.parts) or path.name == ".coverage":
        issues.append(f"{name}: forbidden development artifact")
    return path, issues


def _expected_zip_time(epoch: int) -> tuple[int, int, int, int, int, int]:
    observed = time.gmtime(epoch)
    return (
        observed.tm_year,
        observed.tm_mon,
        observed.tm_mday,
        observed.tm_hour,
        observed.tm_min,
        observed.tm_sec - observed.tm_sec % 2,
    )


def _tar_metadata_issues(member: tarfile.TarInfo, epoch: int | None) -> list[str]:
    if epoch is None:
        return []
    path = PurePosixPath(member.name)
    expected_mode = (
        0o755 if member.isdir() or (path.name == "awq" and path.parent.name == "tools") else 0o644
    )
    if (
        member.mtime != epoch
        or member.mode != expected_mode
        or member.uid != 0
        or member.gid != 0
        or member.uname
        or member.gname
        or member.pax_headers
    ):
        return [f"{member.name}: noncanonical archive metadata"]
    return []


def _tar_members(path: Path, epoch: int | None) -> Iterator[ArchiveMember]:
    with tarfile.open(path, mode="r:gz") as archive:
        for index, member in enumerate(archive, start=1):
            if index > MAX_MEMBERS:
                raise DistributionError("archive member count exceeds the review bound")
            metadata = _tar_metadata_issues(member, epoch)
            if member.isdir():
                yield member.name, b"", metadata
                continue
            if not member.isfile():
                yield member.name, None, metadata
                continue
            if member.size > MAX_MEMBER_BYTES:
                raise DistributionError(f"{member.name}: member exceeds the review bound")
            stream = archive.extractfile(member)
            if stream is None:
                raise DistributionError(f"{member.name}: regular member is unreadable")
            with stream:
                content = stream.read(MAX_MEMBER_BYTES + 1)
            if len(content) > MAX_MEMBER_BYTES:
                raise DistributionError(f"{member.name}: member exceeds the review bound")
            yield member.name, content, metadata


def _zip_metadata_issues(member: zipfile.ZipInfo, epoch: int | None) -> list[str]:
    if epoch is None:
        return []
    path = PurePosixPath(member.filename)
    expected_mode = 0o644 if any(part.endswith(".dist-info") for part in path.parts) else 0o100644
    if (
        member.is_dir()
        or member.date_time != _expected_zip_time(epoch)
        or member.create_system != 3
        or member.external_attr >> 16 != expected_mode
        or member.compress_type != zipfile.ZIP_DEFLATED
        or member.flag_bits != 0
        or member.extra
        or member.comment
    ):
        return [f"{member.filename}: noncanonical archive metadata"]
    return []


def _zip_members(path: Path, epoch: int | None) -> Iterator[ArchiveMember]:
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS:
            raise DistributionError("archive member count exceeds the review bound")
        if epoch is not None and archive.comment:
            raise DistributionError("wheel archive comment is noncanonical")
        for member in members:
            metadata = _zip_metadata_issues(member, epoch)
            if member.is_dir():
                yield member.filename, b"", metadata
                continue
            if member.file_size > MAX_MEMBER_BYTES:
                raise DistributionError(f"{member.filename}: member exceeds the review bound")
            kind = stat.S_IFMT(member.external_attr >> 16)
            if kind not in {0, stat.S_IFREG}:
                yield member.filename, None, metadata
                continue
            yield member.filename, archive.read(member), metadata


def _excluding_when_disabled(
    required: frozenset[str], assets: set[str], *, enabled: bool
) -> frozenset[str]:
    return required if enabled else required - assets


def _required_schemas(
    require_sbom_assets: bool,
    require_provenance_assets: bool,
    require_promotion_assets: bool,
    require_formal_assets: bool,
    require_lifecycle_assets: bool,
    require_refinement_assets: bool,
    require_python_refactor_assets: bool,
    require_adversarial_assets: bool,
    require_reliability_assets: bool,
    require_onboarding_assets: bool,
    require_contract_catalog_assets: bool,
    require_test_report_assets: bool,
) -> frozenset[str]:
    required_schemas = (
        REQUIRED_SCHEMAS if require_sbom_assets else REQUIRED_SCHEMAS - SBOM_SCHEMA_ASSETS
    )
    if not require_provenance_assets:
        required_schemas = required_schemas - PROVENANCE_SCHEMA_ASSETS
    if not require_promotion_assets:
        required_schemas = required_schemas - PROMOTION_SCHEMA_ASSETS
    if not require_formal_assets:
        required_schemas = required_schemas - FORMAL_SCHEMA_ASSETS
    if not require_lifecycle_assets:
        required_schemas = required_schemas - LIFECYCLE_SCHEMA_ASSETS
    if not require_refinement_assets:
        required_schemas = required_schemas - REFINEMENT_SCHEMA_ASSETS
    if not require_python_refactor_assets:
        required_schemas = required_schemas - PYTHON_REFACTOR_SCHEMA_ASSETS
    if not require_adversarial_assets:
        required_schemas = required_schemas - ADVERSARIAL_SCHEMA_ASSETS
    if not require_reliability_assets:
        required_schemas = required_schemas - RELIABILITY_SCHEMA_ASSETS
    if not require_onboarding_assets:
        required_schemas = required_schemas - ONBOARDING_SCHEMA_ASSETS
    required_schemas = _excluding_when_disabled(
        required_schemas,
        CONTRACT_CATALOG_SCHEMA_ASSETS,
        enabled=require_contract_catalog_assets,
    )
    return _excluding_when_disabled(
        required_schemas,
        TEST_REPORT_SCHEMA_ASSETS,
        enabled=require_test_report_assets,
    )


def inspect_archive(
    path: Path,
    *,
    source_date_epoch: int | None = None,
    require_sbom_assets: bool = True,
    require_provenance_assets: bool = True,
    require_promotion_assets: bool = True,
    require_formal_assets: bool = True,
    require_lifecycle_assets: bool = True,
    require_refinement_assets: bool = True,
    require_python_refactor_assets: bool = True,
    require_adversarial_assets: bool = True,
    require_reliability_assets: bool = True,
    require_onboarding_assets: bool = True,
    require_contract_catalog_assets: bool = True,
    require_test_report_assets: bool = True,
) -> list[str]:
    """Return bounded archive findings without extracting any member."""
    required_schemas = _required_schemas(
        require_sbom_assets,
        require_provenance_assets,
        require_promotion_assets,
        require_formal_assets,
        require_lifecycle_assets,
        require_refinement_assets,
        require_python_refactor_assets,
        require_adversarial_assets,
        require_reliability_assets,
        require_onboarding_assets,
        require_contract_catalog_assets,
        require_test_report_assets,
    )
    required_data = (
        REQUIRED_DATA
        if require_contract_catalog_assets
        else REQUIRED_DATA - CONTRACT_CATALOG_DATA_ASSETS
    )
    required_data = (
        required_data | ONBOARDING_DATA_ASSETS if require_onboarding_assets else required_data
    )
    try:
        if path.name.endswith(".tar.gz"):
            members = _tar_members(path, source_date_epoch)
        elif path.suffix == ".whl":
            members = _zip_members(path, source_date_epoch)
        else:
            raise DistributionError(f"{path.name}: unsupported distribution format")
        issues: list[str] = []
        names: list[PurePosixPath] = []
        seen: set[str] = set()
        total = 0
        for name, content, metadata_issues in members:
            normalized, path_issues = _checked_name(name)
            names.append(normalized)
            issues.extend(path_issues)
            issues.extend(metadata_issues)
            if name in seen:
                issues.append(f"{name}: duplicate archive path")
            seen.add(name)
            if content is None:
                issues.append(f"{name}: non-regular archive member")
                continue
            total += len(content)
            if total > MAX_TOTAL_BYTES:
                raise DistributionError("archive content exceeds the review bound")
            if content and any(pattern.search(content) for pattern in PRIVATE_CONTENT):
                issues.append(f"{name}: private or machine-specific content")
        present_schemas = {
            name.name for name in names if len(name.parts) >= 2 and name.parts[-2] == "schemas"
        }
        present_data = {
            name.name
            for name in names
            if len(name.parts) >= 3 and tuple(name.parts[-3:-1]) == ("awq", "data")
        }
        issues.extend(
            f"{path.name}: required packaged schema is missing: {schema}"
            for schema in sorted(required_schemas - present_schemas)
        )
        issues.extend(
            f"{path.name}: required packaged data is missing: {item}"
            for item in sorted(required_data - present_data)
        )
        return issues
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise DistributionError(f"{path.name}: cannot inspect archive") from error


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ReleaseError(f"{label} has unknown or missing fields")
    return value


def _text(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ReleaseError(f"{label} is invalid")
    return value


def _integer(value: object, low: int, high: int, label: str) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ReleaseError(f"{label} is invalid")
    return value


def _validate_source(value: object) -> None:
    source = _exact(
        value,
        {"repository", "commit", "tree", "source_date_epoch"},
        "release source",
    )
    if source["repository"] != "https://github.com/martin-beck/agent-workflow-quality":
        raise ReleaseError("source repository is invalid")
    _text(source["commit"], GIT_ID, "source commit")
    _text(source["tree"], GIT_ID, "source tree")
    _integer(source["source_date_epoch"], 315532800, 4_102_444_800, "source epoch")


def _validate_builder(value: object) -> None:
    builder = _exact(
        value,
        {
            "recipe",
            "python_version",
            "uv_version",
            "hatchling_version",
            "host",
            "build_constraints_sha256",
        },
        "release builder",
    )
    expected = {
        "recipe": "awq-release-v1",
        "python_version": "3.13.15",
        "uv_version": "0.12.8",
        "hatchling_version": "1.27.0",
        "host": "linux-x86_64",
        "build_constraints_sha256": BUILD_CONSTRAINTS_SHA256,
    }
    if builder != expected:
        raise ReleaseError("release builder identity is invalid")


def _validate_registries(value: object) -> None:
    registries = _exact(value, set(REGISTRY_PATHS), "release registries")
    for name in REGISTRY_PATHS:
        _text(registries[name], SHA256, f"registry {name}")


def _validate_artifact(value: object) -> dict[str, Any]:
    item = _exact(value, {"name", "kind", "media_type", "size", "sha256"}, "release artifact")
    _text(item["name"], SAFE_NAME, "artifact name")
    kind = item["kind"]
    if not isinstance(kind, str) or kind not in ARTIFACT_MEDIA:
        raise ReleaseError("artifact kind is invalid")
    if item["media_type"] != ARTIFACT_MEDIA[kind]:
        raise ReleaseError("artifact media type is invalid")
    _integer(item["size"], 1, MAX_TOTAL_BYTES, "artifact size")
    _text(item["sha256"], SHA256, "artifact digest")
    return item


def _validate_artifacts(value: object, version: str) -> None:
    if not isinstance(value, list) or not 2 <= len(value) <= MAX_ARTIFACTS:
        raise ReleaseError("release artifact list is invalid")
    artifacts = [_validate_artifact(item) for item in value]
    if artifacts != sorted(artifacts, key=lambda item: str(item["name"])):
        raise ReleaseError("release artifacts are not canonically ordered")
    names = [str(item["name"]) for item in artifacts]
    kinds = [str(item["kind"]) for item in artifacts]
    if len(names) != len(set(names)) or len(kinds) != len(set(kinds)):
        raise ReleaseError("release artifact identity is duplicated")
    if not {"wheel", "sdist"} <= set(kinds):
        raise ReleaseError("wheel and source artifacts are required")
    by_kind = {str(item["kind"]): item for item in artifacts}
    expected = {
        "wheel": f"agent_workflow_quality-{version}-py3-none-any.whl",
        "sdist": f"agent_workflow_quality-{version}.tar.gz",
    }
    if any(by_kind[kind]["name"] != name for kind, name in expected.items()):
        raise ReleaseError("distribution artifact name is invalid")


def _validate_sbom_manifest(manifest: dict[str, Any]) -> None:
    from awq.sbom import PROFILE, SCHEMA_SHA256, SPEC

    item = _exact(
        manifest["sbom"],
        {
            "profile",
            "spec_version",
            "schema_sha256",
            "lock_sha256",
            "license_inventory_sha256",
            "source_license_sha256",
        },
        "SBOM binding",
    )
    if (item["profile"], item["spec_version"], item["schema_sha256"]) != (
        PROFILE,
        SPEC,
        SCHEMA_SHA256,
    ):
        raise ReleaseError("SBOM format or schema identity differs")
    for name in ("lock_sha256", "license_inventory_sha256", "source_license_sha256"):
        _text(item[name], SHA256, "SBOM input digest")
    records = [record for record in manifest["artifacts"] if record["kind"] == "sbom"]
    if len(records) != 1 or records[0]["name"] != (
        f"agent_workflow_quality-{manifest['version']}.spdx.json"
    ):
        raise ReleaseError("SBOM release artifact is absent or misnamed")


def _validate_provenance_manifest(manifest: dict[str, Any]) -> None:
    item = _exact(
        manifest["provenance"], {"name", "media_type", "size", "sha256"}, "provenance binding"
    )
    if (
        item["name"] != f"agent_workflow_quality-{manifest['version']}.provenance.json"
        or item["media_type"] != ARTIFACT_MEDIA["provenance"]
    ):
        raise ReleaseError("provenance identity is invalid")
    _integer(item["size"], 1, 1_000_000, "provenance size")
    _text(item["sha256"], SHA256, "provenance digest")
    _text(manifest["trust_policy_sha256"], SHA256, "trust policy digest")
    if {record["kind"] for record in manifest["artifacts"]} != {"wheel", "sdist", "sbom"}:
        raise ReleaseError("v3 payload artifacts must be exactly wheel, sdist and SBOM")


def validate_manifest(value: object) -> dict[str, Any]:
    """Validate exact release-manifest semantics without third-party packages."""
    manifest = _exact(
        value,
        {"schema_version", "package", "version", "source", "builder", "registries", "artifacts"}
        | ({"sbom"} if isinstance(value, dict) and value.get("schema_version") in {2, 3} else set())
        | (
            {"provenance", "trust_policy_sha256"}
            if isinstance(value, dict) and value.get("schema_version") == 3
            else set()
        ),
        "release manifest",
    )
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] not in {1, 2, 3}
        or manifest["package"] != "agent-workflow-quality"
    ):
        raise ReleaseError("release identity is invalid")
    version = _text(manifest["version"], VERSION, "release version")
    _validate_source(manifest["source"])
    _validate_builder(manifest["builder"])
    _validate_registries(manifest["registries"])
    _validate_artifacts(manifest["artifacts"], version)
    if manifest["schema_version"] in {2, 3}:
        _validate_sbom_manifest(manifest)
    if manifest["schema_version"] == 3:
        _validate_provenance_manifest(manifest)
    return manifest


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError("release manifest contains a duplicate key")
        result[key] = value
    return result


def load_manifest(path: Path) -> dict[str, Any]:
    """Load a canonical strict JSON manifest from an exact regular file."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ReleaseError("release manifest is unavailable or exceeds its bound")
    raw = path.read_bytes()
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError("release manifest is not strict JSON") from error
    manifest = validate_manifest(value)
    if canonical_bytes(manifest) != raw:
        raise ReleaseError("release manifest is not canonical JSON")
    return manifest


def registry_digests(root: Path) -> dict[str, str]:
    """Bind every public registry used to interpret a release."""
    result: dict[str, str] = {}
    for name, relative in REGISTRY_PATHS.items():
        path = root / relative
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_MEMBER_BYTES:
            raise ReleaseError(f"registry {name} is unavailable")
        result[name] = sha256_file(path)
    return result


def build_constraints_digest(root: Path) -> str:
    """Validate and bind the reviewed release-build dependency closure."""
    path = root / BUILD_CONSTRAINTS_PATH
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_MEMBER_BYTES:
        raise ReleaseError("release build constraints are unavailable")
    digest = sha256_file(path)
    if digest != BUILD_CONSTRAINTS_SHA256:
        raise ReleaseError("release build constraints differ from the reviewed recipe")
    return digest


def _git(root: Path, *arguments: str) -> str:
    from awq.trust import git

    output = git(root, *arguments)
    if len(output) > 4096:
        raise ReleaseError("source Git identity is unavailable")
    try:
        return output.decode("ascii").strip()
    except UnicodeError as error:
        raise ReleaseError("source Git identity is invalid") from error


def _tracked_member(root: Path, entry: bytes) -> tuple[bytes, int]:
    from awq.trust import read_file

    header, separator, name_raw = entry.partition(b"\t")
    fields = header.split(b" ")
    if (
        not separator
        or len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
    ):
        raise ReleaseError("source tracked member kind is unsupported")
    try:
        name = name_raw.decode("utf-8")
    except UnicodeError as error:
        raise ReleaseError("source tracked path is invalid") from error
    path = PurePosixPath(name)
    if (
        not name
        or path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != name
        or "\\" in name
    ):
        raise ReleaseError("source tracked path is unsafe")
    raw = read_file(root / name, MAX_MEMBER_BYTES)
    observed = (
        hashlib.sha1(f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False)
        .hexdigest()
        .encode()
    )
    executable = bool((root / name).stat().st_mode & 0o111)
    if observed != fields[2] or executable != (fields[0] == b"100755"):
        raise ReleaseError("source has tracked changes")
    return fields[0] + b" " + fields[2] + b" 0\t" + name_raw + b"\0", len(raw)


def _tracked_source(root: Path) -> None:
    """Compare raw Git/index/worktree identities without evaluating checkout filters."""
    from awq.trust import git

    tree_raw = git(root, "ls-tree", "-r", "-z", "--full-tree", "HEAD")
    tree = tree_raw.split(b"\0")
    if tree[-1] != b"" or not 1 < len(tree) <= MAX_MEMBERS + 1:
        raise ReleaseError("source tracked member count is invalid")
    expected_index: list[bytes] = []
    total = 0
    for entry in tree[:-1]:
        index_entry, size = _tracked_member(root, entry)
        total += size
        if total > MAX_TOTAL_BYTES:
            raise ReleaseError("source tracked content exceeds its aggregate bound")
        expected_index.append(index_entry)
    if git(root, "ls-files", "--stage", "-z") != b"".join(expected_index):
        raise ReleaseError("source has tracked changes in its index")


def source_identity(root: Path) -> dict[str, object]:
    """Return a clean exact Git source identity without exposing its path."""
    if root.is_symlink():
        raise ReleaseError("source worktree cannot be a symlink")
    resolved = root.resolve(strict=True)
    observed_root = Path(_git(resolved, "rev-parse", "--show-toplevel")).resolve(strict=True)
    if observed_root != resolved:
        raise ReleaseError("source is not the Git worktree root")
    _tracked_source(resolved)
    commit = _text(_git(resolved, "rev-parse", "HEAD"), GIT_ID, "source commit")
    tree = _text(_git(resolved, "rev-parse", "HEAD^{tree}"), GIT_ID, "source tree")
    epoch_text = _git(resolved, "show", "-s", "--format=%ct", "HEAD")
    if not epoch_text.isdigit():
        raise ReleaseError("source epoch is invalid")
    epoch = _integer(int(epoch_text), 315532800, 4_102_444_800, "source epoch")
    return {
        "repository": "https://github.com/martin-beck/agent-workflow-quality",
        "commit": commit,
        "tree": tree,
        "source_date_epoch": epoch,
    }


def make_manifest(
    *,
    version: str,
    source: dict[str, object],
    builder: dict[str, str],
    registries: dict[str, str],
    artifacts: list[dict[str, object]],
) -> dict[str, Any]:
    """Create and validate a canonical release manifest value."""
    value: dict[str, Any] = {
        "schema_version": 1,
        "package": "agent-workflow-quality",
        "version": version,
        "source": source,
        "builder": builder,
        "registries": registries,
        "artifacts": sorted(artifacts, key=lambda item: str(item["name"])),
    }
    return validate_manifest(value)


def _wheel_version(path: Path) -> str:
    try:
        with zipfile.ZipFile(path) as archive:
            names = [
                item
                for item in archive.infolist()
                if PurePosixPath(item.filename).name == "METADATA"
                and PurePosixPath(item.filename).parent.name.endswith(".dist-info")
            ]
            if len(names) != 1 or names[0].file_size > MAX_MEMBER_BYTES:
                raise ReleaseError("wheel metadata is invalid")
            metadata = archive.read(names[0]).decode("utf-8")
    except (OSError, UnicodeError, zipfile.BadZipFile) as error:
        raise ReleaseError("wheel metadata is unreadable") from error
    fields: dict[str, list[str]] = {}
    for line in metadata.splitlines():
        name, separator, value = line.partition(": ")
        if separator and name in {"Name", "Version", "Requires-Dist"}:
            fields.setdefault(name, []).append(value)
    if fields.get("Name") != ["agent-workflow-quality"] or "Requires-Dist" in fields:
        raise ReleaseError("wheel package metadata is invalid")
    versions = fields.get("Version", [])
    if len(versions) != 1:
        raise ReleaseError("wheel version metadata is invalid")
    return versions[0]


def _sdist_version(path: Path) -> str:
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = [
                member
                for member in archive
                if PurePosixPath(member.name).name == "pyproject.toml"
                and len(PurePosixPath(member.name).parts) == 2
            ]
            if len(members) != 1 or not members[0].isfile() or members[0].size > MAX_MEMBER_BYTES:
                raise ReleaseError("source package metadata is invalid")
            stream = archive.extractfile(members[0])
            if stream is None:
                raise ReleaseError("source package metadata is unreadable")
            with stream:
                raw = stream.read(MAX_MEMBER_BYTES + 1)
            if len(raw) > MAX_MEMBER_BYTES:
                raise ReleaseError("source package metadata exceeds its bound")
            project = tomllib.loads(raw.decode("utf-8"))["project"]
    except (
        OSError,
        UnicodeError,
        KeyError,
        TypeError,
        tarfile.TarError,
        tomllib.TOMLDecodeError,
    ) as error:
        raise ReleaseError("source package metadata is unreadable") from error
    if not isinstance(project, dict) or project.get("name") != "agent-workflow-quality":
        raise ReleaseError("source package metadata is invalid")
    version = project.get("version")
    if not isinstance(version, str):
        raise ReleaseError("source package version is invalid")
    return version


def _verify_artifact(
    bundle: Path,
    item: dict[str, Any],
    version: str,
    source_date_epoch: int,
) -> dict[str, object]:
    name = str(item["name"])
    path = bundle / name
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size != item["size"]
        or sha256_file(path) != item["sha256"]
    ):
        raise ReleaseError(f"artifact {name} does not match the manifest")
    kind = str(item["kind"])
    if kind in {"wheel", "sdist"}:
        try:
            issues = inspect_archive(
                path,
                source_date_epoch=source_date_epoch,
                require_sbom_assets=tuple(int(part) for part in version.split(".")) >= (0, 14, 0),
                require_provenance_assets=tuple(int(part) for part in version.split("."))
                >= (0, 15, 0),
                require_promotion_assets=tuple(int(part) for part in version.split("."))
                >= (0, 16, 0),
                require_formal_assets=tuple(int(part) for part in version.split(".")) >= (0, 17, 0),
                require_lifecycle_assets=tuple(int(part) for part in version.split("."))
                >= (0, 18, 0),
                require_refinement_assets=tuple(int(part) for part in version.split("."))
                >= (0, 19, 0),
                require_python_refactor_assets=tuple(int(part) for part in version.split("."))
                >= (0, 20, 0),
                require_adversarial_assets=tuple(int(part) for part in version.split("."))
                >= (0, 21, 0),
                require_reliability_assets=tuple(int(part) for part in version.split("."))
                >= (0, 22, 0),
                require_onboarding_assets=tuple(int(part) for part in version.split("."))
                >= (0, 23, 0),
                require_contract_catalog_assets=tuple(int(part) for part in version.split("."))
                >= (0, 30, 0),
                require_test_report_assets=tuple(int(part) for part in version.split("."))
                >= (0, 31, 0),
            )
        except DistributionError as error:
            raise ReleaseError(f"artifact {name} is not a valid distribution") from error
        if issues:
            raise ReleaseError(f"artifact {name} fails bounded archive verification")
        observed = _wheel_version(path) if kind == "wheel" else _sdist_version(path)
        if observed != version:
            raise ReleaseError(f"artifact {name} has the wrong package version")
    return {
        "name": name,
        "kind": kind,
        "sha256": item["sha256"],
        "size": item["size"],
    }


def _verify_sbom_bundle(bundle: Path, manifest: dict[str, Any], source: Path | None = None) -> None:
    from awq.sbom import MAX_BYTES, archive_inputs, source_inputs, verify

    records = {item["kind"]: item for item in manifest["artifacts"]}
    path = bundle / records["sbom"]["name"]
    if path.stat().st_size > MAX_BYTES:
        raise ReleaseError("SBOM exceeds its byte bound")
    inputs = archive_inputs(bundle / records["sdist"]["name"], manifest["version"])
    verify(path.read_bytes(), inputs, manifest)
    if source is not None and source_inputs(source) != inputs:
        raise ReleaseError("SBOM source inputs differ from the checked source")


def _verified_sidecars(
    manifest_path: Path, manifest: dict[str, Any], source: Path | None
) -> set[str]:
    bundle = manifest_path.parent
    declared: set[str] = set()
    if manifest["schema_version"] == 3:
        from awq.provenance import verify
        from awq.trust import read_file

        declared.add(manifest["provenance"]["name"])
        verify(bundle, manifest, source)
        signature = manifest_path.with_name(manifest_path.name + ".sig")
        if signature.exists() or signature.is_symlink():
            if not read_file(signature, 8192):
                raise ReleaseError("release signature sidecar is empty")
            declared.add(signature.name)
    return declared


def verify_release(manifest_path: Path, source: Path | None = None) -> dict[str, Any]:
    """Verify a complete local release bundle and optional source tree offline."""
    manifest = load_manifest(manifest_path)
    if tuple(int(part) for part in manifest["version"].split(".")) >= (0, 14, 0) and manifest[
        "schema_version"
    ] not in {2, 3}:
        raise ReleaseError("this release requires an SPDX SBOM")
    if (
        tuple(int(part) for part in manifest["version"].split(".")) >= (0, 15, 0)
        and manifest["schema_version"] != 3
    ):
        raise ReleaseError("this release requires signed-update provenance")
    bundle = manifest_path.parent
    if bundle.is_symlink() or not bundle.is_dir():
        raise ReleaseError("release bundle is unavailable")
    declared = {manifest_path.name, *(str(item["name"]) for item in manifest["artifacts"])}
    source_date_epoch = int(manifest["source"]["source_date_epoch"])
    results = [
        _verify_artifact(
            bundle,
            item,
            str(manifest["version"]),
            source_date_epoch,
        )
        for item in manifest["artifacts"]
    ]
    if manifest["schema_version"] in {2, 3}:
        _verify_sbom_bundle(bundle, manifest, source)
    declared |= _verified_sidecars(manifest_path, manifest, source)
    entries = list(bundle.iterdir())
    if len(entries) > MAX_ARTIFACTS + 1 or {entry.name for entry in entries} != declared:
        raise ReleaseError("release bundle contains undeclared entries")
    if source is not None:
        if source_identity(source) != manifest["source"]:
            raise ReleaseError("release source identity does not match")
        if registry_digests(source) != manifest["registries"]:
            raise ReleaseError("release registry bindings do not match")
        if build_constraints_digest(source) != manifest["builder"]["build_constraints_sha256"]:
            raise ReleaseError("release build constraints do not match")
    return {
        "status": "pass",
        "schema_version": manifest["schema_version"],
        "version": manifest["version"],
        "source_commit": manifest["source"]["commit"],
        "manifest_sha256": sha256_file(manifest_path),
        "authentication": "not-checked",
        "artifacts": results,
    }
