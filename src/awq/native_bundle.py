# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Bounded offline native-package and runtime-bundle assurance."""

from __future__ import annotations

import hashlib
import re
import stat
import tarfile
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, cast

from awq import __version__, project
from awq.registry import canonical_bytes
from awq.release import MAX_MEMBER_BYTES, MAX_MEMBERS, MAX_TOTAL_BYTES, PRIVATE_CONTENT
from awq.sbom import strict_json
from awq.trust import read_file

HASH = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){1,7}$")
TOKEN = re.compile(r"^[a-z0-9][a-z0-9.+_-]{0,99}$")
TARGET = re.compile(r"^[a-z0-9_]+(?:-[a-z0-9_]+){2,5}$")
REPOSITORY = re.compile(r"^https://github[.]com/[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
LIMITATIONS = (
    "Native bundle verification is not an execution sandbox or authorization to run binaries.",
    "ELF observations are bounded to the declared policy, target and pinned offline tools.",
    "External signer policy authenticates authority; structural signature binding alone does not.",
)
NON_CLAIMS = ("execution-safety", "feature-completeness", "malware-absence", "runtime-portability")


def _fail(code: str) -> NoReturn:
    raise project.ProjectError("native bundle invalid: " + code)


def _object(value: Any, fields: str, code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(fields.split()):
        _fail(code)
    return cast(dict[str, Any], value)


def _digest(value: object, code: str = "digest") -> str:
    if not isinstance(value, str) or HASH.fullmatch(value) is None:
        _fail(code)
    return value


def _identifier(value: object, prefix: str, code: str) -> str:
    if (
        not isinstance(value, str)
        or IDENTIFIER.fullmatch(value) is None
        or not value.startswith(prefix + "-")
    ):
        _fail(code)
    return value


def _integer(value: object, low: int, high: int, code: str) -> int:
    if type(value) is not int or not low <= value <= high:
        _fail(code)
    return value


def _path(value: object, code: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        _fail(code)
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or ".." in parsed.parts or parsed.as_posix() != value:
        _fail(code)
    return value


def _sorted_strings(
    value: object, pattern: re.Pattern[str], low: int, high: int, code: str
) -> list[str]:
    if not isinstance(value, list) or not low <= len(value) <= high:
        _fail(code)
    result = []
    for item in value:
        if not isinstance(item, str) or pattern.fullmatch(item) is None:
            _fail(code)
        result.append(item)
    if result != sorted(set(result)):
        _fail(code)
    return result


def _tool_identity(value: object, label: str) -> dict[str, str]:
    item = _object(value, "id version sha256 output_sha256", label)
    _identifier(item["id"], "TOOL", label)
    if not isinstance(item["version"], str) or TOKEN.fullmatch(item["version"]) is None:
        _fail(label)
    _digest(item["sha256"], label)
    _digest(item["output_sha256"], label)
    return item


def _elf(value: object, policy: dict[str, Any], size: int) -> dict[str, Any]:
    item = _object(
        value,
        "class machine architecture dynamic_dependencies hardening executable_stack "
        "text_relocations features strings symbols max_alignment readelf_sha256 nm_sha256 "
        "observation_sha256 readelf_tool nm_tool",
        "elf-fields",
    )
    dependencies = _sorted_strings(item["dynamic_dependencies"], TOKEN, 0, 128, "elf-dependencies")
    hardening = _sorted_strings(item["hardening"], TOKEN, 0, 32, "elf-hardening")
    features = _sorted_strings(item["features"], TOKEN, 0, 64, "elf-features")
    strings = _sorted_strings(item["strings"], TOKEN, 0, 128, "elf-strings")
    symbols = _sorted_strings(item["symbols"], TOKEN, 0, 256, "elf-symbols")
    if (
        item["class"] not in policy["classes"]
        or item["machine"] not in policy["machines"]
        or item["architecture"] not in policy["architectures"]
        or not set(dependencies) <= set(policy["allowed_dynamic_dependencies"])
        or not set(policy["required_hardening"]) <= set(hardening)
        or item["executable_stack"] is not False
        or item["text_relocations"] is not False
        or set(features) & set(policy["forbidden_features"])
        or set(strings) & set(policy["forbidden_strings"])
        or not set(policy["required_symbols"]) <= set(symbols)
        or _integer(item["max_alignment"], 1, policy["max_alignment"], "elf-alignment")
        != item["max_alignment"]
        or size > policy["max_size"]
    ):
        _fail("elf-policy")
    for field in ("readelf_sha256", "nm_sha256", "observation_sha256"):
        _digest(item[field], "elf-evidence")
    _tool_identity(item["readelf_tool"], "readelf-tool")
    _tool_identity(item["nm_tool"], "nm-tool")
    return item


def _elf_policy(value: object) -> dict[str, Any] | None:
    if value is None:
        return None
    item = _object(
        value,
        "architectures classes machines allowed_dynamic_dependencies required_hardening "
        "forbidden_features forbidden_strings required_symbols max_alignment max_size",
        "elf-policy-fields",
    )
    for field in (
        "architectures",
        "classes",
        "machines",
        "allowed_dynamic_dependencies",
        "required_hardening",
        "forbidden_features",
        "forbidden_strings",
        "required_symbols",
    ):
        item[field] = _sorted_strings(
            item[field], TOKEN, 0 if "forbidden" in field else 1, 128, "elf-policy"
        )
    item["max_alignment"] = _integer(item["max_alignment"], 1, 1 << 30, "elf-policy")
    item["max_size"] = _integer(item["max_size"], 1, MAX_MEMBER_BYTES, "elf-policy")
    return item


def _archive_members(  # noqa: C901 - archive kinds share one strict result contract.
    path: Path, archive_format: str, epoch: int
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    total = 0
    try:
        if archive_format == "tar-gzip":
            with tarfile.open(path, "r:gz") as archive:
                tar_members = archive.getmembers()
                if len(tar_members) > MAX_MEMBERS:
                    _fail("archive-member-bound")
                for tar_member in tar_members:
                    if not tar_member.isfile() or tar_member.issym() or tar_member.islnk():
                        _fail("archive-member-kind")
                    if (
                        tar_member.mtime != epoch
                        or tar_member.uid != 0
                        or tar_member.gid != 0
                        or tar_member.uname
                        or tar_member.gname
                        or tar_member.pax_headers
                    ):
                        _fail("archive-metadata")
                    stream = archive.extractfile(tar_member)
                    if stream is None:
                        _fail("archive-member-kind")
                    content = stream.read(MAX_MEMBER_BYTES + 1)
                    result.append(
                        {
                            "path": tar_member.name,
                            "mode": tar_member.mode,
                            "size": tar_member.size,
                            "content": content,
                        }
                    )
        elif archive_format == "zip":
            with zipfile.ZipFile(path) as archive:
                zip_members = archive.infolist()
                if len(zip_members) > MAX_MEMBERS:
                    _fail("archive-member-bound")
                for zip_member in zip_members:
                    mode = zip_member.external_attr >> 16
                    if zip_member.is_dir() or stat.S_IFMT(mode) not in {0, stat.S_IFREG}:
                        _fail("archive-member-kind")
                    expected = time.gmtime(epoch)
                    stamp = (
                        expected.tm_year,
                        expected.tm_mon,
                        expected.tm_mday,
                        expected.tm_hour,
                        expected.tm_min,
                        expected.tm_sec - expected.tm_sec % 2,
                    )
                    if zip_member.date_time != stamp or zip_member.extra or zip_member.comment:
                        _fail("archive-metadata")
                    result.append(
                        {
                            "path": zip_member.filename,
                            "mode": stat.S_IMODE(mode),
                            "size": zip_member.file_size,
                            "content": archive.read(zip_member),
                        }
                    )
        else:
            _fail("archive-format")
    except (OSError, tarfile.TarError, zipfile.BadZipFile):
        _fail("archive-unavailable")
    names: list[str] = []
    for result_member in result:
        name = _path(result_member["path"], "archive-path")
        content = result_member.pop("content")
        if len(content) != result_member["size"] or len(content) > MAX_MEMBER_BYTES:
            _fail("archive-member-bound")
        total += len(content)
        if total > MAX_TOTAL_BYTES or any(pattern.search(content) for pattern in PRIVATE_CONTENT):
            _fail("archive-content")
        names.append(name)
        result_member["sha256"] = hashlib.sha256(content).hexdigest()
    if names != sorted(set(names)):
        _fail("archive-order-or-duplicate")
    return result


def _regular(root: Path, relative: str, digest: str, size: int) -> Path:
    path = root / _path(relative, "file-path")
    if (
        path.is_symlink()
        or not path.is_file()
        or (
            path.resolve(strict=True).parent != root.resolve(strict=True)
            and root.resolve(strict=True) not in path.resolve(strict=True).parents
        )
    ):
        _fail("file-unavailable")
    raw = read_file(path, MAX_TOTAL_BYTES)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        _fail("file-integrity")
    return path


def evaluate(root: Path, value: Any) -> dict[str, Any]:  # noqa: C901
    item = _object(
        value,
        "schema_version kind source toolchain target elf_policy packages signer_policy "
        "signatures rebuild limitations non_claims",
        "fields",
    )
    if item["schema_version"] != 1 or item["kind"] != "native-bundle-assurance":
        _fail("identity")
    source = _object(item["source"], "repository commit tree archive_sha256", "source-fields")
    if (
        not isinstance(source["repository"], str)
        or REPOSITORY.fullmatch(source["repository"]) is None
    ):
        _fail("source-repository")
    for field in ("commit", "tree"):
        if (
            not isinstance(source[field], str)
            or re.fullmatch(r"[0-9a-f]{40}", source[field]) is None
        ):
            _fail("source-identity")
    _digest(source["archive_sha256"], "source-identity")
    toolchain = _object(item["toolchain"], "id version sha256", "toolchain-fields")
    _identifier(toolchain["id"], "TOOLCHAIN", "toolchain")
    if not isinstance(toolchain["version"], str) or TOKEN.fullmatch(toolchain["version"]) is None:
        _fail("toolchain")
    _digest(toolchain["sha256"], "toolchain")
    if not isinstance(item["target"], str) or TARGET.fullmatch(item["target"]) is None:
        _fail("target")
    elf_policy = _elf_policy(item["elf_policy"])
    signer = _object(item["signer_policy"], "id sha256", "signer-policy")
    _identifier(signer["id"], "SIGNER", "signer-policy")
    _digest(signer["sha256"], "signer-policy")

    packages = item["packages"]
    if not isinstance(packages, list) or not 1 <= len(packages) <= 16:
        _fail("package-bound")
    package_ids: list[str] = []
    package_digests: dict[str, str] = {}
    manifest_digests: dict[str, str] = {}
    file_count = 0
    for raw in packages:
        package = _object(
            raw, "id kind archive normalized_timestamp inventory notices", "package-fields"
        )
        identifier = _identifier(package["id"], "PACKAGE", "package-id")
        if package["kind"] not in {"native-package", "runtime-bundle"}:
            _fail("package-kind")
        archive = _object(package["archive"], "path format size sha256", "archive-fields")
        archive_digest = _digest(archive["sha256"], "archive-digest")
        archive_path = _regular(
            root,
            archive["path"],
            archive_digest,
            _integer(archive["size"], 1, MAX_TOTAL_BYTES, "archive-size"),
        )
        timestamp = _integer(package["normalized_timestamp"], 315532800, 4102444800, "timestamp")
        observed = _archive_members(archive_path, archive["format"], timestamp)
        inventory = package["inventory"]
        if not isinstance(inventory, list) or not 1 <= len(inventory) <= MAX_MEMBERS:
            _fail("inventory-bound")
        normalized = []
        paths: list[str] = []
        for record in inventory:
            entry = _object(
                record, "path mode size sha256 target license_id kind elf", "inventory-fields"
            )
            path = _path(entry["path"], "inventory-path")
            mode = _integer(entry["mode"], 0, 0o7777, "inventory-mode")
            size = _integer(entry["size"], 0, MAX_MEMBER_BYTES, "inventory-size")
            _digest(entry["sha256"], "inventory-digest")
            if entry["target"] != item["target"] or entry["kind"] not in {
                "data",
                "executable",
                "license",
                "notice",
            }:
                _fail("inventory-classification")
            _identifier(entry["license_id"], "LICENSE", "inventory-license")
            if (entry["kind"] == "executable") != (entry["elf"] is not None):
                _fail("inventory-elf")
            if entry["elf"] is not None:
                if elf_policy is None:
                    _fail("inventory-elf")
                _elf(entry["elf"], elf_policy, size)
            normalized.append({"path": path, "mode": mode, "size": size, "sha256": entry["sha256"]})
            paths.append(path)
        if paths != sorted(set(paths)) or normalized != observed:
            _fail("inventory-completeness")
        notices = [_path(path, "notice-path") for path in package["notices"]]
        kinds = {entry["path"]: entry["kind"] for entry in inventory}
        if (
            notices != sorted(set(notices))
            or not notices
            or any(kinds.get(path) not in {"license", "notice"} for path in notices)
        ):
            _fail("notice-coverage")
        package_ids.append(identifier)
        package_digests[identifier] = archive_digest
        manifest_digests[identifier] = hashlib.sha256(canonical_bytes(inventory)).hexdigest()
        file_count += len(inventory)
    if package_ids != sorted(set(package_ids)):
        _fail("package-order-or-duplicate")

    signatures = item["signatures"]
    if not isinstance(signatures, list) or len(signatures) != len(packages):
        _fail("signature-coverage")
    signed_ids: list[str] = []
    for raw in signatures:
        signature = _object(
            raw,
            "package_id path size sha256 artifact_sha256 signer_id signer_policy_sha256",
            "signature-fields",
        )
        package_id = _identifier(signature["package_id"], "PACKAGE", "signature-package")
        digest = _digest(signature["sha256"], "signature-digest")
        _regular(
            root, signature["path"], digest, _integer(signature["size"], 1, 8192, "signature-size")
        )
        if (
            signature["artifact_sha256"] != package_digests.get(package_id)
            or signature["signer_id"] != signer["id"]
            or signature["signer_policy_sha256"] != signer["sha256"]
        ):
            _fail("signature-binding")
        signed_ids.append(package_id)
    if signed_ids != package_ids:
        _fail("signature-coverage")

    rebuild = item["rebuild"]
    if not isinstance(rebuild, list) or len(rebuild) != len(packages):
        _fail("rebuild-coverage")
    rebuilt_ids: list[str] = []
    for raw in rebuild:
        record = _object(
            raw, "package_id first_sha256 second_sha256 manifest_sha256", "rebuild-fields"
        )
        package_id = _identifier(record["package_id"], "PACKAGE", "rebuild-package")
        first, second = _digest(record["first_sha256"]), _digest(record["second_sha256"])
        if (
            first != second
            or first != package_digests.get(package_id)
            or record["manifest_sha256"] != manifest_digests.get(package_id)
        ):
            _fail("rebuild-mismatch")
        rebuilt_ids.append(package_id)
    if rebuilt_ids != package_ids:
        _fail("rebuild-coverage")
    if tuple(item["limitations"]) != LIMITATIONS or tuple(item["non_claims"]) != NON_CLAIMS:
        _fail("claims")
    return {
        "schema_version": 1,
        "kind": "native-bundle-assurance-result",
        "status": "pass",
        "awq_version": __version__,
        "target": item["target"],
        "package_count": len(packages),
        "file_count": file_count,
        "source_sha256": source["archive_sha256"],
        "toolchain_sha256": toolchain["sha256"],
        "signer_policy_sha256": signer["sha256"],
        "manifest_sha256": hashlib.sha256(canonical_bytes(value)).hexdigest(),
        "limitations": list(LIMITATIONS),
        "non_claims": list(NON_CLAIMS),
    }


def evaluate_file(root: Path, relative: str) -> dict[str, Any]:
    path = project.confined_path(root, relative)
    try:
        raw = read_file(path, 2_000_000)
        value = strict_json(raw)
        if canonical_bytes(value) != raw:
            _fail("canonical-json")
        return evaluate(root, value)
    except (OSError, ValueError):
        _fail("input")
