# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Authenticated, monotonic, data-only updates with one atomic consumer-lock mutation."""

from __future__ import annotations

import difflib
import hashlib
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any

from awq.candidate import candidate_lock
from awq.project import ProjectError, load_project
from awq.registry import RegistryError, canonical_bytes
from awq.release import ReleaseError, validate_manifest, verify_release
from awq.sbom import strict_json
from awq.trust import (
    authenticate,
    digest,
    load_policy,
    read_file,
    transition,
    validate_receipt,
    verify_tag,
)


def version_tuple(value: object) -> tuple[int, ...]:
    """Require a canonical numeric release version, never a mutable channel."""
    if not isinstance(value, str) or not re.fullmatch(
        r"(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})", value
    ):
        raise ReleaseError("update requires a canonical immutable release version")
    return tuple(int(part) for part in value.split("."))


def _directory(path: Path) -> Path:
    try:
        if not path.is_absolute() or path.resolve(strict=True) != path or not path.is_dir():
            raise ReleaseError("verification directory is unsafe")
    except OSError as error:
        raise ReleaseError("verification directory is unavailable") from error
    return path


def authenticated_release(
    manifest_path: Path,
    policy_path: Path,
    source: Path,
    tag: str,
    tag_object: str,
    *,
    consumer: Path | None = None,
    receipt: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Authenticate old authority before accepting a manifest-bound candidate policy."""
    _directory(source)
    bundle = _directory(manifest_path.parent)
    excluded = (source, bundle) if consumer is None else (source, bundle, consumer)
    new_policy = load_policy(policy_path, excluded)
    raw = read_file(manifest_path)
    manifest = validate_manifest(strict_json(raw))
    if manifest["schema_version"] != 3:
        raise ReleaseError("authenticated updates require manifest v3 provenance")
    old_policy = new_policy
    if receipt is not None:
        validate_receipt(receipt)
        old_policy = receipt["trust_policy"]
    elif new_policy["generation"] != 1:
        raise ReleaseError("bootstrap requires an independently provisioned generation-1 policy")
    signature = read_file(manifest_path.with_name(manifest_path.name + ".sig"), 8192)
    signer = authenticate(raw, signature, old_policy)
    if manifest["trust_policy_sha256"] != digest(new_policy):
        raise ReleaseError("signed manifest does not bind the candidate trust policy")
    transition(old_policy, new_policy, signer)
    verify_tag(source, tag, tag_object, manifest, signer)
    verify_release(manifest_path, source)
    if read_file(manifest_path) != raw:
        raise ReleaseError("release manifest changed during verification")
    result = {
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "source_commit": manifest["source"]["commit"],
        "tag_object": tag_object,
        "policy_sha256": digest(new_policy),
        "policy_generation": new_policy["generation"],
        "signer": signer["principal"],
        "signer_fingerprint": signer["fingerprint"],
        "trust_policy": new_policy,
        "provenance_sha256": manifest["provenance"]["sha256"],
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
        "tag_ref": tag,
    }
    validate_receipt(result)
    return manifest, result


def verify(
    manifest: Path,
    policy: Path,
    source: Path,
    tag: str,
    tag_object: str,
) -> dict[str, Any]:
    """Verify a bootstrap release offline; no hosted-attestation or SLSA-level claim."""
    release, receipt = authenticated_release(manifest, policy, source, tag, tag_object)
    return {
        "status": "pass",
        "version": release["version"],
        "authentication": "external-ssh-policy",
        "receipt": receipt,
        "slsa_level": None,
        "hosted_attestation_verified": False,
    }


def _replace(path: Path, expected: bytes, updated: bytes, policy: Path, policy_bytes: bytes) -> str:
    """Stage bytes on the same filesystem; the replace is the sole success commit point."""
    descriptor, name = tempfile.mkstemp(prefix=".awq-update-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(updated)
            stream.flush()
            os.fchmod(stream.fileno(), stat.S_IMODE(path.stat().st_mode))
            os.fsync(stream.fileno())
        if read_file(path) != expected or read_file(policy) != policy_bytes:
            raise ReleaseError("consumer files changed during verified update")
        temporary.replace(path)
        try:
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            return "unconfirmed"
        return "confirmed"
    finally:
        temporary.unlink(missing_ok=True)


def _update_locked(
    root: Path,
    target: str,
    dry_run: bool,
    manifest: Path,
    trust_policy: Path,
    source: Path,
    tag: str,
    tag_object: str,
) -> dict[str, Any]:
    policy_path, lock_path = root / "quality/awq.json", root / "quality/awq.lock.json"
    policy_bytes, original = read_file(policy_path), read_file(lock_path)
    policy, old = load_project(root)
    if version_tuple(target) <= version_tuple(old["awq_version"]):
        raise ReleaseError("update rejects release rollback or replay")
    release, receipt = authenticated_release(
        manifest,
        trust_policy,
        source,
        tag,
        tag_object,
        consumer=root,
        receipt=old.get("receipt"),
    )
    if release["version"] != target:
        raise ReleaseError("authenticated release differs from the exact update target")
    new = candidate_lock(source, target, policy["profiles"], release["registries"])
    new["receipt"] = receipt
    updated = canonical_bytes(new)
    if len(updated) > 256_000:
        raise ReleaseError("updated lock exceeds its byte bound")
    if read_file(policy_path) != policy_bytes or read_file(lock_path) != original:
        raise ReleaseError("consumer files changed during verified update")
    result = {
        "status": "ok",
        "dry_run": dry_run,
        "changed": original != updated,
        "committed": False,
        "durability": "not-applicable",
        "from": old["awq_version"],
        "to": target,
        "before_sha256": hashlib.sha256(original).hexdigest(),
        "after_sha256": hashlib.sha256(updated).hexdigest(),
        "lock_diff": list(
            difflib.unified_diff(
                original.decode("utf-8").splitlines(True),
                updated.decode("utf-8").splitlines(True),
                fromfile="quality/awq.lock.json",
                tofile="quality/awq.lock.json",
            )
        ),
        "receipt": receipt,
    }
    if not dry_run:
        result["durability"] = _replace(lock_path, original, updated, policy_path, policy_bytes)
        result["committed"] = True
    return result


def update(
    root: Path,
    target: str,
    dry_run: bool,
    manifest: Path,
    trust_policy: Path,
    source: Path,
    tag: str,
    tag_object: str,
) -> dict[str, Any]:
    """Require all local evidence for both dry-run and write; never execute candidate code."""
    if os.name != "posix":
        raise ReleaseError("verified lock updates require the reviewed POSIX host")
    import fcntl

    directory = _directory(_directory(root) / "quality")
    try:
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as error:
        raise ReleaseError("consumer update directory is unavailable") from error
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ReleaseError("another verified update owns the consumer directory") from error
        return _update_locked(
            root, target, dry_run, manifest, trust_policy, source, tag, tag_object
        )
    except (OSError, ProjectError, RegistryError) as error:
        raise ReleaseError("verified lock update failed before publication") from error
    finally:
        os.close(descriptor)
