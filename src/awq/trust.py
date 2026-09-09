# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Independently provisioned SSH trust roots and bounded offline authentication."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import signal
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from awq.registry import canonical_bytes
from awq.release import ReleaseError
from awq.sbom import strict_json

MAX_BYTES = 256_000
MAX_ROOTS = 8
TIMEOUT = 30
SHA = re.compile(r"[a-f0-9]{64}")
OID = re.compile(r"[a-f0-9]{40}")
PRINCIPAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@+-]{0,127}")
POLICY_KEYS = {
    "repository",
    "schema_version",
    "generation",
    "previous_policy_sha256",
    "roots",
    "retired",
}
ROOT_KEYS = {"principal", "public_key", "fingerprint", "valid_after", "valid_until"}
RECEIPT_KEYS = {
    "manifest_sha256",
    "source_commit",
    "tag_object",
    "policy_sha256",
    "policy_generation",
    "signer",
    "signer_fingerprint",
    "trust_policy",
    "provenance_sha256",
    "signature_sha256",
    "tag_ref",
}


def read_file(path: Path, bound: int = MAX_BYTES) -> bytes:
    """Read a bounded regular canonical path, rejecting every symlink component."""
    try:
        if not path.is_absolute() or path.resolve(strict=True) != path or not path.is_file():
            raise ReleaseError("verification input path is unsafe")
        with path.open("rb") as stream:
            raw = stream.read(bound + 1)
        if len(raw) > bound:
            raise ReleaseError("verification input exceeds its byte bound")
        return raw
    except OSError as error:
        raise ReleaseError("verification input is unavailable") from error


def digest(value: object) -> str:
    """Hash the exact canonical public document."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value):
        raise ReleaseError("trust validity timestamp is invalid")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReleaseError("trust validity timestamp is invalid") from error


def fingerprint(key: object) -> str:
    """Accept only a canonical bare Ed25519 key, without options or comments."""
    if not isinstance(key, str) or not key.startswith("ssh-ed25519 "):
        raise ReleaseError("trust key is not a canonical Ed25519 key")
    try:
        blob = base64.b64decode(key[12:], validate=True)
    except (ValueError, binascii.Error) as error:
        raise ReleaseError("trust key encoding is invalid") from error
    prefix = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
    if (
        len(blob) != 51
        or not blob.startswith(prefix)
        or base64.b64encode(blob).decode() != key[12:]
    ):
        raise ReleaseError("trust key wire format is invalid")
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _root(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != ROOT_KEYS:
        raise ReleaseError("trust root has unknown or missing fields")
    principal = value["principal"]
    if not isinstance(principal, str) or not PRINCIPAL.fullmatch(principal):
        raise ReleaseError("trust principal is invalid")
    if fingerprint(value["public_key"]) != value["fingerprint"]:
        raise ReleaseError("trust fingerprint does not match its key")
    if _timestamp(value["valid_after"]) >= _timestamp(value["valid_until"]):
        raise ReleaseError("trust validity interval is invalid")
    return value


def validate_policy(value: object) -> dict[str, Any]:
    """Validate an exact, bounded trust policy without trusting its provenance."""
    if (
        not isinstance(value, dict)
        or set(value) != POLICY_KEYS
        or type(value["schema_version"]) is not int
    ):
        raise ReleaseError("trust policy has unknown or missing fields")
    if value["repository"] != "https://github.com/martin-beck/agent-workflow-quality":
        raise ReleaseError("trust policy repository is invalid")
    if (
        value["schema_version"] != 1
        or type(value["generation"]) is not int
        or not 1 <= value["generation"] <= 1000
    ):
        raise ReleaseError("trust policy generation is invalid")
    previous = value["previous_policy_sha256"]
    if (value["generation"] == 1 and previous is not None) or (
        value["generation"] != 1 and (not isinstance(previous, str) or not SHA.fullmatch(previous))
    ):
        raise ReleaseError("trust policy chain is invalid")
    roots = value["roots"]
    if not isinstance(roots, list) or not 1 <= len(roots) <= MAX_ROOTS:
        raise ReleaseError("trust policy requires bounded nonempty roots")
    checked = [_root(item) for item in roots]
    identities = [item["fingerprint"] for item in checked]
    retired = value["retired"]
    if (
        identities != sorted(set(identities))
        or not isinstance(retired, list)
        or len(retired) > 1000
        or not all(
            isinstance(item, str) and re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", item)
            for item in retired
        )
        or retired != sorted(set(retired))
        or set(retired).intersection(identities)
    ):
        raise ReleaseError("trust root identities conflict")
    return value


def load_policy(path: Path, excluded: tuple[Path, ...]) -> dict[str, Any]:
    """Require an external policy; independent provisioning remains an operator duty."""
    raw = read_file(path)
    if any(path.is_relative_to(root.resolve(strict=True)) for root in excluded):
        raise ReleaseError(
            "trust policy must be independently provisioned outside candidate and consumer"
        )
    return validate_policy(strict_json(raw))


def active(root: dict[str, Any]) -> bool:
    """Evaluate key validity at verification time, never caller-supplied release time."""
    return _timestamp(root["valid_after"]) <= datetime.now(UTC) < _timestamp(root["valid_until"])


def transition(old: dict[str, Any], new: dict[str, Any], signer: dict[str, Any]) -> None:
    """Require exact chained add-overlap-retire transitions authenticated by an old key."""
    validate_policy(old)
    validate_policy(new)
    if old == new:
        if signer not in old["roots"] or not active(signer):
            raise ReleaseError("release signer is not active")
        return
    if new["generation"] != old["generation"] + 1 or new["previous_policy_sha256"] != digest(old):
        raise ReleaseError("trust rotation is not the exact next chained generation")
    before = {item["fingerprint"]: item for item in old["roots"]}
    after = {item["fingerprint"]: item for item in new["roots"]}
    added, removed = after.keys() - before.keys(), before.keys() - after.keys()
    overlap = before.keys() & after.keys()
    if (
        not overlap
        or (added and removed)
        or (not added and not removed)
        or any(before[key] != after[key] for key in overlap)
        or new["retired"] != sorted(set(old["retired"]) | removed)
        or set(old["retired"]).intersection(after)
        or signer not in old["roots"]
        or signer not in new["roots"]
        or not active(signer)
    ):
        raise ReleaseError("trust rotation lacks an authorized unchanged active overlap")


def validate_receipt(value: object) -> dict[str, Any]:
    """Validate the lock's authenticated rollback anchor."""
    if not isinstance(value, dict) or set(value) != RECEIPT_KEYS:
        raise ReleaseError("update receipt has unknown or missing fields")
    for key in ("manifest_sha256", "policy_sha256", "provenance_sha256", "signature_sha256"):
        if not isinstance(value[key], str) or not SHA.fullmatch(value[key]):
            raise ReleaseError("update receipt digest is invalid")
    for key in ("source_commit", "tag_object"):
        if not isinstance(value[key], str) or not OID.fullmatch(value[key]):
            raise ReleaseError("update receipt object is invalid")
    if type(value["policy_generation"]) is not int or not 1 <= value["policy_generation"] <= 1000:
        raise ReleaseError("update receipt generation is invalid")
    if not isinstance(value["signer"], str) or not PRINCIPAL.fullmatch(value["signer"]):
        raise ReleaseError("update receipt signer is invalid")
    if not isinstance(value["signer_fingerprint"], str) or not re.fullmatch(
        r"SHA256:[A-Za-z0-9+/]{43}", value["signer_fingerprint"]
    ):
        raise ReleaseError("update receipt fingerprint is invalid")
    _receipt_anchor(value)
    return value


def _receipt_anchor(value: dict[str, Any]) -> None:
    if not isinstance(value["tag_ref"], str) or not re.fullmatch(
        r"refs/tags/v[0-9]+\.[0-9]+\.[0-9]+", value["tag_ref"]
    ):
        raise ReleaseError("update receipt tag reference is invalid")
    policy = validate_policy(value["trust_policy"])
    if (
        digest(policy) != value["policy_sha256"]
        or policy["generation"] != value["policy_generation"]
    ):
        raise ReleaseError("update receipt policy anchor differs")
    if not any(
        item["principal"] == value["signer"] and item["fingerprint"] == value["signer_fingerprint"]
        for item in policy["roots"]
    ):
        raise ReleaseError("update receipt signer is not in its authenticated policy")


def _limits() -> None:
    import resource

    resource.setrlimit(resource.RLIMIT_FSIZE, (1_000_000, 1_000_000))
    resource.setrlimit(resource.RLIMIT_CPU, (TIMEOUT, TIMEOUT))


def run(argv: list[str], data: bytes = b"") -> bytes:
    """Run an absolute reviewed verifier with no inherited credentials or diagnostics."""
    if os.name != "posix":
        raise ReleaseError("offline SSH verification requires the reviewed POSIX host")
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }
    with tempfile.TemporaryFile() as incoming, tempfile.TemporaryFile() as outgoing:
        incoming.write(data)
        incoming.seek(0)
        try:
            with subprocess.Popen(  # noqa: S603 - absolute fixed verifier argv; no shell.
                argv,
                stdin=incoming,
                stdout=outgoing,
                stderr=subprocess.DEVNULL,
                env=environment,
                start_new_session=True,
                preexec_fn=_limits,
            ) as process:
                try:
                    status = process.wait(timeout=TIMEOUT)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    raise ReleaseError("offline verification exceeded its deadline") from None
            outgoing.seek(0)
            output = outgoing.read(1_000_001)
            if status or len(output) > 1_000_000:
                raise ReleaseError("offline verification failed")
            return output
        except OSError as error:
            raise ReleaseError("offline verifier is unavailable") from error


def verify_signature(data: bytes, signature: bytes, root: dict[str, Any], namespace: str) -> None:
    """Authenticate bytes against one independently authorized root."""
    if not active(root) or len(signature) > 8192:
        raise ReleaseError("signature or signer is invalid")
    with tempfile.TemporaryDirectory(prefix="awq-trust-") as name:
        scratch = Path(name)
        allowed = scratch / "allowed"
        signed = scratch / "signature"
        allowed.write_text(f"{root['principal']} {root['public_key']}\n", encoding="ascii")
        signed.write_bytes(signature)
        run(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(allowed),
                "-I",
                root["principal"],
                "-n",
                namespace,
                "-s",
                str(signed),
            ],
            data,
        )


def authenticate(data: bytes, signature: bytes, policy: dict[str, Any]) -> dict[str, Any]:
    """Find an active authorized signer, never accepting candidate-only roots."""
    for root in policy["roots"]:
        if active(root):
            try:
                verify_signature(data, signature, root, "awq-release")
                return _root(root)
            except ReleaseError:
                continue
    raise ReleaseError("release signature is not authorized by the trusted policy")


def git(source: Path, *arguments: str) -> bytes:
    """Use only bounded Git plumbing, disabling machine and checkout helpers."""
    return run(
        [
            "/usr/bin/git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(source),
            *arguments,
        ]
    )


def verify_tag(
    source: Path, tag: str, tag_object: str, manifest: dict[str, Any], signer: dict[str, Any]
) -> None:
    """Verify an explicitly pinned annotated SSH tag without clone-local trust config."""
    if tag != f"refs/tags/v{manifest['version']}" or not OID.fullmatch(tag_object):
        raise ReleaseError("an exact release tag and full tag-object pin are required")
    if git(source, "rev-parse", "--verify", tag).decode("ascii").strip() != tag_object:
        raise ReleaseError("release tag moved or differs from the reviewed pin")
    raw = git(source, "cat-file", "tag", tag_object)
    marker = b"-----BEGIN SSH SIGNATURE-----\n"
    if raw.count(marker) != 1:
        raise ReleaseError("release tag is not SSH-signed annotated data")
    data, signature = raw.split(marker)
    prefix = (
        f"object {manifest['source']['commit']}\ntype commit\ntag v{manifest['version']}\ntagger "
    ).encode()
    if not data.startswith(prefix):
        raise ReleaseError("signed release tag target or name differs")
    verify_signature(data, marker + signature, signer, "git")
