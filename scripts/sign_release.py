# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Sign a reviewed AWQ manifest and create its matching SSH-signed tag.

This helper deliberately stops at local signing.  It never pushes a ref, uploads an
asset, or creates a GitHub release.  Private keys are only passed to the reviewed
SSH/Git commands and are never read by Python.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Any

MAX_OUTPUT = 4096
TIMEOUT = 30
ALLOWED_KEY_TYPES = frozenset(
    {"ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"}
)


class SigningError(ValueError):
    """A release signing precondition failed."""


def _terminate(process: subprocess.Popen[bytes]) -> None:
    """Terminate the bounded command and any child processes it spawned."""
    if process.poll() is not None:
        return
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    with contextlib.suppress(OSError):
        process.kill()
    with contextlib.suppress(OSError):
        process.wait()


def _run(  # noqa: C901 - bounded process lifecycle is intentionally explicit
    argv: list[str], *, cwd: Path | None = None
) -> tuple[int, bytes]:
    """Run a fixed argument vector with bounded, non-persistent output."""
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(  # noqa: S603 - argv is constructed as an explicit vector
            argv,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
        )
        if process.stdout is None:
            raise SigningError(f"{argv[0]} did not provide a readable output stream")
        fd = process.stdout.fileno()
        os.set_blocking(fd, False)
        output = bytearray()
        deadline = time.monotonic() + TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv[0], TIMEOUT)
            ready, _, _ = select.select([fd], [], [], remaining)
            if ready:
                chunk = os.read(fd, MAX_OUTPUT + 1 - len(output))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > MAX_OUTPUT:
                    raise SigningError(f"{argv[0]} produced too much output")
            elif process.poll() is not None:
                break
        return process.wait(timeout=1), bytes(output)
    except SigningError:
        if process is not None:
            _terminate(process)
        raise
    except (OSError, subprocess.TimeoutExpired) as error:
        if process is not None:
            _terminate(process)
        raise SigningError(f"command unavailable or timed out: {argv[0]}") from error
    finally:
        if process is not None and process.stdout is not None:
            process.stdout.close()


def _git(root: Path, *args: str) -> tuple[int, bytes]:
    return _run(["/usr/bin/git", *args], cwd=root)


def _require_clean_source(source: Path) -> str:
    code, output = _git(source, "status", "--porcelain=v1", "--untracked-files=all")
    if code or output:
        raise SigningError("source checkout must be clean (including untracked files)")
    code, output = _git(source, "rev-parse", "--verify", "HEAD")
    if code or len(output) > 64:
        raise SigningError("source HEAD is unavailable")
    commit = output.decode("ascii", errors="strict").strip()
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise SigningError("source HEAD is not an exact commit")
    return commit


def _version(source: Path) -> str:
    try:
        with (source / "pyproject.toml").open("rb") as stream:
            value = tomllib.load(stream)["project"]["version"]
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        raise SigningError("project version is unavailable") from error
    if (
        not isinstance(value, str)
        or not value
        or any(character not in "0123456789." for character in value)
    ):
        raise SigningError("project version is invalid")
    return value


def _manifest(bundle: Path, version: str) -> Path:
    expected = bundle / f"agent_workflow_quality-{version}.release.json"
    if not expected.is_file() or expected.is_symlink():
        raise SigningError(f"expected manifest is missing: {expected.name}")
    return expected


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _public_key(private_key: Path, public_key: Path) -> str:
    if private_key.is_symlink() or not private_key.is_file() or not os.access(private_key, os.R_OK):
        raise SigningError("dedicated release private key is unavailable")
    if public_key.exists() and (public_key.is_symlink() or not public_key.is_file()):
        raise SigningError("release public key must be a regular file")
    code, output = _run(["/usr/bin/ssh-keygen", "-y", "-f", str(private_key)])
    if code or len(output) > MAX_OUTPUT:
        raise SigningError("release private key cannot derive a public key")
    derived = output.decode("ascii", errors="strict").strip()
    if not derived:
        raise SigningError("release public key is empty")
    if public_key.exists():
        try:
            declared = public_key.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as error:
            raise SigningError("release public key is unreadable") from error
        declared_fields = declared.split()
        derived_fields = derived.split()
        if len(declared_fields) < 2 or declared_fields[:2] != derived_fields[:2]:
            raise SigningError("private and public release keys do not match")
    return derived


def _key_type(public: str) -> str:
    key_type = public.split(maxsplit=1)[0]
    if key_type not in ALLOWED_KEY_TYPES:
        raise SigningError("release key type is not accepted by GitHub SSH signing")
    return key_type


def _fingerprint(public: str) -> str:
    with tempfile.NamedTemporaryFile(
        "w", encoding="ascii", prefix="awq-key-", delete=True
    ) as stream:
        stream.write(public + "\n")
        stream.flush()
        code, output = _run(["/usr/bin/ssh-keygen", "-lf", stream.name, "-E", "sha256"])
    if code or len(output) > MAX_OUTPUT:
        raise SigningError("release public key fingerprint cannot be verified")
    fields = output.decode("ascii", errors="strict").split()
    if len(fields) < 2 or not fields[1].startswith("SHA256:"):
        raise SigningError("release public key fingerprint is invalid")
    return fields[1]


def _ordinary_commit_key(source: Path) -> str | None:
    code, output = _git(source, "config", "--get", "user.signingkey")
    if code or not output:
        return None
    configured = output.decode("utf-8", errors="strict").strip()
    if configured.startswith("SHA256:"):
        return configured
    path = Path(configured).expanduser()
    if not path.is_absolute():
        path = source / path
    if path.suffix != ".pub":
        candidate = Path(str(path) + ".pub")
        if candidate.is_file():
            path = candidate
    if not path.is_file() or path.is_symlink():
        return configured
    try:
        return _fingerprint(path.read_text(encoding="ascii").strip())
    except (OSError, UnicodeError, SigningError):
        return configured


def _state_release_ready(state_repo: Path) -> str:
    """Require the state task to authorize the exact candidate for external signing."""
    task_path = state_repo / "tasks" / "AR-0054.md"
    try:
        raw = task_path.read_text(encoding="utf-8")
        _, payload, _ = raw.split("---\n", 2)
        task: dict[str, Any] = json.loads(payload)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SigningError("release state task is unavailable or malformed") from error
    if task.get("status") != "open" or task.get("owner") or task.get("claim_expires"):
        raise SigningError("AR-0054 is not open and ownerless for external release signing")
    expected = task.get("observed_head")
    if (
        not isinstance(expected, str)
        or len(expected) != 40
        or any(character not in "0123456789abcdef" for character in expected)
    ):
        raise SigningError("release state has no exact candidate commit")
    if task.get("observed_dirty") != 0:
        raise SigningError("release state records a dirty candidate tree")
    next_action = task.get("next_action")
    if not isinstance(next_action, str) or not next_action.lower().startswith(
        "authorized external signer"
    ):
        raise SigningError("release state does not authorize signing")
    return expected


def _authorized_github_key(public: str, allowed_signers: Path) -> None:
    """Require the key to match the reviewed GitHub SSH-signing policy entry."""
    if not allowed_signers.is_file() or allowed_signers.is_symlink():
        raise SigningError("reviewed allowed-signers policy is unavailable")
    fields = public.split()
    if len(fields) < 2:
        raise SigningError("release public key is malformed")
    try:
        policy_lines = allowed_signers.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise SigningError("reviewed allowed-signers policy is unreadable") from error
    if not any(
        line.split()[1:3] == fields[:2] and line.split()[0].endswith("@users.noreply.github.com")
        for line in policy_lines
        if len(line.split()) >= 3 and not line.startswith("#")
    ):
        raise SigningError("release key is not the reviewed GitHub signing key")


def _check_key(source: Path, private_key: Path, public_key: Path, allowed_signers: Path) -> str:
    public = _public_key(private_key, public_key)
    _key_type(public)
    _authorized_github_key(public, allowed_signers)
    fingerprint = _fingerprint(public)
    ordinary = _ordinary_commit_key(source)
    code, output = _git(source, "show", "-s", "--format=%GK", "HEAD")
    commit_key = output.decode("ascii", errors="ignore").strip() if not code else None
    if (
        ordinary == fingerprint
        or commit_key == fingerprint
        or ordinary == str(public_key)
        or ordinary == str(private_key)
    ):
        raise SigningError("release key is also configured for ordinary commits")
    return fingerprint


def _verify_manifest(source: Path, manifest: Path) -> None:
    code, _ = _run(
        [
            sys.executable,
            "-m",
            "awq",
            "--root",
            str(source),
            "release-verify",
            str(manifest),
            "--source",
            "--format",
            "json",
        ],
        cwd=source,
    )
    if code:
        raise SigningError("structural release verification failed")


def _tag_exists(source: Path, tag: str) -> bool:
    code, _ = _git(source, "rev-parse", "--verify", f"refs/tags/{tag}")
    return code == 0


def sign_release(  # noqa: C901 - the bounded preflight is intentionally fail-closed
    source: Path,
    bundle: Path,
    private_key: Path,
    *,
    public_key: Path | None = None,
    state_repo: Path | None = None,
    allowed_signers: Path | None = None,
    version: str | None = None,
    tag: str | None = None,
    confirm: bool = False,
) -> dict[str, str]:
    """Validate and locally sign one exact bundle and annotated tag."""
    source = source.resolve(strict=True)
    bundle = bundle.resolve(strict=True)
    private_key = private_key.expanduser().resolve(strict=True)
    public_key = (public_key or Path(str(private_key) + ".pub")).expanduser().resolve()
    state_repo = (state_repo or source.parent / "agent-workflow-quality-state").resolve()
    allowed_signers = (
        (allowed_signers or source.parent / "awq-release-trust" / "allowed_signers")
        .expanduser()
        .resolve()
    )
    state_commit = _state_release_ready(state_repo)
    commit = _require_clean_source(source)
    if commit != state_commit:
        if not confirm:
            raise SigningError(
                "preview requires the clone at the state-authorized commit; rerun with --yes "
                "only after reviewing the requested detached checkout"
            )
        _checkout_exact(source, state_commit)
        commit = _require_clean_source(source)
        if commit != state_commit:
            raise SigningError("checkout did not reach the state-authorized release commit")
    observed_version = version or _version(source)
    observed_tag = tag or f"v{observed_version}"
    if observed_tag != f"v{observed_version}" or "/" in observed_tag or ".." in observed_tag:
        raise SigningError("tag must be the version tag")
    manifest = _manifest(bundle, observed_version)
    before = _digest(manifest)
    _verify_manifest(source, manifest)
    fingerprint = _check_key(source, private_key, public_key, allowed_signers)
    if _tag_exists(source, observed_tag):
        raise SigningError("release tag already exists; refusing to replace it")
    signature = manifest.with_name(manifest.name + ".sig")
    if signature.exists() or signature.is_symlink():
        raise SigningError("manifest signature already exists; refusing to replace it")
    result = {
        "version": observed_version,
        "commit": commit,
        "manifest_sha256": before,
        "signer_fingerprint": fingerprint,
        "tag": observed_tag,
    }
    if not confirm:
        return result
    with tempfile.TemporaryDirectory(prefix="awq-sign-", dir=bundle.parent) as temporary:
        temporary_manifest = Path(temporary) / manifest.name
        shutil.copyfile(manifest, temporary_manifest)
        code, _ = _run(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(private_key),
                "-n",
                "awq-release",
                str(temporary_manifest),
            ]
        )
        if code or not (temporary_manifest.with_name(temporary_manifest.name + ".sig")).is_file():
            raise SigningError("manifest signing failed")
        if _digest(manifest) != before:
            raise SigningError("manifest changed during signing")
        temporary_manifest.with_name(temporary_manifest.name + ".sig").replace(signature)
    if _require_clean_source(source) != commit or _tag_exists(source, observed_tag):
        with contextlib.suppress(OSError):
            signature.unlink()
        raise SigningError("release changed during signing; nothing was tagged")
    try:
        code, _ = _run(
            [
                "/usr/bin/git",
                "-c",
                "gpg.format=ssh",
                "-c",
                f"user.signingKey={private_key}",
                "tag",
                "-s",
                "-a",
                observed_tag,
                commit,
                "-m",
                f"AWQ {observed_tag}",
            ],
            cwd=source,
        )
    except SigningError as error:
        with contextlib.suppress(OSError):
            signature.unlink()
        with contextlib.suppress(SigningError):
            _run(["/usr/bin/git", "tag", "-d", observed_tag], cwd=source)
        raise SigningError("annotated SSH tag creation failed") from error
    if code:
        with contextlib.suppress(OSError):
            signature.unlink()
        with contextlib.suppress(SigningError):
            _run(["/usr/bin/git", "tag", "-d", observed_tag], cwd=source)
        raise SigningError("annotated SSH tag creation failed")
    return result


def _checkout_exact(source: Path, commit: str) -> None:
    """Detach a clean operator clone at the state-authorized immutable commit."""
    code, _ = _git(source, "checkout", "--detach", commit)
    if code:
        raise SigningError("could not checkout the state-authorized release commit")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=Path.cwd(),
        help="clean release clone (default: current directory)",
    )
    parser.add_argument(
        "--bundle",
        type=Path,
        default=Path("..") / "awq-release",
        help="external bundle directory (default: ../awq-release)",
    )
    parser.add_argument(
        "--key",
        type=Path,
        default=Path("~/.ssh/awq-release-signing"),
        help="dedicated GitHub SSH signing key",
    )
    parser.add_argument(
        "--allowed-signers",
        type=Path,
        default=None,
        help=(
            "external reviewed allowed-signers file (default: ../awq-release-trust/allowed_signers)"
        ),
    )
    parser.add_argument(
        "--state-repo",
        type=Path,
        default=None,
        help="local AWQ state clone (default: ../agent-workflow-quality-state)",
    )
    parser.add_argument("--public-key", type=Path, help="matching public key (default: KEY.pub)")
    parser.add_argument("--version", help="release version (default: pyproject.toml)")
    parser.add_argument("--tag", help="annotated tag (default: vVERSION)")
    parser.add_argument("--yes", action="store_true", help="perform signing and local tag creation")
    args = parser.parse_args(argv)
    try:
        result = sign_release(
            args.source,
            args.bundle,
            args.key,
            state_repo=args.state_repo,
            allowed_signers=args.allowed_signers,
            public_key=args.public_key,
            version=args.version,
            tag=args.tag,
            confirm=args.yes,
        )
    except (OSError, SigningError) as error:
        print(f"Release signing stopped: {error}.", file=sys.stderr)
        print(
            "No manifest signature, tag, or push was authorized. Correct the reported input "
            "and rerun this command from the clean reviewed clone.",
            file=sys.stderr,
        )
        return 1
    print(
        json.dumps(
            {"status": "signed" if args.yes else "ready", **result},
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    if not args.yes:
        print("Ready. Re-run the same command with --yes to create the signature and local tag.")
    else:
        print(
            "Local signing complete; push and publish only through the established release gates."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
