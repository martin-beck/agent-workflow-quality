# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Deterministic shared repository checks."""

from __future__ import annotations

import fnmatch
import json
import os
import py_compile
import re
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from awq.adapters import run_adapter
from awq.project import ProjectError, tracked_files

TEXT_SUFFIXES = {
    ".cfg",
    ".json",
    ".kt",
    ".kts",
    ".md",
    ".py",
    ".rs",
    ".sh",
    ".toml",
    ".tla",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
    ".properties",
    ".gradle",
    ".lock",
}
KNOWN_NAMES = {
    ".gitattributes",
    ".gitignore",
    "AGENTS.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "CODEOWNERS",
    "LICENSE",
    "Makefile",
    "README.md",
    "SECURITY.md",
    "allowed_signers",
    "Cargo.lock",
    "Cargo.toml",
}
ACTION_REF = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
MARKDOWN_LINK = re.compile(r"!?\[[^]]*\]\(([^)]+)\)")
LOCAL_WORKFLOW_PATH = re.compile(
    r"(?<![A-Za-z0-9_.-])((?:\./|tools/|scripts/|schema/|schemas/)[A-Za-z0-9_./-]+)"
)
PRIVATE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?<![A-Za-z0-9_])/home/[A-Za-z0-9._-]+/"),
    re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\s]+\\"),
)
TIER_INDEX = {
    name: index
    for index, name in enumerate(("local", "pr", "scheduled", "trusted-host", "release"))
}
FORMAL_EVIDENCE_PATH = "formal/evidence.json"
FORMAL_EVIDENCE_CLASSES = {
    "mechanical",
    "contract-test",
    "property-or-fuzz",
    "bounded-model",
    "environmental",
}


@dataclass(frozen=True)
class Finding:
    """One content-minimized requirement failure."""

    code: str
    path: str
    message: str

    def json(self) -> dict[str, str]:
        """Return stable evidence fields."""
        return {"code": self.code, "path": self.path, "message": self.message[:500]}


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _is_fixture(relative: str, policy: dict[str, Any]) -> bool:
    return any(
        relative == prefix or relative.startswith(prefix.rstrip("/") + "/")
        for prefix in policy["fixture_paths"]
    )


def _read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
        if b"\0" in data or len(data) > 2_000_000:
            return None
        return data.decode("utf-8")
    except (OSError, UnicodeError):
        return None


def _is_shebang_script(path: Path) -> bool:
    try:
        # Format recognition must not depend on unavailable Windows POSIX mode bits.
        with path.open("rb") as stream:
            return stream.read(2) == b"#!"
    except OSError:
        return False


def portable_text(root: Path, paths: list[Path], policy: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        relative = _relative(root, path)
        if _is_fixture(relative, policy) or (
            path.suffix not in TEXT_SUFFIXES and not _is_shebang_script(path)
        ):
            continue
        try:
            data = path.read_bytes()
            data.decode("utf-8")
        except (OSError, UnicodeError):
            findings.append(Finding("invalid-utf8", relative, "tracked text is not UTF-8"))
            continue
        if b"\r" in data:
            findings.append(Finding("non-lf", relative, "tracked text contains carriage returns"))
        if data and not data.endswith(b"\n"):
            findings.append(
                Finding("missing-final-newline", relative, "tracked text lacks a final newline")
            )
    return findings


def path_integrity(root: Path, paths: list[Path], policy: dict[str, Any]) -> list[Finding]:
    del policy
    findings: list[Finding] = []
    names: dict[str, str] = {}
    for path in paths:
        relative = _relative(root, path)
        folded = relative.casefold()
        if folded in names and names[folded] != relative:
            findings.append(Finding("case-collision", relative, f"collides with {names[folded]}"))
        names[folded] = relative
        if path.is_symlink():
            try:
                target = path.resolve(strict=True)
            except OSError:
                findings.append(
                    Finding("broken-symlink", relative, "tracked symlink target is missing")
                )
                continue
            if root not in (target, *target.parents):
                findings.append(
                    Finding("escaping-symlink", relative, "tracked symlink escapes repository")
                )
    return findings


def merge_markers(root: Path, paths: list[Path], policy: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    start_marker = re.compile(r"^<<<<<<<(?:[ \t].*)?$")
    separator = re.compile(r"^=======$")
    end_marker = re.compile(r"^>>>>>>>(?:[ \t].*)?$")
    for path in paths:
        relative = _relative(root, path)
        text = None if _is_fixture(relative, policy) else _read_text(path)
        if text is None:
            continue
        lines = text.splitlines()
        conflict = False
        for index, line in enumerate(lines):
            if not start_marker.fullmatch(line):
                continue
            limit = min(len(lines), index + 202)
            separator_index = next(
                (
                    candidate
                    for candidate in range(index + 1, limit)
                    if separator.fullmatch(lines[candidate])
                ),
                None,
            )
            if separator_index is not None and any(
                end_marker.fullmatch(lines[candidate])
                for candidate in range(separator_index + 1, limit)
            ):
                conflict = True
                break
        if conflict:
            findings.append(Finding("merge-marker", relative, "unresolved merge marker"))
    return findings


def classified_formats(root: Path, paths: list[Path], policy: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    declared = {suffix for item in policy["extensions"] for suffix in item.get("formats", [])}
    for path in paths:
        relative = _relative(root, path)
        if (
            _is_fixture(relative, policy)
            or path.name in KNOWN_NAMES
            or path.suffix in TEXT_SUFFIXES
            or _is_shebang_script(path)
        ):
            continue
        if (
            path.suffix in {".png", ".jpg", ".jpeg", ".gif", ".jar", ".zip"}
            or path.suffix in declared
        ):
            continue
        findings.append(
            Finding("unknown-format", relative, "tracked file format has no declared quality owner")
        )
    return findings


def action_pins(root: Path, paths: list[Path], policy: dict[str, Any]) -> list[Finding]:
    del policy
    findings: list[Finding] = []
    for path in paths:
        relative = _relative(root, path)
        if not relative.startswith(".github/workflows/") or path.suffix not in {".yml", ".yaml"}:
            continue
        text = _read_text(path) or ""
        for match in ACTION_REF.finditer(text):
            value = match.group(1)
            if value.startswith("./"):
                continue
            ref = value.rsplit("@", 1)[-1] if "@" in value else ""
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                findings.append(
                    Finding(
                        "mutable-action",
                        relative,
                        "remote action is not pinned to a full SHA",
                    )
                )
    return findings


def workflow_policy(root: Path, paths: list[Path], policy: dict[str, Any]) -> list[Finding]:
    del policy
    findings: list[Finding] = []
    for path in paths:
        relative = _relative(root, path)
        if relative.startswith(".github/workflows/") and path.suffix in {".yml", ".yaml"}:
            text = _read_text(path) or ""
            if not re.search(r"(?m)^permissions:\s*(?:\{\}|$)", text):
                findings.append(
                    Finding(
                        "missing-permissions",
                        relative,
                        "workflow lacks top-level explicit permissions",
                    )
                )
            if "timeout-minutes:" not in text:
                findings.append(
                    Finding("missing-timeout", relative, "workflow has no finite job timeout")
                )
    return findings


def workflow_local_paths(root: Path, paths: list[Path], policy: dict[str, Any]) -> list[Finding]:
    del policy
    findings: list[Finding] = []
    for path in paths:
        relative = _relative(root, path)
        if not relative.startswith(".github/workflows/") or path.suffix not in {".yml", ".yaml"}:
            continue
        for raw in LOCAL_WORKFLOW_PATH.findall(_read_text(path) or ""):
            target = raw.removeprefix("./").rstrip(".,:;)")
            if not (root / target).exists():
                findings.append(
                    Finding(
                        "missing-workflow-path",
                        relative,
                        f"workflow references a missing local path: {target}",
                    )
                )
    return findings


def python_syntax(root: Path, paths: list[Path], policy: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        relative = _relative(root, path)
        if path.suffix != ".py" or _is_fixture(relative, policy):
            continue
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError:
            findings.append(Finding("python-syntax", relative, "Python source does not compile"))
    return findings


def shell_entrypoints(root: Path, paths: list[Path], policy: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        relative = _relative(root, path)
        if _is_fixture(relative, policy) or path.suffix != ".sh" or not os.access(path, os.X_OK):
            continue
        first = (_read_text(path) or "").splitlines()[:1]
        if not first or not re.fullmatch(r"#!\s*/(?:usr/bin/env\s+)?(?:ba|da|k|z)?sh.*", first[0]):
            findings.append(
                Finding("shell-shebang", relative, "executable shell file lacks a shell shebang")
            )
    return findings


def local_links(root: Path, paths: list[Path], policy: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        relative = _relative(root, path)
        text = None if _is_fixture(relative, policy) else _read_text(path)
        if path.suffix != ".md" or text is None:
            continue
        for raw in MARKDOWN_LINK.findall(text):
            target = raw.split(maxsplit=1)[0].strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or target.startswith(("#", "mailto:")):
                continue
            candidate = (path.parent / unquote(parsed.path)).resolve()
            if root not in (candidate, *candidate.parents) or not candidate.exists():
                findings.append(
                    Finding(
                        "broken-local-link", relative, f"local link target is missing: {target}"
                    )
                )
    return findings


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    del value
    raise ValueError("non-finite JSON number")


def json_parse(root: Path, paths: list[Path], policy: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        relative = _relative(root, path)
        if path.suffix != ".json" or _is_fixture(relative, policy):
            continue
        try:
            json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
        except (OSError, UnicodeError, ValueError, RecursionError):
            findings.append(
                Finding("invalid-json", relative, "JSON document is invalid or ambiguous")
            )
    return findings


def privacy_patterns(root: Path, paths: list[Path], policy: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        relative = _relative(root, path)
        text = None if _is_fixture(relative, policy) else _read_text(path)
        if text is not None and any(pattern.search(text) for pattern in PRIVATE_PATTERNS):
            findings.append(
                Finding(
                    "private-content",
                    relative,
                    "tracked text matches a credential or private-path signature",
                )
            )
    return findings


def lock_integrity(root: Path, paths: list[Path], policy: dict[str, Any]) -> list[Finding]:
    del paths, policy
    from awq.project import load_project
    from awq.registry import expand_profiles, load_registry

    try:
        project, lock = load_project(root)
        _, _, digest = load_registry()
        expected = expand_profiles(project["profiles"])
        if (
            lock["registry_sha256"] != digest
            or lock["requirements"] != expected
            or lock["profiles"] != sorted(project["profiles"])
        ):
            return [
                Finding(
                    "stale-lock",
                    "quality/awq.lock.json",
                    "policy lock does not match the installed registry and profiles",
                )
            ]
    except (ProjectError, KeyError, TypeError) as error:
        return [Finding("invalid-lock", "quality/awq.lock.json", str(error))]
    return []


def formal_claims(root: Path, paths: list[Path], policy: dict[str, Any]) -> list[Finding]:
    del policy
    formal = [path for path in paths if "formal" in path.parts and path.suffix in {".tla", ".als"}]
    if not formal:
        return []
    metadata = next(
        (path for path in paths if _relative(root, path) == FORMAL_EVIDENCE_PATH),
        None,
    )
    if metadata is None:
        return [
            Finding(
                "formal-evidence-metadata",
                "formal",
                "formal evidence requires formal/evidence.json",
            )
        ]
    raw = _read_text(metadata)
    try:
        value = json.loads(
            raw or "", object_pairs_hook=_unique_json_object, parse_constant=_reject_json_constant
        )
    except (TypeError, ValueError, RecursionError):
        value = None
    required = {
        "schema_version",
        "evidence_class",
        "scope",
        "bounds",
        "assumptions",
        "correspondence",
        "non_claims",
        "limitations",
    }
    if not isinstance(value, dict) or set(value) != required:
        return [
            Finding("formal-evidence-metadata", FORMAL_EVIDENCE_PATH, "invalid evidence fields")
        ]
    if value["schema_version"] != 1 or value["evidence_class"] not in FORMAL_EVIDENCE_CLASSES:
        return [
            Finding(
                "formal-evidence-metadata", FORMAL_EVIDENCE_PATH, "invalid evidence classification"
            )
        ]
    if (
        not isinstance(value["scope"], str)
        or re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", value["scope"]) is None
        or value["correspondence"] not in {"not-proven", "bounded-correspondence"}
    ):
        return [Finding("formal-evidence-metadata", FORMAL_EVIDENCE_PATH, "invalid evidence scope")]
    bounds = value["bounds"]
    if (
        not isinstance(bounds, dict)
        or not bounds
        or any(
            not isinstance(key, str)
            or re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", key) is None
            or type(item) is not int
            or not 1 <= item <= 1_000_000
            for key, item in bounds.items()
        )
    ):
        return [
            Finding("formal-evidence-metadata", FORMAL_EVIDENCE_PATH, "invalid evidence bounds")
        ]
    for field in ("assumptions", "non_claims", "limitations"):
        items = value[field]
        if (
            not isinstance(items, list)
            or not 1 <= len(items) <= 64
            or len(set(items)) != len(items)
            or any(not isinstance(item, str) or not 1 <= len(item) <= 500 for item in items)
        ):
            return [
                Finding(
                    "formal-evidence-metadata", FORMAL_EVIDENCE_PATH, f"invalid evidence {field}"
                )
            ]
    return []


def rust_lock(root: Path, paths: list[Path], policy: dict[str, Any]) -> list[Finding]:
    del paths, policy
    return (
        []
        if not (root / "Cargo.toml").exists() or (root / "Cargo.lock").is_file()
        else [
            Finding(
                "missing-cargo-lock", "Cargo.lock", "Rust project has no tracked dependency lock"
            )
        ]
    )


def gradle_integrity(root: Path, paths: list[Path], policy: dict[str, Any]) -> list[Finding]:
    del paths, policy
    is_gradle = any(
        (root / name).exists()
        for name in ("settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts")
    )
    metadata = root / "gradle" / "verification-metadata.xml"
    return (
        []
        if not is_gradle or metadata.is_file()
        else [
            Finding(
                "missing-gradle-verification",
                "gradle/verification-metadata.xml",
                "Gradle project lacks dependency verification metadata",
            )
        ]
    )


CHECKS: dict[str, Callable[[Path, list[Path], dict[str, Any]], list[Finding]]] = {
    "portable-text": portable_text,
    "path-integrity": path_integrity,
    "merge-markers": merge_markers,
    "classified-formats": classified_formats,
    "action-pins": action_pins,
    "workflow-policy": workflow_policy,
    "workflow-local-paths": workflow_local_paths,
    "python-syntax": python_syntax,
    "shell-entrypoints": shell_entrypoints,
    "local-links": local_links,
    "json-parse": json_parse,
    "privacy-patterns": privacy_patterns,
    "lock-integrity": lock_integrity,
    "formal-claims": formal_claims,
    "rust-lock": rust_lock,
    "gradle-integrity": gradle_integrity,
}


def _exceptions(policy: dict[str, Any], requirement: str, finding: Finding) -> list[str]:
    """Return active exception identifiers matching one bounded finding path."""
    matched: list[str] = []
    now = time.time()
    for item in policy["exceptions"]:
        if item.get("revocation") is not None:
            continue
        try:
            expires = (
                __import__("datetime")
                .datetime.fromisoformat(item["expires_at"].replace("Z", "+00:00"))
                .timestamp()
            )
        except (TypeError, ValueError):
            continue
        scopes = item["scope"]
        if (
            item["requirement"] == requirement
            and expires > now
            and any(fnmatch.fnmatch(finding.path, scope) for scope in scopes)
        ):
            matched.append(item["id"])
    return sorted(matched)


def run_requirement(
    root: Path, policy: dict[str, Any], requirement: dict[str, Any], paths: list[Path]
) -> dict[str, Any]:
    """Run one built-in requirement and return a bounded evidence record."""
    started = time.monotonic()
    findings = CHECKS[requirement["command"]](root, paths, policy)
    used = sorted(
        {
            identifier
            for finding in findings
            for identifier in _exceptions(policy, requirement["id"], finding)
        }
    )
    findings = [
        finding for finding in findings if not _exceptions(policy, requirement["id"], finding)
    ]
    failed = bool(findings) and not (
        requirement["command"] == "classified-formats" and policy["unknown_formats"] == "advisory"
    )
    return {
        "id": requirement["id"],
        "status": "fail" if failed else "pass",
        "evidence": requirement["evidence"],
        "limitation": requirement["limitation"],
        "remediation": requirement["remediation"],
        "duration_ms": int((time.monotonic() - started) * 1000),
        "exceptions": used,
        "findings": [finding.json() for finding in findings[:100]],
    }


def run_extension(root: Path, extension: dict[str, Any]) -> dict[str, Any]:
    """Run one explicit bounded local gate without a shell or retained output."""
    started = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 - policy accepts argv arrays only; no shell is used.
            extension["argv"],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=extension["timeout_seconds"],
            check=False,
        )
        message = "local gate returned a non-zero status"
        failed = proc.returncode != 0
    except (OSError, subprocess.TimeoutExpired):
        message = "local gate was unavailable or exceeded its deadline"
        failed = True
    findings = [Finding("local-gate-failed", "", message).json()] if failed else []
    return {
        "id": extension["id"],
        "status": "fail" if failed else "pass",
        "evidence": extension["evidence"],
        "limitation": extension["limitation"],
        "remediation": extension["remediation"],
        "duration_ms": int((time.monotonic() - started) * 1000),
        "exceptions": [],
        "findings": findings,
    }


def run_checks(
    root: Path,
    policy: dict[str, Any],
    requirement_ids: list[str],
    tier: str,
    *,
    include_local: bool = True,
) -> list[dict[str, Any]]:
    """Run selected built-ins and applicable project-local gates."""
    from awq.registry import load_registry

    requirements, _, _ = load_registry()
    paths = tracked_files(root)
    results = [
        run_requirement(root, policy, requirements[item], paths)
        for item in requirement_ids
        if TIER_INDEX[requirements[item]["tier"]] <= TIER_INDEX[tier]
    ]
    if not include_local:
        return results
    results.extend(
        run_extension(root, item)
        for item in policy["extensions"]
        if TIER_INDEX[item["tier"]] <= TIER_INDEX[tier]
    )
    results.extend(
        run_adapter(root, item)
        for item in sorted(policy["adapters"], key=lambda candidate: candidate["id"])
        if TIER_INDEX[item["tier"]] <= TIER_INDEX[tier]
    )
    return results
