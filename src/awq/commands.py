"""AWQ command behavior independent from console formatting."""

from __future__ import annotations

import json
import shutil
import subprocess
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from awq import __version__
from awq.checks import run_checks
from awq.project import (
    ProjectError,
    load_project,
    make_policy,
    policy_paths,
    sha256_json,
    tracked_files,
    validate_lock,
    validate_policy,
    write_initialization,
)
from awq.registry import expand_profiles, load_registry, load_standards


def _git() -> str:
    executable = shutil.which("git")
    if executable is None:
        raise ProjectError("git executable is unavailable")
    return executable


def detected_profiles(root: Path) -> tuple[list[str], dict[str, int]]:
    """Detect applicable built-in profiles without mutating the project."""
    paths = tracked_files(root)
    suffixes = Counter(path.suffix or path.name for path in paths)
    profiles = {"core", "privacy", "supply-chain"}
    names = {path.name for path in paths}
    if suffixes[".py"]:
        profiles.add("python")
    if suffixes[".sh"]:
        profiles.add("shell")
    if suffixes[".md"]:
        profiles.add("docs")
    if suffixes[".json"]:
        profiles.add("schemas")
    if any(path.relative_to(root).parts[0] == ".github" for path in paths):
        profiles.add("github-actions")
    if "Cargo.toml" in names:
        profiles.add("rust")
    if names.intersection(
        {"settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts"}
    ):
        profiles.add("android-jvm")
    if any("formal" in path.relative_to(root).parts for path in paths):
        profiles.add("formal-evidence")
    return sorted(profiles), dict(sorted(suffixes.items()))


def inspect(root: Path) -> dict[str, Any]:
    """Return a deterministic project inventory and recommended profile set."""
    profiles, formats = detected_profiles(root)
    return {
        "status": "ok",
        "root": ".",
        "tracked_files": sum(formats.values()),
        "formats": formats,
        "recommended_profiles": profiles,
    }


def initialize(root: Path, profiles: list[str] | None, dry_run: bool) -> dict[str, Any]:
    """Plan or create a deterministic consumer policy."""
    selected = profiles or detected_profiles(root)[0]
    policy, lock = make_policy(selected)
    files = ["quality/awq.json", "quality/awq.lock.json", "tools/awq"]
    if not dry_run:
        files = write_initialization(root, policy, lock)
    return {
        "status": "ok",
        "dry_run": dry_run,
        "files": files,
        "policy_sha256": sha256_json(policy),
        "registry_sha256": lock["registry_sha256"],
        "profiles": lock["profiles"],
        "requirements": lock["requirements"],
    }


def plan(root: Path, changed: bool, base: str) -> dict[str, Any]:
    """Return the selected requirement plan, optionally scoped by a Git diff."""
    policy, lock = load_project(root)
    paths: list[str] = []
    if changed:
        proc = subprocess.run(  # noqa: S603 - resolved executable and controlled argv structure.
            [_git(), "-C", str(root), "diff", "--name-only", f"{base}...HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if proc.returncode:
            raise ProjectError("cannot compute changed-file plan")
        paths = sorted(line for line in proc.stdout.splitlines() if line)
    requirements, _, _ = load_registry()
    gates = [
        {
            "id": item,
            "tier": requirements[item]["tier"],
            "command": requirements[item]["command"],
            "evidence": requirements[item]["evidence"],
        }
        for item in lock["requirements"]
    ]
    return {
        "status": "ok",
        "changed_only": changed,
        "paths": paths,
        "gates": gates,
        "local_extensions": [
            {"id": item["id"], "tier": item["tier"]} for item in policy["extensions"]
        ],
    }


def check(root: Path, tier: str) -> dict[str, Any]:
    """Run shared and local requirements and return bounded results."""
    policy, lock = load_project(root)
    results = run_checks(root, policy, lock["requirements"], tier)
    failed = any(item["status"] == "fail" for item in results)
    return {"status": "fail" if failed else "pass", "tier": tier, "requirements": results}


def evidence(root: Path, tier: str) -> dict[str, Any]:
    """Create the normalized content-minimized evidence envelope."""
    policy, lock = load_project(root)
    result = check(root, tier)
    return {
        "schema_version": 1,
        "awq_version": __version__,
        "registry_sha256": lock["registry_sha256"],
        "policy_sha256": sha256_json(policy),
        "tier": tier,
        "result": result["status"],
        "requirements": result["requirements"],
    }


def explain(identifier: str) -> dict[str, Any]:
    """Explain one stable shared requirement."""
    requirements, _, _ = load_registry()
    sources, mappings, standards_digest = load_standards()
    if identifier not in requirements:
        raise ProjectError(f"unknown requirement: {identifier}")
    traceability = []
    for mapping in mappings.values():
        if mapping["requirement"] != identifier:
            continue
        source = sources[mapping["source"]]
        control = next(item for item in source["controls"] if item["id"] == mapping["control"])
        traceability.append(
            {
                **mapping,
                "source_title": source["title"],
                "source_url": source["source_url"],
                "control_title": control["title"],
                "control_url": control["url"],
            }
        )
    return {
        "status": "ok",
        "requirement": requirements[identifier],
        "standards_registry_sha256": standards_digest,
        "traceability": traceability,
    }


def standards() -> dict[str, Any]:
    """Return deterministic machine-readable standards traceability."""
    sources, mappings, digest = load_standards()
    return {
        "status": "ok",
        "standards_registry_sha256": digest,
        "claim": "alignment-not-certification",
        "sources": [sources[identifier] for identifier in sorted(sources)],
        "mappings": [mappings[identifier] for identifier in sorted(mappings)],
    }


def doctor(root: Path) -> dict[str, Any]:
    """Validate registry, policy, lock, exceptions and current installation."""
    policy, lock = load_project(root)
    _, _, digest = load_registry()
    _, _, standards_digest = load_standards()
    findings: list[dict[str, str]] = []
    if lock["awq_version"] != __version__:
        findings.append(
            {"code": "version-drift", "message": "lock AWQ version differs from installed version"}
        )
    if lock["registry_sha256"] != digest:
        findings.append(
            {
                "code": "registry-drift",
                "message": "lock registry digest differs from installed registry",
            }
        )
    if lock["profiles"] != sorted(policy["profiles"]) or lock["requirements"] != expand_profiles(
        policy["profiles"]
    ):
        findings.append(
            {"code": "lock-drift", "message": "lock expansion differs from project policy"}
        )
    now = datetime.now(UTC)
    for item in policy["exceptions"]:
        try:
            expires = datetime.fromisoformat(item["expires_at"].replace("Z", "+00:00"))
        except (TypeError, ValueError):
            findings.append(
                {
                    "code": "invalid-exception-date",
                    "message": f"{item.get('id', '?')} has an invalid expiry",
                }
            )
            continue
        if expires <= now:
            findings.append({"code": "expired-exception", "message": f"{item['id']} is expired"})
        if item["requirement"] not in lock["requirements"]:
            findings.append(
                {
                    "code": "unknown-exception-requirement",
                    "message": f"{item['id']} targets an inactive requirement",
                }
            )
    return {
        "status": "fail" if findings else "pass",
        "awq_version": __version__,
        "registry_sha256": digest,
        "standards_registry_sha256": standards_digest,
        "findings": findings,
    }


def update(root: Path, target: str, dry_run: bool) -> dict[str, Any]:
    """Refresh the lock only for the explicitly installed target release."""
    if target != __version__:
        raise ProjectError(
            f"installed AWQ is {__version__}; install {target} before updating the lock"
        )
    policy, old_lock = load_project(root)
    _, new_lock = make_policy(policy["profiles"])
    changed = old_lock != new_lock
    if changed and not dry_run:
        _, lock_path = policy_paths(root)
        lock_path.write_text(
            json.dumps(new_lock, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    return {
        "status": "ok",
        "dry_run": dry_run,
        "changed": changed,
        "from": old_lock,
        "to": new_lock,
    }


def _git_json(root: Path, revision: str, path: str) -> dict[str, Any]:
    proc = subprocess.run(  # noqa: S603 - resolved executable and controlled argv structure.
        [_git(), "-C", str(root), "show", f"{revision}:{path}"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if proc.returncode:
        raise ProjectError(f"cannot read {path} at {revision}")
    value = json.loads(proc.stdout)
    if not isinstance(value, dict):
        raise ProjectError(f"{path} at {revision} is not an object")
    return value


def policy_diff(root: Path, base: str, head: str) -> dict[str, Any]:
    """Classify review-sensitive and weakening changes between Git revisions."""
    old_policy = _git_json(root, base, "quality/awq.json")
    new_policy = _git_json(root, head, "quality/awq.json")
    old_lock = _git_json(root, base, "quality/awq.lock.json")
    new_lock = _git_json(root, head, "quality/awq.lock.json")
    validate_policy(old_policy)
    validate_policy(new_policy)
    validate_lock(old_lock)
    validate_lock(new_lock)
    changes: list[dict[str, str]] = []
    changes.extend(
        {
            "classification": "weakening",
            "field": "profiles",
            "message": f"removed profile {profile}",
        }
        for profile in sorted(set(old_policy["profiles"]) - set(new_policy["profiles"]))
    )
    if old_policy["unknown_formats"] == "error" and new_policy["unknown_formats"] != "error":
        changes.append(
            {
                "classification": "weakening",
                "field": "unknown_formats",
                "message": "unknown formats no longer fail",
            }
        )
    old_extensions = {item["id"] for item in old_policy["extensions"]}
    new_extensions = {item["id"] for item in new_policy["extensions"]}
    changes.extend(
        {
            "classification": "weakening",
            "field": "extensions",
            "message": f"removed local gate {identifier}",
        }
        for identifier in sorted(old_extensions - new_extensions)
    )
    changes.extend(
        {
            "classification": "weakening",
            "field": "exceptions",
            "message": f"added exception {identifier}",
        }
        for identifier in sorted(
            {item["id"] for item in new_policy["exceptions"]}
            - {item["id"] for item in old_policy["exceptions"]}
        )
    )
    if (
        old_lock["registry_sha256"] != new_lock["registry_sha256"]
        or old_lock["awq_version"] != new_lock["awq_version"]
    ):
        changes.append(
            {"classification": "review", "field": "lock", "message": "quality bundle pin changed"}
        )
    return {
        "status": "fail"
        if any(item["classification"] == "weakening" for item in changes)
        else "pass",
        "base": base,
        "head": head,
        "changes": changes,
    }
