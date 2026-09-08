"""AWQ command behavior independent from console formatting."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from awq import __version__
from awq.checks import run_checks
from awq.project import (
    EXCEPTION_KEYS,
    POLICY_KEYS,
    ProjectError,
    _timestamp,
    load_project,
    make_policy,
    policy_paths,
    sha256_json,
    tracked_files,
    validate_lock,
    validate_policy,
    write_initialization,
)
from awq.registry import TIERS, expand_profiles, load_registry, load_standards


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
        if item["revocation"] is not None:
            continue
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


def governance(root: Path) -> dict[str, Any]:
    """Return deterministic ownership suggestions for sensitive policy surfaces."""
    policy, _ = load_project(root)
    owners = policy["governance"]["owners"]
    patterns = (
        "/quality/",
        "/schemas/",
        "/src/awq/data/",
        "/.github/workflows/",
        "/.github/CODEOWNERS",
    )
    return {
        "status": "ok",
        "schema_version": 1,
        "owners": owners,
        "codeowners_suggestions": [{"pattern": pattern, "owners": owners} for pattern in patterns],
        "limitation": (
            "Suggestions are offline policy output; repository hosting rules require a "
            "separate environmental observation."
        ),
    }


def _github_json(url: str, headers: dict[str, str]) -> object:
    request = Request(url, headers=headers)  # noqa: S310 - fixed HTTPS API origin.
    try:
        with urlopen(request, timeout=5) as response:  # noqa: S310 - fixed HTTPS API origin.
            payload = response.read(1_000_001)
    except OSError as error:
        raise ProjectError("GitHub ruleset observation failed") from error
    if len(payload) > 1_000_000:
        raise ProjectError("GitHub ruleset observation exceeded the response bound")
    return json.loads(payload)


def _github_rulesets(repository: str) -> tuple[str, list[dict[str, Any]]]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ProjectError("repository must be an owner/name identifier")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "agent-workflow-quality",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    origin = f"https://api.github.com/repos/{repository}"
    metadata = _github_json(origin, headers)
    if (
        not isinstance(metadata, dict)
        or not isinstance(metadata.get("default_branch"), str)
        or not metadata["default_branch"]
    ):
        raise ProjectError("GitHub repository observation returned an unexpected shape")
    default_branch = metadata["default_branch"]
    summaries = _github_json(f"{origin}/rulesets", headers)
    if not isinstance(summaries, list):
        raise ProjectError("GitHub ruleset observation returned an unexpected shape")
    if len(summaries) > 10:
        raise ProjectError("GitHub ruleset observation exceeded the ruleset count bound")
    detailed: list[dict[str, Any]] = []
    for summary in summaries:
        if (
            not isinstance(summary, dict)
            or not isinstance(summary.get("id"), int)
            or isinstance(summary.get("id"), bool)
        ):
            continue
        detail = _github_json(f"{origin}/rulesets/{summary['id']}", headers)
        if not isinstance(detail, dict):
            raise ProjectError("GitHub ruleset detail returned an unexpected shape")
        detailed.append(detail)
    return default_branch, detailed


def _applies_to_default(item: dict[str, Any], default_branch: str) -> bool:
    conditions = item.get("conditions")
    if not isinstance(conditions, dict):
        return False
    ref_name = conditions.get("ref_name")
    if not isinstance(ref_name, dict):
        return False
    include, exclude = ref_name.get("include"), ref_name.get("exclude")
    if (
        not isinstance(include, list)
        or not isinstance(exclude, list)
        or not all(isinstance(value, str) for value in [*include, *exclude])
    ):
        return False
    selectors = {"~ALL", "~DEFAULT_BRANCH", f"refs/heads/{default_branch}"}
    return bool(selectors.intersection(include)) and not bool(selectors.intersection(exclude))


def hosting_observation(repository: str) -> dict[str, Any]:
    """Observe public GitHub rulesets as bounded, time-stamped environmental evidence."""
    default_branch, rulesets = _github_rulesets(repository)
    observed: list[dict[str, Any]] = []
    for item in rulesets:
        identifier = item.get("id")
        target = item.get("target")
        enforcement = item.get("enforcement")
        if (
            not isinstance(identifier, int)
            or isinstance(identifier, bool)
            or not isinstance(target, str)
            or not isinstance(enforcement, str)
        ):
            continue
        rules = item.get("rules", [])
        if not isinstance(rules, list):
            rules = []
        rule_types = {
            rule.get("type")
            for rule in rules
            if isinstance(rule, dict) and isinstance(rule.get("type"), str)
        }
        status_checks: set[str] = set()
        for rule in rules:
            if (
                not isinstance(rule, dict)
                or rule.get("type") != "required_status_checks"
                or not isinstance(rule.get("parameters"), dict)
            ):
                continue
            declared = rule["parameters"].get("required_status_checks", [])
            if not isinstance(declared, list):
                continue
            status_checks.update(
                check["context"]
                for check in declared
                if isinstance(check, dict)
                and isinstance(check.get("context"), str)
                and check["context"]
            )
        observed.append(
            {
                "id": identifier,
                "name": str(item.get("name", ""))[:100],
                "target": target,
                "enforcement": enforcement,
                "applies_to_default_branch": _applies_to_default(item, default_branch),
                "rule_types": sorted(rule_types),
                "required_status_checks": sorted(status_checks),
            }
        )
    active_types = {
        rule_type
        for item in observed
        if item["target"] == "branch"
        and item["enforcement"] == "active"
        and item["applies_to_default_branch"]
        for rule_type in item["rule_types"]
        if rule_type != "required_status_checks" or item["required_status_checks"]
    }
    missing = sorted({"pull_request", "required_status_checks"} - active_types)
    return {
        "status": "fail" if missing else "pass",
        "schema_version": 1,
        "repository": repository,
        "default_branch": default_branch,
        "observed_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "tier": "scheduled",
        "evidence": "environmental",
        "network": True,
        "rulesets": sorted(observed, key=lambda item: (str(item["id"]), item["name"])),
        "findings": [{"code": "missing-hosting-rule", "rule": rule_type} for rule_type in missing],
        "limitation": (
            "This is a point-in-time GitHub API observation, not offline proof and not evidence "
            "that every hosting bypass or administrator action is controlled."
        ),
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
    """Classify every semantic policy and lock change between Git revisions."""
    old_policy = _git_json(root, base, "quality/awq.json")
    new_policy = _git_json(root, head, "quality/awq.json")
    old_lock = _git_json(root, base, "quality/awq.lock.json")
    new_lock = _git_json(root, head, "quality/awq.lock.json")
    old_policy = _policy_v2(old_policy, new_policy)
    validate_policy(old_policy)
    validate_policy(new_policy)
    validate_lock(old_lock)
    validate_lock(new_lock)
    changes: list[dict[str, str]] = []
    _compare_policy(old_policy, new_policy, changes)
    _compare_lock(old_lock, new_lock, changes)
    weakening = any(item["classification"] == "weakening" for item in changes)
    return {
        "status": "fail" if weakening else "pass",
        "review_required": bool(changes),
        "base": base,
        "head": head,
        "changes": changes,
    }


def _policy_v2(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Normalize the one supported v1-to-v2 migration for semantic comparison."""
    if old.get("schema_version") == 2:
        return old
    legacy_keys = POLICY_KEYS - {"governance"}
    if (
        old.get("schema_version") != 1
        or set(old) != legacy_keys
        or old.get("exceptions")
        or not isinstance(new.get("governance"), dict)
    ):
        raise ProjectError("cannot compare unsupported historical policy schema")
    return {**old, "schema_version": 2, "governance": new["governance"]}


def _change(changes: list[dict[str, str]], classification: str, field: str, message: str) -> None:
    changes.append({"classification": classification, "field": field, "message": message})


def _compare_set(
    old: list[str],
    new: list[str],
    field: str,
    removed_class: str,
    added_class: str,
    changes: list[dict[str, str]],
) -> None:
    for value in sorted(set(old) - set(new)):
        _change(changes, removed_class, field, f"removed {value}")
    for value in sorted(set(new) - set(old)):
        _change(changes, added_class, field, f"added {value}")


def _compare_extensions(
    old_items: list[dict[str, Any]],
    new_items: list[dict[str, Any]],
    changes: list[dict[str, str]],
) -> None:
    old = {item["id"]: item for item in old_items}
    new = {item["id"]: item for item in new_items}
    for identifier in sorted(old.keys() - new.keys()):
        _change(changes, "weakening", f"extensions.{identifier}", "removed local gate")
    for identifier in sorted(new.keys() - old.keys()):
        _change(changes, "strengthening", f"extensions.{identifier}", "added local gate")
    for identifier in sorted(old.keys() & new.keys()):
        _compare_extension(identifier, old[identifier], new[identifier], changes)


def _compare_extension(
    identifier: str,
    old: dict[str, Any],
    new: dict[str, Any],
    changes: list[dict[str, str]],
) -> None:
    prefix = f"extensions.{identifier}"
    _compare_set(
        old["formats"],
        new["formats"],
        f"{prefix}.formats",
        "weakening",
        "strengthening",
        changes,
    )
    if old["tier"] != new["tier"]:
        classification = (
            "weakening" if TIERS.index(new["tier"]) > TIERS.index(old["tier"]) else "strengthening"
        )
        _change(changes, classification, f"{prefix}.tier", "execution tier changed")
    for field in ("argv", "evidence", "limitation"):
        if old[field] != new[field]:
            _change(changes, "weakening", f"{prefix}.{field}", f"{field} changed")
    if old["timeout_seconds"] != new["timeout_seconds"]:
        classification = (
            "weakening" if new["timeout_seconds"] < old["timeout_seconds"] else "strengthening"
        )
        _change(changes, classification, f"{prefix}.timeout_seconds", "deadline changed")
    if old["remediation"] != new["remediation"]:
        _change(changes, "review", f"{prefix}.remediation", "remediation changed")


def _valid_renewal(old: dict[str, Any], new: dict[str, Any]) -> bool:
    renewals = new["renewals"]
    return (
        len(renewals) == len(old["renewals"]) + 1
        and renewals[:-1] == old["renewals"]
        and renewals[-1]["previous_expires_at"] == old["expires_at"]
        and renewals[-1]["expires_at"] == new["expires_at"]
    )


def _compare_exception(
    identifier: str,
    old: dict[str, Any],
    new: dict[str, Any],
    changes: list[dict[str, str]],
) -> None:
    prefix = f"exceptions.{identifier}"
    _compare_set(
        old["scope"],
        new["scope"],
        f"{prefix}.scope",
        "strengthening",
        "weakening",
        changes,
    )
    if old["expires_at"] != new["expires_at"]:
        old_expiry = _timestamp(old["expires_at"], "expires_at")
        new_expiry = _timestamp(new["expires_at"], "expires_at")
        if new_expiry < old_expiry:
            classification, message = "strengthening", "expiry shortened"
        elif _valid_renewal(old, new):
            classification, message = "review", "expiry renewed with history"
        else:
            classification, message = "weakening", "expiry silently extended"
        _change(changes, classification, f"{prefix}.expires_at", message)
    old_revocation, new_revocation = old["revocation"], new["revocation"]
    if old_revocation != new_revocation:
        classification = "strengthening" if old_revocation is None else "weakening"
        _change(changes, classification, f"{prefix}.revocation", "revocation changed")
    if old["renewals"] != new["renewals"] and not (
        old["expires_at"] != new["expires_at"] and _valid_renewal(old, new)
    ):
        _change(changes, "weakening", f"{prefix}.renewals", "renewal history changed")
    ignored = {"id", "scope", "expires_at", "renewals", "revocation"}
    for field in sorted(EXCEPTION_KEYS - ignored):
        if old[field] != new[field]:
            _change(changes, "weakening", f"{prefix}.{field}", f"{field} changed")


def _compare_exceptions(
    old_items: list[dict[str, Any]],
    new_items: list[dict[str, Any]],
    changes: list[dict[str, str]],
) -> None:
    old = {item["id"]: item for item in old_items}
    new = {item["id"]: item for item in new_items}
    for identifier in sorted(old.keys() - new.keys()):
        _change(
            changes,
            "weakening",
            f"exceptions.{identifier}",
            "exception record removed instead of revoked",
        )
    for identifier in sorted(new.keys() - old.keys()):
        _change(changes, "review", f"exceptions.{identifier}", "approved exception added")
    for identifier in sorted(old.keys() & new.keys()):
        _compare_exception(identifier, old[identifier], new[identifier], changes)


def _compare_policy(
    old: dict[str, Any], new: dict[str, Any], changes: list[dict[str, str]]
) -> None:
    _compare_set(
        old["profiles"], new["profiles"], "profiles", "weakening", "strengthening", changes
    )
    if old["unknown_formats"] != new["unknown_formats"]:
        classification = "weakening" if new["unknown_formats"] == "advisory" else "strengthening"
        _change(changes, classification, "unknown_formats", "unknown-format behavior changed")
    _compare_set(
        old["fixture_paths"],
        new["fixture_paths"],
        "fixture_paths",
        "strengthening",
        "weakening",
        changes,
    )
    old_governance, new_governance = old["governance"], new["governance"]
    _compare_set(
        old_governance["owners"],
        new_governance["owners"],
        "governance.owners",
        "weakening",
        "review",
        changes,
    )
    for field in ("max_standard_days", "max_emergency_hours"):
        if old_governance[field] != new_governance[field]:
            classification = (
                "weakening" if new_governance[field] > old_governance[field] else "strengthening"
            )
            _change(changes, classification, f"governance.{field}", "lifetime bound changed")
    _compare_extensions(old["extensions"], new["extensions"], changes)
    _compare_exceptions(old["exceptions"], new["exceptions"], changes)


def _compare_lock(old: dict[str, Any], new: dict[str, Any], changes: list[dict[str, str]]) -> None:
    if old["schema_version"] != new["schema_version"]:
        _change(changes, "weakening", "lock.schema_version", "lock schema changed")
    for field in ("awq_version", "registry_sha256"):
        if old[field] != new[field]:
            _change(changes, "review", f"lock.{field}", f"{field} pin changed")
    _compare_set(
        old["profiles"],
        new["profiles"],
        "lock.profiles",
        "weakening",
        "review",
        changes,
    )
    _compare_set(
        old["requirements"],
        new["requirements"],
        "lock.requirements",
        "weakening",
        "review",
        changes,
    )
