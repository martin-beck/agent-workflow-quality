# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Closed, non-executing consumer assurance-plan contracts."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Never

from awq.contracts import load_contract_catalog
from awq.native_mapping import PLATFORM_CLASSES, validate_identity
from awq.project import ProjectError
from awq.registry import EVIDENCE_CLASSES, TIERS, canonical_bytes
from awq.sbom import strict_json
from awq.trust import read_file

MAX_BYTES = 512_000
MAX_DOMAINS = 128
MAX_GATES = 256
MAX_UNSUPPORTED = 128
MAX_OBSERVATIONS = 256
HASH = re.compile(r"[0-9a-f]{64}", re.ASCII)
COMMIT = re.compile(r"[0-9a-f]{40}", re.ASCII)
IDENTIFIER = re.compile(r"(?:DOMAIN|GATE|UNSUPPORTED)-[A-Z0-9]+(?:-[A-Z0-9]+)*", re.ASCII)
OWNER = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*", re.ASCII)
INVARIANT = re.compile(r"INV-[A-Z0-9]+(?:-[A-Z0-9]+)*", re.ASCII)
NATIVE_MAPPING = re.compile(r"NATIVE-[A-Z0-9]+(?:-[A-Z0-9]+)*", re.ASCII)
REPOSITORY = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*/[a-z0-9]+(?:-[a-z0-9]+)*", re.ASCII)
REVIEW = re.compile(r"REVIEW-[A-Z0-9]+(?:-[A-Z0-9]+)*", re.ASCII)
TIMESTAMP = re.compile(
    r"20[0-9]{2}-(?:0[1-9]|1[0-2])-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
    re.ASCII,
)
DOMAIN_KINDS = ("language", "build-system", "runtime-surface", "quality-domain")
OBSERVATION_SOURCES = ("executed", "native-environment")
OBSERVATION_STATUSES = ("pass", "fail", "error", "skip")
PRIVATE_MARKERS = (
    "/home/",
    "/users/",
    "\\users\\",
    "authorization:",
    "bearer ",
    "ghp_",
    "password=",
    "secret=",
    "token=",
)
SHELLS = {"bash", "cmd", "cmd.exe", "dash", "fish", "powershell", "pwsh", "sh", "zsh"}


def _fail(code: str) -> Never:
    raise ProjectError("assurance plan invalid: " + code)


def _object(value: Any, keys: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys.split()):
        _fail("fields")
    return dict(value)


def _text(value: Any, *, minimum: int = 1, maximum: int = 500) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value.strip()) <= maximum
        or not value.isascii()
        or any(ord(character) < 32 for character in value)
        or "\\" in value
        or any(marker in value.casefold() for marker in PRIVATE_MARKERS)
    ):
        _fail("text")
    return value


def _identifier(value: Any, prefix: str) -> str:
    if (
        not isinstance(value, str)
        or IDENTIFIER.fullmatch(value) is None
        or not value.startswith(prefix + "-")
    ):
        _fail("identifier")
    return value


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        _fail("timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ProjectError("assurance plan invalid: timestamp") from error
    if result.tzinfo != UTC:
        _fail("timestamp")
    return result


def _repository(value: Any) -> dict[str, str]:
    item = _object(value, "id source_commit source_tree reviewed_base tree_state")
    if not isinstance(item["id"], str) or REPOSITORY.fullmatch(item["id"]) is None:
        _fail("repository")
    for field in ("source_commit", "source_tree", "reviewed_base"):
        if not isinstance(item[field], str) or COMMIT.fullmatch(item[field]) is None:
            _fail("repository-revision")
    if item["tree_state"] != "clean":
        _fail("repository-tree-state")
    return {key: str(item[key]) for key in item}


def _domain(value: Any) -> dict[str, str]:
    item = _object(value, "id kind owner description")
    identifier = _identifier(item["id"], "DOMAIN")
    if item["kind"] not in DOMAIN_KINDS:
        _fail("domain-kind")
    if not isinstance(item["owner"], str) or OWNER.fullmatch(item["owner"]) is None:
        _fail("owner")
    return {
        "id": identifier,
        "kind": str(item["kind"]),
        "owner": str(item["owner"]),
        "description": _text(item["description"], minimum=20),
    }


def _argv(value: Any) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        _fail("argv")
    result: list[str] = []
    for argument in value:
        if (
            not isinstance(argument, str)
            or not 1 <= len(argument) <= 200
            or not argument.isascii()
            or any(ord(character) < 32 for character in argument)
            or argument.startswith(("/", "~"))
            or ".." in argument.split("/")
            or "\\" in argument
            or "://" in argument
            or any(marker in argument for marker in ("$", "`", ";", "&&", "||", "\n", "\r"))
            or any(marker in argument.casefold() for marker in PRIVATE_MARKERS)
        ):
            _fail("argv")
        result.append(argument)
    if result[0].casefold() in SHELLS:
        _fail("shell-command")
    return result


def _input_scope(value: Any) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        _fail("input-scope")
    result: list[str] = []
    for path in value:
        if (
            not isinstance(path, str)
            or not 1 <= len(path) <= 200
            or not path.isascii()
            or path.startswith(("/", "~"))
            or ".." in path.split("/")
            or "\\" in path
            or ":" in path
            or any(ord(character) < 32 for character in path)
            or any(marker in path.casefold() for marker in PRIVATE_MARKERS)
        ):
            _fail("input-scope")
        result.append(path)
    if result != sorted(set(result)):
        _fail("input-scope-order")
    return result


def _correlation(value: Any, repository: dict[str, str]) -> dict[str, Any]:
    item = _object(
        value,
        "source_commit source_tree reviewed_base tree_state gate_definition_sha256 "
        "configuration_sha256 input_sha256 platform_class",
    )
    for field in ("source_commit", "source_tree", "reviewed_base", "tree_state"):
        if item[field] != repository[field]:
            _fail("correlation-repository")
    for field in ("gate_definition_sha256", "configuration_sha256", "input_sha256"):
        if not isinstance(item[field], str) or HASH.fullmatch(item[field]) is None:
            _fail("correlation-digest")
    if item["platform_class"] not in PLATFORM_CLASSES:
        _fail("correlation-platform")
    return item


def _gate(
    value: Any,
    repository: dict[str, str],
    domains: set[str],
    report_contracts: set[str],
) -> dict[str, Any]:
    item = _object(
        value,
        "id owner invariant domains tier evidence_class argv input_scope report_contract "
        "remediation limitation depends_on native_mapping correlation",
    )
    identifier = _identifier(item["id"], "GATE")
    if not isinstance(item["owner"], str) or OWNER.fullmatch(item["owner"]) is None:
        _fail("owner")
    if not isinstance(item["invariant"], str) or INVARIANT.fullmatch(item["invariant"]) is None:
        _fail("invariant")
    if (
        not isinstance(item["domains"], list)
        or not item["domains"]
        or item["domains"] != sorted(set(item["domains"]))
        or not set(item["domains"]) <= domains
    ):
        _fail("gate-domains")
    if item["tier"] not in TIERS:
        _fail("tier")
    if item["evidence_class"] not in EVIDENCE_CLASSES:
        _fail("evidence-class")
    if item["report_contract"] not in report_contracts:
        _fail("report-contract")
    if (
        not isinstance(item["depends_on"], list)
        or item["depends_on"] != sorted(set(item["depends_on"]))
        or any(not isinstance(dependency, str) for dependency in item["depends_on"])
    ):
        _fail("dependencies")
    native = item["native_mapping"]
    if native is not None and (
        not isinstance(native, str) or NATIVE_MAPPING.fullmatch(native) is None
    ):
        _fail("native-mapping")
    return {
        **item,
        "id": identifier,
        "argv": _argv(item["argv"]),
        "input_scope": _input_scope(item["input_scope"]),
        "remediation": _text(item["remediation"], minimum=20),
        "limitation": _text(item["limitation"], minimum=20),
        "correlation": _correlation(item["correlation"], repository),
    }


def _unsupported(value: Any, domains: set[str]) -> dict[str, str]:
    item = _object(value, "id domain owner rationale review")
    identifier = _identifier(item["id"], "UNSUPPORTED")
    if item["domain"] not in domains:
        _fail("unsupported-domain")
    if not isinstance(item["owner"], str) or OWNER.fullmatch(item["owner"]) is None:
        _fail("owner")
    if not isinstance(item["review"], str) or REVIEW.fullmatch(item["review"]) is None:
        _fail("unsupported-review")
    return {
        "id": identifier,
        "domain": str(item["domain"]),
        "owner": str(item["owner"]),
        "rationale": _text(item["rationale"], minimum=20),
        "review": str(item["review"]),
    }


def _ensure_dependencies(gates: list[dict[str, Any]]) -> None:
    remaining = {item["id"]: item for item in gates}
    complete: set[str] = set()
    for item in gates:
        ready = sorted(
            identifier
            for identifier, candidate in remaining.items()
            if set(candidate["depends_on"]) <= complete
        )
        if not ready or item["id"] != ready[0]:
            _fail("dependency-order")
        complete.add(item["id"])
        del remaining[item["id"]]


def validate(value: Any) -> dict[str, Any]:  # noqa: C901
    """Validate a plan without executing any declared command."""
    plan = _object(
        value,
        "schema_version repository evaluated_at domains gates unsupported observations",
    )
    if plan["schema_version"] != 1 or type(plan["schema_version"]) is not int:
        _fail("schema-version")
    evaluated_at = _timestamp(plan["evaluated_at"])
    repository = _repository(plan["repository"])
    if not isinstance(plan["domains"], list) or not 1 <= len(plan["domains"]) <= MAX_DOMAINS:
        _fail("domains")
    domains = [_domain(item) for item in plan["domains"]]
    domain_ids = [item["id"] for item in domains]
    if domain_ids != sorted(set(domain_ids)):
        _fail("domain-order")
    catalog, _ = load_contract_catalog()
    if not isinstance(plan["gates"], list) or len(plan["gates"]) > MAX_GATES:
        _fail("gates")
    gates = [_gate(item, repository, set(domain_ids), set(catalog)) for item in plan["gates"]]
    gate_ids = [item["id"] for item in gates]
    if len(gate_ids) != len(set(gate_ids)):
        _fail("gate-identifiers")
    invariants = [item["invariant"] for item in gates]
    if len(invariants) != len(set(invariants)):
        _fail("duplicate-invariant")
    _ensure_dependencies(gates)
    if not isinstance(plan["unsupported"], list) or len(plan["unsupported"]) > MAX_UNSUPPORTED:
        _fail("unsupported")
    unsupported = [_unsupported(item, set(domain_ids)) for item in plan["unsupported"]]
    unsupported_ids = [item["id"] for item in unsupported]
    unsupported_domains = [item["domain"] for item in unsupported]
    if unsupported_ids != sorted(set(unsupported_ids)) or len(unsupported_domains) != len(
        set(unsupported_domains)
    ):
        _fail("unsupported-order")
    covered = {domain for gate in gates for domain in gate["domains"]}
    declared_unsupported = set(unsupported_domains)
    if covered & declared_unsupported or covered | declared_unsupported != set(domain_ids):
        _fail("domain-coverage")
    if not isinstance(plan["observations"], list) or len(plan["observations"]) > MAX_OBSERVATIONS:
        _fail("observations")
    gate_by_id = {item["id"]: item for item in gates}
    observations: list[dict[str, Any]] = []
    seen_observations: set[str] = set()
    for raw in plan["observations"]:
        item = _object(raw, "gate source status identity")
        gate_id = item["gate"]
        if gate_id not in gate_by_id or gate_id in seen_observations:
            _fail("observation-gate")
        seen_observations.add(gate_id)
        if item["source"] not in OBSERVATION_SOURCES:
            _fail("observation-source")
        if (item["source"] == "native-environment") != (
            gate_by_id[gate_id]["native_mapping"] is not None
        ):
            _fail("observation-source-binding")
        if item["status"] not in OBSERVATION_STATUSES:
            _fail("observation-status")
        identity = validate_identity(item["identity"])
        gate = gate_by_id[gate_id]
        expected_correlation = hashlib.sha256(canonical_bytes(gate["correlation"])).hexdigest()
        if (
            identity["correlation_sha256"] != expected_correlation
            or identity["evidence_class"] != gate["evidence_class"]
            or identity["platform_class"] != gate["correlation"]["platform_class"]
        ):
            _fail("observation-identity")
        collected_at = _timestamp(identity["collected_at"])
        if collected_at > evaluated_at:
            _fail("observation-future")
        freshness = identity["freshness"]
        if (
            freshness is not None
            and (evaluated_at - collected_at).total_seconds() > freshness["max_age_seconds"]
        ):
            _fail("observation-stale")
        observations.append({**item, "identity": identity})
    if [item["gate"] for item in observations] != sorted(seen_observations):
        _fail("observation-order")
    return {
        "schema_version": 1,
        "repository": repository,
        "evaluated_at": plan["evaluated_at"],
        "domains": domains,
        "gates": gates,
        "unsupported": unsupported,
        "observations": observations,
    }


def evaluate(value: Any) -> dict[str, Any]:
    """Return bounded plan coverage without exposing commands or evidence identities."""
    plan = validate(value)
    observations = {item["gate"]: item["status"] for item in plan["observations"]}
    results = [
        {
            "id": gate["id"],
            "status": observations.get(gate["id"], "declared"),
            "evidence_class": gate["evidence_class"],
            "native_gate": "retain" if gate["native_mapping"] is not None else "not-declared",
        }
        for gate in plan["gates"]
    ]
    statuses = {item["status"] for item in results}
    status = (
        "fail"
        if statuses & {"fail", "error", "skip"}
        else ("declared" if not results or "declared" in statuses else "pass")
    )
    return {
        "status": status,
        "schema_version": 1,
        "repository": plan["repository"]["id"],
        "source_commit": plan["repository"]["source_commit"],
        "plan_sha256": hashlib.sha256(canonical_bytes(plan)).hexdigest(),
        "coverage": {
            "domains": len(plan["domains"]),
            "gates": len(plan["gates"]),
            "observed": len(plan["observations"]),
            "unsupported": len(plan["unsupported"]),
        },
        "gates": results,
        "unsupported_domains": sorted(item["domain"] for item in plan["unsupported"]),
        "limitation": (
            "Plan validation does not execute commands or prove downstream domain semantics."
        ),
    }


def load_file(root: Path, relative: str | Path) -> dict[str, Any]:
    path = Path(relative)
    if path.suffix != ".json" or path.is_absolute() or ".." in path.parts:
        _fail("path")
    return validate(strict_json(read_file(root / path, MAX_BYTES)))


def evaluate_file(root: Path, relative: str | Path) -> dict[str, Any]:
    return evaluate(load_file(root, relative))


def diff(base: Any, head: Any) -> dict[str, Any]:
    """Classify deterministic assurance-plan policy changes."""
    before = validate(base)
    after = validate(head)
    changes: list[dict[str, str]] = []
    for field in ("domains", "gates", "unsupported"):
        old = {item["id"]: item for item in before[field]}
        new = {item["id"]: item for item in after[field]}
        for identifier in sorted(set(old) | set(new)):
            if identifier not in new:
                classification = "weakening"
                action = "removed"
            elif identifier not in old:
                classification = "review"
                action = "added"
            elif canonical_bytes(old[identifier]) != canonical_bytes(new[identifier]):
                classification = "review"
                action = "changed"
            else:
                continue
            changes.append(
                {
                    "id": identifier,
                    "section": field,
                    "action": action,
                    "classification": classification,
                }
            )
    return {
        "status": (
            "fail" if any(item["classification"] == "weakening" for item in changes) else "pass"
        ),
        "base_sha256": hashlib.sha256(canonical_bytes(before)).hexdigest(),
        "head_sha256": hashlib.sha256(canonical_bytes(after)).hexdigest(),
        "changes": changes,
        "limitation": "Diff classification does not execute or validate downstream gates.",
    }


def diff_files(root: Path, base: str | Path, head: str | Path) -> dict[str, Any]:
    return diff(load_file(root, base), load_file(root, head))
