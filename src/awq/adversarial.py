# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Deterministic synthetic adversarial campaigns with independent construction-based oracles."""

from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from awq import __version__, adapters, checks, commands, project, sbom
from awq.registry import canonical_bytes
from awq.sbom import strict_json
from awq.trust import read_file

OPERATORS = {
    "paths": ("safe", "traversal", "absolute", "symlink"),
    "policies": ("valid", "unknown", "duplicate-profile", "unsafe-fixture"),
    "schemas": ("valid", "unknown", "boolean-timeout", "missing"),
    "parsers": ("canonical", "duplicate", "noncanonical", "nonfinite", "truncated"),
    "workflows": ("pinned", "floating", "missing-permissions", "missing-timeout"),
    "redaction": ("clean", "credential", "workflow-credential"),
    "weakening": ("unchanged", "relax-formats", "strengthen-formats", "exclude-fixture"),
}
MUTATIONS = {
    "paths": "drop-path-check",
    "policies": "allow-unknown-policy",
    "schemas": "allow-unknown-schema",
    "parsers": "permissive-json",
    "workflows": "drop-workflow-dispatch",
    "redaction": "echo-private-result",
    "weakening": "suppress-weakening",
}
PROFILES = {"pr": 4, "scheduled": 32}
MAX_REPRODUCERS = 32
LIMITATION = (
    "Synthetic bounded generated cases and seven reviewed boundary fault injections only. "
    "The score is not whole-program source mutation coverage, exhaustive fuzzing, a sandbox, "
    "or proof of privacy or correctness for arbitrary inspected content. Native gates retained."
)


@dataclass(frozen=True)
class Case:
    """A public-safe recipe, never an inspected source value."""

    family: str
    operator: str
    variant: int

    def json(self) -> dict[str, Any]:
        return {"family": self.family, "operator": self.operator, "variant": self.variant}


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def validate(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "profile",
        "seed",
        "samples_per_operator",
        "mutation_threshold",
    }:
        raise project.ProjectError("adversarial contract fields are invalid")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise project.ProjectError("adversarial contract version is invalid")
    profile = value["profile"]
    if not isinstance(profile, str) or profile not in PROFILES:
        raise project.ProjectError("adversarial profile is unsupported")
    if type(value["seed"]) is not int or not 0 <= value["seed"] <= 2**31 - 1:
        raise project.ProjectError("adversarial seed is outside the bound")
    if (
        type(value["samples_per_operator"]) is not int
        or value["samples_per_operator"] != PROFILES[profile]
    ):
        raise project.ProjectError("adversarial campaign bounds cannot be weakened")
    if value["mutation_threshold"] != {"numerator": 7, "denominator": 7} or any(
        type(number) is not int for number in value["mutation_threshold"].values()
    ):
        raise project.ProjectError("adversarial critical mutation floor must be seven of seven")
    return dict(value)


def generate(contract: dict[str, Any]) -> list[Case]:
    """LCG profile v1 fixes integer arithmetic and iteration order across Python versions."""
    value = validate(contract)
    cursor = value["seed"]
    cases = []
    for family, operators in OPERATORS.items():
        for operator in operators:
            for _ in range(value["samples_per_operator"]):
                cursor = (1664525 * cursor + 1013904223) % 2**32
                cases.append(Case(family, operator, 1 + cursor % 32))
    return cases


def oracle(case: Case) -> str:
    """Expected labels follow reviewed construction tags, not the production validator."""
    if case.family == "weakening":
        return {
            "unchanged": "none",
            "relax-formats": "weakening",
            "strengthen-formats": "strengthening",
            "exclude-fixture": "weakening",
        }[case.operator]
    return (
        "accept" if case.operator in {"safe", "valid", "canonical", "pinned", "clean"} else "reject"
    )


def _policy(case: Case, mutant: bool) -> str:
    value, _ = project.make_policy(["core"])
    if case.operator == "unknown":
        value["unreviewed_field"] = case.variant
        if mutant:
            del value["unreviewed_field"]
    elif case.operator == "duplicate-profile":
        value["profiles"] *= 2
    elif case.operator == "unsafe-fixture":
        value["fixture_paths"] = ["../" + "p" * case.variant]
    project.validate_policy(value)
    return "accept"


def _schema(case: Case, mutant: bool) -> str:
    value: dict[str, Any] = {
        "id": "ADAPTER-SYNTHETIC-CHECK",
        "tool": "synthetic",
        "version": "1",
        "version_argv": ["synthetic", "--version"],
        "version_output": "synthetic 1",
        "argv": ["synthetic", "check"],
        "timeout_seconds": case.variant,
        "tier": "pr",
        "evidence": "mechanical",
        "limitation": "Synthetic schema validation only.",
        "remediation": "Review the synthetic contract.",
        "formats": [".json"],
        "config_paths": [],
    }
    if case.operator == "unknown":
        value["unreviewed_field"] = case.variant
        if mutant:
            del value["unreviewed_field"]
    elif case.operator == "boolean-timeout":
        value["timeout_seconds"] = True
    elif case.operator == "missing":
        del value["tool"]
    adapters.validate_adapter(value)
    return "accept"


def _parser(case: Case, mutant: bool) -> str:
    canonical = canonical_bytes({"value": case.variant})
    raw = {
        "canonical": canonical,
        "duplicate": b'{"value":0,"value":' + str(case.variant).encode() + b"}\n",
        "noncanonical": b" " + canonical,
        "nonfinite": b'{"value":NaN}\n',
        "truncated": canonical[:-2],
    }[case.operator]
    if mutant:
        json.loads(raw)
    else:
        strict_json(raw)
    return "accept"


def _path(case: Case, root: Path, mutant: bool) -> str:
    name = "p" * case.variant + ".json"
    (root / name).write_bytes(b"{}\n")
    if case.operator == "symlink":
        (root / "link.json").symlink_to(root / name)
        name = "link.json"
    elif case.operator == "traversal":
        name = "../" + name
    elif case.operator == "absolute":
        name = "/AWQ-SYNTHETIC/" + name
    if not mutant:
        project.confined_path(root, name)
    return "accept"


def _requirement(root: Path, path: Path, command: str) -> dict[str, Any]:
    policy, _ = project.make_policy(["core"])
    requirement = {
        "id": "AWQ-GHA-001",
        "command": command,
        "evidence": "mechanical",
        "limitation": "Synthetic gate sensitivity.",
        "remediation": "Review the gate.",
    }
    return checks.run_requirement(root, policy, requirement, [path])


def _workflow(case: Case, root: Path, mutant: bool) -> str:
    path = root / ".github/workflows/verify.yml"
    path.parent.mkdir(parents=True)
    ref = "v" + str(case.variant) if case.operator == "floating" else "a" * 40
    text = "permissions: {}\njobs:\n  test:\n    timeout-minutes: 2\n    steps:\n"
    text += "      - uses: public/action@" + ref + "\n"
    if case.operator == "missing-permissions":
        text = text.replace("permissions: {}\n", "")
    elif case.operator == "missing-timeout":
        text = text.replace("    timeout-minutes: 2\n", "")
    path.write_text(text)
    if mutant:
        return "accept"
    records = [_requirement(root, path, command) for command in ("action-pins", "workflow-policy")]
    return "reject" if any(record["status"] == "fail" for record in records) else "accept"


def _redaction(case: Case, root: Path, mutant: bool) -> str:
    marker = "gh" + "p_" + "A" * (20 + case.variant)
    if case.operator == "workflow-credential":
        path = root / ".github/workflows/verify.yml"
        path.parent.mkdir(parents=True)
        path.write_text("steps:\n  - uses: public/action@" + marker + "\n")
        command = "action-pins"
    else:
        path = root / "public.txt"
        path.write_text("public synthetic text\n" if case.operator == "clean" else marker + "\n")
        command = "privacy-patterns"
    record = _requirement(root, path, command)
    serialized = canonical_bytes(record).decode() + (marker if mutant else "")
    if marker in serialized:
        return "leak"
    return "reject" if record["status"] == "fail" else "accept"


def _weakening(case: Case, mutant: bool) -> str:
    old, _ = project.make_policy(["core"])
    new, _ = project.make_policy(["core"])
    if case.operator == "relax-formats":
        new["unknown_formats"] = "advisory"
    elif case.operator == "strengthen-formats":
        old["unknown_formats"] = "advisory"
    elif case.operator == "exclude-fixture":
        new["fixture_paths"] = ["public-" + str(case.variant)]
    changes: list[dict[str, str]] = []
    commands._compare_policy(old, new, changes)
    kinds = {change["classification"] for change in changes}
    if mutant:
        kinds.discard("weakening")
    return (
        "weakening"
        if "weakening" in kinds
        else "strengthening"
        if "strengthening" in kinds
        else "none"
    )


def observe(case: Case, scratch: Path, mutant: bool = False) -> str:
    """Run only fixed synthetic validators; no arbitrary programs or repositories are inspected."""
    with tempfile.TemporaryDirectory(prefix="awq-case-", dir=scratch) as directory:
        root = Path(directory)
        try:
            if case.family == "paths":
                return _path(case, root, mutant)
            if case.family == "policies":
                return _policy(case, mutant)
            if case.family == "schemas":
                return _schema(case, mutant)
            if case.family == "parsers":
                return _parser(case, mutant)
            if case.family == "workflows":
                return _workflow(case, root, mutant)
            if case.family == "redaction":
                return _redaction(case, root, mutant)
            return _weakening(case, mutant)
        except (project.ProjectError, adapters.AdapterError, ValueError):
            return "reject"


def minimize(case: Case, scratch: Path) -> Case:
    """Find the first still-failing variant in the explicitly finite family order."""
    for variant in range(1, case.variant + 1):
        candidate = Case(case.family, case.operator, variant)
        if observe(candidate, scratch) != oracle(candidate):
            return candidate
    return case


def campaign(value: Any, scratch: Path) -> dict[str, Any]:
    """Require all baseline properties and all seven critical boundary fault detections."""
    contract = validate(value)
    _scratch(scratch)
    cases = generate(contract)
    failures: dict[tuple[str, str], dict[str, Any]] = {}
    counts = dict.fromkeys(OPERATORS, 0)
    for case in cases:
        counts[case.family] += 1
        if observe(case, scratch) != oracle(case) and (case.family, case.operator) not in failures:
            reduced = minimize(case, scratch)
            failures[(case.family, case.operator)] = {
                **reduced.json(),
                "schema_version": 1,
                "case_sha256": _digest(reduced.json()),
                "code": "oracle-mismatch",
            }
    mutations = []
    for family, name in MUTATIONS.items():
        killed = any(
            observe(case, scratch, True) != oracle(case) for case in cases if case.family == family
        )
        mutations.append({"id": name, "status": "killed" if killed else "survived"})
    killed_count = sum(record["status"] == "killed" for record in mutations)
    reproducers = [failures[key] for key in sorted(failures)]
    return {
        "schema_version": 1,
        "awq_version": __version__,
        "status": "pass" if not failures and killed_count == 7 else "fail",
        "profile": contract["profile"],
        "seed": contract["seed"],
        "samples_per_operator": contract["samples_per_operator"],
        "cases": len(cases),
        "family_counts": counts,
        "corpus_sha256": _digest([case.json() for case in cases]),
        "contract_sha256": _digest(contract),
        "engine_sha256": hashlib.sha256(read_file(Path(__file__), 1_000_000)).hexdigest(),
        "target_sha256": _targets(),
        "mutation_kind": "reviewed-boundary-fault-injection",
        "mutation_score_valid": not failures,
        "mutation_score": {"numerator": killed_count, "denominator": 7},
        "mutations": mutations,
        "reproducers": reproducers[:MAX_REPRODUCERS],
        "native_gate": "retain",
        "limitation": LIMITATION,
    }


def run_file(root: Path, relative: str, scratch: Path) -> dict[str, Any]:
    """Read one confined canonical public campaign request with minimized error output."""
    try:
        path = project.confined_path(root, relative)
        return campaign(strict_json(read_file(path, 100_000)), scratch)
    except Exception as error:
        raise project.ProjectError("adversarial request is invalid or unavailable") from error


def _case(value: Any) -> Case:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "family",
        "operator",
        "variant",
        "case_sha256",
        "code",
    }:
        raise project.ProjectError("adversarial reproducer fields are invalid")
    family = value["family"]
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or not isinstance(family, str)
        or family not in OPERATORS
        or value["operator"] not in OPERATORS[family]
        or type(value["variant"]) is not int
        or not 1 <= value["variant"] <= 32
        or value["code"] != "oracle-mismatch"
    ):
        raise project.ProjectError("adversarial reproducer profile is invalid")
    case = Case(family, value["operator"], value["variant"])
    if value["case_sha256"] != _digest(case.json()):
        raise project.ProjectError("adversarial reproducer digest differs")
    return case


def replay_file(root: Path, relative: str, scratch: Path) -> dict[str, Any]:
    """Reconstruct only a reviewed public recipe; never accept raw fuzz bytes or code."""
    try:
        case = _case(strict_json(read_file(project.confined_path(root, relative), 10_000)))
        _scratch(scratch)
        observed = observe(case, scratch)
        return {
            "schema_version": 1,
            "status": "pass" if observed == oracle(case) else "fail",
            "case_sha256": _digest(case.json()),
            "expected": oracle(case),
            "observed": observed,
            "native_gate": "retain",
            "limitation": LIMITATION,
        }
    except Exception as error:
        raise project.ProjectError("adversarial reproducer is invalid or unavailable") from error


def _scratch(path: Path) -> None:
    if not path.is_absolute() or path.resolve(strict=True) != path or not path.is_dir():
        raise project.ProjectError("adversarial scratch must be an existing canonical directory")


def _targets() -> dict[str, str]:
    return {
        module.__name__: _source_digest(module.__file__)
        for module in (adapters, checks, commands, project, sbom)
    }


def _source_digest(filename: str | None) -> str:
    if filename is None:
        raise project.ProjectError("adversarial target source is unavailable")
    return hashlib.sha256(read_file(Path(filename), 1_000_000)).hexdigest()
