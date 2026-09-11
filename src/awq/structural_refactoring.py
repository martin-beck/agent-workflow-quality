# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Read-only verification of bounded, language-neutral structural refactoring plans."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Never

from awq import __version__
from awq.project import ProjectError, confined_path
from awq.registry import canonical_bytes

MAX_BYTES = 500_000
HASH = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){1,8}$")
TOKEN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+){0,7}$")
PATH_PATTERN = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_.-]+)*$")
ROOT_PATTERN = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9_.-]*$")
VERSION = re.compile(
    r"^(?!.*(?:^|[.+-])(?:head|latest|main|master|nightly|release|snapshot|x)(?:$|[.+-]))"
    r"[0-9]+(?:[.][0-9]+){1,3}(?:[-+][0-9a-z.-]+)?$"
)
RISKS = {"low", "medium", "high"}
TRANSFORMATIONS = {
    "api-shape-change",
    "behavior-change",
    "dependency-change",
    "generated-file-change",
    "symbol-rename",
    "syntax-rewrite",
}
SHELLS = {"bash", "cmd", "powershell", "pwsh", "sh", "zsh"}
LIMITATION = (
    "Read-only verification of consumer-supplied identities, budgets, fixtures and convergence; "
    "AWQ does not execute or apply transformations, inspect source, establish language semantics, "
    "or prove behavior preservation. Native gates and consumer review remain required."
)


def _fail(code: str) -> Never:
    raise ProjectError("structural refactoring invalid: " + code)


def _object(value: Any, fields: str) -> dict[str, Any]:
    expected = set(fields.split())
    if not isinstance(value, dict) or set(value) != expected:
        _fail("fields")
    return dict(value)


def _identifier(value: object, prefix: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 100
        or IDENTIFIER.fullmatch(value) is None
        or not value.startswith(prefix + "-")
    ):
        _fail("identifier")
    return value


def _digest(value: object) -> str:
    if not isinstance(value, str) or HASH.fullmatch(value) is None:
        _fail("digest")
    return value


def _commit(value: object) -> str:
    if not isinstance(value, str) or COMMIT.fullmatch(value) is None:
        _fail("commit")
    return value


def _token(value: object) -> str:
    if not isinstance(value, str) or len(value) > 80 or TOKEN.fullmatch(value) is None:
        _fail("token")
    return value


def _path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 240
        or PATH_PATTERN.fullmatch(value) is None
        or "\\" in value
        or "//" in value
    ):
        _fail("path")
    return value


def _root(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 80
        or ROOT_PATTERN.fullmatch(value) is None
    ):
        _fail("include-scope")
    return value


def _sorted_unique(values: Any, minimum: int, maximum: int, parser: Any, code: str) -> list[Any]:
    if not isinstance(values, list) or not minimum <= len(values) <= maximum:
        _fail(code)
    parsed = [parser(item) for item in values]
    if len(parsed) != len(set(parsed)):
        _fail(code)
    return sorted(parsed)


def _tool(value: Any, prefix: str) -> dict[str, str]:
    item = _object(value, "id version sha256")
    identifier = _identifier(item["id"], prefix)
    if not isinstance(item["version"], str) or VERSION.fullmatch(item["version"]) is None:
        _fail("tool-version")
    return {"id": identifier, "version": item["version"], "sha256": _digest(item["sha256"])}


def _scope(value: Any) -> dict[str, dict[str, dict[str, list[str]]]]:
    item = _object(value, "include_roots")
    raw_roots = item["include_roots"]
    if not isinstance(raw_roots, dict) or not 1 <= len(raw_roots) <= 128:
        _fail("include-scope")
    roots: dict[str, dict[str, list[str]]] = {}
    for raw_include, raw_entry in raw_roots.items():
        include = _root(raw_include)
        entry = _object(raw_entry, "exclude_relative_paths")
        roots[include] = {
            "exclude_relative_paths": _sorted_unique(
                entry["exclude_relative_paths"], 0, 128, _path, "exclude-scope"
            )
        }
    return {"include_roots": {include: roots[include] for include in sorted(roots)}}


def _commitments(value: Any, prefix: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        _fail("commitment-bound")
    result = []
    identities = []
    for raw in value:
        item = _object(raw, "id evidence_sha256")
        identifier = _identifier(item["id"], prefix)
        identities.append(identifier)
        result.append({"id": identifier, "evidence_sha256": _digest(item["evidence_sha256"])})
    if len(identities) != len(set(identities)):
        _fail("commitment-order")
    return sorted(result, key=lambda record: record["id"])


def _fixture(value: Any) -> dict[str, str]:
    item = _object(value, "id path sha256")
    return {
        "id": _identifier(item["id"], "FIXTURE"),
        "path": _path(item["path"]),
        "sha256": _digest(item["sha256"]),
    }


def _fixtures(value: Any) -> tuple[dict[str, list[dict[str, str]]], list[str]]:
    item = _object(value, "positive negative golden")
    result: dict[str, list[dict[str, str]]] = {}
    all_ids: list[str] = []
    all_paths: list[str] = []
    for kind in ("positive", "negative", "golden"):
        raw = item[kind]
        if not isinstance(raw, list) or not 1 <= len(raw) <= 32:
            _fail("fixture-bound")
        records = [_fixture(entry) for entry in raw]
        identities = [entry["id"] for entry in records]
        paths = [entry["path"] for entry in records]
        if len(identities) != len(set(identities)) or len(paths) != len(set(paths)):
            _fail("fixture-order")
        result[kind] = sorted(records, key=lambda record: record["id"])
        all_ids.extend(identities)
        all_paths.extend(paths)
    if len(all_ids) != len(set(all_ids)) or len(all_paths) != len(set(all_paths)):
        _fail("fixture-duplicate")
    digests = [record["sha256"] for records in result.values() for record in records]
    if len(digests) != len(set(digests)):
        _fail("fixture-digest-duplicate")
    return result, sorted(all_ids)


def _argv(value: Any) -> list[list[str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        _fail("command-bound")
    result = []
    for raw in value:
        if not isinstance(raw, list) or not 1 <= len(raw) <= 32:
            _fail("command-array")
        if any(
            not isinstance(argument, str)
            or not 1 <= len(argument) <= 200
            or "\n" in argument
            or "\r" in argument
            or "\x00" in argument
            for argument in raw
        ):
            _fail("command-argument")
        if TOKEN.fullmatch(raw[0]) is None or raw[0] in SHELLS:
            _fail("command-executable")
        result.append(list(raw))
    return result


def _budgets(value: Any) -> dict[str, int]:
    item = _object(value, "max_files max_changed_lines max_matches max_seconds")
    limits = {
        "max_files": 1000,
        "max_changed_lines": 100_000,
        "max_matches": 100_000,
        "max_seconds": 3600,
    }
    for key, maximum in limits.items():
        if type(item[key]) is not int or not 1 <= item[key] <= maximum:
            _fail("budget")
    return item


def _recipe(value: Any) -> tuple[dict[str, Any], list[str], set[str]]:
    item = _object(
        value,
        "id tool parser language scope prohibited_classes risk behavior_claim preconditions "
        "invariants budgets fixtures verification application",
    )
    identifier = _identifier(item["id"], "RECIPE")
    tool = _tool(item["tool"], "TOOL")
    parser = _tool(item["parser"], "PARSER")
    language = _token(item["language"])
    scope = _scope(item["scope"])
    prohibited = _sorted_unique(
        item["prohibited_classes"], 1, len(TRANSFORMATIONS), _token, "prohibited-class"
    )
    if not set(prohibited) <= TRANSFORMATIONS or "behavior-change" not in prohibited:
        _fail("prohibited-class")
    if not isinstance(item["risk"], str) or item["risk"] not in RISKS:
        _fail("risk")
    behavior = _object(item["behavior_claim"], "kind evidence_refs")
    if behavior["kind"] != "consumer-evidence-required":
        _fail("behavior-claim")
    evidence_refs = _sorted_unique(
        behavior["evidence_refs"],
        1,
        64,
        lambda value: _identifier(value, "EVIDENCE"),
        "evidence-ref",
    )
    preconditions = _commitments(item["preconditions"], "PRECONDITION")
    invariants = _commitments(item["invariants"], "INVARIANT")
    budgets = _budgets(item["budgets"])
    fixtures, fixture_ids = _fixtures(item["fixtures"])
    verification = _object(item["verification"], "focused_argv full_argv")
    if item["application"] != "read-only-verification":
        _fail("application")
    focused_argv = _argv(verification["focused_argv"])
    full_argv = _argv(verification["full_argv"])
    if focused_argv == full_argv:
        _fail("verification-command-duplicate")
    normalized = {
        **item,
        "id": identifier,
        "tool": tool,
        "parser": parser,
        "language": language,
        "scope": scope,
        "prohibited_classes": prohibited,
        "behavior_claim": {"kind": behavior["kind"], "evidence_refs": evidence_refs},
        "preconditions": preconditions,
        "invariants": invariants,
        "budgets": budgets,
        "fixtures": fixtures,
        "verification": {
            "focused_argv": focused_argv,
            "full_argv": full_argv,
        },
    }
    return normalized, fixture_ids, set(prohibited)


def _counts(item: dict[str, Any], budgets: dict[str, int]) -> None:
    for key, budget_key in (
        ("changed_files", "max_files"),
        ("changed_lines", "max_changed_lines"),
        ("matches", "max_matches"),
        ("elapsed_seconds", "max_seconds"),
    ):
        if type(item[key]) is not int or not 0 <= item[key] <= budgets[budget_key]:
            _fail("budget-exceeded")
    if not item["changed_files"] or not item["changed_lines"] or not item["matches"]:
        _fail("empty-transformation")


def _fixture_results(value: Any, fixture_ids: list[str]) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 3 <= len(value) <= 96:
        _fail("fixture-result-bound")
    results = []
    result_ids = []
    for raw in value:
        record = _object(raw, "id status evidence_sha256")
        identifier = _identifier(record["id"], "FIXTURE")
        if record["status"] != "pass":
            _fail("fixture-failure")
        result_ids.append(identifier)
        results.append(
            {
                "id": identifier,
                "status": "pass",
                "evidence_sha256": _digest(record["evidence_sha256"]),
            }
        )
    if sorted(result_ids) != fixture_ids:
        _fail("fixture-result-coverage")
    digests = [result["evidence_sha256"] for result in results]
    if len(digests) != len(set(digests)):
        _fail("fixture-result-digest-duplicate")
    return sorted(results, key=lambda record: record["id"])


def _result(
    value: Any,
    contract: dict[str, Any],
    budgets: dict[str, int],
    fixture_ids: list[str],
    prohibited: set[str],
) -> dict[str, Any]:
    item = _object(
        value,
        "plan_id recipe_sha256 base_commit catalog_sha256 input_tree_sha256 output_tree_sha256 "
        "changed_files "
        "changed_lines matches elapsed_seconds transformation_classes fixture_results "
        "second_plan_output_sha256 convergence evidence_sha256",
    )
    identities = (
        (_identifier(item["plan_id"], "PLAN"), contract["plan_id"], "plan-mismatch"),
        (_digest(item["recipe_sha256"]), contract["recipe_sha256"], "recipe-mismatch"),
        (_commit(item["base_commit"]), contract["base_commit"], "stale-base"),
        (_digest(item["catalog_sha256"]), contract["catalog_sha256"], "catalog-drift"),
        (_digest(item["input_tree_sha256"]), contract["input_tree_sha256"], "input-drift"),
        (
            _digest(item["output_tree_sha256"]),
            contract["proposed_output_tree_sha256"],
            "output-mismatch",
        ),
    )
    for observed, expected, code in identities:
        if observed != expected:
            _fail(code)
    _counts(item, budgets)
    classes = _sorted_unique(
        item["transformation_classes"], 1, len(TRANSFORMATIONS), _token, "transformation-class"
    )
    if not set(classes) <= TRANSFORMATIONS or set(classes) & prohibited:
        _fail("prohibited-transformation")
    results = _fixture_results(item["fixture_results"], fixture_ids)
    if (
        _digest(item["second_plan_output_sha256"]) != contract["proposed_output_tree_sha256"]
        or item["convergence"] != "converged"
    ):
        _fail("non-convergence")
    return {
        **item,
        "transformation_classes": classes,
        "fixture_results": results,
        "evidence_sha256": _digest(item["evidence_sha256"]),
    }


def evaluate(value: Any) -> dict[str, Any]:
    """Validate one plan and observed result without executing or mutating consumer code."""
    contract = _object(
        value,
        "schema_version kind plan_id base_commit catalog_sha256 input_tree_sha256 "
        "proposed_output_tree_sha256 recipe_sha256 recipe native_mapping result",
    )
    if (
        type(contract["schema_version"]) is not int
        or contract["schema_version"] != 1
        or contract["kind"] != "structural-refactoring-plan"
    ):
        _fail("kind-or-version")
    plan_id = _identifier(contract["plan_id"], "PLAN")
    base_commit = _commit(contract["base_commit"])
    catalog_sha256 = _digest(contract["catalog_sha256"])
    input_tree_sha256 = _digest(contract["input_tree_sha256"])
    output_tree_sha256 = _digest(contract["proposed_output_tree_sha256"])
    if input_tree_sha256 == output_tree_sha256:
        _fail("unchanged-output")
    recipe, fixture_ids, prohibited = _recipe(contract["recipe"])
    recipe_sha256 = hashlib.sha256(canonical_bytes(recipe)).hexdigest()
    if _digest(contract["recipe_sha256"]) != recipe_sha256:
        _fail("recipe-digest")
    mapping = _object(contract["native_mapping"], "family contract_sha256 retained")
    family = _token(mapping["family"])
    if type(mapping["retained"]) is not bool or not mapping["retained"]:
        _fail("native-gate")
    native_contract = _digest(mapping["contract_sha256"])
    normalized_contract = {
        **contract,
        "plan_id": plan_id,
        "base_commit": base_commit,
        "catalog_sha256": catalog_sha256,
        "input_tree_sha256": input_tree_sha256,
        "proposed_output_tree_sha256": output_tree_sha256,
        "recipe_sha256": recipe_sha256,
        "recipe": recipe,
        "native_mapping": {
            "family": family,
            "contract_sha256": native_contract,
            "retained": True,
        },
    }
    result = _result(
        contract["result"], normalized_contract, recipe["budgets"], fixture_ids, prohibited
    )
    normalized_contract["result"] = result
    return {
        "status": "pass",
        "schema_version": 1,
        "awq_version": __version__,
        "kind": "structural-refactoring-verification",
        "plan_id": plan_id,
        "recipe_id": recipe["id"],
        "recipe_sha256": recipe_sha256,
        "language": recipe["language"],
        "risk": recipe["risk"],
        "execution": "read-only",
        "base_commit": base_commit,
        "catalog_sha256": catalog_sha256,
        "input_tree_sha256": input_tree_sha256,
        "output_tree_sha256": output_tree_sha256,
        "verification_sha256": hashlib.sha256(canonical_bytes(normalized_contract)).hexdigest(),
        "result_evidence_sha256": result["evidence_sha256"],
        "fixture_result_set_sha256": hashlib.sha256(
            canonical_bytes(result["fixture_results"])
        ).hexdigest(),
        "changed_files": result["changed_files"],
        "changed_lines": result["changed_lines"],
        "matches": result["matches"],
        "convergence": "converged",
        "native_mapping": {
            "family": family,
            "contract_sha256": native_contract,
            "retained": True,
        },
        "native_gate": "retain",
        "application": "read-only-verification",
        "limitation": LIMITATION,
    }


def evaluate_file(root: Path, relative: str) -> dict[str, Any]:
    """Load one canonical, confined plan and return content-minimized evidence."""
    try:
        path = confined_path(root, _path(relative))
        raw = path.read_bytes()
        if not raw or len(raw) > MAX_BYTES:
            _fail("byte-bound")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object_pairs)
        if raw != canonical_bytes(value):
            _fail("canonical-json")
        return evaluate(value)
    except ProjectError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ProjectError("structural refactoring input is invalid or unavailable") from error


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate-key")
        result[key] = value
    return result
