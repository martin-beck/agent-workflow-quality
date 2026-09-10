# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Strict native-gate mapping contracts and content-minimized equivalence evidence."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Never

from awq import __version__
from awq.adapters import load_adapter_catalog
from awq.project import ProjectError
from awq.registry import EVIDENCE_CLASSES, TIERS, canonical_bytes, load_registry
from awq.release import ReleaseError
from awq.sbom import strict_json
from awq.trust import read_file

MAX_BYTES = 256_000
MAX_MAPPINGS = 256
HASH = re.compile(r"[0-9a-f]{64}", re.ASCII)
IDENTIFIER = re.compile(r"NATIVE-[A-Z0-9]+(?:-[A-Z0-9]+)*", re.ASCII)
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}", re.ASCII)
SCOPE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*", re.ASCII)
CLAIM = "bounded-equivalence-not-certification"
STATUSES = ("pass", "fail", "error", "skip")
PLATFORM_CLASSES = ("native", "emulated", "hosted-portability", "build-only", "partial")
PRIVATE_MARKERS = ("/home/", "/users/", "token=", "password=", "secret=", "authorization:")
RUN_ID = re.compile(r"RUN-[A-Z0-9]+(?:-[A-Z0-9]+)*", re.ASCII)
TIMESTAMP = re.compile(
    r"20[0-9]{2}-(?:0[1-9]|1[0-2])-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", re.ASCII
)
OBSERVATION_SET = re.compile(r"SET-[A-Z0-9]+(?:-[A-Z0-9]+)*", re.ASCII)


def _fail(code: str) -> Never:
    raise ProjectError("native-gate mapping invalid: " + code)


def _object(value: Any, keys: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys.split()):
        _fail("fields")
    return dict(value)


def _text(value: Any, *, limit: int = 500) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        _fail("text")
    if any(ord(character) < 32 for character in value):
        _fail("text")
    if any(marker in value.casefold() for marker in PRIVATE_MARKERS):
        _fail("private-text")
    return value


def _tool_pin(value: Any) -> dict[str, str]:
    pin = _object(value, "name version sha256")
    if (
        not isinstance(pin["name"], str)
        or not isinstance(pin["version"], str)
        or TOKEN.fullmatch(pin["name"]) is None
        or TOKEN.fullmatch(pin["version"]) is None
    ):
        _fail("tool-pin")
    if not isinstance(pin["sha256"], str) or HASH.fullmatch(pin["sha256"]) is None:
        _fail("tool-pin")
    return {key: str(pin[key]) for key in ("name", "version", "sha256")}


def _command(value: Any, tool: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        _fail("native-command")
    command: list[str] = []
    for argument in value:
        if not isinstance(argument, str) or not argument or len(argument) > 200:
            _fail("native-command")
        if any(ord(character) < 32 for character in argument):
            _fail("native-command")
        if argument.startswith(("/", "~")) or ".." in argument.split("/"):
            _fail("native-command")
        if "://" in argument or any(marker in argument for marker in ("$", "`", "\n", "\r")):
            _fail("native-command")
        if any(marker in argument.casefold() for marker in PRIVATE_MARKERS):
            _fail("private-command")
        command.append(argument)
    if command[0] != tool:
        _fail("native-command-tool")
    return command


def _awq_result(value: Any, requirement: str, adapters: set[str]) -> dict[str, str]:
    result = _object(value, "kind identifier")
    if not isinstance(result["kind"], str) or not isinstance(result["identifier"], str):
        _fail("awq-result")
    if result["kind"] == "requirement" and result["identifier"] == requirement:
        return {"kind": "requirement", "identifier": requirement}
    if result["kind"] == "adapter" and result["identifier"] in adapters:
        return {"kind": "adapter", "identifier": str(result["identifier"])}
    _fail("awq-result")


def _mapping(
    value: Any, requirements: dict[str, dict[str, Any]], adapters: set[str]
) -> dict[str, Any]:
    mapping = _object(
        value,
        "id requirement awq_result native_command tool_pin tier evidence_class input_scope "
        "deadline_seconds limitation claim",
    )
    identifier = mapping["id"]
    requirement = mapping["requirement"]
    if not isinstance(identifier, str) or IDENTIFIER.fullmatch(identifier) is None:
        _fail("mapping-id")
    if not isinstance(requirement, str) or requirement not in requirements:
        _fail("requirement")
    pin = _tool_pin(mapping["tool_pin"])
    if mapping["tier"] not in TIERS or mapping["tier"] != requirements[requirement]["tier"]:
        _fail("tier")
    if (
        not isinstance(mapping["evidence_class"], str)
        or mapping["evidence_class"] not in EVIDENCE_CLASSES
    ):
        _fail("evidence-class")
    if (
        not isinstance(mapping["input_scope"], str)
        or SCOPE.fullmatch(mapping["input_scope"]) is None
    ):
        _fail("input-scope")
    if type(mapping["deadline_seconds"]) is not int or not 1 <= mapping["deadline_seconds"] <= 900:
        _fail("deadline")
    if mapping["claim"] != CLAIM:
        _fail("certification-claim")
    return {
        **mapping,
        "awq_result": _awq_result(mapping["awq_result"], requirement, adapters),
        "native_command": _command(mapping["native_command"], pin["name"]),
        "tool_pin": pin,
        "limitation": _text(mapping["limitation"]),
    }


def _correlation(value: Any) -> dict[str, Any]:
    correlation = _object(
        value,
        "observation_set_id source_commit source_tree reviewed_base tree_state "
        "gate_definition_sha256 configuration_sha256 input_sha256 platform_class",
    )
    if (
        not isinstance(correlation["observation_set_id"], str)
        or len(correlation["observation_set_id"]) > 100
        or OBSERVATION_SET.fullmatch(correlation["observation_set_id"]) is None
    ):
        _fail("observation-set")
    for field in ("source_commit", "source_tree", "reviewed_base"):
        if (
            not isinstance(correlation[field], str)
            or re.fullmatch(r"[0-9a-f]{40}", correlation[field]) is None
        ):
            _fail("correlation-source")
    if correlation["tree_state"] != "clean":
        _fail("correlation-tree-state")
    for field in ("gate_definition_sha256", "configuration_sha256", "input_sha256"):
        if not isinstance(correlation[field], str) or HASH.fullmatch(correlation[field]) is None:
            _fail("correlation-digest")
    if correlation["platform_class"] not in PLATFORM_CLASSES:
        _fail("correlation-platform-class")
    return correlation


def _mapping_v2(
    value: Any, requirements: dict[str, dict[str, Any]], adapters: set[str]
) -> dict[str, Any]:
    mapping = _object(
        value,
        "id requirement awq_result native_command tool_pin tier evidence_class input_scope "
        "deadline_seconds limitation claim correlation",
    )
    base = _mapping(
        {key: item for key, item in mapping.items() if key != "correlation"}, requirements, adapters
    )
    return {**base, "correlation": _correlation(mapping["correlation"])}


def _observation(value: Any, mapping_ids: set[str]) -> dict[str, str]:
    observation = _object(value, "mapping source status evidence_sha256")
    if not isinstance(observation["mapping"], str) or observation["mapping"] not in mapping_ids:
        _fail("observation-mapping")
    if not isinstance(observation["source"], str) or observation["source"] not in (
        "native-gate",
        "awq-requirement",
        "awq-adapter",
    ):
        _fail("observation-source")
    if not isinstance(observation["status"], str) or observation["status"] not in STATUSES:
        _fail("observation-status")
    digest = observation["evidence_sha256"]
    if not isinstance(digest, str) or HASH.fullmatch(digest) is None:
        _fail("observation-digest")
    return {key: str(observation[key]) for key in observation}


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        _fail("timestamp")
    try:
        observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ProjectError("native-gate mapping invalid: timestamp") from error
    if observed.tzinfo != UTC:
        _fail("timestamp")
    return observed


def validate_identity(value: Any) -> dict[str, Any]:
    """Validate and normalize one content-minimized evidence identity envelope."""
    identity = _object(
        value,
        "schema_version correlation_sha256 producer_sha256 tool_sha256 run_id attempt "
        "evidence_class platform_class collected_at freshness evidence_sha256",
    )
    if type(identity["schema_version"]) is not int or identity["schema_version"] != 1:
        _fail("identity-schema-version")
    for field in (
        "correlation_sha256",
        "producer_sha256",
        "tool_sha256",
        "evidence_sha256",
    ):
        if not isinstance(identity[field], str) or HASH.fullmatch(identity[field]) is None:
            _fail("identity-digest")
    if (
        not isinstance(identity["run_id"], str)
        or len(identity["run_id"]) > 100
        or RUN_ID.fullmatch(identity["run_id"]) is None
    ):
        _fail("identity-run")
    if type(identity["attempt"]) is not int or not 1 <= identity["attempt"] <= 10_000:
        _fail("identity-attempt")
    if identity["evidence_class"] not in EVIDENCE_CLASSES:
        _fail("identity-evidence-class")
    if identity["platform_class"] not in PLATFORM_CLASSES:
        _fail("identity-platform-class")
    _timestamp(identity["collected_at"])
    freshness = identity["freshness"]
    if freshness is not None:
        freshness = _object(freshness, "max_age_seconds")
        if (
            type(freshness["max_age_seconds"]) is not int
            or not 1 <= freshness["max_age_seconds"] <= 2_678_400
        ):
            _fail("identity-freshness")
    return {**identity, "freshness": freshness}


def _observation_v2(value: Any, mapping_ids: set[str]) -> dict[str, Any]:
    observation = _object(value, "mapping source status identity")
    common = _observation(
        {
            "mapping": observation["mapping"],
            "source": observation["source"],
            "status": observation["status"],
            "evidence_sha256": "0" * 64,
        },
        mapping_ids,
    )
    return {key: common[key] for key in ("mapping", "source", "status")} | {
        "identity": validate_identity(observation["identity"])
    }


def _correlation_mismatches(
    awq: dict[str, Any], native: dict[str, Any], mapping: dict[str, Any], evaluated_at: datetime
) -> list[str]:
    awq_identity = awq["identity"]
    native_identity = native["identity"]
    correlation_sha256 = hashlib.sha256(canonical_bytes(mapping["correlation"])).hexdigest()
    mismatches: list[str] = []
    for source, identity in (("awq", awq_identity), ("native", native_identity)):
        if identity["correlation_sha256"] != correlation_sha256:
            mismatches.append(source + "-correlation")
        if identity["evidence_class"] != mapping["evidence_class"]:
            mismatches.append(source + "-evidence-class")
        if identity["platform_class"] != mapping["correlation"]["platform_class"]:
            mismatches.append(source + "-platform-class-promotion")
    if native_identity["tool_sha256"] != mapping["tool_pin"]["sha256"]:
        mismatches.append("native-tool-pin")
    for source, identity in (("awq", awq_identity), ("native", native_identity)):
        collected_at = _timestamp(identity["collected_at"])
        if collected_at > evaluated_at:
            mismatches.append(source + "-collected-in-future")
        freshness = identity["freshness"]
        if (
            freshness is not None
            and (evaluated_at - collected_at).total_seconds() > freshness["max_age_seconds"]
        ):
            mismatches.append(source + "-stale")
    return sorted(set(mismatches))


def _evaluate_v1(document: dict[str, Any]) -> dict[str, Any]:
    return _evaluate_version(document, 1, None)


def _evaluate_version(
    document: dict[str, Any], version: int, evaluated_at: datetime | None
) -> dict[str, Any]:
    requirements, _, _ = load_registry()
    families, _ = load_adapter_catalog()
    adapters = {contract["id"] for family in families.values() for contract in family["contracts"]}
    mapping_parser = _mapping if version == 1 else _mapping_v2
    mappings = [mapping_parser(item, requirements, adapters) for item in document["mappings"]]
    mapping_ids = [item["id"] for item in mappings]
    if mapping_ids != sorted(mapping_ids) or len(mapping_ids) != len(set(mapping_ids)):
        _fail("mapping-order-or-duplicate")
    if version == 2:
        observation_sets = [item["correlation"]["observation_set_id"] for item in mappings]
        if len(observation_sets) != len(set(observation_sets)):
            _fail("observation-set-duplicate")
    if not isinstance(document["observations"], list):
        _fail("observations")
    parser = _observation if version == 1 else _observation_v2
    observations = [parser(item, set(mapping_ids)) for item in document["observations"]]
    keys = [(item["mapping"], item["source"]) for item in observations]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        _fail("observation-order-or-contradiction")
    rows: list[dict[str, Any]] = []
    for mapping in mappings:
        expected_awq = "awq-" + mapping["awq_result"]["kind"]
        pair = [item for item in observations if item["mapping"] == mapping["id"]]
        if [item["source"] for item in pair] != [expected_awq, "native-gate"]:
            _fail("missing-or-wrong-evidence")
        awq, native = pair
        mismatches = (
            []
            if version == 1
            else _correlation_mismatches(
                awq, native, mapping, evaluated_at or datetime.min.replace(tzinfo=UTC)
            )
        )
        equivalent = (
            not mismatches
            and awq["status"] == native["status"]
            and awq["status"] in ("pass", "fail")
        )
        row = {
            "mapping": mapping["id"],
            "requirement": mapping["requirement"],
            "awq_result": mapping["awq_result"],
            "native_status": native["status"],
            "awq_status": awq["status"],
            "equivalent": equivalent,
            "evidence_class": mapping["evidence_class"],
            "input_scope": mapping["input_scope"],
            "limitation": mapping["limitation"],
            "native_gate": "retain",
        }
        if version == 2:
            row["platform_class"] = mapping["correlation"]["platform_class"]
            row["observation_set_id"] = mapping["correlation"]["observation_set_id"]
            row["correlation_mismatches"] = mismatches
        rows.append(row)
    matched = sum(row["equivalent"] for row in rows)
    return {
        "status": "pass" if matched == len(rows) else "fail",
        "schema_version": version,
        "awq_version": __version__,
        "contract_sha256": hashlib.sha256(canonical_bytes(document)).hexdigest(),
        "coverage": {
            "mapped": len(rows),
            "equivalent": matched,
            "unresolved": len(rows) - matched,
        },
        "mappings": rows,
        "native_gate": "retain",
        "claim": CLAIM,
    }


def evaluate(value: Any) -> dict[str, Any]:
    """Validate one mapping document and normalize its paired observations."""
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int:
        _fail("schema-version")
    version = value["schema_version"]
    if version == 1:
        document = _object(value, "schema_version mappings observations")
    elif version == 2:
        document = _object(value, "schema_version evaluated_at mappings observations")
    else:
        _fail("schema-version")
    if (
        not isinstance(document["mappings"], list)
        or not 1 <= len(document["mappings"]) <= MAX_MAPPINGS
    ):
        _fail("mappings")
    if version == 1:
        return _evaluate_v1(document)
    return _evaluate_version(document, 2, _timestamp(document["evaluated_at"]))


def evaluate_file(root: Path, relative: str) -> dict[str, Any]:
    """Read a bounded canonical mapping contract below the selected repository root."""
    if (
        not isinstance(relative, str)
        or len(relative) > 200
        or re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_.-]+)*[.]json", relative) is None
        or any(part in (".", "..") for part in relative.split("/"))
        or root.is_symlink()
    ):
        _fail("path")
    try:
        value = strict_json(read_file(root.resolve(strict=True) / relative, MAX_BYTES))
    except (OSError, ValueError, ReleaseError) as error:
        raise ProjectError("native-gate mapping invalid: unreadable-or-noncanonical") from error
    return evaluate(value)
