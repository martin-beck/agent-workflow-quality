# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Strict, bounded lexical terminology contracts owned by each consumer."""

from __future__ import annotations

import fnmatch
import json
import re
import unicodedata
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Never
from urllib.parse import urlsplit

from awq.project import ProjectError, confined_path

CONTRACT_PATH = "quality/terminology.json"
SCOPES = {"normative", "example", "quotation", "generated"}
SEVERITIES = {"error", "advisory"}
CASE_POLICIES = {"exact", "casefold"}
FORMATS = {".json", ".md", ".txt", ".yaml", ".yml"}
ROOT_KEYS = {"schema_version", "default_scope", "formats", "scope_rules", "terms", "exceptions"}
RULE_KEYS = {"scope", "paths"}
TERM_KEYS = {"id", "canonical", "aliases", "scopes", "severity", "case_policy"}
EXCEPTION_KEYS = {
    "id",
    "term",
    "owner",
    "reason",
    "paths",
    "scopes",
    "created_at",
    "expires_at",
    "compensating_evidence",
    "review_reference",
}
TOKEN = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$", re.ASCII)
OWNER = re.compile(r"^@[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:/[A-Za-z0-9_.-]+)?$", re.ASCII)
MAX_CONTRACT_BYTES = 256_000
MAX_TERMS = 256
MAX_ALIASES = 16
MAX_EXCEPTIONS = 256
MAX_FINDINGS = 100


class TerminologyError(ProjectError):
    """A terminology contract is unsafe, ambiguous, or unsupported."""


def _fail(code: str) -> Never:
    raise TerminologyError("terminology contract invalid: " + code)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail("duplicate-json-key")
        value[key] = item
    return value


def _reject_constant(_: str) -> None:
    _fail("non-finite-json-number")


def _text(value: object, maximum: int = 500) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= maximum


def _array(value: object, low: int, high: int) -> list[Any]:
    if not isinstance(value, list) or not low <= len(value) <= high:
        _fail("count")
    return value


def _safe_pattern(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= 200
        and not Path(value).is_absolute()
        and ".." not in Path(value).parts
        and "\\" not in value
    )


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        _fail("timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail("timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail("timestamp")
    return parsed.astimezone(UTC)


def _review_reference(value: object) -> bool:
    if not _text(value, 300):
        return False
    parsed = urlsplit(str(value))
    return (parsed.scheme == "urn" and bool(parsed.path)) or (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
    )


def _normal(value: str, policy: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    return normalized if policy == "exact" else normalized.casefold()


def _validate_aliases(raw: dict[str, Any], seen: set[str]) -> None:
    policy = raw["case_policy"]
    canonical = _normal(raw["canonical"], policy)
    local: set[str] = set()
    for alias in _array(raw["aliases"], 1, MAX_ALIASES):
        if not _text(alias, 100):
            _fail("alias")
        candidate = _normal(alias, policy)
        if candidate == canonical or not candidate.strip():
            _fail("alias-equals-canonical")
        overlap_key = _normal(alias, "casefold")
        if overlap_key in seen or candidate in local:
            _fail("duplicate-alias")
        seen.add(overlap_key)
        local.add(candidate)


def _validated_term(raw: object, identifiers: set[str], aliases: set[str]) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != TERM_KEYS:
        _fail("term-fields")
    identifier = raw["id"]
    if not isinstance(identifier, str) or TOKEN.fullmatch(identifier) is None:
        _fail("term-id")
    if identifier in identifiers:
        _fail("duplicate-term-id")
    identifiers.add(identifier)
    if raw["case_policy"] not in CASE_POLICIES or raw["severity"] not in SEVERITIES:
        _fail("term-classification")
    if not _text(raw["canonical"], 100):
        _fail("canonical")
    scopes = _array(raw["scopes"], 1, len(SCOPES))
    if len(set(scopes)) != len(scopes) or any(scope not in SCOPES for scope in scopes):
        _fail("term-scopes")
    _validate_aliases(raw, aliases)
    return raw


def _validate_terms(value: object) -> dict[str, dict[str, Any]]:
    identifiers: set[str] = set()
    aliases: set[str] = set()
    terms = [_validated_term(raw, identifiers, aliases) for raw in _array(value, 1, MAX_TERMS)]
    _validate_vocabulary(terms)
    return {item["id"]: item for item in terms}


def _validate_vocabulary(terms: list[dict[str, Any]]) -> None:
    canonicals = [_normal(item["canonical"], "casefold") for item in terms]
    if len(canonicals) != len(set(canonicals)):
        _fail("duplicate-canonical")
    for owner in terms:
        for alias in owner["aliases"]:
            for target in terms:
                policies = {owner["case_policy"], target["case_policy"]}
                policy = "exact" if policies == {"exact"} else "casefold"
                if _normal(alias, policy) == _normal(target["canonical"], policy):
                    _fail("alias-canonical-collision")


def _validate_rules(value: object) -> list[dict[str, Any]]:
    rules = _array(value, 0, 64)
    seen: set[str] = set()
    for raw in rules:
        if not isinstance(raw, dict) or set(raw) != RULE_KEYS or raw["scope"] not in SCOPES:
            _fail("scope-rule-fields")
        paths = _array(raw["paths"], 1, 64)
        if len(set(paths)) != len(paths) or any(not _safe_pattern(path) for path in paths):
            _fail("scope-rule-paths")
        if seen.intersection(paths):
            _fail("duplicate-scope-rule-path")
        seen.update(paths)
    return rules


def _validate_exceptions(value: object, terms: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    exceptions = _array(value, 0, MAX_EXCEPTIONS)
    seen: set[str] = set()
    for raw in exceptions:
        if not isinstance(raw, dict) or set(raw) != EXCEPTION_KEYS:
            _fail("exception-fields")
        identifier = raw["id"]
        if (
            not isinstance(identifier, str)
            or TOKEN.fullmatch(identifier) is None
            or identifier in seen
        ):
            _fail("exception-id")
        seen.add(identifier)
        owner = raw["owner"]
        if raw["term"] not in terms or not isinstance(owner, str) or OWNER.fullmatch(owner) is None:
            _fail("exception-owner-or-term")
        if not _text(raw["reason"]) or not _text(raw["compensating_evidence"]):
            _fail("exception-guidance")
        if not _review_reference(raw["review_reference"]):
            _fail("exception-review")
        paths = _array(raw["paths"], 1, 32)
        scopes = _array(raw["scopes"], 1, len(SCOPES))
        if len(set(paths)) != len(paths) or any(not _safe_pattern(path) for path in paths):
            _fail("exception-paths")
        if len(set(scopes)) != len(scopes) or any(scope not in SCOPES for scope in scopes):
            _fail("exception-scopes")
        created = _timestamp(raw["created_at"])
        expires = _timestamp(raw["expires_at"])
        if not created < expires or expires - created > timedelta(days=90):
            _fail("exception-lifetime")
    return exceptions


def validate(value: object) -> dict[str, Any]:
    """Validate and return one exact terminology registry document."""
    if not isinstance(value, dict) or set(value) != ROOT_KEYS or value["schema_version"] != 1:
        _fail("fields-or-version")
    if value["default_scope"] not in SCOPES:
        _fail("default-scope")
    formats = _array(value["formats"], 1, len(FORMATS))
    if len(set(formats)) != len(formats) or any(item not in FORMATS for item in formats):
        _fail("formats")
    terms = _validate_terms(value["terms"])
    _validate_rules(value["scope_rules"])
    _validate_exceptions(value["exceptions"], terms)
    return value


def load(root: Path) -> dict[str, Any]:
    """Load a confined consumer registry without accepting ambiguous JSON."""
    path = confined_path(root, CONTRACT_PATH)
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_CONTRACT_BYTES:
            _fail("file-size")
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise TerminologyError("cannot read terminology contract") from error
    return validate(value)


def _path_scope(relative: str, contract: dict[str, Any]) -> str:
    matches = {
        rule["scope"]
        for rule in contract["scope_rules"]
        if any(fnmatch.fnmatchcase(relative, pattern) for pattern in rule["paths"])
    }
    if len(matches) > 1:
        _fail("ambiguous-path-scope")
    return str(next(iter(matches), contract["default_scope"]))


def _segments(path: Path, text: str, base_scope: str) -> list[tuple[str, str]]:
    if path.suffix != ".md" or base_scope in {"example", "quotation"}:
        return [(base_scope, text)]
    segments: list[tuple[str, str]] = []
    fenced = False
    fence = ""
    for line in text.splitlines(keepends=True):
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if marker and (not fenced or marker.group(1).startswith(fence[0])):
            fenced = not fenced
            fence = marker.group(1) if fenced else ""
            segments.append(("example", line))
        elif fenced:
            segments.append(("example", line))
        elif re.match(r"^ {0,3}>", line):
            segments.append(("quotation", line))
        else:
            segments.append((base_scope, line))
    return segments


def _boundary(character: str) -> bool:
    return bool(character) and (character.isalnum() or character == "_")


def _contains(text: str, alias: str) -> bool:
    cursor = 0
    while True:
        index = text.find(alias, cursor)
        if index < 0:
            return False
        before = text[index - 1] if index else ""
        end = index + len(alias)
        after = text[end] if end < len(text) else ""
        if not _boundary(before) and not _boundary(after):
            return True
        cursor = index + 1


def _active_exception(
    contract: dict[str, Any], term: str, relative: str, scope: str, now: datetime
) -> str | None:
    for item in contract["exceptions"]:
        if (
            item["term"] == term
            and scope in item["scopes"]
            and _timestamp(item["created_at"]) <= now < _timestamp(item["expires_at"])
            and any(fnmatch.fnmatchcase(relative, pattern) for pattern in item["paths"])
        ):
            return str(item["id"])
    return None


def _read_candidate(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
        return raw.decode("utf-8") if len(raw) <= 2_000_000 and b"\0" not in raw else None
    except (OSError, UnicodeError):
        return None


def _segment_findings(
    contract: dict[str, Any], relative: str, scope: str, segment: str, now: datetime
) -> tuple[list[dict[str, str]], set[str]]:
    findings: list[dict[str, str]] = []
    used: set[str] = set()
    for term in sorted(contract["terms"], key=lambda item: item["id"]):
        if scope not in term["scopes"]:
            continue
        normalized = _normal(segment, term["case_policy"])
        if not any(
            _contains(normalized, _normal(alias, term["case_policy"])) for alias in term["aliases"]
        ):
            continue
        exception = _active_exception(contract, term["id"], relative, scope, now)
        if exception is not None:
            used.add(exception)
            continue
        findings.append(
            {
                "code": "terminology-" + term["severity"],
                "path": relative,
                "message": f"{term['id']} has a forbidden alias in {scope} scope",
            }
        )
    return findings, used


def _path_findings(
    contract: dict[str, Any], path: Path, relative: str, now: datetime
) -> tuple[list[dict[str, str]], set[str]]:
    text = _read_candidate(path)
    if text is None:
        return [], set()
    findings: list[dict[str, str]] = []
    used: set[str] = set()
    scope = _path_scope(relative, contract)
    for segment_scope, segment in _segments(path, text, scope):
        segment_results, segment_used = _segment_findings(
            contract, relative, segment_scope, segment, now
        )
        for finding in segment_results:
            if finding not in findings:
                findings.append(finding)
        used.update(segment_used)
    return findings, used


def evaluate(
    root: Path, paths: list[Path], *, now: datetime | None = None
) -> tuple[list[dict[str, str]], list[str]]:
    """Return bounded, snippet-free lexical findings and used exception identifiers."""
    contract = load(root)
    observed_at = datetime.now(UTC) if now is None else now.astimezone(UTC)
    findings: list[dict[str, str]] = []
    used: set[str] = set()
    formats = set(contract["formats"])
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative == CONTRACT_PATH or path.suffix not in formats:
            continue
        path_results, path_used = _path_findings(contract, path, relative, observed_at)
        findings.extend(path_results[: MAX_FINDINGS - len(findings)])
        used.update(path_used)
        if len(findings) >= MAX_FINDINGS:
            return findings, sorted(used)
    return findings, sorted(used)
