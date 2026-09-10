# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Strict, bounded and language-neutral JUnit report evidence."""

from __future__ import annotations

import datetime
import hashlib
import json
import re
import stat
import subprocess
import xml.etree.ElementTree as ElementTree
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = 1
MAX_CONTRACT_BYTES = 256_000
MAX_REPORT_BYTES = 5_000_000
MAX_TOTAL_BYTES = 50_000_000
MAX_REPORTS = 1_000
MAX_MODULES = 200
MAX_SUITES = 10_000
MAX_CASES = 1_000_000
MAX_XML_DEPTH = 64
MAX_XML_NODES = 1_100_000
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_REVISION = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$")
MODULE = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
REPORT_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$")
TIMESTAMP = re.compile(r"^20[0-9]{2}-(?:0[1-9]|1[0-2])-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
CONTRACT_KEYS = {
    "collected_at",
    "kind",
    "max_age_seconds",
    "minimum_discovered",
    "minimum_executed",
    "producer",
    "report_roots",
    "reports",
    "required_modules",
    "schema_version",
    "skip_policy",
    "source_revision",
}
PRODUCER_KEYS = {"configuration_sha256", "id", "version"}
REPORT_KEYS = {"module", "path", "sha256"}


class TestReportError(ValueError):
    """A declared JUnit observation is malformed or does not prove execution."""


def canonical_bytes(value: object) -> bytes:
    """Return the canonical representation used by report evidence digests."""
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TestReportError("duplicate JSON key")
        result[key] = value
    return result


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise TestReportError(f"{label} has unknown or missing fields")
    return value


def _integer(value: object, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise TestReportError(f"{label} is outside its bound")
    return value


def _relative(value: object) -> str:
    if not isinstance(value, str) or REPORT_PATH.fullmatch(value) is None:
        raise TestReportError("report path is not repository-relative POSIX")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or value != path.as_posix() or value == ".":
        raise TestReportError("report path escapes the repository")
    return value


def _confined(root: Path, relative: str, *, directory: bool = False) -> Path:
    path = root.joinpath(*PurePosixPath(relative).parts)
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise TestReportError("declared report input is unavailable") from error
    if root not in (resolved, *resolved.parents):
        raise TestReportError("declared report input escapes the repository")
    metadata = path.lstat()
    expected = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if path.is_symlink() or not expected:
        raise TestReportError("declared report input is not a regular confined object")
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _timestamp(value: object, label: str) -> datetime.datetime:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        raise TestReportError(f"{label} is invalid")
    try:
        result = datetime.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise TestReportError(f"{label} is invalid") from error
    if result.isoformat(timespec="seconds").replace("+00:00", "Z") != value:
        raise TestReportError(f"{label} is invalid")
    return result


def _git_revision(root: Path) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed absolute executable and argv.
        ["/usr/bin/git", "-C", str(root), "rev-parse", "HEAD"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    try:
        revision = completed.stdout.decode("ascii").strip()
    except UnicodeError as error:
        raise TestReportError("source revision is unavailable") from error
    if completed.returncode or GIT_REVISION.fullmatch(revision) is None:
        raise TestReportError("source revision is unavailable")
    return revision


def _xml_depth_and_nodes(document: ElementTree.Element) -> None:
    stack = [(document, 1)]
    nodes = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if depth > MAX_XML_DEPTH or nodes > MAX_XML_NODES:
            raise TestReportError("JUnit report exceeds XML structural bounds")
        stack.extend((child, depth + 1) for child in node)


def _count_value(suite: ElementTree.Element, name: str) -> int:
    value = suite.attrib.get(name)
    if value is None or re.fullmatch(r"[0-9]+", value) is None:
        raise TestReportError("JUnit suite has a missing or invalid count")
    result = int(value)
    if result > MAX_CASES:
        raise TestReportError("JUnit suite count exceeds its bound")
    return result


def _suite_observation(suite: ElementTree.Element) -> dict[str, int]:
    cases = list(suite.findall("./testcase"))
    children = list(suite.findall("./testsuite"))
    if not cases and not children:
        raise TestReportError("JUnit report contains an empty suite")
    observed = {"discovered": len(cases), "failures": 0, "errors": 0, "skipped": 0}
    for case in cases:
        outcomes = [
            outcome for outcome in ("failure", "error", "skipped") if case.find(outcome) is not None
        ]
        if len(outcomes) > 1:
            raise TestReportError("JUnit testcase has contradictory outcomes")
        if outcomes:
            key = {"failure": "failures", "error": "errors", "skipped": "skipped"}[outcomes[0]]
            observed[key] += 1
    for child in children:
        nested = _suite_observation(child)
        for key in observed:
            observed[key] += nested[key]
            if observed[key] > MAX_CASES:
                raise TestReportError("JUnit aggregate count exceeds its bound")
    declared = {
        "discovered": _count_value(suite, "tests"),
        "failures": _count_value(suite, "failures"),
        "errors": _count_value(suite, "errors"),
        "skipped": _count_value(suite, "skipped"),
    }
    if (
        declared != observed
        or sum(declared[key] for key in ("failures", "errors", "skipped")) > declared["discovered"]
    ):
        raise TestReportError("JUnit suite counts are inconsistent")
    return observed


def parse_junit_report(path: Path) -> dict[str, Any]:  # noqa: C901
    """Parse one report into content-minimized suite and count evidence."""
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_REPORT_BYTES:
        raise TestReportError("JUnit report byte size is outside its bound")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise TestReportError("JUnit report is not UTF-8") from error
    upper = text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise TestReportError("JUnit report contains forbidden markup")
    try:
        document = ElementTree.fromstring(text)  # noqa: S314 - DTD/entities rejected above.
    except ElementTree.ParseError as error:
        raise TestReportError("JUnit report is malformed") from error
    _xml_depth_and_nodes(document)
    if document.tag == "testsuite":
        roots = [document]
        suites = [document, *document.findall(".//testsuite")]
    elif document.tag == "testsuites":
        roots = list(document.findall("./testsuite"))
        suites = list(document.findall(".//testsuite"))
    else:
        raise TestReportError("JUnit report root is unsupported")
    if not roots or not suites or len(suites) > MAX_SUITES:
        raise TestReportError("JUnit report suite count is outside its bound")
    totals = dict.fromkeys(("discovered", "failures", "errors", "skipped"), 0)
    suite_names: list[str] = []
    for suite in suites:
        name = suite.attrib.get("name")
        if not isinstance(name, str) or not name or len(name) > 500:
            raise TestReportError("JUnit suite name is missing or oversized")
        suite_names.append(name)
    for suite in roots:
        observed = _suite_observation(suite)
        for key in totals:
            totals[key] += observed[key]
            if totals[key] > MAX_CASES:
                raise TestReportError("JUnit aggregate count exceeds its bound")
    totals["executed"] = totals["discovered"] - totals["skipped"]
    return {
        **totals,
        "suite_count": len(suites),
        "suite_sha256": hashlib.sha256(canonical_bytes(sorted(suite_names))).hexdigest(),
    }


def _check_summary_bounds(summary: dict[str, Any], label: str) -> None:
    if summary["suites"] > MAX_SUITES or any(
        summary[key] > MAX_CASES
        for key in ("discovered", "executed", "skipped", "failures", "errors")
    ):
        raise TestReportError(f"{label} aggregate exceeds its bound")


def summarize_declared_reports(root: Path, reports: list[dict[str, str]]) -> dict[str, Any]:
    """Verify declared report digests and summarize their bounded JUnit contents."""
    if not reports or len(reports) > MAX_REPORTS:
        raise TestReportError("declared report count is outside its bound")
    total_bytes = 0
    modules: dict[str, dict[str, Any]] = {}
    suite_digests: list[str] = []
    aggregate = dict.fromkeys(
        ("suites", "discovered", "executed", "skipped", "failures", "errors"), 0
    )
    for record in reports:
        path = _confined(root, record["path"])
        size = path.stat().st_size
        total_bytes += size
        if size > MAX_REPORT_BYTES or total_bytes > MAX_TOTAL_BYTES:
            raise TestReportError("declared report bytes exceed their bound")
        if _sha256(path) != record["sha256"]:
            raise TestReportError("declared report digest mismatch")
        counts = parse_junit_report(path)
        aggregate["suites"] += counts["suite_count"]
        for key in ("discovered", "executed", "skipped", "failures", "errors"):
            aggregate[key] += counts[key]
        _check_summary_bounds(aggregate, "cross-report")
        suite_digests.append(counts["suite_sha256"])
        module = modules.setdefault(
            record["module"],
            {
                "id": record["module"],
                "reports": 0,
                "suites": 0,
                "discovered": 0,
                "executed": 0,
                "skipped": 0,
                "failures": 0,
                "errors": 0,
                "suite_digests": [],
            },
        )
        if len(modules) > MAX_MODULES:
            raise TestReportError("cross-report module count exceeds its bound")
        module["reports"] += 1
        module["suites"] += counts["suite_count"]
        module["suite_digests"].append(counts["suite_sha256"])
        for key in ("discovered", "executed", "skipped", "failures", "errors"):
            module[key] += counts[key]
        _check_summary_bounds(module, "module report")
    normalized_modules = []
    for module in modules.values():
        digests = module.pop("suite_digests")
        module["suite_sha256"] = hashlib.sha256(canonical_bytes(digests)).hexdigest()
        normalized_modules.append(module)
    normalized_modules.sort(key=lambda item: item["id"])
    totals = {
        "reports": len(reports),
        "modules": len(normalized_modules),
        **aggregate,
    }
    return {
        "modules": normalized_modules,
        "report_set_sha256": hashlib.sha256(canonical_bytes(reports)).hexdigest(),
        "suite_set_sha256": hashlib.sha256(canonical_bytes(suite_digests)).hexdigest(),
        "totals": totals,
    }


def _validate_contract(value: object) -> dict[str, Any]:  # noqa: C901
    contract = _exact(value, CONTRACT_KEYS, "test-report contract")
    if contract["schema_version"] != SCHEMA_VERSION or contract["kind"] != "junit-report-contract":
        raise TestReportError("test-report contract version or kind is unsupported")
    revision = contract["source_revision"]
    if not isinstance(revision, str) or GIT_REVISION.fullmatch(revision) is None:
        raise TestReportError("source revision is invalid")
    producer = _exact(contract["producer"], PRODUCER_KEYS, "producer")
    if not isinstance(producer["id"], str) or IDENTIFIER.fullmatch(producer["id"]) is None:
        raise TestReportError("producer identifier is invalid")
    version = producer["version"]
    if not isinstance(version, str) or not version or len(version) > 100:
        raise TestReportError("producer version is invalid")
    digest = producer["configuration_sha256"]
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        raise TestReportError("producer configuration digest is invalid")
    roots = contract["report_roots"]
    if not isinstance(roots, list) or not roots or len(roots) > MAX_MODULES:
        raise TestReportError("report roots are invalid")
    roots = [_relative(item) for item in roots]
    if roots != sorted(set(roots)):
        raise TestReportError("report roots are not sorted and unique")
    raw_reports = contract["reports"]
    if not isinstance(raw_reports, list) or not raw_reports or len(raw_reports) > MAX_REPORTS:
        raise TestReportError("declared reports are invalid")
    reports: list[dict[str, str]] = []
    for raw in raw_reports:
        item = _exact(raw, REPORT_KEYS, "report record")
        module, report_digest = item["module"], item["sha256"]
        if not isinstance(module, str) or MODULE.fullmatch(module) is None:
            raise TestReportError("report module is invalid")
        if not isinstance(report_digest, str) or SHA256.fullmatch(report_digest) is None:
            raise TestReportError("report digest is invalid")
        reports.append({"module": module, "path": _relative(item["path"]), "sha256": report_digest})
    if reports != sorted(reports, key=lambda item: item["path"]) or len(
        {item["path"] for item in reports}
    ) != len(reports):
        raise TestReportError("report records are not sorted and unique")
    for report in reports:
        path = PurePosixPath(report["path"])
        if not any(
            PurePosixPath(root) == path or PurePosixPath(root) in path.parents for root in roots
        ):
            raise TestReportError("declared report is outside every report root")
    required = contract["required_modules"]
    if (
        not isinstance(required, list)
        or not required
        or len(required) > MAX_MODULES
        or any(not isinstance(item, str) or MODULE.fullmatch(item) is None for item in required)
    ):
        raise TestReportError("required modules are invalid")
    if required != sorted(set(required)):
        raise TestReportError("required modules are not sorted and unique")
    minimum_discovered = _integer(
        contract["minimum_discovered"], 1, MAX_CASES, "minimum discovered"
    )
    minimum_executed = _integer(
        contract["minimum_executed"], 1, minimum_discovered, "minimum executed"
    )
    if contract["skip_policy"] not in {"allow", "forbid"}:
        raise TestReportError("skip policy is invalid")
    _integer(contract["max_age_seconds"], 1, 2_678_400, "maximum age")
    _timestamp(contract["collected_at"], "collection time")
    return {
        **contract,
        "producer": producer,
        "report_roots": roots,
        "reports": reports,
        "required_modules": required,
        "minimum_discovered": minimum_discovered,
        "minimum_executed": minimum_executed,
    }


def evaluate(root: Path, value: object, as_of: str) -> dict[str, Any]:  # noqa: C901
    """Evaluate a closed report contract against an exact repository revision and time."""
    contract = _validate_contract(value)
    evaluated_at = _timestamp(as_of, "evaluation time")
    collected_at = _timestamp(contract["collected_at"], "collection time")
    age = int((evaluated_at - collected_at).total_seconds())
    if age < 0 or age > contract["max_age_seconds"]:
        raise TestReportError("test-report evidence is stale or from the future")
    if _git_revision(root) != contract["source_revision"]:
        raise TestReportError("test-report evidence is from the wrong source revision")
    declared = {item["path"] for item in contract["reports"]}
    discovered: set[str] = set()
    visited = 0
    for relative in contract["report_roots"]:
        directory = _confined(root, relative, directory=True)
        for path in directory.rglob("*"):
            visited += 1
            if visited > MAX_REPORTS:
                raise TestReportError("report discovery exceeds its bound")
            metadata = path.lstat()
            if path.is_symlink():
                raise TestReportError("report root contains a non-regular entry")
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise TestReportError("report root contains a non-regular entry")
            if path.suffix.casefold() == ".xml":
                discovered.add(path.relative_to(root).as_posix())
    if discovered != declared:
        raise TestReportError("declared report set is missing or contains unexpected reports")
    summary = summarize_declared_reports(root, contract["reports"])
    modules = {item["id"] for item in summary["modules"]}
    totals = summary["totals"]
    if not set(contract["required_modules"]) <= modules:
        raise TestReportError("required module report evidence is missing")
    if (
        totals["discovered"] < contract["minimum_discovered"]
        or totals["executed"] < contract["minimum_executed"]
    ):
        raise TestReportError("test-report evidence does not meet its count floor")
    if totals["failures"] or totals["errors"]:
        raise TestReportError("test-report evidence contains failures or errors")
    if contract["skip_policy"] == "forbid" and totals["skipped"]:
        raise TestReportError("test-report evidence violates the skip policy")
    producer_sha256 = hashlib.sha256(canonical_bytes(contract["producer"])).hexdigest()
    return {
        "status": "pass",
        "schema_version": 1,
        "kind": "junit-report-evidence",
        "classification": "executed-test-report",
        "source_revision": contract["source_revision"],
        "producer_sha256": producer_sha256,
        "report_set_sha256": summary["report_set_sha256"],
        "suite_set_sha256": summary["suite_set_sha256"],
        "freshness": {
            "age_seconds": age,
            "collected_at": contract["collected_at"],
            "evaluated_at": as_of,
            "max_age_seconds": contract["max_age_seconds"],
            "status": "fresh",
        },
        "totals": totals,
        "modules": summary["modules"],
    }


def evaluate_file(root: Path, relative: str, as_of: str) -> dict[str, Any]:
    """Load one canonical repository-owned contract and evaluate it."""
    path = _confined(root, _relative(relative))
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_CONTRACT_BYTES:
        raise TestReportError("test-report contract byte size is outside its bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise TestReportError("test-report contract is invalid JSON") from error
    if raw != canonical_bytes(value):
        raise TestReportError("test-report contract is not canonical JSON")
    return evaluate(root, value, as_of)
