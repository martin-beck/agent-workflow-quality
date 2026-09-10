# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Bounded synthetic reliability observations and metadata-only retention decisions."""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import signal
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from awq import __version__, project
from awq.registry import canonical_bytes
from awq.sbom import strict_json
from awq.trust import read_file

STAGES = ("discovery", "checks", "evidence", "policy-diff")
FIXTURES = {"small": (16, 64), "medium": (128, 1024), "large": (512, 4096)}
REPEATS = {"pr": 3, "scheduled": 7}
MAX_OUTPUT = 65536
TIMEOUT = 30
SHA = re.compile(r"^[0-9a-f]{64}$")
LIMITATION = (
    "Synthetic fixed recipes and sampled repeats only; no universal performance, determinism, "
    "privacy or flake proof. Timing is observational; reference ceilings and extension results "
    "are caller-reviewed, not authenticated history. Caller-selected UTC is not trusted clock "
    "evidence. Retention decisions inspect metadata, not retained bytes. Native gates retained."
)


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _shape(value: Any, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise project.ProjectError("reliability fields are invalid")
    return value


def _integer(value: object, lower: int, upper: int) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise project.ProjectError("reliability integer is outside the bound")
    return value


def _hash(value: object) -> str:
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise project.ProjectError("reliability digest is invalid")
    return value


def timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
    ):
        raise project.ProjectError("reliability timestamp is invalid")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise project.ProjectError("reliability timestamp is invalid") from error


def _profile(value: dict[str, Any], kind: str) -> str:
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["kind"] != kind
    ):
        raise project.ProjectError("reliability kind or version is invalid")
    profile = value["profile"]
    if not isinstance(profile, str) or profile not in REPEATS:
        raise project.ProjectError("reliability profile is unsupported")
    return profile


def references(value: Any) -> dict[str, Any]:
    result = _shape(value, set(FIXTURES))
    for record in result.values():
        for sample in _shape(record, set(STAGES)).values():
            _integer(sample, 1, 2_000_000_000)
    return result


def request(value: Any) -> dict[str, Any]:
    result = _shape(value, {"schema_version", "kind", "profile", "reference_ns"})
    _profile(result, "reliability-budget")
    references(result["reference_ns"])
    return result


def _sample(value: Any) -> dict[str, Any]:
    item = _shape(value, {"elapsed_ns", "status", "semantic_sha256"})
    _integer(item["elapsed_ns"], 0, 60_000_000_000)
    _hash(item["semantic_sha256"])
    if item["status"] not in ("pass", "error", "timeout", "truncated"):
        raise project.ProjectError("reliability sample status is invalid")
    return item


def _runs(value: Any, repeats: int) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(FIXTURES) * repeats:
        raise project.ProjectError("reliability trials are incomplete")
    expected = [(name, trial) for name in FIXTURES for trial in range(repeats)]
    for record, identity in zip(value, expected, strict=True):
        item = _shape(record, {"fixture", "trial", "stages"})
        _integer(item["trial"], 0, repeats - 1)
        if (item["fixture"], item["trial"]) != identity:
            raise project.ProjectError("reliability trials are duplicated or unordered")
        for sample in _shape(item["stages"], set(STAGES)).values():
            _sample(sample)
    return value


def _identifier(value: object, prefix: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(prefix + r"-[A-Z0-9]{1,32}", value):
        raise project.ProjectError("reliability public identifier is invalid")
    return value


def _extensions(value: Any, repeats: int) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 16:
        raise project.ProjectError("reliability extension observations exceed the bound")
    seen = set()
    for record in value:
        item = _shape(record, {"id", "source_sha256", "samples"})
        identifier = _identifier(item["id"], "GATE")
        if identifier in seen:
            raise project.ProjectError("reliability extension identity is duplicated")
        seen.add(identifier)
        _hash(item["source_sha256"])
        samples = item["samples"]
        if not isinstance(samples, list) or not repeats <= len(samples) <= 32:
            raise project.ProjectError("reliability extension repeats are incomplete")
        for sample in samples:
            _shape(sample, {"status", "semantic_sha256"})
            _hash(sample["semantic_sha256"])
            if sample["status"] not in ("pass", "fail", "error", "timeout", "truncated"):
                raise project.ProjectError("reliability extension status is invalid")
    return value


def _retained(value: Any, now: datetime) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 128:
        raise project.ProjectError("reliability retention inventory exceeds the bound")
    seen: set[str] = set()
    hashes: set[str] = set()
    for record in value:
        item = _shape(
            record, {"id", "sha256", "bytes", "created_at", "expires_at", "classification"}
        )
        identifier = _identifier(item["id"], "EVIDENCE")
        sha = _hash(item["sha256"])
        if identifier in seen or sha in hashes:
            raise project.ProjectError("reliability retained identity is duplicated")
        seen.add(identifier)
        hashes.add(sha)
        _integer(item["bytes"], 1, MAX_OUTPUT * 2)
        created, expires = timestamp(item["created_at"]), timestamp(item["expires_at"])
        if created > now or expires <= created:
            raise project.ProjectError("reliability retention chronology is invalid")
        if item["classification"] not in ("aggregate-only", "unreviewed", "raw-content"):
            raise project.ProjectError("reliability retention classification is invalid")
    return value


def _timing_decisions(
    runs: list[dict[str, Any]], reference: dict[str, Any]
) -> list[dict[str, Any]]:
    decisions = []
    for fixture in FIXTURES:
        for stage in STAGES:
            samples = [item["stages"][stage] for item in runs if item["fixture"] == fixture]
            values = sorted(item["elapsed_ns"] for item in samples)
            reasons = []
            if any(item["status"] != "pass" for item in samples):
                reasons.append("incomplete-or-failed-trial")
            if len({item["semantic_sha256"] for item in samples}) != 1:
                reasons.append("nondeterministic-result")
            median = values[len(values) // 2]
            if median > reference[fixture][stage] * 2:
                reasons.append("median-regression")
            if values[-1] > 4_000_000_000:
                reasons.append("absolute-runtime-budget")
            decisions.append(
                {
                    "fixture": fixture,
                    "stage": stage,
                    "median_ns": median,
                    "maximum_ns": values[-1],
                    "reasons": reasons,
                }
            )
    return decisions


def _retention_decisions(records: list[dict[str, Any]], now: datetime) -> list[dict[str, str]]:
    decisions = []
    for item in records:
        created, expires = timestamp(item["created_at"]), timestamp(item["expires_at"])
        if item["classification"] != "aggregate-only":
            reason = "unreviewed-or-raw-content"
        elif item["bytes"] > MAX_OUTPUT:
            reason = "record-size-budget"
        elif expires - created > timedelta(days=7):
            reason = "retention-window-budget"
        elif expires <= now or now - created > timedelta(days=7):
            reason = "expired-evidence"
        else:
            continue
        decisions.append({"id": item["id"], "action": "review-and-remove", "reason": reason})
    if len(records) > 64 or sum(item["bytes"] for item in records) > 1_048_576:
        decisions.append(
            {"id": "EVIDENCE-INVENTORY", "action": "review-and-trim", "reason": "inventory-budget"}
        )
    return decisions


def evaluate(value: Any, as_of: str) -> dict[str, Any]:
    item = _shape(
        value,
        {
            "schema_version",
            "kind",
            "profile",
            "reference_ns",
            "observed_at",
            "fixture_set_sha256",
            "runs",
            "extensions",
            "retained",
            "collector_version",
            "collector_sha256",
        },
    )
    profile = _profile(item, "reliability-evidence")
    _hash(item["collector_sha256"])
    if not isinstance(item["collector_version"], str) or not re.fullmatch(
        r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}", item["collector_version"]
    ):
        raise project.ProjectError("reliability collector version is invalid")
    reference = references(item["reference_ns"])
    if item["fixture_set_sha256"] != digest(FIXTURES):
        raise project.ProjectError("reliability fixture identity differs")
    now, observed = timestamp(as_of), timestamp(item["observed_at"])
    if now < observed:
        raise project.ProjectError("reliability evaluation predates observation")
    runs = _runs(item["runs"], REPEATS[profile])
    extensions = _extensions(item["extensions"], REPEATS[profile])
    retained = _retained(item["retained"], now)
    decisions = _timing_decisions(runs, reference)
    cleanup = _retention_decisions(retained, now)
    extension_results = []
    for record in extensions:
        samples = record["samples"]
        failures = sum(sample["status"] != "pass" for sample in samples)
        unstable = len({(sample["status"], sample["semantic_sha256"]) for sample in samples}) != 1
        extension_results.append(
            {
                "id": record["id"],
                "trials": len(samples),
                "failures": failures,
                "nondeterministic": unstable,
                "status": "fail" if unstable or failures * 100 > len(samples) * 5 else "pass",
            }
        )
    stale = now - observed > timedelta(days=7)
    failed = (
        stale
        or bool(cleanup)
        or any(record["reasons"] for record in decisions)
        or any(record["status"] == "fail" for record in extension_results)
    )
    return {
        "schema_version": 1,
        "awq_version": __version__,
        "status": "fail" if failed else "pass",
        "evidence_sha256": digest(item),
        "as_of": as_of,
        "stale": stale,
        "timing": decisions,
        "extensions": extension_results,
        "cleanup": cleanup,
        "native_gate": "retain",
        "limitation": LIMITATION,
    }


def _limits() -> None:
    import resource

    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT, MAX_OUTPUT))
    resource.setrlimit(resource.RLIMIT_CPU, (TIMEOUT, TIMEOUT))


def _trial(fixture: str, scratch: Path) -> dict[str, Any]:
    if os.name != "posix":
        raise project.ProjectError("reliability collection requires the reviewed POSIX host")
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "TMPDIR": str(scratch),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "",
        "PYTHONHASHSEED": "0",
    }
    argv = [sys.executable, "-I", "-B", "-m", "awq.reliability_worker", fixture, str(scratch)]
    status = "error"
    with tempfile.TemporaryFile(dir=scratch) as output:
        try:
            with subprocess.Popen(  # noqa: S603 - fixed installed worker argv; no consumer code.
                argv,
                stdout=output,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                env=environment,
                start_new_session=True,
                preexec_fn=_limits,
            ) as process:
                try:
                    code = process.wait(timeout=TIMEOUT)
                except subprocess.TimeoutExpired:
                    status = "timeout"
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    code = -1
                finally:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
            output.seek(0)
            raw = output.read(MAX_OUTPUT + 1)
            if len(raw) >= MAX_OUTPUT:
                status = "truncated"
            elif code == 0:
                record = _shape(strict_json(raw), set(STAGES))
                for sample in record.values():
                    _sample(sample)
                return record
        except (OSError, ValueError, project.ProjectError):
            status = "error"
    return {
        stage: {"elapsed_ns": 0, "status": status, "semantic_sha256": "0" * 64} for stage in STAGES
    }


def collect(value: Any, scratch: Path, as_of: str) -> dict[str, Any]:
    contract = request(value)
    timestamp(as_of)
    if not scratch.is_absolute() or scratch.resolve(strict=True) != scratch or not scratch.is_dir():
        raise project.ProjectError("reliability scratch must be an existing canonical directory")
    runs: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="awq-reliability-", dir=scratch) as directory:
        for fixture in FIXTURES:
            runs.extend(
                {"fixture": fixture, "trial": trial, "stages": _trial(fixture, Path(directory))}
                for trial in range(REPEATS[contract["profile"]])
            )
    evidence = {
        **contract,
        "kind": "reliability-evidence",
        "observed_at": as_of,
        "fixture_set_sha256": digest(FIXTURES),
        "collector_version": __version__,
        "collector_sha256": digest(
            {
                name: hashlib.sha256(
                    read_file(Path(__file__).with_name(name), 1_000_000)
                ).hexdigest()
                for name in (
                    "reliability.py",
                    "reliability_worker.py",
                    "project.py",
                    "commands.py",
                    "checks.py",
                )
            }
        ),
        "runs": runs,
        "extensions": [],
        "retained": [],
    }
    result = evaluate(evidence, as_of)
    return {**result, "observation": evidence}


def run_file(root: Path, relative: str, as_of: str, scratch: Path | None = None) -> dict[str, Any]:
    try:
        value = strict_json(read_file(project.confined_path(root, relative), 256000))
        return evaluate(value, as_of) if scratch is None else collect(value, scratch, as_of)
    except Exception as error:
        raise project.ProjectError(
            "reliability input or execution is invalid or unavailable"
        ) from error
