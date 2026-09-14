# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Bounded, privacy-safe GitHub Actions trust-transition checks."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

POLICY_PATH = Path("quality/workflow-trust.json")
POLICY_KEYS = {
    "schema_version",
    "events",
    "runners",
    "protected_branches",
    "publication_events",
    "required_gate_workflows",
    "publication_workflows",
}
EVENT_KEYS = {"untrusted", "environmental", "trusted", "prohibited"}
RUNNER_KEYS = {"disposable", "trusted", "persistent"}
KNOWN_EVENTS = {
    "pull_request",
    "pull_request_target",
    "push",
    "schedule",
    "workflow_call",
    "workflow_dispatch",
}
PATH_PATTERN = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
SHA_EXPRESSION = "${{ github.event.pull_request.head.sha }}"


class WorkflowTrustError(ValueError):
    """The workflow trust policy is unavailable or invalid."""


def _strict_object(raw: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                raise WorkflowTrustError("workflow trust policy contains duplicate keys")
            value[key] = item
        return value

    try:
        value = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except WorkflowTrustError:
        raise
    except (json.JSONDecodeError, ValueError) as error:
        raise WorkflowTrustError("workflow trust policy is not strict JSON") from error
    if not isinstance(value, dict):
        raise WorkflowTrustError("workflow trust policy must be an object")
    return value


def _strings(value: object, *, name: str, maximum: int = 32) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > maximum
        or any(not isinstance(item, str) or not item or len(item) > 100 for item in value)
        or len(set(value)) != len(value)
    ):
        raise WorkflowTrustError(f"{name} must be a bounded unique string list")
    return value


def validate_policy(value: object) -> dict[str, Any]:  # noqa: C901
    """Validate the closed policy shape and cross-field trust classes."""
    if not isinstance(value, dict) or set(value) != POLICY_KEYS or value.get("schema_version") != 1:
        raise WorkflowTrustError("workflow trust policy has unknown or missing fields")
    events = value["events"]
    runners = value["runners"]
    if not isinstance(events, dict) or set(events) != EVENT_KEYS:
        raise WorkflowTrustError("event trust classes are incomplete")
    if not isinstance(runners, dict) or set(runners) != RUNNER_KEYS:
        raise WorkflowTrustError("runner trust classes are incomplete")
    event_sets = {key: set(_strings(events[key], name=f"events.{key}")) for key in EVENT_KEYS}
    if set().union(*event_sets.values()) != KNOWN_EVENTS:
        raise WorkflowTrustError("event trust classes must cover the supported event set exactly")
    if sum(len(items) for items in event_sets.values()) != len(KNOWN_EVENTS):
        raise WorkflowTrustError("event trust classes must not overlap")
    runner_sets = {key: set(_strings(runners[key], name=f"runners.{key}")) for key in RUNNER_KEYS}
    if any(
        runner_sets[left] & runner_sets[right]
        for left, right in (
            ("disposable", "trusted"),
            ("disposable", "persistent"),
            ("trusted", "persistent"),
        )
    ):
        raise WorkflowTrustError("runner trust classes must not overlap")
    for field in ("protected_branches", "publication_events"):
        _strings(value[field], name=field)
    for field in ("required_gate_workflows", "publication_workflows"):
        paths = _strings(value[field], name=field)
        if any(not PATH_PATTERN.fullmatch(path) for path in paths):
            raise WorkflowTrustError(f"{field} contains an unsafe workflow path")
    if not set(value["publication_events"]) <= {"push-tags", "workflow_dispatch"}:
        raise WorkflowTrustError("publication events contain an unsupported privilege boundary")
    return value


def load_policy(root: Path) -> dict[str, Any]:
    path = root.resolve() / POLICY_PATH
    try:
        if path.resolve(strict=True) != path or not path.is_file():
            raise WorkflowTrustError("workflow trust policy path is unsafe")
        with path.open("rb") as stream:
            encoded = stream.read(16385)
        if len(encoded) > 16384:
            raise WorkflowTrustError("workflow trust policy exceeds the byte limit")
        raw = encoded.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise WorkflowTrustError("workflow trust policy is missing or unreadable") from error
    return validate_policy(_strict_object(raw))


def _events(text: str) -> set[str]:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = re.fullmatch(r'(?:"on"|on):\s*(.*)', line)
        if not match:
            continue
        tail = match.group(1).strip()
        if tail:
            if tail.startswith("[") and tail.endswith("]"):
                return {item.strip().strip("'\"") for item in tail[1:-1].split(",") if item.strip()}
            return {tail.strip("'\"")}
        found: set[str] = set()
        for nested in lines[index + 1 :]:
            if not nested.strip() or nested.lstrip().startswith("#"):
                continue
            if nested and not nested.startswith(" "):
                break
            event = re.match(r"^  ([a-z_]+):", nested)
            if event:
                found.add(event.group(1))
        return found
    return set()


def _jobs(text: str) -> list[str]:
    match = re.search(r"(?m)^jobs:\s*$", text)
    if not match:
        return []
    body = text[match.end() :]
    starts = list(re.finditer(r"(?m)^  [A-Za-z0-9_-]+:\s*$", body))
    return [
        body[item.end() : starts[index + 1].start() if index + 1 < len(starts) else None]
        for index, item in enumerate(starts)
    ]


def _runner_values(text: str, job: str) -> set[str] | None:
    match = re.search(r"(?m)^    runs-on:\s*(.+?)\s*$", job)
    if not match:
        return None
    value = match.group(1).strip().strip("'\"")
    if value == "${{ matrix.os }}":
        matrix = re.search(r"(?m)^        os:\s*\[([^]]+)\]", text)
        if not matrix:
            return set()
        return {item.strip().strip("'\"") for item in matrix.group(1).split(",")}
    if value.startswith("[") and value.endswith("]"):
        return {item.strip().strip("'\"") for item in value[1:-1].split(",")}
    if "${{" in value:
        return set()
    return {value}


def _permission_writes(job: str) -> set[str]:
    block = re.search(r"(?m)^    permissions:[ \t]*$((?:\n      [^\n]+)*)", job)
    if not block:
        return set()
    return {
        match.group(1)
        for match in re.finditer(r"(?m)^      ([a-z-]+):\s*write\s*$", block.group(1))
    }


def _permissions_invalid(job: str) -> bool:
    inline = re.search(r"(?m)^    permissions:[ \t]*(\S[^\n]*)?$", job)
    if inline and inline.group(1) and inline.group(1).strip() != "{}":
        return True
    block = re.search(r"(?m)^    permissions:[ \t]*$((?:\n      [^\n]+)*)", job)
    if not block:
        return False
    lines = [line for line in block.group(1).splitlines() if line.strip()]
    if not lines:
        return True
    entries = re.findall(r"(?m)^      ([a-z-]+):\s*([a-z-]+)\s*$", block.group(1))
    allowed = {"actions", "attestations", "checks", "contents", "id-token", "packages"}
    return any(
        key not in allowed or value not in {"none", "read", "write"} for key, value in entries
    ) or len(entries) != len(lines)


def _top_permissions_invalid(text: str) -> bool:
    declaration = re.search(r"(?m)^permissions:[ \t]*(\S[^\n]*)?$", text)
    if not declaration:
        return True
    if declaration.group(1):
        return declaration.group(1).strip() != "{}"
    block = re.search(r"(?m)^permissions:[ \t]*$((?:\n  [^\n]+)*)", text)
    if not block:
        return True
    lines = [line for line in block.group(1).splitlines() if line.strip()]
    entries = re.findall(r"(?m)^  ([a-z-]+):\s*([a-z-]+)\s*$", block.group(1))
    return not lines or len(entries) != len(lines) or entries != [("contents", "read")]


def _checkout_blocks(job: str) -> list[str]:
    starts = list(re.finditer(r"(?m)^      - uses: actions/checkout@[^\s]+\s*$", job))
    blocks: list[str] = []
    for index, item in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(job)
        next_step = re.search(r"(?m)^      - ", job[item.end() : end])
        if next_step:
            end = item.end() + next_step.start()
        blocks.append(job[item.start() : end])
    return blocks


def _pinned_checkout(block: str) -> bool:
    return bool(re.search(r"(?m)^      - uses: actions/checkout@[0-9a-f]{40}\s*$", block))


def _run_content(text: str) -> str:
    """Return only command-bearing scalar and block lines."""
    lines = text.splitlines()
    selected: list[str] = []
    block_indent: int | None = None
    for line in lines:
        indent = len(line) - len(line.lstrip(" "))
        if block_indent is not None:
            if line.strip() and indent <= block_indent:
                block_indent = None
            else:
                selected.append(line)
                continue
        match = re.match(r"^\s*(?:-\s+)?run:\s*(.*)$", line)
        if match:
            selected.append(match.group(1))
            if match.group(1).strip() in {"|", ">", "|-", ">-"}:
                block_indent = indent
    return "\n".join(selected)


def _finding(code: str, message: str) -> tuple[str, str]:
    return code, message


def evaluate_workflow(  # noqa: C901
    relative: str, text: str, policy: dict[str, Any]
) -> list[tuple[str, str]]:
    """Return content-minimized trust findings for one bounded workflow."""
    if len(text.encode()) > 262144:
        return [_finding("workflow-size-limit", "workflow exceeds the bounded inspection limit")]
    if re.search(r"(?m)(?:^|\s)[&*!][A-Za-z_]", text):
        return [
            _finding("unsupported-workflow-syntax", "workflow uses unsupported YAML indirection")
        ]
    if any(
        len(re.findall(pattern, text)) != 1
        for pattern in (r'(?m)^(?:"on"|on):', r"(?m)^permissions:", r"(?m)^jobs:")
    ):
        return [
            _finding(
                "unsupported-workflow-syntax",
                "workflow has missing or duplicate trust-critical declarations",
            )
        ]
    findings: list[tuple[str, str]] = []
    events = _events(text)
    classified = {event: key for key, values in policy["events"].items() for event in values}
    unknown = events - set(classified)
    if not events or unknown:
        findings.append(
            _finding("unsupported-workflow-event", "workflow event is missing or unsupported")
        )
    if events & set(policy["events"]["prohibited"]):
        findings.append(
            _finding("prohibited-trust-event", "workflow crosses a prohibited event trust boundary")
        )
    is_untrusted = bool(events & set(policy["events"]["untrusted"]))
    push_tags = bool(re.search(r"(?m)^    tags:\s*(?:\[|$)", text))
    publication_event = (
        "push" in events and push_tags and "push-tags" in policy["publication_events"]
    ) or ("workflow_dispatch" in events and "workflow_dispatch" in policy["publication_events"])
    publication_workflow = relative in policy["publication_workflows"]
    required_gate = relative in policy["required_gate_workflows"]
    if "push" in events and not push_tags:
        branch_match = re.search(r"(?m)^    branches:\s*\[([^]]+)\]", text)
        branches = (
            {item.strip().strip("'\"") for item in branch_match.group(1).split(",")}
            if branch_match
            else set()
        )
        if not branches or not branches <= set(policy["protected_branches"]):
            findings.append(
                _finding(
                    "unprotected-push",
                    "trusted push workflow is not restricted to policy-owned protected branches",
                )
            )
    if re.search(r"(?m)^\s*continue-on-error:\s*true\s*$", text):
        findings.append(
            _finding("required-gate-fail-open", "required workflow execution can fail open")
        )
    if re.search(
        r"(?m)^\s*(?:container:\s*[^\s{]|image:\s*)[^\n]*?(?<!@sha256:[0-9a-f]{64})\s*$", text
    ):
        findings.append(
            _finding("mutable-container-image", "container image is not pinned by SHA-256 digest")
        )
    expressions = re.findall(r"\$\{\{\s*([^}]+?)\s*}}", _run_content(text))
    if any(
        re.search(
            r"(?:github\.event\.(?!pull_request\.(?:base|head)\.sha)|github\.head_ref|inputs\.|secrets\.)",
            expression,
        )
        for expression in expressions
    ):
        findings.append(
            _finding(
                "caller-controlled-expression",
                "workflow uses caller-controlled data across a command or privilege boundary",
            )
        )
    if is_untrusted and re.search(r"\$\{\{\s*secrets\.", text):
        findings.append(
            _finding(
                "secret-exposure",
                "untrusted event references a secret-bearing expression",
            )
        )
    jobs = _jobs(text)
    if not jobs:
        findings.append(
            _finding("unsupported-workflow-jobs", "workflow has no statically inspectable jobs")
        )
    disposable = set(policy["runners"]["disposable"])
    trusted = set(policy["runners"]["trusted"]) | set(policy["runners"]["persistent"])
    for job in jobs:
        if (
            len(re.findall(r"(?m)^    runs-on:", job)) != 1
            or len(re.findall(r"(?m)^    permissions:", job)) > 1
        ):
            findings.append(
                _finding(
                    "unsupported-workflow-syntax",
                    "job has missing or duplicate trust-critical declarations",
                )
            )
        runners = _runner_values(text, job)
        if runners is None or not runners or not runners <= disposable | trusted:
            findings.append(
                _finding(
                    "unknown-runner-class", "job runner cannot be mapped to a declared trust class"
                )
            )
            continue
        privileged = _permission_writes(job)
        if _permissions_invalid(job):
            findings.append(
                _finding(
                    "widened-job-permissions",
                    "job permissions are dynamic, unsupported, or wider than the reviewed set",
                )
            )
        if is_untrusted and runners & trusted:
            findings.append(
                _finding(
                    "untrusted-code-trusted-runner",
                    "unreviewed event code targets trusted or persistent capacity",
                )
            )
        manual_guard = re.search(
            r"(?m)^    if:\s*github\.ref\s*==\s*['\"]refs/heads/([A-Za-z0-9_.-]+)['\"]\s*$",
            job,
        )
        if (
            "workflow_dispatch" in events
            and runners & trusted
            and (not manual_guard or manual_guard.group(1) not in policy["protected_branches"])
        ):
            findings.append(
                _finding(
                    "unguarded-manual-trusted-runner",
                    "manual trusted-runner job lacks a static protected-ref guard",
                )
            )
        if privileged and not (publication_workflow and publication_event and not is_untrusted):
            findings.append(
                _finding(
                    "privilege-boundary",
                    "write permission is outside a policy-owned publication boundary",
                )
            )
        if (privileged or runners & trusted) and re.search(
            r"\$\{\{\s*(?:inputs\.|github\.event\.inputs)", job
        ):
            findings.append(
                _finding(
                    "caller-controlled-privilege",
                    "caller-controlled input reaches a privileged job",
                )
            )
        checkouts = _checkout_blocks(job)
        if required_gate and len(checkouts) != 1:
            findings.append(
                _finding(
                    "required-gate-checkout",
                    "required-gate candidate evidence requires exactly one "
                    "statically inspectable checkout",
                )
            )
        if required_gate and len(checkouts) == 1 and not _pinned_checkout(checkouts[0]):
            findings.append(
                _finding(
                    "required-gate-checkout",
                    "required-gate candidate evidence requires exactly one "
                    "statically inspectable checkout",
                )
            )
        for checkout in checkouts:
            if not re.search(r"(?m)^\s+persist-credentials:\s*false\s*$", checkout):
                findings.append(
                    _finding(
                        "checkout-credentials", "checkout credentials are not explicitly disabled"
                    )
                )
            if required_gate and not re.search(
                rf"(?m)^\s+ref:\s*{re.escape(SHA_EXPRESSION)}\s*$", checkout
            ):
                findings.append(
                    _finding(
                        "checkout-not-exact-head",
                        "candidate evidence checkout is not bound to the pull-request head SHA",
                    )
                )
    if not re.search(r"(?m)^permissions:", text):
        findings.append(
            _finding("missing-permissions", "workflow lacks top-level explicit permissions")
        )
    elif _top_permissions_invalid(text):
        findings.append(
            _finding(
                "widened-workflow-permissions",
                "top-level workflow permissions are missing, unsupported, or exceed contents read",
            )
        )
    return sorted(set(findings))
