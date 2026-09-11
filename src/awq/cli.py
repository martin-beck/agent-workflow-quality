# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Stable command-line interface for humans and coding agents."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from awq import (
    adversarial,
    assurance,
    commands,
    contracts,
    native_mapping,
    onboarding,
    promotion,
    refactor,
    reliability,
    test_reports,
    verified_update,
)
from awq.project import ProjectError, confined_root
from awq.registry import TIERS, RegistryError
from awq.release import ReleaseError


def _format_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=("text", "json"), default="text")


def parser() -> argparse.ArgumentParser:
    """Construct the complete CLI parser."""
    result = argparse.ArgumentParser(prog="awq")
    result.add_argument("--root", type=Path, default=Path.cwd())
    sub = result.add_subparsers(dest="command", required=True)
    for name in ("inspect", "doctor", "standards", "governance", "contract-catalog"):
        _format_argument(sub.add_parser(name))
    item = sub.add_parser("onboarding")
    item.add_argument("--capability", choices=onboarding.CAPABILITIES, default="core")
    _format_argument(item)
    item = sub.add_parser("migration-preview")
    item.add_argument("contract")
    _format_argument(item)
    item = sub.add_parser("init")
    item.add_argument("--profiles", nargs="+")
    item.add_argument("--dry-run", action="store_true")
    _format_argument(item)
    item = sub.add_parser("plan")
    item.add_argument("--changed", action="store_true")
    item.add_argument("--base", default="HEAD~1")
    _format_argument(item)
    for name in ("check", "evidence"):
        item = sub.add_parser(name)
        item.add_argument("--tier", choices=TIERS, default="pr")
        if name == "check":
            item.add_argument("--requirement", action="append")
        _format_argument(item)
    item = sub.add_parser("explain")
    item.add_argument("requirement")
    _format_argument(item)
    item = sub.add_parser("adapter-run")
    item.add_argument("contract")
    _format_argument(item)
    item = sub.add_parser("adapter-catalog")
    item.add_argument("--family")
    _format_argument(item)
    item = sub.add_parser("hosting-observe")
    item.add_argument("--repository", required=True)
    _format_argument(item)
    item = sub.add_parser("update")
    item.add_argument("--to", required=True)
    _authenticated_arguments(item)
    item.add_argument("--dry-run", action="store_true")
    _format_argument(item)
    item = sub.add_parser("policy-diff")
    item.add_argument("base")
    item.add_argument("head")
    _format_argument(item)
    item = sub.add_parser("release-verify")
    item.add_argument("manifest", type=Path)
    item.add_argument("--source", action="store_true")
    _format_argument(item)
    item = sub.add_parser("refactor-collect")
    item.add_argument("contract")
    item.add_argument("--tools", type=Path, required=True)
    _format_argument(item)
    for name in ("reliability-collect", "reliability-evaluate"):
        item = sub.add_parser(name)
        item.add_argument("contract")
        item.add_argument("--as-of", required=True)
        if name == "reliability-collect":
            item.add_argument("--scratch", type=Path, required=True)
        _format_argument(item)
    for name in ("adversarial-check", "adversarial-replay"):
        item = sub.add_parser(name)
        item.add_argument("contract")
        item.add_argument("--scratch", type=Path, required=True)
        _format_argument(item)
    item = sub.add_parser("assurance-check")
    item.add_argument("contract")
    _format_argument(item)
    item = sub.add_parser("promotion-evaluate")
    item.add_argument("evidence")
    item.add_argument("--as-of", required=True)
    _format_argument(item)
    item = sub.add_parser("native-map-evaluate")
    item.add_argument("contract")
    _format_argument(item)
    item = sub.add_parser("test-report-evaluate")
    item.add_argument("contract")
    item.add_argument("--as-of", required=True)
    _format_argument(item)
    item = sub.add_parser("release-authenticate")
    _authenticated_arguments(item)
    _format_argument(item)
    return result


def _authenticated_arguments(item: argparse.ArgumentParser) -> None:
    for name in ("manifest", "trust-policy", "source"):
        item.add_argument("--" + name, type=Path, required=True)
    item.add_argument("--tag", required=True)
    item.add_argument("--tag-object", required=True)


def _dispatch(args: argparse.Namespace, root: Path) -> dict[str, Any]:
    table: dict[str, Callable[[], dict[str, Any]]] = {
        "onboarding": lambda: onboarding.diagnose(args.capability),
        "migration-preview": lambda: onboarding.migration_file(root, args.contract),
        "inspect": lambda: commands.inspect(root),
        "refactor-collect": lambda: refactor.collect(root, args.contract, args.tools),
        "reliability-collect": lambda: reliability.run_file(
            root, args.contract, args.as_of, args.scratch
        ),
        "reliability-evaluate": lambda: reliability.run_file(root, args.contract, args.as_of),
        "adversarial-check": lambda: adversarial.run_file(root, args.contract, args.scratch),
        "adversarial-replay": lambda: adversarial.replay_file(root, args.contract, args.scratch),
        "assurance-check": lambda: assurance.evaluate_file(root, args.contract),
        "init": lambda: commands.initialize(root, args.profiles, args.dry_run),
        "plan": lambda: commands.plan(root, args.changed, args.base),
        "check": lambda: commands.check(root, args.tier, args.requirement),
        "promotion-evaluate": lambda: promotion.evaluate_file(root, args.evidence, args.as_of),
        "native-map-evaluate": lambda: native_mapping.evaluate_file(root, args.contract),
        "test-report-evaluate": lambda: test_reports.evaluate_file(root, args.contract, args.as_of),
        "evidence": lambda: commands.evidence(root, args.tier),
        "explain": lambda: commands.explain(args.requirement),
        "standards": commands.standards,
        "doctor": lambda: commands.doctor(root),
        "update": lambda: verified_update.update(
            root,
            args.to,
            args.dry_run,
            args.manifest,
            args.trust_policy,
            args.source,
            args.tag,
            args.tag_object,
        ),
        "release-authenticate": lambda: verified_update.verify(
            args.manifest, args.trust_policy, args.source, args.tag, args.tag_object
        ),
        "governance": lambda: commands.governance(root),
        "contract-catalog": contracts.summary,
        "adapter-run": lambda: commands.adapter_run(root, args.contract),
        "adapter-catalog": lambda: commands.adapter_catalog(args.family),
        "hosting-observe": lambda: commands.hosting_observation(args.repository),
        "policy-diff": lambda: commands.policy_diff(root, args.base, args.head),
        "release-verify": lambda: commands.release_verify(root, args.manifest, args.source),
    }
    return table[args.command]()


def _text(payload: dict[str, Any]) -> str:
    lines = [f"status: {payload.get('status', 'ok')}"]
    for key, value in payload.items():
        if key != "status":
            lines.append(f"{key}: {json.dumps(value, sort_keys=True)}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Run one command, returning 0 only for successful or passing evidence."""
    args = parser().parse_args(argv)
    try:
        payload = _dispatch(args, confined_root(args.root))
    except (
        ProjectError,
        contracts.ContractCatalogError,
        RegistryError,
        ReleaseError,
        test_reports.TestReportError,
        json.JSONDecodeError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        payload = {"status": "error", "error": str(error)}
    output = (
        json.dumps(payload, sort_keys=True, separators=(",", ":"))
        if args.format == "json"
        else _text(payload)
    )
    print(output)
    return 0 if payload.get("status") in {"ok", "pass"} else 1


if __name__ == "__main__":
    sys.exit(main())
