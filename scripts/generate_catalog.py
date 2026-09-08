# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Render the public requirement catalogue from the executable registry."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from awq.registry import load_registry, load_standards, standards_drift

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "docs" / "REQUIREMENTS.md"
STANDARDS_TARGET = ROOT / "docs" / "STANDARDS.md"


def render() -> str:
    requirements, profiles, digest = load_registry()
    lines = [
        "# Requirement catalogue",
        "",
        "This file is generated from the registry consumed by AWQ. Do not edit it directly.",
        "",
        f"Registry SHA-256: `{digest}`",
        "",
        "## Profiles",
        "",
        "| Profile | Purpose | Requirements |",
        "| --- | --- | --- |",
    ]
    for name, profile in sorted(profiles.items()):
        lines.append(f"| `{name}` | {profile['description']} | {len(profile['requirements'])} |")
    lines.extend(["", "## Requirements", ""])
    for identifier, item in sorted(requirements.items()):
        lines.extend(
            [
                f"### {identifier}: {item['title']}",
                "",
                item["statement"],
                "",
                f"- Profiles: {', '.join(f'`{name}`' for name in item['profiles'])}",
                f"- Tier: `{item['tier']}`",
                f"- Evidence: `{item['evidence']}`",
                f"- Deterministic: `{str(item['deterministic']).lower()}`",
                f"- Network: `{str(item['network']).lower()}`",
                f"- Limitation: {item['limitation']}",
                f"- Remediation: {item['remediation']}",
                f"- Exception policy: {item['exception_policy']}",
                f"- Standards: {', '.join(item['standards']) or 'project-specific'}",
                "",
            ]
        )
    return "\n".join(lines)


def render_standards() -> str:
    requirements, profiles, _ = load_registry()
    sources, mappings, digest = load_standards()
    by_requirement: dict[str, list[dict[str, Any]]] = {
        identifier: [] for identifier in requirements
    }
    mapped_controls: set[tuple[str, str]] = set()
    for mapping in mappings.values():
        by_requirement[mapping["requirement"]].append(mapping)
        mapped_controls.add((mapping["source"], mapping["control"]))
    lines = [
        "# Standards traceability",
        "",
        "This file is generated from version-pinned control sources and reviewed mappings.",
        "Mappings express alignment only. They do not assert certification, compliance, or a",
        "framework maturity level.",
        "",
        f"Standards registry SHA-256: `{digest}`",
        "",
        "## Pinned sources",
        "",
        "| Source | Edition | Scope | Limitation |",
        "| --- | --- | --- | --- |",
    ]
    for identifier, source in sorted(sources.items()):
        lines.append(
            f"| [{identifier}]({source['source_url']}) | `{source['edition']}` | "
            f"{source['scope']} | {source['limitation']} |"
        )
    lines.extend(["", "## Profile matrices", ""])
    for name, profile in sorted(profiles.items()):
        lines.extend(
            [
                f"### `{name}`",
                "",
                "| Requirement | Source control | Relationship | Evidence | Limitation |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for requirement in sorted(profile["requirements"]):
            for mapping in sorted(by_requirement[requirement], key=lambda item: item["id"]):
                source = sources[mapping["source"]]
                control = next(
                    item for item in source["controls"] if item["id"] == mapping["control"]
                )
                lines.append(
                    f"| [{requirement}](REQUIREMENTS.md) | "
                    f"[{mapping['source']} {mapping['control']}]({control['url']}) | "
                    f"`{mapping['relationship']}` | `{mapping['evidence']}` | "
                    f"{mapping['limitation']} |"
                )
        lines.append("")
    lines.extend(
        [
            "## Coverage gaps",
            "",
            "### AWQ requirements without a mapping",
            "",
        ]
    )
    missing_requirements = sorted(
        identifier for identifier, items in by_requirement.items() if not items
    )
    lines.extend(f"- `{identifier}`" for identifier in missing_requirements)
    if not missing_requirements:
        lines.append("- None.")
    lines.extend(["", "### Catalogued source controls without an AWQ mapping", ""])
    missing_controls = [
        (source_id, control)
        for source_id, source in sorted(sources.items())
        for control in source["controls"]
        if (source_id, control["id"]) not in mapped_controls
    ]
    lines.extend(
        f"- [{source_id} {control['id']}]({control['url']}): {control['title']}"
        for source_id, control in missing_controls
    )
    if not missing_controls:
        lines.append("- None.")
    drift = standards_drift(sources, mappings)
    lines.extend(["", "## Source-version drift", ""])
    if drift:
        lines.extend(
            f"- `{item['mapping']}`: mapped `{item['mapped_edition']}`, "
            f"catalogue `{item['catalogue_edition']}`"
            for item in drift
        )
    else:
        lines.append("- None; every mapping names its source's pinned edition.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs = {TARGET: render(), STANDARDS_TARGET: render_standards()}
    if args.check:
        stale = [
            path.name
            for path, expected in outputs.items()
            if not path.exists() or path.read_text(encoding="utf-8") != expected
        ]
        if stale:
            raise SystemExit(f"generated catalogues are stale: {', '.join(stale)}")
    else:
        for path, expected in outputs.items():
            path.write_text(expected, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
