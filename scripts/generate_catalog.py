"""Render the public requirement catalogue from the executable registry."""

from __future__ import annotations

import argparse
from pathlib import Path

from awq.registry import load_registry

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "docs" / "REQUIREMENTS.md"


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render()
    if args.check:
        if not TARGET.exists() or TARGET.read_text(encoding="utf-8") != expected:
            raise SystemExit("generated requirement catalogue is stale")
    else:
        TARGET.write_text(expected, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
