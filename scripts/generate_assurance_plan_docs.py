# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Generate the bounded consumer assurance-plan documentation view."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from awq.assurance_plan import validate

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "docs/ASSURANCE_PLANS.md"
FIXTURES = (
    ROOT / "fixtures/conforming/assurance-plan/agent-relay.json",
    ROOT / "fixtures/conforming/assurance-plan/agent-systems-benchmark.json",
)


def render() -> str:
    plans = [validate(json.loads(path.read_bytes())) for path in FIXTURES]
    lines = [
        "# Consumer assurance plans",
        "",
        "This generated view summarizes sanitized representative inventories. "
        "The machine-readable schema and runtime validator remain authoritative.",
        "",
        "| Repository | Domains | Gates | Unsupported | Evidence state |",
        "| --- | ---: | ---: | ---: | --- |",
    ]
    for plan in plans:
        state = "observed" if plan["observations"] else "declarations only"
        lines.append(
            f"| `{plan['repository']['id']}` | {len(plan['domains'])} | "
            f"{len(plan['gates'])} | {len(plan['unsupported'])} | {state} |"
        )
    lines.extend(
        [
            "",
            "## Contract boundary",
            "",
            "An assurance plan inventories languages, build systems, runtime surfaces and quality "
            "domains. Every domain is covered by an owned gate or a reviewed unsupported "
            "declaration. Gates retain repository-native ownership and declare bounded argument "
            "arrays, input scope, invariants, evidence class, report contract, remediation, "
            "limitations, ordering and optional native mapping.",
            "",
            "Validation never executes a command. A declaration without exact AR-0034 evidence "
            "identity is reported as `declared`, never `pass`. Observations bind the clean "
            "source revision, gate definition, configuration, input, platform and freshness. "
            "The generated examples are descriptive inventories, not coordinator state and not "
            "proof that downstream gates ran.",
            "The named repositories above are sanitized, non-authoritative fixtures only; AWQ does not "
            "execute them or require them at runtime. Consumers own their native Android/JVM evidence "
            "and must bind it to the generic AWQ adapter contract.",
            "",
            "Use `awq assurance-plan-check PLAN --format json` for content-minimized validation "
            "and `awq assurance-plan-diff BASE HEAD --format json` for deterministic review. "
            "Removing a declared domain, gate or unsupported record is classified as weakening; "
            "other changes require review.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    content = render()
    if args.check:
        if not DOCUMENT.is_file() or DOCUMENT.read_text(encoding="utf-8") != content:
            raise SystemExit("generated assurance-plan documentation is stale")
    else:
        DOCUMENT.write_text(content, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
