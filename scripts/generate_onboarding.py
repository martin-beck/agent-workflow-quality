# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Regenerate exact release-version onboarding metadata without network access."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from awq import onboarding
from awq.registry import canonical_bytes

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    schema_path = ROOT / "schemas/onboarding.schema.json"
    schema = json.loads(schema_path.read_bytes())
    schema["oneOf"][:2] = [{"const": onboarding.compatibility()}, {"const": onboarding.recipes()}]
    expected = {
        ROOT / "src/awq/data/compatibility.json": canonical_bytes(onboarding.compatibility()),
        ROOT / "src/awq/data/agent_recipes.json": canonical_bytes(onboarding.recipes()),
        schema_path: canonical_bytes(schema),
    }
    for path, content in expected.items():
        if args.check:
            if path.read_bytes() != content:
                print("onboarding metadata drift")
                return 1
        else:
            path.write_bytes(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
