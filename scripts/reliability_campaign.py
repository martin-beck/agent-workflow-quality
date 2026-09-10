# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Run synthetic reliability gates with an explicit caller-selected UTC timestamp."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from awq import reliability
from awq.project import ProjectError
from awq.registry import canonical_bytes

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", default="templates/reliability-pr.json")
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--as-of", required=True)
    args = parser.parse_args(argv)
    try:
        result = reliability.run_file(ROOT, args.contract, args.as_of, args.scratch)
    except ProjectError:
        sys.stdout.buffer.write(
            b'{"status":"error","error":"reliability campaign could not complete"}\n'
        )
        return 1
    sys.stdout.buffer.write(canonical_bytes(result))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
