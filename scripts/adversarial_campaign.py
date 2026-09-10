# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Run the bounded PR or scheduled adversarial campaign offline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from awq import adversarial
from awq.project import ProjectError

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", default="templates/adversarial-pr.json")
    parser.add_argument("--scratch", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = adversarial.run_file(ROOT, args.contract, args.scratch)
    except (OSError, ValueError, ProjectError):
        print('{"status":"error","error":"adversarial campaign could not complete"}')
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
