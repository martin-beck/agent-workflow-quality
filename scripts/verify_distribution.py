# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Reject unsafe, private, or incomplete AWQ distribution archives."""

from __future__ import annotations

import argparse
from pathlib import Path

from awq.release import DistributionError, inspect_archive

__all__ = ["DistributionError", "inspect_archive", "main"]


def main(argv: list[str] | None = None) -> int:
    """Inspect named archives and report content-minimized findings."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", nargs="+", type=Path)
    paths = parser.parse_args(argv).archives
    try:
        issues = [
            issue
            for path in sorted(paths, key=lambda item: item.name)
            for issue in inspect_archive(path)
        ]
    except DistributionError as error:
        print(f"distribution verification failed: {error}")
        return 2
    if issues:
        print("\n".join(issues))
        return 1
    print(f"Verified {len(paths)} bounded distribution archives.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
