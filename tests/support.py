# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Synthetic repository helpers."""

from __future__ import annotations

import json
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


class Repository:
    """A disposable Git repository with deterministic identity."""

    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.root)], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.name", "AWQ Fixture"], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.email", "fixture@example.invalid"],
            check=True,
        )

    def close(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, content: str | bytes, executable: bool = False) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8", newline="\n")
        if executable:
            path.chmod(0o755)
        return path

    def json(self, relative: str, value: object) -> Path:
        return self.write(relative, json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")

    def commit(self, message: str = "fixture") -> str:
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-q", "-m", message], check=True)
        return subprocess.check_output(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True
        ).strip()

    def head(self) -> str:
        return subprocess.check_output(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True
        ).strip()


def base_policy(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": 3,
        "profiles": ["core"],
        "unknown_formats": "error",
        "fixture_paths": [],
        "extensions": [],
        "exceptions": [],
        "governance": {
            "owners": ["@owner"],
            "max_standard_days": 30,
            "max_emergency_hours": 24,
        },
        "adapters": [],
    }
    value.update(updates)
    return value


def base_exception(**updates: Any) -> dict[str, Any]:
    created = datetime.now(UTC) - timedelta(hours=1)
    value: dict[str, Any] = {
        "id": "EX-0001",
        "kind": "standard",
        "requirement": "AWQ-CORE-001",
        "owner": "@owner",
        "reason": "Bounded fixture exception.",
        "scope": ["README.md"],
        "created_at": created.isoformat(),
        "expires_at": (created + timedelta(days=1)).isoformat(),
        "compensating_evidence": "Reviewed contract-test evidence.",
        "approval": "urn:awq:approval:EX-0001",
        "renewals": [],
        "revocation": None,
    }
    value.update(updates)
    return value


def packaged_schema_bytes(name: str) -> bytes:
    """Return real immutable SPDX bytes and minimal JSON schema fixture content."""
    if name == "spdx-3.0.1.schema.zip":
        return (Path(__file__).resolve().parents[1] / "schemas" / name).read_bytes()
    return b"{}\n"
