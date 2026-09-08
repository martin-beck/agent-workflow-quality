"""Validate every shipped JSON contract and live AWQ record."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path

import jsonschema

from awq.commands import evidence

ROOT = Path(__file__).resolve().parents[1]


def validate(instance: object, schema_name: str) -> None:
    schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(
        instance
    )


def main() -> int:
    requirements = json.loads(files("awq.data").joinpath("requirements.json").read_text())
    profiles = json.loads(files("awq.data").joinpath("profiles.json").read_text())
    policy = json.loads((ROOT / "quality" / "awq.json").read_text())
    lock = json.loads((ROOT / "quality" / "awq.lock.json").read_text())
    validate(requirements, "requirement-registry.schema.json")
    validate(profiles, "profile-registry.schema.json")
    validate(policy, "project-policy.schema.json")
    validate(lock, "lock.schema.json")
    validate(evidence(ROOT, "pr"), "evidence.schema.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
