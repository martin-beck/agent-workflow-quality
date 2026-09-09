# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Generate public synthetic provenance fixtures, never a publisher trust anchor."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from awq import provenance, trust
from awq.registry import canonical_bytes

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/conforming/release-provenance"


def render() -> dict[str, bytes]:
    """Return deterministic profile examples using an explicitly synthetic public key."""
    wire = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))
    key = "ssh-ed25519 " + base64.b64encode(wire).decode()
    policy = {
        "schema_version": 1,
        "repository": provenance.REPOSITORY,
        "generation": 1,
        "previous_policy_sha256": None,
        "retired": [],
        "roots": [
            {
                "principal": "synthetic-example@example.invalid",
                "public_key": key,
                "fingerprint": trust.fingerprint(key),
                "valid_after": "2020-01-01T00:00:00Z",
                "valid_until": "2090-01-01T00:00:00Z",
            }
        ],
    }
    manifest = json.loads((ROOT / "fixtures/conforming/release-sbom/manifest.json").read_bytes())
    manifest["schema_version"] = 3
    manifest["trust_policy_sha256"] = trust.digest(policy)
    raw = canonical_bytes(provenance.generate(manifest, provenance.source_materials(ROOT)))
    manifest["provenance"] = {
        "name": f"agent_workflow_quality-{manifest['version']}.provenance.json",
        "media_type": provenance.MEDIA,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    return {
        "trust-policy.json": canonical_bytes(policy),
        "manifest.json": canonical_bytes(manifest),
        "statement.json": raw,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = render()
    if not args.check:
        FIXTURE.mkdir(parents=True, exist_ok=True)
    for name, raw in rendered.items():
        path = FIXTURE / name
        if args.check:
            if path.read_bytes() != raw:
                raise SystemExit("provenance fixture generation differs")
        else:
            path.write_bytes(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
