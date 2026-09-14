# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Synthetic agent-runtime replay contract and hostile boundary tests."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from awq import agent_replay
from awq.cli import main
from awq.project import ProjectError
from awq.registry import canonical_bytes
from scripts.validate_contracts import validate

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/conforming/agent-runtime-replay.json"


def document() -> dict[str, Any]:
    return dict(json.loads(FIXTURE.read_bytes()))


class AgentReplayTests(unittest.TestCase):
    def test_canonical_replay_schema_runtime_cli_and_redaction(self) -> None:
        value = document()
        validate(value, "agent-runtime-replay.schema.json")
        first = agent_replay.evaluate(value)
        second = agent_replay.evaluate(copy.deepcopy(value))
        self.assertEqual(first, second)
        self.assertEqual("pass", first["status"])
        self.assertEqual("contract-test", first["evidence_class"])
        self.assertEqual("retain", first["native_gate"])
        self.assertEqual("pre-serialization", first["redaction_stage"])
        rendered = json.dumps(first, sort_keys=True)
        for prohibited in ("chat-completions", "content-type", "RESOLVER-SYNTHETIC"):
            self.assertNotIn(prohibited, rendered)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(
                [
                    "--root",
                    str(ROOT),
                    "agent-replay-evaluate",
                    "fixtures/conforming/agent-runtime-replay.json",
                    "--format",
                    "json",
                ]
            )
        self.assertEqual(0, code)
        self.assertEqual(first, json.loads(output.getvalue()))

    def test_timeline_matching_bounds_uncertainty_and_live_promotion_fail_closed(self) -> None:
        cases: list[tuple[str, list[str | int], Any]] = [
            ("unconsumed", ["consumption", "unconsumed_frames"], 1),
            ("reordered", ["cassette", "interactions", 0, "events", 1, "sequence"], 3),
            (
                "correlation",
                ["cassette", "interactions", 0, "events", 1, "correlation_id"],
                "CORRELATION-OTHER",
            ),
            ("limit", ["cassette", "limits", "max_frames"], 0),
            ("redaction", ["cassette", "redaction", "version"], "awq-redaction-v2"),
            ("live", ["classification"], "live-observation"),
            ("network", ["launch", "network", "mode"], "live"),
            ("telemetry", ["launch", "telemetry", "mode"], "enabled"),
        ]
        for name, path, replacement in cases:
            with self.subTest(name=name):
                value = document()
                target: Any = value
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = replacement
                with self.assertRaises(ProjectError):
                    agent_replay.evaluate(value)

        ambiguous = document()
        repeated = copy.deepcopy(ambiguous["cassette"]["interactions"][0])
        repeated["id"] = "INTERACTION-0002"
        repeated["correlation_id"] = "CORRELATION-0002"
        for event in repeated["events"]:
            event["correlation_id"] = "CORRELATION-0002"
        ambiguous["cassette"]["interactions"].append(repeated)
        ambiguous["consumption"]["interactions"] = 2
        ambiguous["consumption"]["events"] = 6
        ambiguous["consumption"]["frames"] = 2
        with self.assertRaisesRegex(ProjectError, "ambiguous-request-match"):
            agent_replay.evaluate(ambiguous)

    def test_uncertain_retry_requires_consumer_idempotency_and_atomic_settings(self) -> None:
        value = document()
        retry = copy.deepcopy(value["cassette"]["interactions"][0])
        retry["id"] = "INTERACTION-0002"
        retry["correlation_id"] = "CORRELATION-0002"
        retry["retry"] = {
            "mode": "consumer-authorized",
            "retry_of": "INTERACTION-0001",
            "idempotency_proof_sha256": "c" * 64,
        }
        for event in retry["events"]:
            event["correlation_id"] = "CORRELATION-0002"
        value["cassette"]["interactions"].append(retry)
        value["consumption"] = {
            "interactions": 2,
            "events": 6,
            "frames": 2,
            "retries": 1,
            "unconsumed_frames": 0,
        }
        self.assertEqual("pass", agent_replay.evaluate(value)["status"])

        missing = copy.deepcopy(value)
        missing["cassette"]["interactions"][1]["retry"]["idempotency_proof_sha256"] = None
        with self.assertRaisesRegex(ProjectError, "idempotency-proof"):
            agent_replay.evaluate(missing)
        mismatch = copy.deepcopy(value)
        request = mismatch["cassette"]["interactions"][1]["request"]
        request["route_id"] = "responses"
        matched = {key: request[key] for key in ("method", "route_id", "headers", "body_sha256")}
        request["match_sha256"] = hashlib.sha256(canonical_bytes(matched)).hexdigest()
        with self.assertRaisesRegex(ProjectError, "retry-request-mismatch"):
            agent_replay.evaluate(mismatch)
        dropped = document()
        dropped["launch"]["adapter_set"]["preserved"] = ["max-tokens"]
        with self.assertRaisesRegex(ProjectError, "adapter-set-not-atomic"):
            agent_replay.evaluate(dropped)

    def test_unknown_fields_and_content_bearing_inputs_are_rejected_without_echo(self) -> None:
        value = document()
        value["launch"]["prompt_transport"]["prompt"] = "private prompt"
        with self.assertRaises(ProjectError):
            agent_replay.evaluate(value)
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "hostile.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(
                    [
                        "--root",
                        str(ROOT),
                        "agent-replay-evaluate",
                        str(path.relative_to(ROOT)),
                        "--format",
                        "json",
                    ]
                )
        self.assertEqual(1, code)
        self.assertNotIn("private prompt", output.getvalue())
        self.assertEqual("error", json.loads(output.getvalue())["status"])


if __name__ == "__main__":
    unittest.main()
