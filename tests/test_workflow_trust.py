# Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# SPDX-License-Identifier: MIT

"""Directive and rollback trust-boundary fixtures."""

from copy import deepcopy

import pytest

from awq import workflow_trust
from awq.release import ReleaseError

AS_OF = "2026-09-25T12:00:00Z"
REVISION = "a" * 40
PAYLOAD = "b" * 64
CHECKPOINT = "c" * 64
RUNNER = {"runner_id": "runner-01", "trust_class": "trusted-host", "platform": "linux"}


def directive() -> dict:
    return {
        "schema_version": 1,
        "id": "DIRECTIVE-ONE",
        "source_revision": REVISION,
        "request_id": "REQUEST-ONE",
        "actor": "human",
        "action": "rollback",
        "created_at": "2026-09-25T10:00:00Z",
        "expires_at": "2026-09-25T13:00:00Z",
        "runner": deepcopy(RUNNER),
        "permission": "approve",
        "payload_sha256": PAYLOAD,
    }


def rollback() -> dict:
    return {
        "schema_version": 1,
        "id": "ROLLBACK-ONE",
        "source_revision": REVISION,
        "checkpoint_sha256": CHECKPOINT,
        "requested_by": "operator@example.test",
        "permission": "operator-approved",
        "publication_state": "review-only",
        "runner": deepcopy(RUNNER),
        "created_at": "2026-09-25T10:01:00Z",
    }


def test_directive_and_rollback_evaluation_is_deterministic_and_non_authorizing() -> None:
    value = {"schema_version": 1, "directives": [directive()], "rollbacks": [rollback()]}
    expected = {
        "schema_version": 1,
        "directive_ids": ["DIRECTIVE-ONE"],
        "rollback_ids": ["ROLLBACK-ONE"],
        "trusted_runner_count": 1,
        "publication_authorized": False,
    }
    assert workflow_trust.evaluate(value, AS_OF) == expected
    assert workflow_trust.evaluate(value, AS_OF) == expected


@pytest.mark.parametrize(
    "mutate",
    [
        lambda item: item.update(expires_at="2026-09-25T11:00:00Z"),
        lambda item: item.update(
            runner={"runner_id": "runner-01", "trust_class": "untrusted", "platform": "linux"}
        ),
        lambda item: item.update(permission="execute", expires_at="2026-09-25T11:00:00Z"),
    ],
)
def test_directive_trust_rejects_expiry_and_unreviewed_runner_boundaries(mutate) -> None:
    item = directive()
    mutate(item)
    with pytest.raises(ReleaseError):
        workflow_trust.validate_directive(item, AS_OF)


def test_rollback_cannot_authorize_publication_or_accept_unknown_fields() -> None:
    item = rollback()
    item["publication_state"] = "published"
    with pytest.raises(ReleaseError):
        workflow_trust.validate_rollback(item, AS_OF)
    item = rollback()
    item["runner"]["expression"] = "secrets.TOKEN"
    with pytest.raises(ReleaseError):
        workflow_trust.validate_rollback(item, AS_OF)
