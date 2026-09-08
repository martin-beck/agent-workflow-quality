# Policy governance

AWQ policy schema version 2 makes governance and exceptions explicit machine-readable contracts.
It does not grant an exception merely because a record exists: the record must pass runtime and JSON
Schema validation, match a finding's requirement and path, remain unexpired, and not be revoked.

## Governance boundary

`quality/awq.json` declares:

- `owners`: unique GitHub user or team handles allowed to own, renew, or revoke exceptions.
- `max_standard_days`: project limit for each standard exception period, capped by AWQ at 90 days.
- `max_emergency_hours`: project limit for emergency exceptions, capped by AWQ at 72 hours.

`awq --root . governance --format json` emits deterministic CODEOWNERS suggestions for the policy,
schemas, built-in registry, workflows, and CODEOWNERS file. The output is an offline suggestion. It
does not claim that repository-hosting settings enforce those owners.

## Exception lifecycle

Every exception has an `EX-NNNN` identifier, `standard` or `emergency` kind, active AWQ
requirement, current governance owner, rationale, bounded repository-relative scope, creation and
expiry timestamps, compensating evidence, and an HTTPS or URN approval reference. Approval URLs
with embedded credentials are rejected. Credentials and approval tokens do not belong in policy.

A standard renewal appendsnever rewritesa history item containing the prior expiry, renewal time,
new expiry, owner, rationale, and approval reference. The history must form a continuous ordered
chain and each period remains within the configured lifetime. Emergency exceptions cannot renew.

Resolved exceptions remain in the policy with a revocation record. Revocation records contain the
time, current owner, reason, and approval reference. A revoked exception no longer suppresses
findings. Deleting an exception or removing its revocation is classified as weakening because it
destroys or reactivates audit history.

Example:

```json
{
  "id": "EX-0042",
  "kind": "standard",
  "requirement": "AWQ-CORE-001",
  "owner": "@example/quality",
  "reason": "Legacy generator migration is in progress.",
  "scope": ["generated/legacy.txt"],
  "created_at": "2026-09-01T09:00:00+00:00",
  "expires_at": "2026-09-15T09:00:00+00:00",
  "compensating_evidence": "Daily byte-level output comparison is retained.",
  "approval": "https://github.com/example/project/pull/42",
  "renewals": [],
  "revocation": null
}
```

`awq doctor` fails expired active exceptions and exceptions targeting requirements outside the
locked profile. Structural validation rejects broadened lifetimes, orphaned owners, unsafe scopes,
broken renewal chains, late revocations, and unknown fields.

## Semantic review gate

`awq policy-diff BASE HEAD --format json` compares the policy and lock at two Git revisions. It
classifies all semantic changes as:

- `weakening`: removed profiles, gates, formats, owners, or lock entries; added fixture exclusions
  or exception scope; later execution tiers; shorter gate deadlines; silent expiry extension;
  altered exception authority or history; and removed revocations.
- `strengthening`: earlier or broader gates, tighter lifetime bounds, shorter exception scope or
  expiry, and added revocations.
- `review`: new fully validated exceptions, append-only validated renewals, new owners, remediation
  text, and version or registry pin changes.

Any weakening makes the command fail. Review and strengthening changes remain visible in its output.
The repository runs this command on pull requests before merge.

## Hosting observation

`awq hosting-observe --repository OWNER/NAME --format json` is the only governance command that
uses the network. It reads GitHub's public repository metadata, ruleset summaries, and then each fixed-origin detail
endpoint, with per-response size, ruleset-count, and timeout bounds. Output is sanitized and contains
no authentication token.

The observation passes only when active rules that include and do not exclude the default branch
expose `pull_request` plus at least one named `required_status_checks` context. Its schema fixes
the evidence class to `environmental`, the tier to
`scheduled`, and records an `observed_at` timestamp. This point-in-time evidence is not offline
proof and does not establish that every bypass or administrator action is controlled.
