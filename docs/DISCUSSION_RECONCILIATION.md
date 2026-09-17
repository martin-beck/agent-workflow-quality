# Discussion reconciliation

The `discussion-reconciliation` profile validates a bounded, digest-only record for a completed
user discussion. It requires symmetric before/after identities for the versioned work plan, design,
dependency graph and specification; an explicit changed-artifact list; and a new passing formal
result bound to the after specification and current task revision. A changed artifact with the
previous formal result is rejected.

Every affected AR has an exact before/after revision and an explicit unchanged, closed, or reopened
disposition. Acceptance is intentionally multidimensional: `user_guidance`, `quality_evidence`,
and `implementation_verification` cannot be collapsed into one approval flag. The required
limitations state that user intent, implementation correctness and formal refinement are not proven,
and that consumer-native gates remain authoritative. Only hashes, bounded identifiers and the
public-safe projection are retained; prompts, transcripts, private paths and credentials are not
part of the contract.

Run one record with:

```sh
awq --root . discussion-reconciliation-evaluate quality/discussion-reconciliation/example.json --format json
```
