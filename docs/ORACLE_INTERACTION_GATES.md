# Typed oracle interaction gates

AWQ profile `interaction-gates` validates one bounded, digest-only record for each
declared oracle interaction. The record binds the Coordinator task identifier and
revision, typed event references, objective/constraint/implication context, before
and after plan/design digests, a passing formal-specification review, a user
disposition, and a public-safe projection.

The `interaction-gate` requirement scans `quality/interaction-gates/*.json` and
fails closed when the directory is absent, empty, non-canonical, unresolved, or
missing any required digest. `interaction-gate-evaluate` validates one confined
record without returning its content.

This is a quality-contract check only. A passing record does not establish user
intent, implementation correctness, formal proof, or the truth of the recorded
disposition. Native project gates remain authoritative. Raw prompts, transcripts,
private paths, and credentials are outside this contract; only digest bindings and
bounded classifications are public evidence.
