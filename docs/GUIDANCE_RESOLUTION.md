# Contradiction and guidance resolution

The `guidance-resolution` profile validates a bounded, digest-only state transition for
ambiguous, contradictory, stale, or scope-changing user guidance. It records the resulting
state (`pending_clarification`, `rejected_proposal`, `user_added_alternative`, `reconciled`,
or `reopened`) and the explicit user-result category without recording the user's content.

Every state other than `reconciled` is non-authorizing. A formal pass does not select an answer
or authorize unresolved work. Only an explicit reconciliation result may be marked authorizing,
and consumer-native gates remain authoritative. Repeated discussions must use a fresh task
revision and formal review; stale results, mismatched result/state pairs, material no-ops, unknown
fields, and non-public projections fail closed.

The checker proves only bounded evidence shape and transition consistency. It does not prove user
intent, implementation correctness, formal refinement, or the truth of the recorded disposition.
