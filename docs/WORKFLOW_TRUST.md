# Directive and rollback workflow trust

`awq.workflow_trust` validates the public boundary of directive and rollback
fixtures without executing them. A directive is revision-bound, expiry-bound,
and carries an explicit actor, action, permission, and bounded runner identity.
Rollback records require explicit operator approval and are limited to
`not-requested` or `review-only` publication state; they cannot authorize an
upload or release.

Runner records contain only an allow-listed identity, trust class, and platform.
Runner labels, expression values, credentials, and secret material are rejected
as unknown fields. The evaluator returns sorted identifiers and counts only, so
outputs are deterministic and content-minimized.
