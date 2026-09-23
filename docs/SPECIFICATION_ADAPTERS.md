# Acceptance specification adapter family

The `specification` family provides an offline, pinned `awq-spec-check` contract for
repository-owned acceptance predicates. The wrapper and specification remain consumer-owned;
AWQ validates the invocation boundary and records only bounded pass/fail evidence. A passing
predicate observation is contract-test evidence and never replaces the consumer's native gates.

The contract requires `quality/acceptance-spec.json`, the exact `awq-spec-check 1.0.0` version
probe, the fixed `acceptance quality/acceptance-spec.json` argument array, and a finite five-minute
deadline. Install or qualify the wrapper separately; adapter execution does not download tools,
contact a service, or retain subprocess output.
