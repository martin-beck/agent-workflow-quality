# Execution budgets and process receipts

The closed [execution receipt schema](../schemas/execution-receipt.schema.json) records nine bounded
resource dimensions: wall time, actions, tokens, cost, CPU, memory, PIDs, disk and output. Every
dimension says whether its value was 'enforced', 'observed', 'estimated' or 'unavailable'; available
values carry a pinned measurement-tool identity. Observation and estimation never imply enforcement.

Reservations describe a finite logical-step lifecycle. An external effect must have a prior
reservation and a single later settlement. Full refund and stale-refund states conserve the
reservation amount; over-settlement, expired active reservations and effects preceding reservation
fail closed. The embedded exhaustive small-state check covers non-negative balance, conservation and
reserve-before-effect/settle chronology, and all bounded descendant/orphan classifications. It is
bounded-model evidence, not implementation refinement.

Process receipts retain only the argv digest, environment classification, process-group/session
policy, deadline, TERM/KILL decisions, descendant result and orphan result. Command text, environment
values, subprocess output and machine paths are excluded. Missing escalation plus surviving or
unknown descendant and orphan outcomes produce stable findings.

Optional network, filesystem and capability records are observations only. They can report a pinned
tool observed a boundary as blocked or allowed, or that the boundary was unavailable. They cannot
claim portable isolation. An observed allowed boundary remains review-visible but does not by itself
fail the receipt because no portable isolation policy is implied. The executable remains trusted
tooling with ambient host capabilities.

An adapter-backed receipt binds the canonical adapter-result digest, the canonical contract argv
digest, contract deadline, minimal runner environment, new-session process scope, wall duration and
measurement-tool identity. `evaluate_adapter_lifecycle` checks those correspondences before the
normal receipt evaluation; it does not infer cleanup or isolation facts the adapter did not record.

Evaluate a repository-owned receipt offline:

    awq --root . execution-receipt-evaluate \
      fixtures/conforming/execution-receipt.json --format json
