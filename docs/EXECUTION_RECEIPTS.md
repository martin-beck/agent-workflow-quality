# Execution budgets and process receipts

The closed [execution receipt schema](../schemas/execution-receipt.schema.json) records nine bounded
resource dimensions: wall time, actions, tokens, cost, CPU, memory, PIDs, disk and output. Every
dimension says whether its value was 'enforced', 'observed', 'estimated' or 'unavailable'; available
values carry a pinned measurement-tool identity. Observation and estimation never imply enforcement.

Reservations describe a finite logical-step lifecycle. An external effect must have a prior
reservation and a single later settlement. Full refund and stale-refund states conserve the
reservation amount; over-settlement, expired active reservations and effects preceding reservation
fail closed. The embedded exhaustive small-state check covers non-negative balance, conservation and
reserve-before-settle invariants. It is bounded-model evidence, not implementation refinement.

Process receipts retain only the argv digest, environment classification, process-group/session
policy, deadline, TERM/KILL decisions, descendant result and orphan result. Command text, environment
values, subprocess output and machine paths are excluded. Missing escalation, surviving descendants
and surviving orphans produce stable findings.

Optional network, filesystem and capability records are observations only. They can report a pinned
tool observed a boundary as blocked or allowed, or that the boundary was unavailable. They cannot
claim portable isolation. The executable remains trusted tooling with ambient host capabilities.

Evaluate a repository-owned receipt offline:

    awq --root . execution-receipt-evaluate \
      fixtures/conforming/execution-receipt.json --format json
