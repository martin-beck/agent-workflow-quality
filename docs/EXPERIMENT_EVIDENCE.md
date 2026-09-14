# Experiment evidence

AWQ validates a benchmark-neutral, data-only experiment receipt. The receipt binds an exact source
revision and tree, workload and configuration digests, a predeclared sampling and stopping design,
bounded resource budgets, environmental conditions, all attempted outcomes, raw-result artifact
digests, bias treatment, uncertainty, and consumer review.

Validation is deterministic and offline. Fixed designs must run their declared sample count.
Precision-or-budget designs may stop early only after meeting the declared precision target.
Completed, failed, timed-out, cancelled, and missing observations must exactly account for every
attempt. Contamination requires an explicit disposition and rationale. A capacity claim cannot
exceed the highest tested capacity or be presented as inferred capacity.

The returned evidence is content-minimized aggregate metadata. It never embeds raw results,
automatically changes a baseline, accepts a regression because of variance, or chooses a score,
threshold, workload, estimator, SLO, or domain conclusion.

## Limits

A valid receipt proves only that the declaration is structurally closed and internally consistent.
It does not prove that a workload represents a population, that an environment was controlled, that
the selected confidence method is scientifically appropriate, or that digest-bound external result
bytes are truthful. Environmental validity and methodology review remain explicit consumer-owned
claims. Native benchmark gates remain authoritative and unchanged.
