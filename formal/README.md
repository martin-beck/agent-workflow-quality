# Bounded review/promotion model

The executable model lives in [awq.formal_model](../src/awq/formal_model.py).
Read [the formal assurance contract](../docs/FORMAL_ASSURANCE.md) for commands, bounds,
assumptions, counterexamples, implementation correspondence and limits. The reviewed
[counterexample fixtures](counterexamples.json) are checked by the offline model regression gate.

The [lifecycle components](../docs/LIFECYCLE_MODELS.md) add independent exception, tier and
publication graphs. Their [ten counterexamples](lifecycle-counterexamples.json) run in the same
regression gate; composition and implementation refinement remain unproven.
