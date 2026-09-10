# Bounded implementation trace correspondence

AWQ 0.19 checks a strict refinement-map contract for review-promotion-v1 against the installed
unmutated model. A pass means the supplied finite observations agree under a reviewed projection,
**not** that an implementation-refinement theorem has been established. Lifecycle and coupled
mappings remain unsupported and require separate reviewed profiles.

## Commands and contract

~~~sh
awq --root . assurance-check fixtures/conforming/refinement/map.json --format json
awq --root . assurance-check templates/refinement-map.json --format text
uv run python scripts/check_assurance_models.py
~~~

The [standalone schema](../schemas/refinement-map.schema.json) and
[shared schema](../schemas/assurance-contract.schema.json) define the closed version-1 profile.
The [template](../templates/refinement-map.json) contains synthetic commitments, four traces and
seven transitions. It is not independently acquired evidence about AWQ or a consumer.
Replace commitments and observations through review; never promote a gate using synthetic data.

Kind=refinement, map_version=1 and schema_version=1 are mandatory. The exact installed
[model source](../src/awq/formal_model.py) SHA-256 is checked against local bytes. The implementation
source SHA-256 is caller-declared: the evaluator never loads, imports, executes or authenticates
the candidate behind that commitment.

## Complete mappings and obligations

Every model state field appears exactly once in sorted order, mapped one-to-one to an opaque
FIELD-NNNN observation slot: revision, tick, reviewed_revision, review_tick, reviewer,
pending_revision, pending_tick, pending_reviewer and enforced. Every allowed action similarly maps
to a unique ACTION-NNNN token: edit, tick, finish-review, enforce and begin-review-N for every actor
slot, including owner zero. Missing, duplicate, ambiguous, reordered or unknown maps fail.

Projection is exact and one-step. Stuttering, hidden implementation steps, many-to-one abstraction,
asynchronous observation and lifecycle composition are not silently accepted.

Six obligations are required in canonical order. Each names an opaque OWNER identifier, a
reviewed-definition SHA-256 and an evidence SHA-256. The evidence digest equals the canonical whole
contract with only obligations omitted. Reviews therefore bind the exact model, implementation
commitment, mappings, bounds, assumptions and complete supplied trace set.

| Obligation | Mechanically checked part |
| --- | --- |
| bounds | All fields, lists and states stay within the profile |
| initial-state | Every model trace begins at the exact initial state |
| invariant-preservation | Each resulting model state satisfies the independent safety oracle |
| state-projection | Each implementation observation projects exactly to its paired model state |
| trace-coverage | Every mapped action occurs in at least one supplied trace |
| transition-simulation | Each step is an actual unmutated model successor for the declared action |

Owners and review digests are declarations, not signatures or authenticated identity. Independent
reviewers must inspect source identity, observation abstraction, collector and omissions.
The evaluator cannot establish whether review or execution occurred.

## Replay, bounds and failures

Every trace has an ordered unique TRACE-NNNN identifier, paired initial states, and one through
64 paired steps. There are one through 64 traces, at most 4,096 examined transitions, and a fixed
256,000-byte canonical-file ceiling. Actors range from two through three, revisions one through
three, logical ticks one through six, and review TTL one through three. Counts are integers, never
floats or Booleans. Negative sentinel values are permitted only in review/pending fields.

Each implementation trace digest binds its initial observation and ordered action/state pairs as
canonical JSON. It is checked independently of the review commitment. Invalid field types,
out-of-bound states and unknown actions fail before the affected transition is attempted.
Invalid global bounds, unknown fields or assumptions fail before replay.

Contradictory valid declarations return status=fail and normalized findings: initial-state,
state-projection, action-projection, transition-simulation, invariant-preservation,
implementation-trace-digest or trace-coverage. Invalid shapes, missing maps, unsupported profiles,
unbound reviews, unsafe files and invalid bounds are errors. Both forms exit nonzero.
No raw trace, observation, owner, review content or input path is printed.

Reviewed negatives cover [missing mapping](../fixtures/nonconforming/refinement/missing-map.json),
[contradictory trace](../fixtures/nonconforming/refinement/contradictory-trace.json) and
[out-of-bound input](../fixtures/nonconforming/refinement/out-of-bound.json).
Tests also cover adversarial digests, duplicates, private tokens, wrong actions, invariant failures,
missing action coverage, noncanonical/oversized JSON and symlink traversal.

## Assumptions and proof limits

The fixed assumptions inherit atomic interleaved actions, bounded monotonic clock/revisions,
honest review records and one policy owner from [formal assurance](FORMAL_ASSURANCE.md).
Additional assumptions explicitly identify caller-declared implementation traces, exact one-step
projection, reviewed observation abstraction and the absence of a hidden-state completeness claim.

Action coverage is not branch coverage, exhaustive transition coverage, negative-input coverage or
proof that the implementation has no extra behavior. A passing corpus can omit implementation bugs.
Hash commitments do not establish truth, authenticity, completeness or privacy; hashing guessable
private material does not make publication safe.

Results always report execution=caller-declared-not-run, refinement=not-proven,
composition=not-proven and native_gate=retain. There is no theorem, unbounded safety, liveness,
fairness, whole-program equivalence, filesystem/clock/host guarantee or compliance claim.
The [lifecycle components](LIFECYCLE_MODELS.md) remain non-compositional.
Language-specific collectors, authenticated execution, stronger abstractions and coupled lifecycle
refinement require later reviewed contracts. Existing native gates remain intact.
