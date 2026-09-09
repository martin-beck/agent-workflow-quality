# Bounded formal and refactoring assurance

AWQ 0.17 provides a zero-runtime-dependency, offline finite-state explorer and a strict declaration
contract for before/after refactoring evidence. Neither feature executes candidate code, starts a
shell, acquires tools, authenticates evidence producers or changes consumer/native gates.

## Agent-ready commands

Run the reviewed baseline and all known-bad models as one regression gate:

~~~sh
uv run python scripts/check_assurance_models.py
~~~

Run one confined canonical contract with deterministic JSON or text output:

~~~sh
awq --root . assurance-check fixtures/conforming/assurance/model.json --format json
awq --root . assurance-check fixtures/conforming/assurance/refactor.json --format text
~~~

The [formal template](../templates/formal-model.json) and
[refactoring template](../templates/refactor-evidence.json) are synthetic examples, not evidence about
a consumer. Replace synthetic commitments and counts with independently reviewed evidence. The
[standalone schema](../schemas/assurance-contract.schema.json) specifies the exact wire shape;
runtime validation also enforces cross-field counts, source change, ordered methods, resource bounds
and exploration completion. Version and kind are checked at runtime before dispatch.

## Finite review/promotion model

The executable transition relation is [formal_model.py](../src/awq/formal_model.py).
The state consists only of bounded integer revision, logical clock, completed review revision/time/
actor, pending review revision/time/actor, and a Boolean enforcement decision. Actor zero owns the
policy. Other actors are independent reviewers.

Actions are edit, tick, begin-review-N, finish-review and enforce. Begin-review captures a revision
and time. Other actions may interleave before finish-review publishes that captured record. This
deliberately permits stale or expired completed reviews; the enforce guard must reject them.
Edits, clock advances and review completion clear the previous decision, requiring reevaluation.
This models an ephemeral authorization decision, not automatic reconfiguration of a persistent
hosted required check.

The independent safety oracle checks each reachable enforced state:

| Invariant | Required fact |
| --- | --- |
| current-revision | Completed review revision equals current policy revision |
| independent-reviewer | Reviewer is not the policy owner |
| unexpired-review | Review age is nonnegative and strictly less than its logical TTL |

Breadth-first exploration visits each reachable state once, with deterministic action ordering.
It explores every action interleaving within the selected finite bounds, including pending reviews
across edits and ticks. Duplicate transitions do not create new states.

| Bound | Allowed values |
| --- | --- |
| Actors, including owner | 2 through 3 |
| Maximum revision | 1 through 3, starting at 0 |
| Maximum logical tick | 1 through 6, starting at 0 |
| Review TTL | 1 through 3 logical ticks |
| Maximum visited states | 1 through 20,000 |
| Maximum examined transitions | Fixed ceiling of 200,000 |

The reviewed default explores 256 states and 514 transitions. Reaching either resource ceiling
returns incomplete with failure, never a partial proof. Counts exclude an unexamined transition
beyond the transition ceiling. A successful unmutated run reports exhausted, meaning the reachable
queue was completely explored under these bounds. A mutation that escapes detection because the
chosen bounds do not expose it reports surviving-mutant and fails.

Assumptions are a fixed, explicit list: atomic interleaved actions, bounded monotonic clock, bounded
monotonic revisions, honest review records and one policy owner. The validator rejects unknown,
omitted or reordered assumptions and invalid bounds before invoking the explorer.

## Reviewed counterexamples

The exact [counterexample record](../formal/counterexamples.json) is checked in CI and unit tests.
Each faulty variant changes only one enforcement guard. Its CLI invocation must return failure:

~~~sh
awq --root . assurance-check fixtures/nonconforming/assurance/stale-review.json --format json
awq --root . assurance-check fixtures/nonconforming/assurance/expired-review.json --format json
awq --root . assurance-check fixtures/nonconforming/assurance/self-review.json --format json
~~~

| Mutation | Expected shortest trace | Violated invariant |
| --- | --- | --- |
| stale-review | begin-review-1, edit, finish-review, enforce | current-revision |
| expired-review | begin-review-1, tick, finish-review, enforce | unexpired-review |
| self-review | begin-review-0, finish-review, enforce | independent-reviewer |

Counterexamples contain only fixed action names and invariant IDs, no execution output or source
data. Tests replay each trace, independently inspect the violating state fields and prove that the
unmutated guard would reject its final enforce action. The regression checker requires the exact
baseline outcome/counts/bounds and all three exact counterexamples; changing expected fixtures needs
semantic review, not automatic acceptance of a new output.

## Implementation correspondence and proof limits

The transition function and its safety oracle are separate functions; this permits a deliberately
broken guard to be detected by the unchanged oracle. It is still a Python checker tested by examples,
not a verified theorem prover or a proof of its own implementation.

| Model concern | Reviewed implementation connection | Strength |
| --- | --- | --- |
| Revision-sensitive authorization | [verified update](../src/awq/verified_update.py) and candidate lock verification | Conceptual, no refinement proof |
| Independent and unexpired review | [promotion review validation](../src/awq/promotion.py) | Predicate correspondence, not whole-system equivalence |
| Fail-closed evidence decisions | [assurance evaluation](../src/awq/assurance.py) and [promotion decisions](PROMOTION.md) | Executable tests, not concurrency refinement |

Every model result explicitly says refinement=not-proven and includes the current model source
SHA-256, AWQ version, canonical contract digest, assumptions and bounds. These bind the inspected
implementation and parameters; they do not establish publisher authenticity or execution provenance.

The model does not prove unbounded safety, fairness, progress, liveness, real-time behavior, trusted
timestamps, signature validity, filesystem atomicity, crash recovery, network/host behavior, actual
GitHub settings, actual multi-process locking or equivalence of any consumer implementation.
Clock advancement conservatively invalidates the prior decision; actual persistent enforcement
requires a separate implementation model and reviewed refinement mapping.

## Refactoring evidence

The refactor kind requires distinct before/after source SHA-256 commitments, an opaque owner,
review commitment and the exact claim bounded-behavior-agreement. It requires exactly four records
in canonical method order: characterization, differential, mutation, property. Formatting alone,
missing methods, duplicate methods, unknown fields or a stronger claim are rejected.

Each record binds an exact reviewed tool/configuration definition, canonical case set, normalized
before/after result commitments, case count, before/after failure counts, mismatch count and mutation
counts. Case counts range from 1 through 100,000; failures/mismatches cannot exceed cases.
Only the mutation record has positive mutant count, at most 10,000, and killed cannot exceed mutants.

Both sides must have zero test failures, zero behavior mismatches, and equal normalized result
commitments. All declared mutants must be killed. A differing commitment fails even when the declared
mismatch count is zero; a surviving mutant fails even when all other records pass. Equivalent-mutant
classification or exclusion is not modeled here and must not be used to silently reduce the count.

Normalization, observables, input domain, seeds, comparison tolerance, before/after environment and
tool versions belong in the reviewed definitions behind the commitments. The evaluator does not
execute these definitions or inspect the original source. A passing record means only that the
bounded declaration is internally acceptable, not that behavior preservation or producer honesty
has been established. Language-specific acquisition/execution/refinement belongs to separate work.

## Privacy and continuation boundary

Contracts are canonical compact UTF-8 JSON, with sorted keys and one final LF, at most 256,000 bytes.
Duplicate keys, non-finite values, fractional counts, unknown fields and malformed digests/owners
fail closed. Files must be normalized repository-relative regular JSON files with no symlink
component. No raw logs, source excerpts, prompts, transcripts, credentials, host paths, names or
email addresses belong in the evidence. Keep opaque owner mappings separately governed. Hashing a
guessable secret does not make publishing it safe.

AR-0006 is an umbrella. This slice covers only the abstract review/promotion model and the shared
refactoring declaration profile. Remaining child work must cover full policy-update/rollback state,
exception expiry and renewal, tier transitions/evidence freshness, multi-reviewer concurrency and
crash behavior, explicit implementation refinement, and language-specific refactoring collectors/
adapters with independent native equivalence and hostile tests. Those children must use the
coordinator, preserve current gates and retain these proof limits until stronger evidence exists.
