# Bounded policy lifecycle components

AWQ 0.18 extends [formal assurance](FORMAL_ASSURANCE.md) with policy-lifecycle-v1.
It exhaustively explores three **independent** finite transition systems, not their combined state
space. Results explicitly state composition=not-proven and refinement=not-proven. No consumer,
native gate, actual file, subprocess, clock, trust policy or hosted setting is changed.

## Commands and contracts

~~~sh
awq --root . assurance-check fixtures/conforming/lifecycle/model.json --format json
uv run python scripts/check_assurance_models.py
~~~

The regression command checks both the original review/promotion model and all lifecycle baselines
and faulty variants. The [template](../templates/lifecycle-model.json) is synthetic.
The [standalone lifecycle schema](../schemas/lifecycle-model.schema.json) and
[shared assurance schema](../schemas/assurance-contract.schema.json) validate its wire format.
Runtime additionally rejects unknown model/kind/version, malformed or weakened assumptions and
invalid bounds before exploration. Canonical JSON, file confinement and privacy rules remain those
of the shared assurance contract.

## Bounds, state and assumptions

All clocks are bounded integer logical ticks, not UTC or trusted wall clocks. Revisions start at
zero. Actors are fixed, distinct slots; ownership and review honesty are assumptions, not
authenticated identities.

| Parameter | Allowed | Reviewed default |
| --- | --- | --- |
| ticks | 1 through 3 | 2 |
| revisions | 1 through 3 | 2 |
| ttl | 1 through 3 | 1 |
| tiers | 1 through 2 above baseline tier zero | 2 |
| rollback_deadline | 1 through 3 logical ticks, exclusive | 2 |
| max_states | 1 through 20,000 per component | 20,000 |
| Transition ceiling | Fixed 200,000 per component | 200,000 |

| Component | Default reachable states | Default examined transitions |
| --- | --- | --- |
| exceptions | 89 | 220 |
| publication | 138 | 250 |
| tiers | 1,086 | 4,512 |

The baseline fully empties each breadth-first search queue. Hitting a state or transition ceiling
returns incomplete and failure; it never authorizes a bounded proof from an unfinished search.
A mutant without a reachable counterexample reports surviving-mutant and fails. For example, a TTL
longer than the explored clock can hide the expiry mutation, which must not count as successful
mutation testing. Counterexample takes precedence in the aggregate outcome when another component
is incomplete; each component's outcome remains explicit and the aggregate still fails.

The fixed assumptions are atomic abstract actions, bounded logical time, bounded monotonic revisions,
honest distinct reviewers, independent components, a single atomic durable publication point, and
staging not being publication. These are intentionally finite abstractions, not guarantees about
Python, filesystems, signatures, processes or operating systems.

## Exception grant, renewal, expiry and revocation

Exception state includes logical tick, generation, expiry, captured review generation/tick and the
approval generation of the published exception. No exception initially exists.

Review-renewal captures the current generation and tick. Publish-renewal requires that same current
generation and logical tick, advances the generation, and grants a TTL from publication. A fresh
review can renew an expired exception. Revocation advances generation and removes the exception but
leaves a previously captured review token stale, so it cannot silently resurrect the old grant.
The original review and renewal share this abstract mechanism; scope, owner identities and approval
signatures remain outside the model.

The use-exception action must observe an existing unexpired grant. Publication must bind approval
to the immediately previous generation. Tick clears the ephemeral use decision. The model checks
authorization at use, not automatic deletion of a persisted exception at expiry.

## Tier promotion, evidence freshness and two reviewers

Tier state includes policy revision, logical tick, current and proposed tier, two independently
captured review revisions, and the evidence revision/tick. Propose-N advances policy revision even
when it changes only a target; captured old reviews and evidence remain visible as stale tokens.

Each reviewer can complete at a different point in the interleaving. Promotion requires both slots
to match the current revision, current-revision evidence younger than TTL, exactly the next tier,
and a still-open rollback deadline. Reviews are revision-bound; independent review-expiry periods
are not modeled in this component. Evidence can be refreshed independently.

Rollback lowers the tier by one only before the configured deadline. This models the authorization
of a routine reviewed rollback, not a prohibition on emergency recovery after a deadline.
No emergency operator or compensating-action protocol is modeled. Likewise, evidence expiry does
not silently remove a persistent hosted gate; checks apply to the promotion transition itself.

## Two writers, publication and crash/restart

Publication state has a durable policy generation and receipt generation, plus two writers' captured
base generations and staging phases. Begin captures the current generation; the first stage action
prepares policy and the second prepares its receipt. Commit requires both phases and compare-and-swap
against the current durable generation, then atomically publishes the next matching pair.

Crash makes the process unavailable while preserving the last durable pair and unpublished staging.
Restart discards both writers' staging and restores availability without promoting temporary data.
Tests cover crash before publication and after publication. The independent oracle checks that the
pair always matches, a commit advances exactly one generation, and crash/restart preserve the
committed pair.

The atomic pair is an **assumed abstract commit primitive**. Successful exploration does not prove
rename/fsync ordering, power-loss durability, kernel behavior, multi-file atomicity or the actual AWQ
lock publisher. A faulty variant can deliberately break the abstraction so the unchanged oracle
detects it. This demonstrates counterexample sensitivity, not validation of a filesystem primitive.

## Ten reviewed faulty variants

Each canonical request under fixtures/nonconforming/lifecycle must exit 1. Exact traces and all
component results are reviewed in [lifecycle-counterexamples.json](../formal/lifecycle-counterexamples.json).
The regression checker compares those exact records, and tests replay the traces, independently
inspect the violating fields, and show that the original transition would not produce the same
unauthorized result.

| Mutation | Deliberate fault | Expected invariant failure |
| --- | --- | --- |
| exception-expiry | Use an expired exception | exception-unexpired |
| stale-renewal | Publish a captured review after revocation changed generation | renewal-current-generation |
| stale-review | Mix old and current review revisions | two-current-reviewers |
| review-quorum | Accept only one reviewer | two-current-reviewers |
| stale-evidence | Ignore elapsed evidence TTL | current-fresh-evidence |
| tier-skip | Jump directly from tier zero to tier two | one-tier-at-a-time |
| late-rollback | Roll back at or after the deadline | rollback-before-deadline |
| lost-update | Publish a stale writer after another writer committed | publication-compare-and-swap |
| torn-publication | Publish policy without its receipt | atomic-policy-receipt |
| restart-uncommitted | Treat incomplete staging as a committed policy on restart | atomic-policy-receipt and recovery-preserves-commit |

Trace actions contain only fixed public tokens. No source excerpts, prompts, logs, private paths,
transcripts, host data or external commands appear in model evidence.

## Correspondence and remaining work

The [executable model](../src/awq/lifecycle_model.py) keeps transitions separate from invariant
oracles. [Exception validation](../src/awq/project.py), [promotion evaluation](../src/awq/promotion.py)
and [verified publication](../src/awq/verified_update.py) are reviewed conceptual correspondences,
not established refinement relations. Output binds the exact model-source hash, canonical request,
AWQ version, bounds and assumptions.

Independent component success does not prove that an exception waiver, tier decision and release
publication compose safely in a real system. In particular, there is no shared transaction linking
exception expiry to publication or mapping the two abstract writers to real processes. Coupled
models, crash-aware implementation refinement, liveness/fairness, real-time constraints and
language-specific refactoring execution remain separately reviewed work. All native gates remain
retained, and no result claims unbounded safety, universal equivalence or compliance certification.

## Reviewed implementation trace correspondence

AWQ 0.19 adds [strict paired trace maps](REFINEMENT.md) for the review/promotion model.
Complete state/action maps and reviewed obligations bind bounded caller-declared observations.
A passing correspondence check is not an implementation-refinement theorem and retains native gates.
