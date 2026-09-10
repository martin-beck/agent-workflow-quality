# Development

The public coordination database is
[`agent-workflow-quality-state`](https://github.com/martin-beck/agent-workflow-quality-state).
Read its complete snapshot, claim one dependency-ready task and use its vendored `handoffctl run`
boundary for every product, Git, test, review and publication mutation.

Work in the task's isolated branch and worktree. Preserve unrelated work. After interruption inspect
task revisions, commits, refs, processes, pull requests and workflow jobs before retrying anything.
Record concise results immediately and renew the lease before expiry.

Freeze schemas and requirement identifiers before adapters depend on them. A requirement change must
update registry validation, schemas, generated documentation, success tests and a fixture proving its
failure path. A profile change must be visible in `policy-diff`. Never add a runtime dependency or
network-required runtime check. Explicit checksum-pinned CI setup may acquire offline-capable tools
before tests execute; runtime contracts must neither acquire them nor contact a service.

Schema adapter changes must keep parsing strict and bounded, reject duplicate keys and unsafe YAML,
confine recursive references below the repository, and test the exact native tool invocation. A
new schema-to-instance mapping needs its own identifier, reviewed schema path, and non-overlapping
compound instance suffixes.

Rust adapter changes must retain the exact stable toolchain declaration, direct regular binaries,
locked/offline Cargo resolution, a proxy-free runtime Cargo home, external scratch and target
directories, and independent native-command equivalence. Rust dependency-policy changes must keep deny policy and exact
lock metadata review-visible; advisory changes must bind an immutable, expiring database; and API
changes must name and digest the default-feature rustdoc baseline. Native diagnostics and private crate
or source paths must not enter AWQ evidence. Rustup, registry/advisory lookup, baseline creation, and
dependency acquisition are installer or setup concerns and must never occur during adapter execution.

Before publication run the commands in `CONTRIBUTING.md`, inspect the full diff, verify DCO and SSH
signatures, review privacy, and follow the exact recipe and trust limitations in `docs/RELEASES.md`. Product commits reach main through a pull request. Completion requires
the merged revision, green required workflows, a public immutable release, and a fresh-clone smoke
test. Consumer integrations use their own coordination projects and retain existing gates.

## Authenticated release updates

See [signed provenance and verified updates](PROVENANCE.md) for external trust, immutable
tag pins, strict data-only candidate updates and atomic lock-only mutation. The legacy unauthenticated
update path is disabled. Structural bundle integrity is distinct from publisher authentication.

## Per-consumer promotion evidence

Use [the promotion contract](PROMOTION.md) for bounded canonical evidence, controlled positive and
negative cases, live observation windows, review expiry and exact integer budgets. Every native
gate remains retained. Promote shared gates independently through consumer-owned review; a green
shadow workflow is not equivalence evidence. The strict check requirement selector runs only
explicit locked, tier-eligible requirements and fails on unknown, duplicate or incomplete selection.

## Bounded formal and refactoring assurance

See [the formal assurance contract](FORMAL_ASSURANCE.md) for the executable finite-state model,
reviewed counterexamples and strict before/after evidence. These checks do not establish
implementation refinement, liveness or universal behavior preservation. Consumer-native gates
remain unchanged; broader models and language-specific collectors require separate child tasks.

## Policy lifecycle components

AWQ 0.18 adds [bounded lifecycle components](LIFECYCLE_MODELS.md) for exception renewal/expiry,
two-reviewer tier and freshness decisions, rollback deadlines, and staged crash/restart publication.
Each component has an exhaustive bounded baseline and reviewed counterexamples. Their success is
not a composition or implementation-refinement proof and never removes a native gate.

## Reviewed implementation trace correspondence

AWQ 0.19 adds [strict paired trace maps](REFINEMENT.md) for the review/promotion model.
Complete state/action maps and reviewed obligations bind bounded caller-declared observations.
A passing correspondence check is not an implementation-refinement theorem and retains native gates.

## Executable Python refactoring observations

AWQ 0.20 adds [the bounded CPython collector](PYTHON_REFACTORING.md) for a restricted integer-function
profile. Exact pinned offline execution collects all four refactoring evidence methods while
retaining native gates and making no universal behavior-preservation claim.

## Bounded adversarial campaigns

See [adversarial assurance](ADVERSARIAL.md) for deterministic PR and scheduled
campaigns, independent construction oracles, minimized public-safe regressions,
and the mandatory seven-of-seven boundary-fault sensitivity floor. Native gates
remain required; these campaigns do not establish universal correctness.

## Reliability and retention budgets

See [bounded reliability observations](RELIABILITY.md) for representative synthetic
repositories, integer timing ceilings, repeat determinism, declared extension
observations and metadata-only retention guidance. Native gates remain required.

## Evidence lineage and hosting lifecycle

See [evidence lifecycle](EVIDENCE_LIFECYCLE.md) for immutable observation and decision chains,
truthful required and optional publication outcomes, and deterministic protected-reference
retention candidates. Evaluation is read-only: AWQ never uploads or deletes artifacts.

## Agent onboarding and compatibility

See [the onboarding guide](ONBOARDING.md) for bounded package diagnostics, explicit
agent argv recipes, reviewed distribution choices, portable core smoke paths and
read-only migration previews. Native gate and trust boundaries remain explicit.
