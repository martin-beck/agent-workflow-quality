# Quality contract

Every pull request must pass deterministic formatting, strict lint and typing, branch-aware tests,
schema tests, generated-catalog drift, self-hosted AWQ checks, negative fixtures, DCO validation,
immutable GitHub Action references and a clean-tree assertion.

Coverage is a regression constraint, not correctness proof. The initial production-code line and
branch floor is 95 percent. Exclusions cover only the console guard. Every shared gate family has an
intentionally broken fixture which the production checker must reject.

## Evidence classes

- `mechanical`: deterministic observation of the checked tree.
- `contract-test`: executable examples and hostile-path tests.
- `property-or-fuzz`: sampled or coverage-guided evidence, never a proof.
- `bounded-model`: exhaustive only within named finite bounds.
- `environmental`: a measured or reviewed assumption outside the model.

Evidence is content-minimized and bounded. It includes the policy and registry digests, selected
profiles, requirement outcomes, elapsed time and limitations. Adapter results additionally identify
the pinned tool and version. Evidence includes reviewed remediation while excluding source excerpts,
command output, environment values, prompts, transcripts, credentials and machine paths. Status and
findings are deterministic for a fixed tree, contract, tool and host; elapsed duration is observational
and intentionally variable.

Standards mappings are review evidence, not certification evidence. Each one names a pinned source
edition and known control, relationship strength, rationale, evidence class, limitation, and
reviewer. Schema and runtime tests reject unknown fields, floating or stale editions, removed
controls, uncovered requirements, and stronger claims. Source text is linked, not copied into AWQ;
normal validation remains offline and deterministic.

Adapter tests cover accepted and rejected contracts, absent and skewed tools, missing and unsafe
configuration, deadlines, output bounds, minimal environments, normalized failures, schema
agreement, semantic weakening, and native-command equivalence on controlled fixtures. Family ARs
must add their own positive, negative, version-skew, and native-equivalence fixtures. Shell and
documentation family tests additionally prove tracked input selection and declared fixture exclusion;
documentation tests distinguish offline local-link evidence from external availability. Schema tests
cover duplicate JSON keys, non-finite constants, restricted YAML, declared dialects, confined local
reference graphs, format assertions, semantic instance failures, file budgets, and content-minimized
errors. Rust tests cover exact direct tool paths, proxy-free runtime configuration, locked/offline
commands, independent native equivalence, format/lint/compile/doc/lock/test failures, dependency
cache misses, bounded scratch space, manifest consumption, and atomic installer publication. Android/JVM tests additionally cover pinned JDK and Gradle acquisition, exact wrapper and repository policy, copied-lock integrity, process-tree deadlines, hostile XML, and fresh source/report-bound device evidence.

Source and wheel archives are inspected without extraction for unsafe paths, development metadata,
duplicate or non-regular members, bounded size, required packaged schemas, immutable catalog data,
private-content signatures, and canonical release timestamps, permissions, ownership and compression
metadata. A canonical manifest binds each artifact to the exact source commit/tree/epoch, public
registries, and hash-complete build dependency closure. The release builder compares independent
tracked-source snapshots byte for byte and publishes with atomic no-replace semantics.
SPDX release graphs must match canonical regeneration and the pinned official schema; see
[the SBOM profile](SBOM.md) for inventory, license, origin and scope boundaries.

Tool and policy updates are explicit semantic diffs. Exceptions require an identifier, owner, reason,
narrow requirement scope, creation and expiry timestamps, compensating evidence and review reference.
Expired or unknown exceptions fail closed.

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

## Agent onboarding and compatibility

See [the onboarding guide](ONBOARDING.md) for bounded package diagnostics, explicit
agent argv recipes, reviewed distribution choices, portable core smoke paths and
read-only migration previews. Native gate and trust boundaries remain explicit.
