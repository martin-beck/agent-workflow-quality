# Agent Workflow Quality

Agent Workflow Quality provides versioned, agent-ready software quality requirements, profiles,
gates, and evidence contracts. It gives new agentic development projects a reproducible baseline
without replacing their domain-specific tests or assurance.

The zero-runtime-dependency `awq` CLI's deterministic checks operate offline after installation.
The separately classified `hosting-observe` command is explicitly online. A consumer pins selected
profiles, expanded requirements, and the registry digest in `quality/awq.lock.json`; updates are
explicit and reviewable.

The opt-in [terminology profile](docs/TERMINOLOGY.md) checks consumer-owned canonical vocabulary
across separately declared normative, example, quotation, and generated lexical scopes. AWQ does
not hard-code coordinator or domain terminology, and the gate makes no semantic-language claim.

## Standards traceability

AWQ ships a version-pinned [control catalogue](docs/STANDARDS.md), strict JSON schemas, and reviewed
many-to-many mappings for NIST SSDF, SLSA, SPDX, the OpenSSF OSPS Baseline, Python, JSON, CommonMark,
and POSIX shell sources. These mappings express alignment only: they never assert certification,
compliance, or a framework maturity level.

Agents can consume the same validated data without scraping documentation:

```sh
awq --root . standards --format json
awq --root . explain AWQ-GHA-002 --format json
```

Unknown controls, floating or stale source editions, removed controls, unmapped AWQ requirements,
and certification claims fail closed. Generated profile matrices expose coverage gaps and edition
drift deterministically.

## Policy governance

Policy schema version 3 adds owned lifetime bounds, strict exception records, and pinned adapter
contracts. Semantic comparison covers policy fields, local commands and adapters, thresholds,
scopes, evidence classifications, and lock pins:

```sh
awq --root . governance --format json
awq --root . policy-diff BASE HEAD --format json
awq hosting-observe --repository OWNER/NAME --format json
```

The pull-request workflow rejects weakening changes. New exceptions and append-only renewals must
carry approval references and remain review-visible. The online hosting observation is timestamped
environmental evidence and explicitly not offline proof. See [policy governance](docs/GOVERNANCE.md)
for the full lifecycle and limitations.

## Pinned adapters

Repository-owned adapter contracts bind a portable executable name to an exact version probe,
argument arrays, project configuration, a finite deadline, execution tier, evidence class, and
honest limitation. The shared runner never invokes a shell, downloads a tool, or records native
diagnostic output. Protocol-enabled contracts may return only canonical bounded identifiers and SHA-256
bindings:

```sh
awq --root . adapter-catalog --family python --format json
awq --root . adapter-catalog --family shell --format json
awq --root . adapter-catalog --family documentation --format json
awq --root . adapter-catalog --family schema --format json
awq --root . adapter-catalog --family rust --format json
awq --root . adapter-catalog --family android-jvm --format json
awq --root . adapter-run quality/adapters/example.json --format json
awq --root . plan --format json
awq --root . check --tier pr --format json
```

Adapter families are delivered independently. See [pinned adapters](docs/ADAPTERS.md) for the
contract, failure taxonomy, security boundary, and migration details. Exact commands, pins,
configuration assumptions, and adoption recipes are documented for the
[Python family](docs/PYTHON_ADAPTERS.md), [shell family](docs/SHELL_ADAPTERS.md),
[documentation family](docs/DOCUMENTATION_ADAPTERS.md),
[schema family](docs/SCHEMA_ADAPTERS.md), and
[Rust family](docs/RUST_ADAPTERS.md), and [Android/JVM family](docs/ANDROID_JVM_ADAPTERS.md).

## Reproducible releases

The exact Linux release recipe creates two independent clean-snapshot builds, requires byte-identical
wheel and source archives, and publishes a canonical offline-verifiable manifest. See
[reproducible releases](docs/RELEASES.md) for the build-input pins, commands, hostile checks, and
trust boundary. Authenticated provenance and verified update metadata use the independent trust
policy described below.

Development is coordinated through
[Agent Workflow Quality State](https://github.com/martin-beck/agent-workflow-quality-state)
using the independently versioned
[Agent Workflow Coordinator](https://github.com/martin-beck/agent-workflow-coordinator).


Release bundles include a deterministic SPDX 3.0.1 inventory. See the
[SBOM profile and offline verification contract](docs/SBOM.md).

## Authenticated release updates

See [signed provenance and verified updates](docs/PROVENANCE.md) for external trust, immutable
tag pins, strict data-only candidate updates and atomic lock-only mutation. The legacy unauthenticated
update path is disabled. Structural bundle integrity is distinct from publisher authentication.

## Consumer promotion

Use the [agent-ready equivalence recipe](docs/PROMOTION.md) to evaluate controlled and live
native/shared comparisons per gate. The offline evaluator retains native gates, blocks false
negatives, exposes reviewed false positives, and checks exact runtime, flake, freshness and rollback
budgets. Consumer-specific required checks can select only reviewed locked requirements.

## Bounded formal and refactoring assurance

See [the formal assurance contract](docs/FORMAL_ASSURANCE.md) for the executable finite-state model,
reviewed counterexamples and strict before/after evidence. These checks do not establish
implementation refinement, liveness or universal behavior preservation. Consumer-native gates
remain unchanged; broader models and language-specific collectors require separate child tasks.

## Policy lifecycle components

AWQ 0.18 adds [bounded lifecycle components](docs/LIFECYCLE_MODELS.md) for exception renewal/expiry,
two-reviewer tier and freshness decisions, rollback deadlines, and staged crash/restart publication.
Each component has an exhaustive bounded baseline and reviewed counterexamples. Their success is
not a composition or implementation-refinement proof and never removes a native gate.

## Reviewed implementation trace correspondence

AWQ 0.19 adds [strict paired trace maps](docs/REFINEMENT.md) for the review/promotion model.
Complete state/action maps and reviewed obligations bind bounded caller-declared observations.
A passing correspondence check is not an implementation-refinement theorem and retains native gates.

## Executable Python refactoring observations

AWQ 0.20 adds [the bounded CPython collector](docs/PYTHON_REFACTORING.md) for a restricted integer-function
profile. Exact pinned offline execution collects all four refactoring evidence methods while
retaining native gates and making no universal behavior-preservation claim.

## Bounded adversarial campaigns

See [adversarial assurance](docs/ADVERSARIAL.md) for deterministic PR and scheduled
campaigns, independent construction oracles, minimized public-safe regressions,
and the mandatory seven-of-seven boundary-fault sensitivity floor. Native gates
remain required; these campaigns do not establish universal correctness.

## Reliability and retention budgets

See [bounded reliability observations](docs/RELIABILITY.md) for representative synthetic
repositories, integer timing ceilings, repeat determinism, declared extension
observations and metadata-only retention guidance. Native gates remain required.

## Agent onboarding and compatibility

See [the onboarding guide](docs/ONBOARDING.md) for bounded package diagnostics, explicit
agent argv recipes, reviewed distribution choices, portable offline source and wheel paths,
native-before-shared CI ordering, authenticated release review and fresh-clone verification.
Native gate and trust boundaries remain explicit.
