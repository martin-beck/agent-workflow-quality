# Requirement catalogue

This file is generated from the registry consumed by AWQ. Do not edit it directly.

Registry SHA-256: `9a6928b779656eaad9ba52a7869bb7608ae769e11633b95388d54aba2c31b69a`

## Profiles

| Profile | Purpose | Requirements |
| --- | --- | --- |
| `android-jvm` | Gradle and Android dependency-integrity baseline. | 1 |
| `core` | Portable repository baseline. | 4 |
| `discussion-batch` | Batched proposal, implication, user-alternative and independent response quality. | 1 |
| `discussion-reconciliation` | Before/after discussion artifact and formal-result consistency. | 1 |
| `docs` | Documentation structure and local integrity. | 1 |
| `formal-evidence` | Truthful bounded formal-evidence claims. | 1 |
| `formal-model` | Bounded external formal-model execution contracts. | 1 |
| `github-actions` | GitHub Actions integrity, trust transitions and permissions. | 3 |
| `guidance-resolution` | Contradiction, clarification, rejection and reopen state transitions. | 1 |
| `interaction-gates` | Typed, privacy-safe oracle interaction-gate evidence. | 1 |
| `privacy` | Content-minimized public repository baseline. | 1 |
| `python` | Python source baseline. | 1 |
| `rust` | Rust dependency-integrity baseline. | 1 |
| `schemas` | Machine-readable JSON baseline. | 1 |
| `shell` | Shell entry-point baseline. | 1 |
| `supply-chain` | Pinned AWQ policy supply chain. | 1 |
| `terminology` | Consumer-owned canonical vocabulary and bounded lexical scope enforcement. | 1 |

## Requirements

### AWQ-CORE-001: Portable text

Tracked text uses UTF-8, LF and a final newline.

- Profiles: `core`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Does not assess prose meaning.
- Remediation: Normalize encoding and line endings.
- Exception policy: No exceptions for first-party text.
- Standards: NIST-SSDF-PO.3

### AWQ-CORE-002: Repository path integrity

Tracked paths are case-unique and symlinks remain inside the repository.

- Profiles: `core`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Assumes the inspected Git index is authoritative.
- Remediation: Repair collisions, broken links or escaping links.
- Exception policy: No exceptions.
- Standards: NIST-SSDF-PS.1

### AWQ-CORE-003: Merge-marker rejection

Tracked text contains no unresolved merge markers.

- Profiles: `core`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Marker-like fixture files require an explicit fixture scope.
- Remediation: Resolve the merge and retain the intended content.
- Exception policy: Fixture paths may be narrowly excluded.
- Standards: NIST-SSDF-PS.1

### AWQ-CORE-004: Classified formats

Every tracked file format is classified or explicitly declared.

- Profiles: `core`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Classification does not validate domain semantics.
- Remediation: Enable a profile or declare the format with a local gate.
- Exception policy: Declarations require a remediation owner.
- Standards: NIST-SSDF-PO.1

### AWQ-DOC-001: Local documentation links

Relative Markdown links resolve inside the repository.

- Profiles: `docs`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: External availability is a scheduled network check.
- Remediation: Repair the path or anchor target.
- Exception policy: Generated external URLs may be scoped separately.
- Standards: NIST-SSDF-PO.3

### AWQ-FORMAL-001: Truthful formal evidence

Formal-method documentation classifies bounds, assumptions and non-claims.

- Profiles: `formal-evidence`, `formal-model`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Text presence does not prove the model ran or refined implementation.
- Remediation: Document evidence class, finite bounds, assumptions and limitations.
- Exception policy: No unclassified proof claims.
- Standards: NIST-SSDF-PW.7

### AWQ-GHA-001: Immutable Actions

GitHub Actions references use complete commit SHAs.

- Profiles: `github-actions`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: A pinned action can still contain vulnerable code.
- Remediation: Pin the reviewed action revision to its full SHA.
- Exception policy: Local actions are exempt; remote mutable refs are not.
- Standards: SLSA-BUILD

### AWQ-GHA-002: Workflow trust boundaries

Each workflow declares bounded event, runner, checkout, permission and publication trust transitions with finite fail-closed jobs.

- Profiles: `github-actions`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Static inspection cannot prove hosted settings, runner isolation, branch protection or runtime grants.
- Remediation: Repair the named trust transition in the repository-owned workflow trust policy and workflow.
- Exception policy: No unclassified event, runner, privilege, credential, expression or fail-open transition.
- Standards: NIST-SSDF-PS.1

### AWQ-GHA-003: Valid workflow-local paths

Paths referenced by GitHub workflow commands exist inside the repository.

- Profiles: `github-actions`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Static token recognition does not interpret dynamically constructed paths.
- Remediation: Correct the reference or add the required tracked file.
- Exception policy: Dynamic references require a narrow project-local gate.
- Standards: NIST-SSDF-PW.7

### AWQ-JVM-001: Verified Gradle dependencies

Gradle projects commit dependency verification metadata.

- Profiles: `android-jvm`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Metadata does not prove dependency behavior is safe.
- Remediation: Review artifacts and regenerate strict SHA-256 verification metadata.
- Exception policy: No unverified release dependency.
- Standards: SLSA-BUILD

### AWQ-ORACLE-001: Typed oracle interaction gates

Typed interaction-gate records bind task revision, context, before/after artifacts, passing formal review, user disposition and a public-safe projection.

- Profiles: `interaction-gates`
- Tier: `pr`
- Evidence: `contract-test`
- Deterministic: `true`
- Network: `false`
- Limitation: A valid record proves only bounded quality-contract completeness; it does not establish user intent, implementation correctness, or the truth of the recorded disposition.
- Remediation: Add the missing typed interaction-gate evidence or keep the quality gate failed.
- Exception policy: No exceptions for missing interaction, review, artifact digest, privacy projection, or unresolved status.
- Standards: NIST-SSDF-PW.7

### AWQ-ORACLE-002: Discussion reconciliation consistency

Completed discussion records bind symmetric before/after artifacts, affected-AR dispositions, current formal results, and distinct guidance, quality, and implementation outcomes.

- Profiles: `discussion-reconciliation`
- Tier: `pr`
- Evidence: `contract-test`
- Deterministic: `true`
- Network: `false`
- Limitation: A valid record proves only bounded reconciliation completeness; it does not prove user intent, implementation correctness, formal refinement, or replace consumer-native gates.
- Remediation: Add a current, public-safe reconciliation record with a refreshed formal result or keep the quality gate failed.
- Exception policy: No exceptions for stale artifacts, stale formal results, unresolved affected ARs, missing limitations, or collapsed acceptance dimensions.
- Standards: NIST-SSDF-PW.7

### AWQ-ORACLE-003: Contradiction and guidance resolution

Ambiguous, contradictory, stale, or scope-changing guidance records an explicit bounded state transition and remains non-authorizing until a fresh discussion and formal review reconcile it.

- Profiles: `guidance-resolution`
- Tier: `pr`
- Evidence: `contract-test`
- Deterministic: `true`
- Network: `false`
- Limitation: A valid record proves only transition-shape completeness; it does not establish user intent, implementation correctness, formal refinement, or the truth of a disposition.
- Remediation: Record the explicit clarification, rejection, alternative, reconciliation, or reopen result with a fresh task revision and public-safe evidence.
- Exception policy: No exceptions for unresolved guidance, stale responses, mismatched state/result pairs, unauthorized transitions, or private projections.

### AWQ-ORACLE-004: Cross-project oracle workflow integration

A bounded synthetic trace binds Coordinator task events, AWG decision semantics, and AWQ quality evidence across every mandatory lifecycle stage.

- Profiles: `oracle-workflow-integration`
- Evidence: `contract-test`
- Limitation: The trace does not prove user intent, implementation correctness, formal refinement, provider integration, or consumer-native gates.
- Exception policy: No exceptions for skipped stages, stale revisions, unresolved guidance, quality-only authorization, or private projections.
- Standards: NIST-SSDF-PW.7

### AWQ-ORACLE-004: Batched proposal and implication quality

Batched discussion points retain ranked evaluated proposals, concise implications, evidence limits, formal references, evaluated user alternatives, and independent revision-bound response authorization.

- Profiles: `discussion-batch`
- Tier: `pr`
- Evidence: `contract-test`
- Deterministic: `true`
- Network: `false`
- Limitation: A valid record proves only bounded packet quality and binding shape; it does not establish user intent, implementation correctness, or formal refinement.
- Remediation: Add a complete public-safe batched discussion quality record or keep the quality gate failed.
- Exception policy: No exceptions for missing proposal evaluation, implication limits, formal evidence, independent response binding, or cross-point authorization.
- Standards: NIST-SSDF-PW.7

### AWQ-PRIV-001: Credential and private-path exclusion

Tracked text excludes credential signatures and machine-private absolute paths.

- Profiles: `privacy`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Pattern scanning cannot prove absence of all sensitive data.
- Remediation: Remove the value, rotate credentials when needed and use synthetic fixtures.
- Exception policy: Synthetic canaries must be isolated under declared fixture paths.
- Standards: NIST-SSDF-PS.3

### AWQ-PY-001: Python syntax

First-party Python files compile under the running supported interpreter.

- Profiles: `python`
- Tier: `pr`
- Evidence: `contract-test`
- Deterministic: `true`
- Network: `false`
- Limitation: Compilation is not typing, lint or runtime behavior evidence.
- Remediation: Repair syntax and rerun project-specific Python gates.
- Exception policy: No exceptions for first-party Python.
- Standards: NIST-SSDF-PW.7

### AWQ-RUST-001: Locked Rust workspace

A Rust project commits Cargo.lock.

- Profiles: `rust`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: A lockfile does not audit advisories or licenses.
- Remediation: Generate, review and commit Cargo.lock.
- Exception policy: Library-only exceptions require an explicit project decision.
- Standards: SLSA-BUILD

### AWQ-SCHEMA-001: Parseable JSON

Every tracked JSON document parses without duplicate structural ambiguity.

- Profiles: `schemas`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Parsing does not establish schema conformance.
- Remediation: Repair JSON and run its owning schema validator.
- Exception policy: No exceptions.
- Standards: NIST-SSDF-PW.7

### AWQ-SHELL-001: Shell entry points

Executable shell files have a shell shebang.

- Profiles: `shell`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Does not replace ShellCheck, shfmt or Bats.
- Remediation: Add the correct shebang and executable mode or remove executable mode.
- Exception policy: No exceptions for first-party executable shell.
- Standards: NIST-SSDF-PW.7

### AWQ-SUPPLY-001: Pinned quality bundle

The project lock binds profiles and requirements to an immutable registry digest.

- Profiles: `supply-chain`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: The digest does not establish upstream trust by itself.
- Remediation: Run an explicit reviewed AWQ update from the intended release.
- Exception policy: No floating bundle references.
- Standards: SLSA-PROVENANCE-V1

### AWQ-TERM-001: Canonical terminology

Selected tracked text uses consumer-declared canonical vocabulary in each applicable lexical scope.

- Profiles: `terminology`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Lexical matching does not establish meaning, intent, translation quality, or complete natural-language interpretation.
- Remediation: Use the canonical label or add a narrow, reviewed, time-bounded terminology exception.
- Exception policy: Exceptions bind one term to explicit paths and scopes for at most 90 days.
- Standards: NIST-SSDF-PO.1
