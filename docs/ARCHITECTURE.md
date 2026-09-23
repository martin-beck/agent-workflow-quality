# Architecture

Agent Workflow Quality is a policy bundle and deterministic execution engine, not a replacement for
a project's domain tests. The package contains the canonical requirement registry and profiles. A
consumer checks in `quality/awq.json` plus `quality/awq.lock.json`; the lock expands every selected
profile and binds it to the registry SHA-256 and AWQ version. A policy may select one of the closed
`default`, `security`, or `documentation` roles; the role contributes its reviewed baseline profiles
before explicit profiles are expanded. Unknown roles fail closed and the selected role is repeated in
the lock so drift is visible.

`awq standards` and `awq explain` expose deterministic machine-readable traceability; generated
`docs/STANDARDS.md` provides the human review surface and explicit gap and drift sections.

## Boundaries

- Python 3.12 standard library is the complete runtime dependency set.
- Startup and normal checks require no network.
- Unknown configuration fields, profiles, requirements and tracked formats fail closed.
- Paths are repository-relative, normalized, non-symlink traversals within the selected root.
- Local gates and adapters are explicit argument arrays, never shell strings, and have finite
  deadlines.
- Pinned adapters use exact version-probe output and repository-owned configuration before running.
- Adapter subprocesses receive a minimal locale-stable environment without credential variables.
- Evidence stores classifications, identifiers, timings and digests, never subprocess output.
- Generic JUnit observations bind an exact fresh source/report set and verify testcase-level counts;
  artifact availability and file presence alone are not execution evidence.
- Execution receipts separate enforced, observed, estimated and unavailable resource dimensions;
  process cleanup and sandbox observations do not turn trusted executables into portable sandboxes.
- Correlated observation sets bind exact source, scope and reviewed definitions while keeping
  producer-specific tool, run, attempt and collection provenance separate.
- Evidence lifecycle records form bounded canonical parent chains; publication outcomes and
  non-authorizing retention candidates remain separate from quality outcomes.
- `init --dry-run` is read-only. Mutating initialization refuses to overwrite existing policy.
- A central release cannot change a consumer until its pinned lock is explicitly updated.

The standards registry is a separate public contract layered over the requirement registry.
`control_sources.json` pins source editions, URLs, and selected control identifiers;
`requirement_mappings.json` records reviewed many-to-many relationships, rationale, evidence
class, and limitations. Runtime validation rejects unknown, removed, stale, or certification-like
mappings before the CLI or documentation generator can expose them.

## Components

`awq.registry` loads and validates the embedded contracts. `awq.project` owns confined repository
discovery and deterministic policy/lock generation. `awq.checks` implements shared, credential-free
checks. `awq.adapters` validates pinned execution contracts and returns content-minimized results.
`awq.commands` creates plans, evidence, policy diffs and doctor results. `awq.release` validates
canonical release manifests, SPDX graph bindings and bounded distribution archives without runtime dependencies or
network access. `awq.cli` is a thin stable command-line boundary with text and JSON output. The
separate release builder materializes two tracked Git snapshots and binds byte-identical outputs to
the exact source, registries, and reviewed build dependency closure.

`awq.contracts` exposes the generated public-contract inventory. Discovery requires every shipped
JSON schema and externally consumed structured registry to have one stable identifier, positive and
hostile executable fixtures, a fixed offline test argv, implementation mapping, documentation and an
exact compatibility baseline. Catalog presence is never semantic evidence by itself; the mapped
implementation test remains the evidence authority.

`awq.assurance_plan` validates a consumer-owned repository-domain inventory, bounded native gate
declarations and optional AR-0034 evidence identities. It performs no subprocess execution. Its
content-minimized evaluation distinguishes declarations from observed results, retains optional
native mappings, rejects stale or revision-mismatched evidence and classifies plan removals as
weakening for review.

`awq.workflow_trust` validates a closed repository-owned GitHub Actions trust policy and performs
bounded lexical classification of supported events, runner classes, checkout identity, permissions,
expressions and publication boundaries. It fails closed on unsupported constructs and emits only
fixed messages; it does not parse arbitrary YAML or attest hosted runner and branch settings.

The adapter runner is an execution boundary, not a process sandbox. It does not initiate network
access or forward credentials, but a configured third-party executable remains trusted project
tooling and could use ambient host capabilities. Contracts and their argv therefore require normal
code review; family ARs select offline-capable invocations.

Project-specific Android, Rust, benchmark, UI, platform and formal semantics stay downstream. AWQ
may classify and invoke a declared local gate, but never claims the gate proves more than the project
declares. Agent Workflow Coordinator and `handoffctl` are deliberately outside this repository.

Formal execution receipt v2 is a shared data-only boundary for exact source, model, configuration,
tool, run, finite-bound, outcome, counterexample-sensitivity and implementation-trace commitments.
Tool-specific acquisition and execution remain separate adapters; receipt validation never runs a
tool or promotes bounded correspondence into an implementation-refinement claim.
