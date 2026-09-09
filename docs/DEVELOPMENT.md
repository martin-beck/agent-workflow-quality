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
