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

Before publication run the commands in `CONTRIBUTING.md`, inspect the full diff, verify DCO and SSH
signatures, and review privacy. Product commits reach main through a pull request. Completion requires
the merged revision, green required workflows, a public immutable release, and a fresh-clone smoke
test. Consumer integrations use their own coordination projects and retain existing gates.
