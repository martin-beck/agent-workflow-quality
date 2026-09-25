# GitHub Actions trust transitions

AWQ validates a bounded repository-owned `quality/workflow-trust.json` policy before classifying
GitHub Actions workflows. The policy assigns supported events and runner labels to disjoint trust
classes, names protected branches, identifies candidate-evidence and publication workflows, and
limits publication to reviewed event classes. Unknown fields, duplicate JSON keys, overlapping
classes, unsafe paths, unsupported events, and oversized inputs fail closed.

The workflow check rejects `pull_request_target`, unreviewed pull-request code on trusted or
persistent runners, write permissions outside a named publication boundary, caller-controlled
privileged inputs, required-gate `continue-on-error`, command-bound secret or event expressions,
mutable container images, retained checkout credentials, and required-gate candidate evidence without exactly one statically inspectable, SHA-pinned
`actions/checkout` step, and candidate checkouts not bound to `${{ github.event.pull_request.head.sha }}`. Matrix runner values are accepted only when their
complete static set belongs to the disposable class.

Findings contain only a stable code, the repository-relative workflow path, and a fixed remediation
message. Runner labels and expression values are never copied into evidence. This static offline
classification does not inspect GitHub settings, prove branch protection, administer runners or
secrets, or establish that a declared label has the claimed runtime isolation.

## Evidence and acceptance boundary

AWQ implementation acceptance is established by this bounded policy contract and its deterministic
positive and hostile tests. Live downstream observations, including consumer device lifecycle,
Rust vulnerability reports, and other native reports, are optional environmental inputs for the
consumer's own review. They are non-authorizing: they never turn an AWQ result into a certification,
replace a retained native gate, or block acceptance of the AWQ implementation when unavailable.
The Android/JVM and Rust adapter contracts still validate their exact native invocations and fail
closed when a consumer elects to run them.

Directive-intake and rollback workflows use the same boundary: manual trusted
capacity requires a protected-ref guard, rollback jobs cannot request write
permissions, and only the separately named tag-publication workflow may cross
the publication boundary. These examples are covered by deterministic fixtures
and findings remain label- and expression-free.
