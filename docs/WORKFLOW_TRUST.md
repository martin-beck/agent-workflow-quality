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
