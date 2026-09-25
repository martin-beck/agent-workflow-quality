# Evidence coverage

`awq coverage [records]` reads a bounded, repository-local evidence-record
document and emits deterministic task/role matrices. Each record contains only
the task identity, locked requirement, role, status, and evidence class; content,
logs, subprocess output, credentials, and artifact bytes are never retained.

The command rejects unknown roles, unlocked requirements, duplicate
task/role/requirement identities, and records beyond the 4096-entry bound.
Output is sorted by task, role, and status so CI can compare it byte-for-byte.
