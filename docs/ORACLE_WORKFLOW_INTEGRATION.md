# Coordinator/AWG/AWQ oracle workflow integration

The `oracle-workflow-integration` profile checks one bounded, offline synthetic trace for the
public lifecycle used by Coordinator and AWG: intake, planning review, discussion, specification
review, reconciliation, implementation, quality, and handoff. Stages are ordered, complete, and
bound to distinct Coordinator task revisions and public event references.

Coordinator owns task identity, revisions, and lifecycle transitions. AWG owns the user-facing
decision and formal-review semantics. AWQ owns quality evidence only. A quality pass cannot replace
an AWG acceptance, skip planning or specification review, or authorize unresolved guidance.

The record contains only bounded identifiers, digests, classifications, and a public-safe
projection. It does not prove user intent, implementation correctness, formal refinement, provider
integration, or consumer-native gate success; those remain separate obligations.
