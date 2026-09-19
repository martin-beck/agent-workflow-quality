# Bounded discussion-batch model

The finite AR-0063 model has `draft`, `batched`, `partially-answered`, and
`complete` states. A batched packet contains independent point identities; each
point has ranked evaluated proposals and each response binds to exactly one
point. Partial responses never authorize an unanswered point, and a user-added
proposal must be evaluated before selection. Coupled points cannot receive
independent authorization.

The executable contract tests are the bounded evidence for this model. They
include positive independent/user-proposal/partial traces and hostile traces for
missing proposals, unbatched queries, cross-point selection, unevaluated user
alternatives, and invalid formal or privacy evidence. This is not an
implementation-refinement or user-intent proof.
