# Bounded discussion-persistence model

The persistence contract checks the finite states `active`, `saving`, `saved`,
`interrupted`, `resumed`, and `re-ask`. A saved record is revision-bound;
partial/interrupted saves cannot be presented as saved, stale resumes are
rejected, and every future request has an explicit AR mapping or rejection.
These are bounded contract observations, not a proof of filesystem power-loss
atomicity, implementation refinement, provider behavior, or user intent.
