# Capability claims

capability_claims.json is a closed, offline registry of bounded AWQ capability claims. Each
claim names a stable identifier, one reviewed maturity state, supported public surfaces,
limitations, review provenance, and evidence bound to the exact source commit.

Maturity is descriptive, not a roadmap or readiness guarantee: planned, foundation, implemented,
integrated, environment-verified, unsupported, and deprecated are the reviewed states.
Environmental verification requires environmental evidence and is never proof of universal
behavior. Unsupported and deprecated claims require an explicit rationale. Unknown fields,
duplicate identifiers, stale evidence, source-revision mismatches, missing surfaces, and attempts
to promote synthetic evidence fail closed.

The registry is content-minimized and performs no subprocess execution or network access.
