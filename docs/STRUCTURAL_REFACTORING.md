# Bounded structural refactoring verification

AWQ validates closed, consumer-supplied structural transformation plans without
running a transformer or changing consumer files. The
`structural-refactor-verify` command accepts one canonical, repository-owned
JSON contract and returns only stable identifiers, digests, counts, and explicit
limitations.

## Plan and recipe identity

Each plan binds an exact base commit, contract-catalog digest, input-tree
digest, and proposed-output digest. Its recipe identifies exact tool and parser
versions and digests, a language, repository-relative include and exclude
scope, risk, prohibited transformation classes, evidence-backed preconditions
and invariants, and positive, negative, and golden fixtures. Focused and full
verification commands are bounded argument arrays, never shell strings.

Versions are numeric and exact. Lists are ordered and unique, paths are
repository-relative and dot-segment free, and every object rejects unknown
fields. The initial application mode is always `read-only-verification`.
Autonomous mutation is outside this contract and would require a separately
reviewed low-risk allowlist.

## Verification result

The result must repeat the exact base, catalog, input, and output identities.
Observed file, changed-line, match, and elapsed counts cannot exceed the
declared budgets. Every fixture must have a passing digest-bound result. The
observed transformation classes cannot intersect the recipe's prohibitions,
and a second planning pass must converge on the same proposed-output digest.

Evidence excludes source text, diffs, subprocess output, environment values,
and machine paths. A verification result is not proof of behavioral
equivalence: consumer-supplied characterization or differential evidence and
the mapped native gate remain required. The existing Python refactoring family
can be named through an explicit digest-bound mapping without weakening its
four-method execution contract.

## Release ordering

The schema, fixtures, runtime verifier, and documentation are staged without a
release-version claim. Contract-catalog and distribution integration wait for
the dependency-ordered release after the active v0.32 work; earlier releases
must not claim this asset.
