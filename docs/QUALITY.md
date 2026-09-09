# Quality contract

Every pull request must pass deterministic formatting, strict lint and typing, branch-aware tests,
schema tests, generated-catalog drift, self-hosted AWQ checks, negative fixtures, DCO validation,
immutable GitHub Action references and a clean-tree assertion.

Coverage is a regression constraint, not correctness proof. The initial production-code line and
branch floor is 95 percent. Exclusions cover only the console guard. Every shared gate family has an
intentionally broken fixture which the production checker must reject.

## Evidence classes

- `mechanical`: deterministic observation of the checked tree.
- `contract-test`: executable examples and hostile-path tests.
- `property-or-fuzz`: sampled or coverage-guided evidence, never a proof.
- `bounded-model`: exhaustive only within named finite bounds.
- `environmental`: a measured or reviewed assumption outside the model.

Evidence is content-minimized and bounded. It includes the policy and registry digests, selected
profiles, requirement outcomes, elapsed time and limitations. Adapter results additionally identify
the pinned tool and version. Evidence includes reviewed remediation while excluding source excerpts,
command output, environment values, prompts, transcripts, credentials and machine paths. Status and
findings are deterministic for a fixed tree, contract, tool and host; elapsed duration is observational
and intentionally variable.

Standards mappings are review evidence, not certification evidence. Each one names a pinned source
edition and known control, relationship strength, rationale, evidence class, limitation, and
reviewer. Schema and runtime tests reject unknown fields, floating or stale editions, removed
controls, uncovered requirements, and stronger claims. Source text is linked, not copied into AWQ;
normal validation remains offline and deterministic.

Adapter tests cover accepted and rejected contracts, absent and skewed tools, missing and unsafe
configuration, deadlines, output bounds, minimal environments, normalized failures, schema
agreement, semantic weakening, and native-command equivalence on controlled fixtures. Family ARs
must add their own positive, negative, version-skew, and native-equivalence fixtures. Shell and
documentation family tests additionally prove tracked input selection and declared fixture exclusion;
documentation tests distinguish offline local-link evidence from external availability. Schema tests
cover duplicate JSON keys, non-finite constants, restricted YAML, declared dialects, confined local
reference graphs, format assertions, semantic instance failures, file budgets, and content-minimized
errors. Rust tests cover exact direct tool paths, proxy-free runtime configuration, locked/offline
commands, independent native equivalence, format/lint/compile/doc/lock/test failures, dependency
cache misses, bounded scratch space, manifest consumption, and atomic installer publication. Android/JVM tests additionally cover pinned JDK and Gradle acquisition, exact wrapper and repository policy, copied-lock integrity, process-tree deadlines, hostile XML, and fresh source/report-bound device evidence.

Source and wheel archives are inspected without extraction for unsafe paths, development metadata,
duplicate or non-regular members, bounded size, required packaged schemas, immutable catalog data,
private-content signatures, and canonical release timestamps, permissions, ownership and compression
metadata. A canonical manifest binds each artifact to the exact source commit/tree/epoch, public
registries, and hash-complete build dependency closure. The release builder compares independent
tracked-source snapshots byte for byte and publishes with atomic no-replace semantics.
SPDX release graphs must match canonical regeneration and the pinned official schema; see
[the SBOM profile](SBOM.md) for inventory, license, origin and scope boundaries.

Tool and policy updates are explicit semantic diffs. Exceptions require an identifier, owner, reason,
narrow requirement scope, creation and expiry timestamps, compensating evidence and review reference.
Expired or unknown exceptions fail closed.

## Authenticated release updates

See [signed provenance and verified updates](PROVENANCE.md) for external trust, immutable
tag pins, strict data-only candidate updates and atomic lock-only mutation. The legacy unauthenticated
update path is disabled. Structural bundle integrity is distinct from publisher authentication.
