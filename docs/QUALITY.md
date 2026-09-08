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
command output, environment values, prompts, transcripts, credentials and machine paths. Status and findings are deterministic for a
fixed tree, contract, tool and host; elapsed duration is observational and intentionally variable.

Standards mappings are review evidence, not certification evidence. Each one names a pinned source
edition and known control, relationship strength, rationale, evidence class, limitation, and
reviewer. Schema and runtime tests reject unknown fields, floating or stale editions, removed
controls, uncovered requirements, and stronger claims. Source text is linked, not copied into AWQ;
normal validation remains offline and deterministic.

Adapter tests cover accepted and rejected contracts, absent and skewed tools, missing and unsafe
configuration, deadlines, output bounds, minimal environments, normalized failures, schema
agreement, semantic weakening, and native-command equivalence on controlled fixtures. Family ARs
must add their own positive, negative, version-skew, and native-equivalence fixtures.

Source and wheel archives are inspected without extraction for unsafe paths, development metadata
that can expose private paths, duplicate or non-regular members, bounded size, required packaged
adapter schemas, and the immutable adapter catalog data.

Tool and policy updates are explicit semantic diffs. Exceptions require an identifier, owner, reason,
narrow requirement scope, creation and expiry timestamps, compensating evidence and review reference.
Expired or unknown exceptions fail closed.
