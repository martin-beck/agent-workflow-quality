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
profiles, requirement outcomes, elapsed time and limitations. It excludes source excerpts, command
output, environment values, prompts, transcripts, credentials and machine paths.

Tool and policy updates are explicit lock diffs. Exceptions require an identifier, owner, reason,
narrow requirement scope, creation and expiry timestamps, compensating evidence and review reference.
Expired or unknown exceptions fail closed.
