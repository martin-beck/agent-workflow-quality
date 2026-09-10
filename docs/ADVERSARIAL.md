# Bounded adversarial assurance

AWQ v0.21 adds deterministic, offline synthetic campaigns for seven security and
quality boundaries. Native gates remain required. A passing campaign is not a
claim that arbitrary code, workflows, or private data are safe.

## Run and replay

Create a canonical absolute scratch directory on the development disk first.
The evaluator creates and removes synthetic per-case directories only there.
From the repository root:

```sh
awq adversarial-check templates/adversarial-pr.json --scratch /reviewed/scratch --format json
awq adversarial-check templates/adversarial-scheduled.json --scratch /reviewed/scratch --format json
awq adversarial-replay fixtures/conforming/adversarial/workflow-redaction.json \
  --scratch /reviewed/scratch --format json
```

The repository script provides the same pass/fail exit contract:

```sh
python scripts/adversarial_campaign.py --scratch /reviewed/scratch
```

Inputs must be canonical JSON under the repository root, without symlink or
traversal components. The public schema is
[adversarial-campaign.schema.json](../schemas/adversarial-campaign.schema.json).
Unknown fields, unsupported versions, non-integer bounds, duplicate JSON keys,
non-finite numbers, oversized inputs, and weakened mutation floors fail closed.
No candidate code, native command, downloaded corpus, or user-supplied payload is
executed. Acquisition of the pinned Python environment is a separate setup step.

## Exact campaign budgets and independent oracles

The PR profile has 4 samples per operator: 112 comparisons. The scheduled profile
has 32 samples per operator: 896 comparisons. Both cover the same 28 operators.
The scheduled profile visits all 32 variants of each operator; PR checks only its
seed-selected subset. Seeds are integers from 0 through 2147483647. Generation
uses fixed family/operator order and the version-1 recurrence
`state = (1664525 * state + 1013904223) modulo 2^32`, with variant
`1 + state modulo 32`. There is no wall clock, random device, or network input.

| Family | Construction properties | Target |
| --- | --- | --- |
| Paths | safe, parent traversal, absolute, symlink | Confined-path validator |
| Policies | valid, unknown field, duplicate profile, unsafe fixture | Policy validator |
| Schemas | valid, unknown field, boolean timeout, missing tool | Adapter validator |
| Parsers | canonical, duplicate key, noncanonical, nonfinite, truncated | Strict JSON reader |
| Workflows | immutable pin, floating pin, missing permissions, missing timeout | Real gate dispatch |
| Redaction | clean text, synthetic credential, credential-shaped action ref | Serialized real findings |
| Weakening | unchanged, relaxed formats, strengthened formats, fixture exclusion | Policy comparison |

The expected labels are a reviewed construction-tag table, independent of the
production validators being exercised. Tests assert that table separately. The
policy comparison target deliberately calls the existing internal comparator;
its source digest is recorded, so this coupling is visible and reviewable.
A separate known-bad boundary fault is injected for each family. These faults
respectively bypass path checking, remove unknown policy/schema fields, use a
permissive JSON parser, skip workflow dispatch, echo a synthetic secret, and
suppress weakening classification. All seven must be detected: 7/7 is mandatory.
A surviving fault blocks the campaign. A failing baseline also blocks and marks
the mutation score invalid, even if all injected faults were detected.

This is a reviewed boundary-fault sensitivity score, not whole-program source
mutation coverage. It does not measure arbitrary mutations, arbitrary YAML
semantics, regex completeness, concurrent execution, or unbounded parser fuzzing.
The scheduled job has a ten-minute outer timeout; requests cannot increase their
fixed work budget. Exhausting a CI timeout is a failure, not a passing campaign.

## Privacy-safe minimized regressions

A mismatch retains at most one recipe per family/operator, sorted deterministically.
The shrinker enumerates variants from 1 to the failing variant and retains the
first still-failing variant. Minimality is only in that finite order, not global
byte-level minimality. Recipes contain public operator labels, an integer variant,
a canonical case digest, and a fixed mismatch code. They never contain inspected
logs, prompts, transcripts, filenames, credentials, or absolute paths. Report
identities bind the contract, corpus, engine, and each exercised target source.

The retained workflow-redaction recipe reproduces a real regression: an action-pin
finding formerly echoed an untrusted action reference. Findings now use a fixed
message. A test reintroduces that fault and requires a minimized variant-1 failure;
replaying the retained recipe against the corrected checker passes. This is
specific regression evidence, not a universal privacy proof.

Outputs are deterministic aggregate JSON (or a text rendering), with explicit
limitations and `native_gate: retain`. Nonzero exit means invalid input, a baseline
mismatch, a surviving fault, or incomplete execution. Automation must consume that
exit status, not infer success from a partial log. No consumer promotion or native
gate removal is authorized by this harness. Broader coverage-guided fuzzing,
language-level mutation engines, and additional independent workflow oracles
remain separate future work.
