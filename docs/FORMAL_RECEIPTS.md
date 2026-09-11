# Formal execution receipts v2

The formal execution receipt v2 is a closed, tool-independent record for one bounded formal-tool
run. It is a data-only validation contract: AWQ does not execute the named tool, authenticate the
producer, retain command output, or replace the consumer's native gate.

## Exact execution identity

Each receipt binds the reviewed Git commit and tree, model and configuration SHA-256 digests, stable
model identifier and language, exact adapter/tool/version/executable digest, opaque run identifier,
attempt, and canonical argv digest. Bounds are sorted named positive integers, limited to 32 entries
and one million per value. Model operation and state vocabularies are sorted, unique, and bounded.

The normalized result binds a result digest, explored state/transition counts, and exactly one of:

- `exhausted` or `verified` with pass status and no counterexample digest;
- `counterexample` with fail status and an exact counterexample digest;
- `incomplete` or `tool-error` with fail status and no counterexample digest.

A separately supplied trusted expectation repeats the exact source, model, configuration, tool,
run, argv, bounds, and expected outcome. Evaluation fails unless every normalized identity matches;
the receipt cannot establish its own expected identity. Tool versions must contain a numeric
component, and all identifiers and echoed evidence remain bounded. A pass is evidence only for the
trusted exact identity and is not an unbounded proof.

## Counterexample sensitivity

Every receipt includes a separately digested negative model, configuration, reviewed mutation and
negative result whose expected and observed outcomes are both `counterexample`. Exact commitments
bind the sensitivity run to the primary tool, run/argv and finite bounds. The negative model must
differ from the primary model. This demonstrates sensitivity to one reviewed defect only; it does
not establish complete mutation coverage or tool correctness.

## Implementation trace correspondence

The receipt declares complete, ordered, one-to-one mappings from every named model operation and
state to opaque implementation tokens. Its bounded ordered trace contains at most 256 events. Each
event must use the declared paired tokens and binds a content-minimized observation digest; the
whole ordered trace is independently SHA-256 committed.

AWQ validates mapping completeness, ordering, uniqueness, event sequence, token correspondence and
the trace commitment. It does not inspect production source, replay the implementation, infer hidden
steps, or prove transition semantics. The correspondence remains caller-declared bounded evidence.
Use the stricter model-specific [refinement map](REFINEMENT.md) where its fixed profile applies.

## Commands and continuation boundary

Validate the synthetic example with:

~~~sh
awq --root . formal-receipt-evaluate \
  templates/formal-execution-receipt.json \
  templates/formal-execution-expectation.json --format json
~~~

The [schema](../schemas/formal-execution-receipt.schema.json) and zero-dependency runtime validator
reject unknown fields, duplicate JSON keys, noncanonical or oversized files, unsafe paths, wrong
identities, invalid bounds/outcome combinations, missing or reordered maps, trace mismatches,
unsuccessful negative-model observations, changed limitations, and stronger proof claims.

Alloy, Kani, Loom, and additional TLC collection are separate reviewable increments. Each adapter
must independently pin offline-capable acquisition and execution, prove native equivalence, enforce
deadlines and output bounds, and populate this receipt without retaining subprocess output.
