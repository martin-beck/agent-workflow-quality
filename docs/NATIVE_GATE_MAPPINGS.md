# Native-gate mapping contracts

AWQ native-gate mappings bind a registered requirement to an existing project command without
replacing, wrapping, or authorizing removal of that command. The project-owned native gate remains
authoritative for domain semantics. AWQ validates declarative mapping data and normalizes already
collected result digests; it does not execute commands from this contract.

Validate and summarize a repository-owned contract with:

```sh
awq --root . native-map-evaluate quality/native-gate-mapping.json --format json
```

The closed schema supports versions 1 and 2:
[`schemas/native-gate-mapping.schema.json`](../schemas/native-gate-mapping.schema.json). Every
mapping identifies a registered requirement, an explicitly typed AWQ requirement or adapter result,
a bounded native argument array, exact tool name/version/digest pin, matching AWQ tier, evidence
class, public input-scope identifier, deadline, limitation, and the fixed
`bounded-equivalence-not-certification` claim.

In version 1, each mapping requires exactly two digest-only observations: `native-gate` and either
`awq-requirement` or `awq-adapter`, matching the declared AWQ result kind. Duplicate source records,
missing pairs, source-kind disagreement, unknown references, unsafe arguments, absolute or parent
paths, URL-like arguments, private markers, and certification claims fail closed. A pass or fail
pair is equivalent only when both statuses agree. Error and skip remain unresolved.

The normalized result reports mapped, equivalent, and unresolved counts. It retains the source
distinction, limitations, and `native_gate: retain`; it omits command arguments and evidence
digests. A result is bounded comparison evidence, not certification, proof of correctness, or
permission to weaken coordinator or consumer gates.

The conforming example covers coordinator-style Python unit tests, schema parsing, documentation
links, bounded formal checking, and coverage. Its tool hashes are illustrative contract data, not
install instructions or executable pins for another repository. Consumers must review and pin
their own native definitions and independently collect both observations on the same revision and
input scope.

## Correlated evidence in version 2

New consumers should write version 2. Each mapping declares one reviewed correlation set containing
an observation-set identifier, exact source commit and tree, reviewed base, clean-tree assertion,
and digests for the equivalence definition, configuration and selected inputs. The set also declares
one of the exact platform classes `native`, `emulated`, `hosted-portability`, `build-only` or
`partial`. Classes are not ordered: an observation must use the declared class, so partial,
build-only, emulated or hosted evidence cannot satisfy a native mapping.

Each member of the pair carries the separately packaged
[`evidence-identity.schema.json`](../schemas/evidence-identity.schema.json) envelope. The envelope
binds the correlation-set digest, producer and tool digests, source-specific run and attempt IDs,
evidence and platform classes, collection time, optional maximum age, and evidence-byte digest.
Producer, tool, run, attempt and collection time may differ because the native and AWQ observations
are separate executions. Their shared correlation digest proves they address the same reviewed
source and scope. The evaluator checks each timestamp independently against the document's explicit
`evaluated_at`, keeping freshness decisions deterministic and replayable.

Version 2 failures contain sorted content-minimized mismatch codes. They identify a wrong correlation
set, evidence-class disagreement, upward platform-class promotion, future collection time or stale
observation without exposing digests, commands, file content, host identity or environment data.

## Version 1 migration

Version 1 remains accepted with its original interpretation and output shape. It proves only status
agreement between two digest-only records; AWQ never silently reports it as version 2-quality
correlation evidence. To migrate, freeze the reviewed source, tree, base, definition, configuration,
input set and platform class; calculate the canonical correlation-object digest; then collect fresh
source-specific envelopes for both observations. Do not manufacture envelopes around historical
digests when the required identity fields were not recorded.
