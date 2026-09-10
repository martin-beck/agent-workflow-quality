# Native-gate mapping contracts

AWQ native-gate mappings bind a registered requirement to an existing project command without
replacing, wrapping, or authorizing removal of that command. The project-owned native gate remains
authoritative for domain semantics. AWQ validates declarative mapping data and normalizes already
collected result digests; it does not execute commands from this contract.

Validate and summarize a repository-owned contract with:

```sh
awq --root . native-map-evaluate quality/native-gate-mapping.json --format json
```

The version 1 schema is
[`schemas/native-gate-mapping.schema.json`](../schemas/native-gate-mapping.schema.json). Every
mapping identifies a registered requirement, an explicitly typed AWQ requirement or adapter result,
a bounded native argument array, exact tool name/version/digest pin, matching AWQ tier, evidence
class, public input-scope identifier, deadline, limitation, and the fixed
`bounded-equivalence-not-certification` claim.

Each mapping requires exactly two digest-only observations: `native-gate` and either
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
