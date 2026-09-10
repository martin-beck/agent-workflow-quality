# Terminology contracts

The opt-in `terminology` profile applies `AWQ-TERM-001` to a consumer-owned
`quality/terminology.json`. AWQ supplies the strict
[`terminology-registry.schema.json`](../schemas/terminology-registry.schema.json), checker, and
[starter template](../templates/terminology.json); it does not embed a product's preferred words.
Coordinator and domain vocabulary therefore remains consumer data.

Each term has a stable identifier, canonical label, forbidden aliases, severity, case policy, and
the lexical scopes where it applies. `exact` preserves case and `casefold` uses deterministic
Unicode NFC normalization plus Unicode case folding. Matching observes Unicode word boundaries, so
an alias is not reported merely because it occurs inside a larger word. The registry itself is not
scanned because it necessarily declares forbidden aliases.

## Scopes and selected formats

The contract selects from Markdown, JSON, plain text, and YAML suffixes. Every selected file starts
in `default_scope`; bounded repository-relative glob rules can classify whole paths as `example`,
`quotation`, or `generated`. A tracked path matching rules for different scopes fails closed.

Within otherwise normative or generated Markdown, fenced code is `example` and block quotes are
`quotation`. JSON and the other selected text formats are checked lexically in their path scope;
AWQ does not claim to infer which JSON values are prose. A term is checked only in its declared
scopes. This lets consumers enforce normative text while retaining historical quotations, examples,
or derived output, or opt those scopes into enforcement explicitly.

## Findings and exceptions

At most 100 deterministic findings are retained. A finding contains only the term identifier, path,
scope, and severity; it never includes the alias, source excerpt, line, command output, or native
diagnostic. Advisory terms remain visible without failing the requirement. Error terms fail it.

Exceptions are data only and bind one term to explicit paths and scopes. They require an owner,
reason, creation and expiry timestamps, compensating evidence, and an HTTPS or URN review reference.
The maximum lifetime is 90 days; future-dated and expired exceptions do not suppress findings.
Registry size, term,
alias, rule, path, exception, input-file, and finding counts are bounded. The check is offline and
has no runtime dependency beyond Python's standard library.

This is lexical evidence, not a semantic, policy-compliance, translation, or natural-language proof.
