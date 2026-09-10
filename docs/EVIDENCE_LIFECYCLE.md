# Evidence lineage, publication and retention lifecycle

AWQ validates bounded metadata that connects observations and decisions without
turning a score, upload, or cleanup suggestion into a quality claim. The command
is offline and read-only:

```sh
awq --root . evidence-lifecycle-evaluate \
  fixtures/conforming/evidence-lifecycle.json \
  --as-of 2026-09-11T00:00:00Z --format json
```

The caller-provided time is not authenticated clock evidence. The complete
input is capped at 512000 bytes. The schema permits at most 256 lineage records,
64 publication records, 512 inventory entries, 64 references in each protected
set, 16 prerequisites per artifact, and 100 retention candidates.
[The closed JSON Schema](../schemas/evidence-lifecycle.schema.json) is the
machine-readable contract and rejects unknown fields.

## Immutable lineage

Each observation or decision binds an exact source revision, verifier-contract
digest, artifact digest, evidence class, attempt identity, outcome, optional
integer score, and UTC observation time. Its canonical record digest includes
all those fields and the preceding record digest. The first parent is null.
Runtime validation rejects changed records, broken or reordered parents,
non-monotonic time, a source revision different from the document source, and
reused record or attempt identities.

An outcome is not derived from the score. For example, a high numeric score can
coexist with a failed decision. Digests establish byte identity, not who
produced the bytes or whether the declared execution happened. Append-only
lineage is a review contract, not an external transparency service.

## Validation and publication

Publication records keep `validation_outcome` separate from
`publication_state`. A validated optional artifact can therefore report a
failed or unavailable upload without rewriting validation as failure. Required
artifacts affect the overall result and must be published after their ordered
prerequisites. A required record with `continue_on_error: true` is rejected;
required quality gates cannot be hidden by workflow fail-open behavior.

Optional upload failure produces partial publication status while preserving
the truthful quality result. Pending, cancelled, unavailable, failed,
not-requested, and published states are explicit. AWQ performs no upload and
does not claim that caller-declared hosting state is authenticated.

## Deterministic retention candidates

The inventory records only public identifiers, artifact roles, byte counts,
UTC creation times, source heads, bounded run identities and states, and
provenance completeness. It contains no artifact contents, filenames, logs,
prompts, transcripts, credentials, host identity, or private URLs.

Candidate planning starts only above the high watermark. Eligible records are
ordered by creation time and then public identity. Selection stops at the low
watermark or the configured maximum count. This hysteresis avoids repeatedly
planning tiny changes around one threshold.

Current main, open pull-request heads, release heads, release artifacts, active
or unknown runs, explicitly active run identities, recent diagnostics, records
younger than the minimum age, and partial or unknown provenance are always
protected. A plan that cannot reach the low watermark says so rather than
selecting protected evidence.

Output uses `mode: dry-run`, `authorization: not-granted`, and
`review-for-removal` actions. AWQ never deletes artifacts, changes hosting
retention, uploads evidence, or decides legal and audit retention. The storage
owner must independently authenticate inventory state and authorize any exact
hosting operation. Native and required quality gates remain retained.
