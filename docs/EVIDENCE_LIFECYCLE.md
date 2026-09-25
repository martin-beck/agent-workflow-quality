# Evidence lineage, publication and retention lifecycle

AWQ validates bounded metadata that connects observations and decisions without
turning a score, upload, or cleanup suggestion into a quality claim. The command
is offline and read-only:

```sh
awq --root . evidence-lifecycle-evaluate \
  fixtures/conforming/evidence-lifecycle.json \
  --as-of 2026-09-11T00:00:00Z \
  --trusted-prior-head genesis --format json
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
all those fields and the preceding record digest. The first parent is null. The
document declares `prior_lineage_head_sha256` and its current
`lineage_head_sha256`, while the caller independently supplies
`--trusted-prior-head`. In append mode, the exact trusted digest must match the
declaration, occur in the chain, and have at least one successor. Runtime
validation therefore rejects self-consistent truncation, replacement, or
reordering of the previously accepted prefix as well as changed records, broken
parents, non-monotonic time, a source revision different from the document
source, and reused record or attempt identities. Every publication and
inventory artifact digest must also identify an artifact present in the lineage.

An outcome is not derived from the score. For example, a high integer score can
coexist with a failed decision. Digests establish byte identity, not who
produced the bytes or whether the declared execution happened. The trusted
prior head must come from an authenticated, previously accepted result and be
stored outside the candidate document. An attacker who controls both the
candidate and supplied anchor can rewrite history. `genesis` explicitly
performs only internal chain validation and makes no append-only comparison.
AWQ is not an external transparency or timestamping service.

## Checkpoint and rollback extension (schema version 2)

Version 2 may carry a bounded `checkpoints` chain and separate
`rollback_outcomes`. Checkpoints are ordered by their canonical parent digest,
bind to the same source revision, and are limited to 64 records. A rollback
references an existing checkpoint and reports only its lifecycle status
(`requested`, `applied`, `rejected`, `failed`, or `cancelled`); it is never
converted into a lineage quality outcome. The evaluator emits checkpoint and
rollback summaries separately from quality, publication, and retention
candidate results. Version 1 documents remain valid and receive empty
checkpoint/rollback summaries.

This contract first ships with AWQ v0.33.0. Because the CLI and schema were not
public in earlier releases, v1 requires `--trusted-prior-head` and the document
anchor from its first release; there is no legacy unanchored mode.

## Validation and publication

Publication records keep `validation_outcome` separate from
`publication_state`. A validated optional artifact can therefore report a
failed or unavailable upload without rewriting validation as failure. Required
artifacts affect the overall result and must be published after their ordered
prerequisites. Publication may truthfully succeed for evidence whose validation
failed; quality remains failed while publication remains successful. A required
record with `continue_on_error: true` is rejected;
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
