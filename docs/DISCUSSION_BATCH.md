# Batched discussion proposal quality

The `discussion-batch` profile validates a bounded, canonical, public-safe packet
of independent discussion points. Every point carries at least two ranked
proposals, multidimensional confidence, concise implications, evidence limits,
and formal references. A response is independently bound to its point and may
remain partial. A user-authored alternative is subject to the same evaluation
fields before it can be selected.

The contract rejects cross-point proposal selection, unreviewed user additions,
non-batched queries, coupled-point authorization, stale or incomplete formal
evidence, unknown fields, and private projections. It proves only packet quality
and identity binding; it does not prove user intent, implementation correctness,
formal refinement, or replace consumer-native gates.

Evaluate a record offline with:

```sh
awq --root . discussion-batch-evaluate quality/discussion-batch/ar-0063-example.json --format json
```
