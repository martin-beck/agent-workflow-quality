# Agent runtime replay and launch provenance

AWQ validates a versioned, canonical synthetic replay contract with:

- hard bounds for serialized bytes, interactions, events, frames, headers,
  retries, and virtual time;
- explicit request normalization and digest matching, ordered correlation, and
  complete frame consumption;
- versioned redaction before serialization;
- seeded delay, connection reset, truncation, cancellation, and
  uncertain-delivery events;
- consumer-authorized retry after uncertainty only when an idempotency proof
  digest is supplied; and
- secret-free launch provenance for the adapter, provider, model settings,
  pinned runtime and executable, workload, source, run attempt, argv,
  environment names, prompt transport, credential resolver, network,
  telemetry, and the complete adapter setting set.

Run the repository-owned conforming cassette offline:

```console
awq --root . agent-replay-evaluate fixtures/conforming/agent-runtime-replay.json --format json
```

The [closed JSON Schema](../schemas/agent-runtime-replay.schema.json) rejects
unknown fields and bounds every collection. The runtime evaluator adds
cross-field checks for canonical request digests, event sequence and virtual
time, correlations, aggregate bounds, complete consumption, uncertain retry
authorization, and atomic preservation of multi-adapter settings. If any
declared setting cannot be preserved, the whole adapter set fails.

The evaluator returns only identifiers, digests, counts, fixed classifications,
and fixed limitations. Cassettes cannot contain prompt text, transcripts,
provider responses, credential values, or retained subprocess output.
Credential evidence identifies only a resolver and its configuration digest.
Runtime execution is opt-in, pinned, replay-only, and offline.

## Evidence boundary

This synthetic contract-test evidence does not establish live provider
compatibility, provider equivalence, model quality, or sandbox containment. It
does not implement provider dialects or contact services. Live observations
belong to a separate environmental evidence class. Consumer-native gates remain
authoritative and must not be replaced or upgraded by replay results.
