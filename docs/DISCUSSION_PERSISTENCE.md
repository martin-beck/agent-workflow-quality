# Discussion persistence and safe exit

The `discussion-persistence` profile validates a bounded, canonical journal
projection. It requires a revision-bound journal identity, complete point
records, an atomic and complete safe-exit marker, explicit re-ask state, and a
resume revision equal to the saved revision. Every future-discussion request
is classified as an existing AR, a new AR, or an explicitly rejected request;
unmapped requests fail closed.

The public projection contains summaries, digests, and redaction labels only.
Prompts, transcripts, credentials, private paths, provider execution, and
network behavior are outside this offline gate. The contract does not prove
filesystem crash guarantees, user intent, or consumer-native implementation
correctness. Evaluate a record with:

```text
awq --root . discussion-persistence-evaluate quality/discussion-persistence/ar-0064-example.json --format json
```
