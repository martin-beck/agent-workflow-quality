# Reliability and retention budgets

AWQ v0.22 adds an offline synthetic benchmark collector and a strict metadata-only
reliability evaluator. They retain native gates and never run consumer extensions,
inspect private repositories, or delete retained evidence.

## Commands and inputs

Create an existing canonical absolute scratch directory on the development disk.
The collector creates and removes only its own synthetic temporary directories.
From the repository root:

```sh
awq reliability-collect templates/reliability-pr.json \
  --scratch /reviewed/scratch --as-of 2026-01-01T00:00:00Z --format json
awq reliability-evaluate fixtures/conforming/reliability/observation.json \
  --as-of 2026-01-01T00:00:00Z --format json
```

The historical example timestamp is not appropriate for current automation.
Automation must supply its current UTC time, reject stale observations and review
stale decisions. Caller-selected time is not authenticated clock evidence. The
evaluator rejects a time before the observation or any retained record creation.
Observations older than seven days fail; equality at the seven-day boundary is
allowed. A caller can falsify observations or time: this evaluator is not a trust
or attestation service.

[The standalone schema](../schemas/reliability-budget.schema.json) describes both
canonical budget requests and normalized observations. Runtime validation adds
cross-field chronology, exact repeat order, uniqueness and fixture identity.
Unknown fields, floats where integers are required, duplicate JSON keys,
noncanonical bytes, unsafe/symlink paths and oversized inputs fail closed.
Inputs are confined repository-relative files, at most 256000 bytes.

## Representative fixtures and measured stages

| Recipe | Synthetic JSON files | Bytes per payload | Total tracked files |
| --- | ---: | ---: | ---: |
| small | 16 | 64 | 19 |
| medium | 128 | 1024 | 131 |
| large | 512 | 4096 | 515 |

Payload counts exclude the generated policy, lock and shell entry point. Each
trial creates a fresh synthetic Git repository and measures four real operations:
tracked discovery, core/schema checks, evidence production and unchanged-policy
Git revision comparison. Setup and interpreter startup are excluded from stage
timings but included in the worker deadline. The policy is constant-sized across
recipes: that stage does not establish scaling for large policy/adapter registries.
The JSON payload is fixed canonical padding, not a representative language mix.

PR runs three trials per recipe (9 repositories, 36 stage observations); scheduled
runs seven (21 repositories, 84 observations). Each worker has a 30-second wall and
CPU deadline, a 65536-byte output/file bound, a credential-free environment and
fixed argument-array invocation. POSIX collection is the reviewed implementation;
offline evaluation has no subprocess requirement. Descendants are terminated on
timeout and worker exit. No network command or package acquisition runs inside a
trial, but process isolation is not a network sandbox. Pinned environment setup is
separate from collection.

Durations are integer monotonic nanoseconds. The median is the middle sorted
sample (both profiles have odd repeat counts). A median above twice its reviewed
reference fails; any sample above four seconds also fails. References may be
strengthened down to one nanosecond but cannot exceed two seconds. Default
references are conservative 200-millisecond review ceilings, NOT invented
historical measurements. They produce a default 400-millisecond median ceiling.
To adopt a measured baseline, collect on a reviewed comparable runner, review its
immutable report and source identity, then explicitly update the reference values.
The evaluator does not authenticate that baseline or establish hardware equivalence.

Three or seven observations are insufficient for confidence intervals or a rare
flake-rate claim. CPU contention, filesystem cache, platform and load affect these
measurements. No automatic baseline learning or upward threshold adjustment occurs.
A timeout, failed trial or truncated output is an explicit failure, never a zero-time
success. Fixed ceilings detect budget violations, not every performance regression.

## Determinism and extension observations

Semantic digests compare repeated outputs with only existing `duration_ms` fields
removed. Every other semantic field participates. The worker validates tracked
file counts, checks success and output size; any digest disagreement blocks.
Evidence records bind the recipe, collector version and an aggregate digest of the
collector, worker and exercised production modules. Hashes establish identity,
not trusted execution. Timing fields intentionally differ between collections;
evaluation is deterministic for identical observations and caller-selected time.

Up to 16 public `GATE-*` extension identities may supply reviewed observations,
each binding an extension source digest and 3/7 through 32 samples. The harness does
not execute them. Results remain caller-declared; an empty list provides NO local
extension flake evidence. Status or semantic disagreement blocks independently of
the maximum five-percent failure budget. Thus the strict determinism requirement
can reject a mixed pass/fail sample even when its failure fraction is below five
percent. Consistent failure also blocks. Comparisons use integer cross-products,
not floating-point probabilities. Errors, timeouts and truncation count as failures.

## Privacy-preserving retention and cleanup

The evaluator accepts at most 128 inventory entries to diagnose a violated budget.
Each contains only a public `EVIDENCE-*` identity, SHA-256, byte count, creation and
expiry UTC timestamps, and a fixed classification. Duplicate identities/digests
are rejected. No logs, prompts, transcripts, filenames, host identifiers or raw
source are accepted. Hashes and classifications are declarations; this mode does
not verify the underlying stored bytes or prove they are redacted. Synthetic
fixture hashes are demonstration values, not measured historical evidence.

The passing retention budget is at most 64 entries, 1 MiB total, 65536 bytes per
entry and seven days per retention window. Entries must be explicitly classified
aggregate-only. Expired, overlong, oversized, unreviewed or raw-content records
produce blocking review-and-remove guidance; excess aggregate count/size produces
review-and-trim guidance. Unexpired aggregate records remain available for audit.
Never automatically delete on an untrusted report: the repository owner reviews
record identities, confirms legal/audit holds and recovery policy, then removes
only exact authorized objects using the owning storage interface. This command
performs no deletion and changes no consumer lock or gate.

Retain the minimized observation and decision with their digests, reviewed reference
contract, and immutable collector release identity. Do not retain worker stdout,
stderr, source snapshots or environment values. Larger representative workloads,
statistical baseline management, real extension collectors and storage-specific
cleanup remain separately reviewable follow-up work.
