# Consumer equivalence and promotion

AWQ 0.16 adds an offline, zero-runtime-dependency evaluator for **one consumer and individual shared
gates**. It does not edit workflows, execute the native or shared commands, acquire evidence, or
remove native gates. A successful old shadow workflow that deliberately exits zero is not equivalence
evidence. Inspect the actual requirement results and compare them to their native counterparts.

## Agent recipe

1. Read the consumer's coordinator and native gate contracts. Open a consumer-specific reviewed task.
   Keep all native gates enabled and collect shared gates in shadow.
2. Copy [the synthetic shadow template](../templates/consumer-equivalence.json) to a reviewed
   repository-relative JSON file. Replace every synthetic hash, case, count, date and owner with
   reviewed evidence; copying the example does not establish any consumer's readiness.
3. Build controlled positive and negative corpora with known native expectations. Run both exact
   definitions on each case. Record only case commitments and normalized outcomes.
4. Observe the live comparisons across at least seven distinct UTC dates and twenty comparisons.
   Record failures, skips and errors, not merely the shadow workflow's successful exit.
5. Evaluate at an explicitly selected UTC instant:

   ~~~sh
   awq --root . promotion-evaluate quality/promotion.json \
     --as-of 2026-09-09T00:00:00Z --format json
   ~~~

6. Review each gate's decision, blocking reasons, factors and rollback record independently. A
   consumer PR may add only explicitly reviewed eligible gates as required checks. Keep the remaining
   shared gates shadow and keep every native gate. This evaluator does not authorize or implement
   native gate removal.
7. Use the strict selector in the required-check workflow, without interpreting logs or using a
   JSON filter to manufacture a passing exit:

   ~~~sh
   awq --root . check --tier pr \
     --requirement AWQ-CORE-001 --requirement AWQ-PRIV-001 --format json
   ~~~

The selector rejects an empty explicit selection, duplicate IDs, unknown or unlocked requirements,
and requirements above the requested tier before any check execution. It runs exactly the selected
built-in requirements, not unrelated shared requirements, local extensions, or adapter entries.
It preserves their policy and reviewed exception semantics. Its output declares the sorted
selection and the omitted local gates. A non-pass or missing selected result fails closed. The
unselected default check remains unchanged and includes applicable local gates. Standalone adapter
promotion is outside this first selector contract; never silently substitute an adapter ID for a
locked shared requirement.

## Evidence and privacy contract

The [standalone JSON Schema](../schemas/consumer-equivalence.schema.json) defines the wire shape.
The [conforming example](../fixtures/conforming/consumer-equivalence.json) is synthetic, not a claim
about the initial four consumers. Runtime validation is authoritative for cross-field arithmetic,
ordering, actual calendar dates, review expiry and policy floors.

Input is canonical UTF-8 JSON: sorted object keys, compact separators, one final LF, no duplicate
keys, non-finite values, extra fields or fractional numeric fields. The file must be a confined
repository-relative regular JSON file with no symlink component. Maximum size is 1,000,000 bytes.
There are at most 200 sorted unique gate IDs, 2,000 sorted unique case SHA-256 commitments per gate
and 366 sorted unique observed dates. Counts are integers between zero and 1,000,000; the total live
comparison count must also fit that bound. Daily native and shared elapsed totals are positive integer
milliseconds, each at most 1,000,000,000. Flaky counts cannot exceed that day's comparisons.

Only fixed enumerations, opaque owner IDs, cryptographic commitments, a source commit, dates and
bounded counts are accepted. Do not include paths, usernames, email addresses, prompts, tool output,
logs, defect descriptions, credentials or machine identifiers. Keep the owner-ID mapping and the
reviewed material behind each hash in the consumer's separately governed evidence store. A hash does
not anonymize a guessable secret: do not hash private prompts, credentials or personal data to make
them appear safe for publication.

The consumer commitment identifies the reviewed consumer without publishing its name. The source
commit identifies the snapshot being considered. Native and AWQ definition commitments must cover
the exact argv, tool versions, configuration and fixture-selection rules in a reviewed canonical
definition; changing any of these starts a new evidence record/window. A case commitment hashes the
reviewed canonical case identity, fixture bytes and expected native outcome. Case lists are sorted
by commitment and duplicates are rejected. No content is copied into the evaluator output.
Approval commitments refer to separately reviewed approval records; they are not signatures.

## Outcome and measurement semantics

Controlled cases declare expected pass/fail and independently observed native/AWQ pass, fail, error
or skip. At least five positive and five negative cases are required. A native result that differs
from the controlled expectation blocks the gate: a broken oracle cannot establish equivalence.

Live daily counts and controlled outcomes use the following normalized taxonomy:

| Category | Native | AWQ | Consequence |
| --- | --- | --- | --- |
| both_pass | pass | pass | Agreement |
| both_fail | fail | fail | Agreement |
| false_positive | pass | fail | Exact active reviewed coverage required |
| false_negative | fail | pass | Always block |
| inconclusive | either tool error or skip | any | Cannot enforce |

Every attempted comparison belongs to exactly one category, including failures and environment
errors. Daily aggregate counts include all attempted comparisons; elapsed totals include the same
commands and retries for both systems. A flaky run is a comparison whose repeated identical-input
outcomes differ under the reviewed repeat policy. Record such comparisons once in flaky_runs, never
discard them or count retries as extra independent evidence. This aggregate evaluator cannot verify
that the collector followed those rules; retain that independent review.

Policy can strengthen, never weaken, these baseline limits:

| Policy | Bound |
| --- | --- |
| Minimum observed dates | 7 through 366 distinct UTC dates |
| Minimum comparisons | At least 20 |
| Minimum controlled cases | At least 5 positive and 5 negative |
| Maximum evidence age | At most 604,800 seconds |
| Runtime budget | Positive numerator/denominator, at most 10 times native elapsed total |
| Flake budget | Nonnegative numerator/positive denominator, at most 1/20 |
| Rational components | Integers at most 1,000,000 |

Budget comparisons use exact integer cross multiplication, not floating-point ratios. Equality
passes. The numerator is the permitted AWQ/native runtime ratio or flaky/comparison ratio.
The runtime bound is an adoption ceiling, not a performance claim or recommended target.

False-positive reviews partition the exact total false positives across controlled and live evidence
by sorted unique configuration, format, tool-version, environment, policy or unknown categories.
Every partition has a positive count, an owner, a distinct reviewer, an approval commitment and an
enumerated remediation: align-policy, repair-adapter, repair-fixture or investigate.
Reviews last at most 30 days and must be unexpired at evaluation. Missing, surplus or expired
coverage blocks. A fully reviewed false positive remains an explicit decision factor even when
enforcement is eligible; review does not erase the mismatch.

Each gate also requires a rollback owner, distinct reviewer, approval commitment, review interval,
deadline and sorted unique triggers. False-negative is mandatory; the other supported triggers are
unreviewed-mismatch, runtime-budget and flake-budget. The deadline cannot outlive its review, and the
review lasts at most 90 days. An expired deadline or review blocks. The consumer owner must actually
implement and test rollback to its prior reviewed shared-gate policy; the evaluator never performs
that action and native gates stay retained.

## Decisions, time and limitations

Blocking reasons dominate all requests, including a retain or shadow request. Any false negative,
broken controlled native oracle, uncovered/expired false positive or expired rollback yields block.
Insufficient observations/corpora, stale evidence, inconclusive results or exceeded runtime/flake
budgets downgrade an enforce request to shadow. Otherwise the requested retain, shadow or enforce
decision is returned. Reviewed false positives remain visible but do not alone prevent enforcement.

Every result says native_gate=retain. The top-level status fails if a gate is blocked; it is not a
global promotion authorization. Consumers must review each decision and leave all other shared gates
shadow. The CLI prints the same deterministic structure as JSON or text, returns 1 for invalid or
blocked evidence, and never hides one gate's failure in another gate's success.

The required as-of timestamp uses exactly YYYY-MM-DDTHH:MM:SSZ. It cannot precede the observation
window end or any review creation, and windows cannot run backwards or exceed 366 days. Observed
dates must lie inside the window. Expiry is exclusive: evaluation at expiry fails. Evidence age is
measured from the window end; equality at the configured age limit passes.

Caller-selected time is **not trusted clock evidence**. An old as-of intentionally evaluates a
historical record, not current eligibility. Promotion automation must supply its actual current UTC,
reject or independently review stale decision records, and reevaluate after any evidence,
definition, policy or approval change. Never reuse the example date in production automation.

Determinism covers the same validated document and explicit evaluation instant. It does not
authenticate collectors, owners, reviews or execution. It does not establish complete corpora,
universal semantic equivalence, trusted timestamps, private-data anonymity, hosted required-check
settings or compliance certification. Consumer integration and native gate retention/removal
decisions remain separately coordinated and reviewed work.
