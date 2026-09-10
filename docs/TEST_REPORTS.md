# Structured test-report evidence

The `test-report-evaluate` command validates a repository-owned, language-neutral JUnit
observation without invoking a test runner:

~~~sh
awq --root . test-report-evaluate quality/test-reports.json \
  --as-of 2026-09-10T20:30:00Z --format json
~~~

The closed v1 contract in `schemas/test-report-evidence.schema.json` binds the exact source
revision, producer identity/version/configuration digest, dedicated report roots, complete sorted
report path and digest set, required modules, count floors, skip policy, collection time and maximum
age. The caller supplies `--as-of`, making freshness evaluation deterministic.

Each report is a regular confined UTF-8 file no larger than 5 MB. At most 1,000 reports and 50 MB
total are accepted. XML depth, nodes, suites and testcase counts are bounded; DTDs and entities are
forbidden. Suite attributes must agree with actual direct testcase outcomes. Missing, extra,
symlinked, empty, malformed, stale, wrong-revision, failing, erroneous and all-skipped evidence
fails closed. `allow` permits some skips only when the positive executed floor remains satisfied;
`forbid` permits none.

Passing output contains only classifications, source/producer/report/suite digests, freshness,
module identifiers and aggregate counts. Testcase names, messages, stack traces, standard streams,
source text and environment data are never returned. Artifact upload availability is not accepted
by the schema and cannot establish test execution.

The evaluator trusts the declared producer and collection timestamp. It proves consistency of the
present bounded reports with the declaration, not that the runner itself was trustworthy, that an
artifact service retained files, or that tests cover all behavior. Native test gates remain the
authority.

Android/JVM connected-test evidence uses the same shared parser and digest/count summarizer while
retaining device API, ABI, image, locale, UI/accessibility and fresh observation requirements.
