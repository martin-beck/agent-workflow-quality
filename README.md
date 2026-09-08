# Agent Workflow Quality

Agent Workflow Quality provides versioned, agent-ready software quality requirements, profiles,
gates, and evidence contracts. It gives new agentic development projects a reproducible baseline
without replacing their domain-specific tests or assurance.

The zero-runtime-dependency `awq` CLI's deterministic checks operate offline after installation.
The separately classified `hosting-observe` command is explicitly online. A consumer pins selected
profiles, expanded requirements, and the registry digest in `quality/awq.lock.json`; updates are
explicit and reviewable.

## Standards traceability

AWQ ships a version-pinned [control catalogue](docs/STANDARDS.md), strict JSON schemas, and reviewed
many-to-many mappings for NIST SSDF, SLSA, SPDX, the OpenSSF OSPS Baseline, Python, JSON, CommonMark,
and POSIX shell sources. These mappings express alignment only: they never assert certification,
compliance, or a framework maturity level.

Agents can consume the same validated data without scraping documentation:

```sh
awq --root . standards --format json
awq --root . explain AWQ-GHA-002 --format json
```

Unknown controls, floating or stale source editions, removed controls, unmapped AWQ requirements,
and certification claims fail closed. Generated profile matrices expose coverage gaps and edition
drift deterministically.

## Policy governance

Policy schema version 2 adds owned lifetime bounds plus strict standard, emergency, renewal, and
revocation records. Semantic comparison covers policy fields, local commands, thresholds, scopes,
evidence classifications, and lock pins:

```sh
awq --root . governance --format json
awq --root . policy-diff BASE HEAD --format json
awq hosting-observe --repository OWNER/NAME --format json
```

The pull-request workflow rejects weakening changes. New exceptions and append-only renewals must
carry approval references and remain review-visible. The online hosting observation is timestamped
environmental evidence and explicitly not offline proof. See [policy governance](docs/GOVERNANCE.md)
for the full lifecycle and limitations.

Development is coordinated through
[Agent Workflow Quality State](https://github.com/martin-beck/agent-workflow-quality-state)
using the independently versioned
[Agent Workflow Coordinator](https://github.com/martin-beck/agent-workflow-coordinator).

