# Agent Workflow Quality

Agent Workflow Quality provides versioned, agent-ready software quality requirements, profiles,
gates, and evidence contracts. It gives new agentic development projects a reproducible baseline
without replacing their domain-specific tests or assurance.

The zero-runtime-dependency `awq` CLI operates offline after installation. A consumer pins selected
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

Development is coordinated through
[Agent Workflow Quality State](https://github.com/martin-beck/agent-workflow-quality-state)
using the independently versioned
[Agent Workflow Coordinator](https://github.com/martin-beck/agent-workflow-coordinator).

