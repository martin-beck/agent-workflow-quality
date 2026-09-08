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

Policy schema version 3 adds owned lifetime bounds, strict exception records, and pinned adapter
contracts. Semantic comparison covers policy fields, local commands and adapters, thresholds,
scopes, evidence classifications, and lock pins:

```sh
awq --root . governance --format json
awq --root . policy-diff BASE HEAD --format json
awq hosting-observe --repository OWNER/NAME --format json
```

The pull-request workflow rejects weakening changes. New exceptions and append-only renewals must
carry approval references and remain review-visible. The online hosting observation is timestamped
environmental evidence and explicitly not offline proof. See [policy governance](docs/GOVERNANCE.md)
for the full lifecycle and limitations.

## Pinned adapters

Repository-owned adapter contracts bind a portable executable name to an exact version probe,
argument arrays, project configuration, a finite deadline, execution tier, evidence class, and
honest limitation. The shared runner never invokes a shell, downloads a tool, or records tool
output:

```sh
awq --root . adapter-catalog --family python --format json
awq --root . adapter-catalog --family shell --format json
awq --root . adapter-run quality/adapters/example.json --format json
awq --root . plan --format json
awq --root . check --tier pr --format json
```

Adapter families are delivered independently. See [pinned adapters](docs/ADAPTERS.md) for the
contract, failure taxonomy, security boundary, and migration details. Exact commands, pins,
configuration assumptions, and adoption recipes are documented for the
[Python family](docs/PYTHON_ADAPTERS.md) and [shell family](docs/SHELL_ADAPTERS.md).
Documentation and schema-format families follow in AR-0014 and AR-0015.

Development is coordinated through
[Agent Workflow Quality State](https://github.com/martin-beck/agent-workflow-quality-state)
using the independently versioned
[Agent Workflow Coordinator](https://github.com/martin-beck/agent-workflow-coordinator).

