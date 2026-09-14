# Consumer assurance plans

This generated view summarizes sanitized representative inventories. The machine-readable schema and runtime validator remain authoritative.

| Repository | Domains | Gates | Unsupported | Evidence state |
| --- | ---: | ---: | ---: | --- |
| `example/agent-relay` | 4 | 2 | 0 | declarations only |
| `example/agent-systems-benchmark` | 4 | 3 | 0 | declarations only |

## Contract boundary

An assurance plan inventories languages, build systems, runtime surfaces and quality domains. Every domain is covered by an owned gate or a reviewed unsupported declaration. Gates retain repository-native ownership and declare bounded argument arrays, input scope, invariants, evidence class, report contract, remediation, limitations, ordering and optional native mapping.

Validation never executes a command. A declaration without exact AR-0034 evidence identity is reported as `declared`, never `pass`. Observations bind the clean source revision, gate definition, configuration, input, platform and freshness. The generated examples are descriptive inventories, not coordinator state and not proof that downstream gates ran.
The named repositories above are sanitized, non-authoritative fixtures only; AWQ does not execute them or require them at runtime. Consumers own their native Android/JVM evidence and must bind it to the generic AWQ adapter contract.

Use `awq assurance-plan-check PLAN --format json` for content-minimized validation and `awq assurance-plan-diff BASE HEAD --format json` for deterministic review. Removing a declared domain, gate or unsupported record is classified as weakening; other changes require review.
