# Pinned adapters

AWQ policy schema version 3 supports opt-in external quality tools without making them runtime
dependencies of AWQ. The umbrella contract and runner are shared by four independently reviewable
families:

- AR-0012: Python formatting, lint, typing, tests, and coverage.
- AR-0013: ShellCheck, shfmt, and Bats.
- AR-0014: Markdown, links, and prose.
- AR-0015: JSON, YAML, and JSON Schema.

No family adapter is enabled merely by upgrading AWQ. A project explicitly checks its contract into
the `adapters` array in `quality/awq.json`.

## Reviewed catalog

Installed releases expose schema-validated, agent-readable family contracts:

~~~sh
awq --root . adapter-catalog --format json
awq --root . adapter-catalog --family python --format json
~~~

The response includes a canonical catalog digest, family assumptions, and complete contracts.
Unknown families fail closed. Catalog entries are templates for explicit review and copying into a
repository policy; they are never enabled automatically. See the
[Python adapter family](PYTHON_ADAPTERS.md), [shell adapter family](SHELL_ADAPTERS.md), and
[documentation adapter family](DOCUMENTATION_ADAPTERS.md) for exact pins and configuration contracts.

## Contract

Each object conforms to `schemas/adapter-contract.schema.json` and contains:

| Field | Meaning |
| --- | --- |
| `id` | Stable `ADAPTER-...` evidence identifier. |
| `tool`, `version` | Portable executable name and exact version pin. |
| `version_argv`, `version_output` | Bounded probe argv and its exact combined output. |
| `argv` | Bounded check argv; element zero must equal `tool`. |
| `timeout_seconds` | Finite deadline shared by probe and execution, with a ten-second probe cap. |
| `tier`, `evidence` | Earliest execution tier and evidence classification. |
| `limitation`, `remediation` | Required bounded review context. |
| `formats` | Unique lowercase suffixes covered by the adapter. |
| `config_paths` | Unique repository-relative project configuration files that must exist. |
| `input_mode` | Optional `explicit` default, `tracked-formats`, or `tracked-shell` selection. |

JSON Schema validates the portable shape. Zero-dependency runtime validation additionally enforces
cross-field conditions that JSON Schema cannot express directly: both argv arrays start with the
declared tool, the pinned version occurs in the expected probe output, paths are safe, and lists are
bounded and unique.

Example:

```json
{
  "id": "ADAPTER-PYTHON-RUFF",
  "tool": "ruff",
  "version": "0.16.5",
  "version_argv": ["ruff", "--version"],
  "version_output": "ruff 0.16.5",
  "argv": ["ruff", "check", "--config", "pyproject.toml", "."],
  "timeout_seconds": 120,
  "tier": "pr",
  "evidence": "mechanical",
  "limitation": "Static analysis cannot prove runtime correctness.",
  "remediation": "Repair findings using the checked-in project configuration.",
  "formats": [".py", ".pyi"],
  "config_paths": ["pyproject.toml"]
}
```

## Execution and evidence

For each eligible tier, AWQ executes eligible adapters in stable identifier order:

1. validates the contract and confines every declared configuration path to the repository;
2. discovers the named executable through `PATH`;
3. runs the capped version probe and requires an exact output match;
4. executes the configured argv from the repository root without a shell; and
5. appends eligible tracked inputs when the reviewed contract selects them; and
6. returns `schemas/adapter-result.schema.json` evidence.

Standard input is closed. Check output is discarded. Probe output is merged, capped at 4096 bytes,
used only for the exact pin comparison, and then discarded. The child receives only `PATH`, fixed
UTF-8 locale controls, `NO_COLOR`, and required operating-system/temp variables; credential and
home variables are not forwarded. AWQ itself performs no download or network request.

The runner does not sandbox the selected executable. A reviewed project tool can still use host
capabilities, including the network, so family contracts must choose offline-capable argv. The
contract is executable project policy and must not be accepted from an untrusted change without
review.

A passing result contains no findings. Failures use stable codes:

| Code | Meaning |
| --- | --- |
| `adapter-config-unsafe` | A declared configuration path escaped confinement. |
| `adapter-config-missing` | Required project configuration was unavailable. |
| `adapter-inputs-missing` | A tracked-input contract selected no eligible source files. |
| `adapter-inputs-limit` | Selected paths exceeded the bounded process-argument budget. |
| `adapter-tool-unavailable` | Discovery or process startup failed. |
| `adapter-version-timeout` | The version probe exceeded its deadline. |
| `adapter-version-output-limit` | Probe output exceeded 4096 bytes. |
| `adapter-version-failed` | The probe could not complete within the runner safety contract. |
| `adapter-version-mismatch` | Probe exit or exact output differed from the pin. |
| `adapter-timeout` | The check exceeded its deadline. |
| `adapter-failed` | The check returned a nonzero status. |

Findings deliberately omit command output and source excerpts. The `duration_ms` measurement varies;
the status, classifications, and messages are stable for an otherwise fixed execution context.

## Agent workflow

Inspect the plan before executing:

```sh
awq --root . plan --format json
```

Run one repository-owned contract during authoring:

```sh
awq --root . adapter-run quality/adapters/example.json --format json
```

Run all adapters eligible at a tier, together with native AWQ requirements and local extensions:

```sh
awq --root . check --tier pr --format json
awq --root . evidence --tier pr --format json
```

Policy diff treats removal, reduced format coverage, later execution, shorter deadlines, changed
tool pins/argv/configuration/evidence/limitations, and other behavior changes as weakening. Adapter
addition and broader or earlier execution are strengthening; remediation-only changes remain
review-visible.
