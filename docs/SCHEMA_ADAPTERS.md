# Schema adapter family

The built-in `schema` family provides reviewed, opt-in contracts for strict JSON, a deliberately
restricted YAML subset, JSON Schema metaschema checks, and project-owned instance validation.
Installing or upgrading AWQ never activates these contracts or downloads their tools.

| Contract | Exact tool bundle | Native command before tracked inputs |
| --- | --- | --- |
| `ADAPTER-SCHEMA-STRICT-JSON` | `awq-schema-check` 1.0.0 | `awq-schema-check json` |
| `ADAPTER-SCHEMA-STRICT-YAML` | `awq-schema-check` 1.0.0 | `awq-schema-check yaml` |
| `ADAPTER-SCHEMA-JSONSCHEMA-METASCHEMA` | `awq-schema-check` 1.0.0 | `awq-schema-check metaschema` |
| `ADAPTER-SCHEMA-JSONSCHEMA-INSTANCE` | `awq-schema-check` 1.0.0 | `awq-schema-check validate quality/schemas/project.schema.json` |

The wrapper version probe is exactly
`awq-schema-check 1.0.0 (StrictYAML 1.7.3; JSON Schema CLI 16.3.0)`. The installed
artifact digests are the authority for the StrictYAML distribution version; its upstream module
version attribute is stale and is not used as evidence.

## Agent adoption

Inspect the immutable family:

```sh
awq --root . adapter-catalog --family schema --format json
```

Review its assumptions, install the exact bundle separately, and copy only accepted contract
objects into `quality/awq.json`. Use `awq policy-diff BASE HEAD --format json` so the mapping and
pin become review-visible. Every contract uses `input_mode: tracked-formats`: AWQ appends only
Git-tracked files matching a declared simple or compound suffix and excludes declared fixture
trees.

The instance contract is an example mapping, not a universal default. Replace
`quality/schemas/project.schema.json` and `.instance.json`, `.instance.yaml`, and `.instance.yml`
with a reviewed repository-owned mapping. Use a separate uniquely identified contract for every
additional schema. Keep suffix sets non-overlapping so an instance is not ambiguously owned.

## Strict data profiles

The JSON mode uses the Python standard-library parser with duplicate-object-key detection and
non-finite constants disabled. It rejects invalid UTF-8, `NaN`, positive or negative infinity, and
duplicate keys before any schema tool runs. This removes common parser ambiguity but does not prove
application semantics.

The YAML mode uses StrictYAML 1.7.3. Its intentionally narrow profile rejects duplicate keys,
explicit tags, anchors, aliases, and flow-style collections. Projects requiring those features
must define a separately reviewed parser contract; broadening this adapter would weaken its stated
evidence.

Neither parse-only contract establishes JSON Schema conformance. Conversely, instance validation
does not replace the standalone metaschema contract: it strictly parses the schema graph and data,
then validates instances, but does not separately invoke the metaschema command.

## Dialects, references, and formats

Every selected schema must end in `.schema.json`, contain an explicit supported `$schema` dialect,
and pass Sourcemeta's metaschema command with format assertions enabled. The reviewed CLI supports
JSON Schema Draft 4, Draft 6, Draft 7, 2019-09, and 2020-12; projects should normally use the current
2020-12 dialect unless compatibility requires an older declared draft.

Before invoking the CLI, the wrapper recursively inspects `$ref`, `$dynamicRef`, and
`$recursiveRef`. Fragment-only references are allowed. Referenced files must use the strict schema
suffix, exist below the repository root, and be addressed by canonical relative paths without a
scheme, authority, query, backslash, or parent traversal. HTTP is never enabled. Percent-decoded
paths remain subject to resolved-path confinement. Fragment syntax and standard keyword semantics
are left to the pinned JSON Schema CLI.

For predictable resolution, use file-local relative references and avoid base-altering `$id`
values in this strict contract. A conflicting base identifier may make the wrapper and validator
resolve differently; that fails closed and requires a separately reviewed mapping.

Instance validation strictly pre-parses `.json`, `.yaml`, and `.yml` inputs, preflights the complete
local schema graph, and invokes `jsonschema validate` with `--format-assertion`. Standard formats
such as email are asserted where implemented by the pinned validator. Format behavior beyond
supported standard formats is implementation-defined and must not be overstated.

## Security and privacy boundary

The wrapper accepts at most 10,000 files. Each unique file is capped at 5 MB and one invocation at
50 MB. AWQ applies matching bounds before process launch, along with path-count, argv, and
configuration limits. All paths are repository-confined. The exact bundled JSON Schema executable
must be a regular non-symlink file and report version 16.3.0 before every check.

Runtime receives a minimal locale-stable environment and does not enable HTTP, install packages,
execute a shell, or invoke an upstream installation script. Standard input is closed. Native tool
stdout and stderr are discarded. Failures emit only `awq-schema-check: validation failed`; AWQ
returns stable finding codes without source excerpts, validator diagnostics, document values,
credentials, or machine paths.

## Reviewed acquisition

The CI installer is explicitly online and supports Linux x86-64. It downloads only:

- Sourcemeta JSON Schema CLI v16.3.0 release associated with GitHub-verified signed tag
  `c343911b3bdd5cae99425e2aeb5b2e1b47f76032`, resolving to commit
  `41bdf8dacccd7e544df48d9e782a9c4dadbdce1e`; release ZIP SHA-256
  `d348714cfceeedf521cffecb13c199ba4b08fd865dc23c985f2de44fda39a9c4`;
- StrictYAML 1.7.3 wheel SHA-256
  `fb5c8a4edb43bebb765959e420f9b3978d7f1af88c80606c03fb420888f5d1c7`;
- python-dateutil 2.9.0.post0 wheel SHA-256
  `a8b2bc7bffae282281c8140a97d3aa9c14da0b136dfe83f850eea9a5f7470427`;
- six 1.17.0 wheel SHA-256
  `4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274`.

```sh
uv run python scripts/install_schema_tools.py --prefix /new/external/prefix
export PATH="/new/external/prefix/bin:$PATH"
```

Downloads and ZIP expansion are bounded. Initial and redirect hosts, hashes, canonical member
paths, duplicates, symlink and special-file types, individual and aggregate bytes, exact executable
name, selected Python payloads, reviewed helper source, and final version output fail closed.
Installation is staged and published by one same-filesystem rename.

Acquisition may use the network. After installation, every adapter command is offline. Relative
remote identifiers are not fetched, and absolute remote references are rejected before execution.

## Evidence and limitations

Executable fixtures cover valid documents and local recursive schemas, duplicate and non-finite
JSON, restricted YAML failures, missing dialects, remote and escaping references, format and
semantic instance failures, version skew, unavailable tools/configuration/inputs, input budgets,
fixture exclusion, native-command equivalence, atomic installation, and hostile archives.

A pass proves only the named parser, schema, dialect, mapping, selected tracked inputs, and pinned
implementation accepted the checked bytes within the stated bounds. It does not prove business
semantics, schema design quality, cross-implementation portability, completeness of format
checking, absence of malicious intent, or conformance by unselected files.
