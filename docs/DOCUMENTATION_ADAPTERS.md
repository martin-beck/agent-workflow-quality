# Documentation adapter family

The built-in `documentation` family provides reviewed, opt-in contracts for Markdown structure,
local links, and repository-owned prose rules. Installing or upgrading AWQ never activates these
tools or downloads them.

| Contract | Exact tool pin | Native command before tracked inputs |
| --- | --- | --- |
| `ADAPTER-DOCUMENTATION-RUMDL-LINKS` | rumdl 0.2.68 | `rumdl check --config .rumdl.toml --no-cache --no-code-block-tools --color never --enable MD051,MD057` |
| `ADAPTER-DOCUMENTATION-RUMDL-STYLE` | rumdl 0.2.68 | `rumdl check --config .rumdl.toml --no-cache --no-code-block-tools --color never --extend-disable MD051,MD057,MD074` |
| `ADAPTER-DOCUMENTATION-VALE` | Vale 3.20.0 | `vale --no-global --config=.vale.ini --no-color` |

## Agent adoption

Inspect the immutable family:

```sh
awq --root . adapter-catalog --family documentation --format json
```

Review its assumptions, install the exact tools separately, and copy accepted contract objects into
the `adapters` array in `quality/awq.json`. Use `awq policy-diff BASE HEAD --format json` to make
the policy change review-visible.

All three contracts use `input_mode: tracked-formats`. AWQ appends only Git-tracked files with a
declared suffix, omits paths below `fixture_paths`, and fails when selection is empty or exceeds
the bounded argument budget. Paths are repository-relative and passed as an argument array without
a shell. Tool output and prose excerpts are discarded.

## Project configuration

Both rumdl contracts require `.rumdl.toml`; its flavors, rule settings, per-file ignores, and
exclusions remain project-owned. Both contracts disable cache state and force
`--no-code-block-tools`, so a project configuration cannot launch external linters or formatters.
The style contract excludes MD051, MD057, and MD074 to keep link evidence separate. The link
contract enables only MD051 and MD057, which validate filesystem targets and heading fragments.

Vale requires `.vale.ini` and supplies `--no-global`, so user-level configuration cannot alter the
result. Keep `StylesPath`, YAML rules, vocabularies, accepted terms, and severity thresholds in the
repository. Do not declare remote `Packages` for an offline gate and never run `vale sync` during
adapter execution.

## External links are separate evidence

rumdl's MD051 and MD057 rules are filesystem-only and skip HTTP, HTTPS, email, and other non-file
schemes. A pass proves only that selected relative file targets and fragments satisfy the reviewed
configuration. Absolute site routes are ignored by default unless the project configures a local
resolution policy. The result does not observe DNS, TLS, HTTP status, redirects, rate limits,
authentication, or current external availability.

If a project needs external-link observations, define a separate scheduled, network-authorized
workflow with environmental evidence and its own retention/privacy review. Never reinterpret the
offline adapter result as that observation.

## Reviewed acquisition

The repository CI installer is explicitly online and supports Linux x86-64. It downloads only:

- rumdl v0.2.68 from signed tag commit
  `5606c5d6cbbfa8d61c2f23206d42aa6457ddd301`, archive SHA-256
  `a5fbbc1ab31400b16896f3e00192f931f766e3374ec5e31aadcd2114533f4f8b`;
- Vale v3.20.0 from lightweight tag commit
  `fdc4cc754f58d953f668586dc1891064a746e0a2`, whose commit signature is verified,
  archive SHA-256 `f59e7030c5d4ace6cf915497d0d076a1699d61e876142765963237e6867c9712`.

The GitHub release API publishes both archive digests. Downloads, archive members, individual and
aggregate expanded bytes are bounded. Redirect hosts, archive paths, duplicates, types, hashes,
exact member names, and final version output fail closed. Installation is staged and published by
one same-filesystem rename, and no upstream installation script executes.

```sh
uv run python scripts/install_documentation_tools.py --prefix /new/external/prefix
export PATH="/new/external/prefix/bin:$PATH"
```

Acquisition may use the network. Adapter execution never installs, resolves, syncs, updates, clones,
downloads, or contacts a service after the reviewed binaries and repository configuration exist.

## Evidence and limitations

Executable fixtures cover conforming documents, independent structure/prose/link failures,
native-command equivalence, exact-version skew, absent tools/configuration/inputs, tracked suffix
selection, fixture exclusion, and an unreachable external URL skipped by filesystem-only rules.

rumdl provides distinct mechanical Markdown structure/style and local-link evidence. Vale provides
mechanical evidence against the checked-in editorial policy. Neither proves factual truth, semantic
completeness, rendered usability, external availability, or overall writing quality.
