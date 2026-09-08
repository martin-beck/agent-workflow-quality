# Shell adapter family

The built-in `shell` family provides reviewed, opt-in contracts for ShellCheck, shfmt, and Bats.
Installing or upgrading AWQ never activates these tools or downloads them.

| Contract | Exact tool pin | Native command before selected inputs |
| --- | --- | --- |
| `ADAPTER-SHELL-SHELLCHECK` | ShellCheck 0.11.0 | `shellcheck --rcfile=.shellcheckrc --external-sources --source-path=SCRIPTDIR` |
| `ADAPTER-SHELL-SHFMT` | shfmt 3.14.1 | `shfmt --diff --apply-ignore` |
| `ADAPTER-SHELL-BATS` | Bats 1.14.0 | `bats --recursive tests` |

## Agent adoption

Inspect the immutable catalog entry:

```sh
awq --root . adapter-catalog --family shell --format json
```

Review its assumptions, install the exact tools separately, and copy accepted contract objects into
the `adapters` array in `quality/awq.json`. Use `awq policy-diff BASE HEAD --format json` to make
the policy change review-visible.

ShellCheck and shfmt use `input_mode: tracked-shell`. AWQ appends tracked `.sh` files and tracked
executable files whose first line declares a supported shell interpreter. Paths below
`fixture_paths` are omitted. Selection is stable, repository-relative, and argument-array based;
no shell expansion, pipe, command substitution, or source content enters evidence. A selected
contract fails with `adapter-inputs-missing` instead of silently checking standard input when no
eligible source exists.

Bats uses the explicit project test directory `tests`. Projects with a different layout must review
and check in a project-specific argv.

## Project configuration

ShellCheck requires `.shellcheckrc`; shfmt requires `.editorconfig`. These remain authoritative.
For example:

```ini
# .shellcheckrc
severity=style
```

```ini
# .editorconfig
root = true

[*.sh]
indent_style = space
indent_size = 2
shell_variant = posix

[tools/run]
indent_style = space
indent_size = 2
shell_variant = posix
```

ShellCheck infers dialect from each shebang. shfmt uses EditorConfig formatting options. Bats itself
requires Bash and its `.bats` syntax is not treated as portable POSIX shell source.

## Reviewed acquisition

The repository CI installer is explicitly online and supports Linux x86-64. It downloads only:

- ShellCheck v0.11.0 with published SHA-256
  `8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198`;
- shfmt v3.14.1 with published SHA-256
  `76e77641faa025814b77f153b29796b8e6fa2fca03e0c76a691608b86c7ea7bf`; and
- Bats v1.14.0 at signed tag commit `eb7f42f8d608ac693d7a4b67474f6714ea68cfc5`,
  whose pinned commit archive hashes to
  `845574549f4c9777bf02fcdf307f1bf347d40c66920fb6b47dcc8fdfa065ac39`.

Downloads and archive members are bounded. Redirect hosts, archive paths, duplicates, member types,
archive symlinks, hashes, and final version output fail closed. Installation is staged and published
by one same-filesystem rename, so a failed verification leaves no partial prefix. The installer
copies only the required executables and Bats runtime files; it never executes an upstream script.

Run it into a new external prefix when needed:

```sh
uv run python scripts/install_shell_tools.py --prefix /new/external/prefix
export PATH="/new/external/prefix/bin:$PATH"
```

Acquisition may use the network. Adapter execution never installs, resolves, updates, clones, or
downloads anything and remains offline after the reviewed tools are available.

## Evidence and limitations

Executable fixtures cover a conforming project, independent failures for all three tools, native
command equivalence, missing tools and configuration, exact-version skew, empty input selection,
extensionless executable scripts, non-executable `.sh` files, and excluded hostile fixtures.

ShellCheck is static evidence, shfmt is layout evidence, and Bats is contract-test evidence. None
proves runtime safety, behavior completeness, POSIX portability, or behavior on platforms and
shells outside the controlled fixture.
