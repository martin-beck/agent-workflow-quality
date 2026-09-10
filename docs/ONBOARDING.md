# Agent onboarding and compatibility

AWQ v0.23 provides offline compatibility metadata, explicit agent recipes and
read-only migration previews. Native project gates remain required. A passing
preflight is not publisher authentication, migration approval or proof that a
third-party adapter is installed and usable.

## Start with a reviewed distribution

Choose one reviewed installation source before executing AWQ:

- Release assets: independently verify the signed manifest, exact annotated tag
  object and external trust policy using the [release procedure](RELEASES.md).
  Install the verified local wheel with `uv pip install --no-index --no-deps`.
- Source pin: review the full 40-hex source commit and its authenticated release
  identity first. Clone with `git -c core.autocrlf=false clone`, detach at that
  exact commit and use `uv sync --locked --python 3.12.14`. Setup may acquire
  pinned packages and Python; subsequent runtime checks are offline.
- Package index: no package-index publication channel is configured here.
  Do not replace a verified release with an unreviewed package-name lookup.

The source recipe assumes Git and pinned uv 0.12.8 are installed. The local wheel
recipe needs an explicitly selected Python environment; do not install into a
system interpreter by accident. Hash matching alone is not publisher trust.
Candidate code must not provision its own trust roots. See
[verified updates](PROVENANCE.md) for the external trust boundary.

The checked-in [GitHub recipe](../templates/github-workflow.yml) requires a full,
independently reviewed AWQ source commit. Its input validation rejects tags,
branches and abbreviated hashes before the AWQ checkout. Its action references
are immutable full commits. The recipe does not authenticate an arbitrary supplied
commit, initialize a consumer or remove native CI. Review it before copying it.

## Generated agent integration workflow

The packaged `agent_recipes.json` is the complete machine-readable adoption workflow. Its
`contracts` object binds the project-policy, terminology, native-mapping and release-manifest
schema versions used to generate the recipe. Its `awq_version` binds the release metadata. The
workflow is an ordered dependency graph, not an executor or authority grant:

1. `diagnostics` performs package and project inspection plus an initialization preview.
2. `adoption` makes the separately approved project-file mutation and checks the consumer-owned
   terminology registry.
3. `native-gates` is an intentionally empty, project-owned stage. The consumer runs its existing
   gates directly; AWQ neither knows nor wraps their argv.
4. `shared-ci` evaluates already recorded native/AWQ pairs, then runs the portable PR tier. It
   depends on native gates, so copying the recipe cannot reorder AWQ ahead of domain validation.
5. `review` exposes the policy diff and read-only migration preview.
6. `release` verifies the local bundle, authenticates the exact tag and source, previews the
   lock-only update, and mutates the lock only after separate approval.
7. `fresh-clone` repeats diagnostics and the PR tier in a newly created consumer checkout.

Every referenced recipe declares an `operation`, an observable `effect`, an approval class and a
fixed argument array. Diagnostics and previews are read-only. Initialization is the only
project-file mutation, and authenticated update is the only lock-file mutation. Native mapping
reads recorded digest-only v1 results or identity-bound v2 results; it does not execute the declared
native commands. Release
verification and authentication are read-only and do not publish a release.

Composition is exact: verify that the recipe starts with the declared three-element
`composition.canonical_prefix`, remove those three elements, and execute
`runtime.command_prefix + recipe.argv[3:]` as one argument array. A missing or different recipe
prefix is contract drift and must block; never concatenate either array into a shell string. The
wheel runtime invokes the selected interpreter directly, so normal runtime has no uv dependency.

The `offline-source` and `offline-wheel` runtime records are portable argument arrays, never shell
programs. Their setup commands explicitly forbid network access. The source path therefore
requires the exact locked environment to have been acquired into the local uv cache during a
separate reviewed setup step. The wheel path accepts only an already authenticated local wheel and
uses `--offline --no-index --no-deps`. Substitute placeholders as individual arguments. For either
runtime, create the consumer fresh clone separately with reviewed Git and then use that checkout as
`{consumer}`; the recipe does not perform cloning or carry credentials.

## Fresh Linux, macOS and Windows checkouts

The repository attributes keep text as LF even when Git enables automatic CRLF conversion.
Canonical JSON verification remains byte-exact; binary schema archives are never normalized.

The portable entry point is `python -m awq` under the selected environment. The
same argv works on all three operating systems; shell quoting is not shared.
Use the selected virtual environment interpreter, or `uv run --frozen python`
from a source installation. Do not assume an activated shell or a global `awq`.

```sh
python -m awq --root . onboarding --format json
python -m awq --root . inspect --format json
python -m awq --root . init --profiles core --dry-run --format json
```

After explicit project-owner approval, run the same init command without
`--dry-run`, review and track its three generated files, then run:

```sh
python -m awq --root . check --tier pr --format json
python -m awq --root . explain AWQ-CORE-001 --format json
```

`tools/awq` generated by init is a POSIX shell convenience, not a Windows launcher.
Windows users use `python -m awq`; the optional
[Python launcher recipe](../templates/awq-local.py) is also shell-independent.
The [agent-instruction template](../templates/AGENT_ONBOARDING.md) makes review,
coordination and native-gate retention explicit.

A dedicated CI matrix targets fresh core setup on Ubuntu 24.04, macOS 14 and
Windows 2022, each with Python 3.12.14 and 3.13.15. These are CI-targeted paths;
compatibility metadata is not a claim that a particular pending workflow already
passed. Consult the exact revision's hosted matrix results. The release workflow
additionally checks onboarding from the newly built Linux wheel. Full native
adapter suites remain Linux-specific and are not implied by the portable smoke.

## Diagnostics and exit codes

`onboarding` checks the installed distribution version, zero runtime dependencies,
required packaged schema/data presence and digests, normalized platform/architecture,
reviewed Python minor and Git availability. It never reports executable locations,
user names, host names, environment variables or metadata exception text. Its
reported asset digest identifies the read bytes but is not an external trust root.
It supports filesystem source installations and installed wheel assets.

| Finding | Required action |
| --- | --- |
| unsupported-platform | Use a reviewed Linux, macOS or Windows core environment and architecture. |
| unreviewed-python | Select the pinned 3.12 or 3.13 interpreter; do not infer support from successful import. |
| package-integrity-or-metadata | Reinstall the verified distribution; resolve version mismatch, missing assets or unexpected runtime dependencies. |
| git-unavailable | Install reviewed Git and expose it to the selected process. |
| native-environment-unreviewed | Use the reviewed Linux x86-64 native path or retain native gates pending platform qualification. |
| ssh-verifier-unavailable | Provision the reviewed offline SSH verifier before authenticated updates. |
| native-tools-not-probed | Install pinned tools separately and run their actual adapter verification; preflight does not probe them. |

`--capability core` is the default. `verified-update` and `reliability-collect`
receive conservative Linux x86-64 environment checks; a pass still does not prove
external trust, writable scratch or every later runtime precondition.
`pinned-adapters` always reports not-probed and fails this preflight, rather than
claiming unavailable tools are ready. macOS POSIX primitives alone are not native
adapter qualification. Core environments outside Python 3.12/3.13 fail conservatively;
`requires-python >=3.12` is an installation lower bound, not universal certification.

Stable CLI exit codes are 0 for passing/successful results, 1 for blocked, failed
or invalid runtime input, and argparse's 2 for invalid arguments. JSON success or
failure results go to stdout; argument usage/errors go to stderr. Consume both the
exit status and structured result. No top-level `--version` interface is promised:
`onboarding --format json` reports runtime version and installed-version agreement.

## Migrations

[Migration preview inputs](../templates/migration-preview.json) are canonical,
closed, bounded JSON with exact source/tag-object pins and policy/trust digests.
The checked-in values are synthetic examples, not authorized release identities.

```sh
python -m awq --root . migration-preview quality/migration.json --format json
```

The preview classifies upgrade, same-version or downgrade. It changes no bytes,
never executes candidate code, never authenticates its supplied hashes, and always
requires explicit review. Downgrades, unsupported historical/future version
families, unreviewed future targets, legacy policy schemas and policy changes
block. Supported input schemas are policy 3 and lock 1/2. Legacy conversions require
separate reviewed edits; there is no silent schema or policy migration.

A passing preview only directs the agent to the existing authenticated
`update --dry-run` recipe. That command needs the complete local manifest bundle
including its conventional detached signature sidecar, independently provisioned
trust policy, candidate source, exact tag ref and full tag-object pin. Review its
exact lock diff before explicitly approving the actual lock-only update. The
preview does not restrict the authenticated updater's independently validated
data-only support for future releases. Same-version preview is not replay approval.
Native gates and consumer policy remain untouched.

## Packaged contracts and maintenance

The machine interfaces are packaged `compatibility.json`, `agent_recipes.json` and
[onboarding.schema.json](../schemas/onboarding.schema.json). Recipes are fixed argv
arrays with explicit placeholders, operations, effects and approval classes; they are
instructions, not an executable plugin protocol. The workflow dependency graph retains
consumer-native CI and separates read-only operations from the two explicit mutation classes.
Substitute reviewed values as individual argv elements, never concatenate them into a shell
program. Tests parse every AWQ recipe against the real CLI, bind the declared schema versions,
reject contract drift and exercise positive/negative migration fixtures.

Run `python scripts/generate_onboarding.py --check` with the other generated gates.
When changing the release version or reviewed recipes, regenerate this metadata
and schema constants, review the diff and retain archive compatibility tests.
Wheel and sdist verification requires all three new assets from v0.23 onward;
historical bundles keep their original asset contract. Additional package-index
publishing and native-platform qualification are separate reviewed work.
