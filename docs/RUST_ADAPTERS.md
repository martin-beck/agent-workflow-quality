# Rust adapter family

The built-in `rust` family provides eight reviewed, opt-in Linux x86-64 contracts using Rust
1.93.0. Installing or upgrading AWQ never activates them, installs a toolchain, fetches a crate,
updates an advisory database, or changes a consumer lockfile.

| Contract | Evidence | Pinned native operation |
| --- | --- | --- |
| `ADAPTER-RUST-ADVISORY` | environmental | `cargo audit --no-fetch --no-yanked` against the bundled RustSec database |
| `ADAPTER-RUST-BUILD` | mechanical | `cargo build --locked --offline --workspace --release` |
| `ADAPTER-RUST-CLIPPY` | mechanical | `cargo clippy --locked --offline --workspace --all-targets -- -D warnings` |
| `ADAPTER-RUST-DOC` | mechanical | `RUSTDOCFLAGS="-D warnings" cargo doc --locked --offline --workspace --no-deps` |
| `ADAPTER-RUST-FMT` | mechanical | `cargo fmt --all -- --check` |
| `ADAPTER-RUST-POLICY` | environmental | `cargo deny --frozen check bans licenses sources` |
| `ADAPTER-RUST-SEMVER` | contract-test | default-feature rustdoc JSON comparison |
| `ADAPTER-RUST-TEST` | contract-test | `cargo test --locked --offline --workspace` |

Formatting, lint, compilation, documentation, dependency policy, advisory observation, public API
comparison, and tests remain separate evidence.

## Agent adoption

Inspect the immutable family, then copy only reviewed contract objects into `quality/awq.json`:

~~~sh
awq --root . adapter-catalog --family rust --format json
awq --root . policy-diff BASE HEAD --format json
~~~

Every contract uses explicit workspace selection; AWQ does not append source paths. The repository
must own exact regular, non-symlink `Cargo.toml`, `Cargo.lock`, `.cargo/config.toml`, and
`rust-toolchain.toml` files. The toolchain declaration is deliberately strict:

~~~toml
[toolchain]
channel = "1.93.0"
profile = "minimal"
components = ["clippy", "rustfmt"]
~~~

Additional keys, another component order, `stable`, or another version fail closed. The
project-owned Cargo configuration declares reviewed offline and source behavior. The wrappers pass
`--locked --offline` or `--frozen` to dependency-resolving operations.

Supply contracts additionally require the policy artifact named in their catalog entry:

| Contract | Repository-owned or immutable input |
| --- | --- |
| Advisory | `quality/rust-advisory-policy.json` and the digest-pinned database bundled by AWQ |
| Policy | `deny.toml` and `quality/rust-registry-snapshot.json` |
| Semver | `quality/rust-semver-baseline.json` and `quality/rust-semver-baseline.lock.json` |

These JSON artifacts must be canonical, bounded, exact regular files. Missing, stale, malformed,
symlinked, or digest-mismatched inputs fail closed.

## Direct, proxy-free runtime

The stable and supply installers retain separate prefixes:

~~~text
RUST_PREFIX/
  bin/awq-rust-check
  lib/awq_rust_helper.py
  runtime-cargo/
  rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/bin/

SUPPLY_PREFIX/
  advisory-db/
  bin/awq-rust-supply-check
  bin/cargo-audit
  bin/cargo-deny
  bin/cargo-semver-checks
  lib/awq_rust_supply_helper.py
  manifest.json
~~~

Runtime never executes Rustup proxies. Both wrappers validate exact regular executable files and
invoke absolute tool paths. Each command receives a fresh external home, cache, Cargo target, and
temporary directory. The runtime Cargo home is proxy-free and may not contain global configuration
or credential files. Standard input is closed and native output is discarded.

The supply wrapper's exact probe is:

~~~text
awq-rust-supply-check 1.0.0 (cargo-deny 0.20.2; cargo-audit 0.22.2; cargo-semver-checks 0.50.0; Rust 1.93.0; advisory-db bf25f6575a93a35f30796c65c0ed91bee7fa19fd)
~~~

Successful supply checks emit one canonical, size-bounded `awq-bindings-v1` record. AWQ retains
only its kind, reviewed identifier, and SHA-256 digest. It never retains native diagnostics, crate
names, source paths, environment values, credentials, or source excerpts. Malformed, oversized, or
noncanonical protocol output fails closed without being copied into evidence.

The helper's 14-minute internal deadline fits inside each catalog contract's 15-minute deadline.
A caller-supplied `TMPDIR` must be an existing canonical absolute directory; otherwise the
operating-system temporary root is used.

## Reviewed acquisition

Install both checksum-pinned bundles into new prefixes outside the repository:

~~~sh
uv run python scripts/install_rust_tools.py --prefix /new/external/rust-tools
uv run python scripts/install_rust_supply_tools.py   --prefix /new/external/rust-supply-tools   --rust-tools-prefix /new/external/rust-tools
export PATH="/new/external/rust-supply-tools/bin:/new/external/rust-tools/bin:$PATH"
~~~

The stable installer downloads Rustup 1.29.0 and the reviewed Rust 1.93.0 channel manifest only from
`static.rust-lang.org`. See its constants and tests for the exact archive digests.

The supply installer downloads only exact release archives, enforces same-host redirects, bounded
streams and members, verifies archive and extracted binary digests, and atomically publishes a
fully probed new prefix:

| Tool | Version | Archive SHA-256 |
| --- | --- | --- |
| cargo-deny | 0.20.2 | `9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f` |
| cargo-audit | 0.22.2 | `ab28a1bdb54db4d5d8ad5981cf1f959410370b3d28250dbd35f6a44248620e39` |
| cargo-semver-checks | 0.50.0 | `52a65dc88dc53fa8b57d6087954eb52cda149ca03bcfca78ce3fdecd23f893c4` |

It also bundles RustSec advisory database commit
`bf25f6575a93a35f30796c65c0ed91bee7fa19fd`, archive SHA-256
`ff54ebd7becdaa59efe2d54e516d8c1e10e7c2fb20c8d3241a20889c5000f3eb`, and deterministic tree
SHA-256 `5cbbfdbbee55950d0fd592e52bc883aba747dad9cb986832b90320d03ce2ac4a`.
That database expires at `2026-12-07T09:58:15Z`; a later AWQ release must replace it.

Both installers are online setup operations, not adapter runtime commands. Existing destinations,
dangling destinations, wrong platforms, unsafe archives, digest mismatches, tool skew, or partial
staging fail before publication.

## Repository policy and refresh workflow

A reviewed `deny.toml` should explicitly define duplicate, wildcard, license, registry, and Git
source policy. For example:

~~~toml
[bans]
multiple-versions = "deny"
wildcards = "deny"

[licenses]
confidence-threshold = 0.8
allow = ["MIT"]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
~~~

Create a time-bounded crates.io yank snapshot only after reviewing the exact lockfile:

~~~sh
uv run python scripts/snapshot_rust_registry.py   --output quality/rust-registry-snapshot.json   --valid-days 30
~~~

The setup command is online. It accepts only crates.io sparse-index package names from the exact
`Cargo.lock`, limits the package set and response sizes, records exact checksums and yank state,
rechecks that the lockfile did not change, and publishes atomically. Validity is limited to 90 days.
Private or alternate registries need a separate reviewed contract.

The advisory policy is a canonical object containing a sorted, unique list of explicitly reviewed
RustSec identifiers:

~~~json
{"ignored_advisories":[],"schema_version":1}
~~~

Ignored advisories remain visible policy. The runtime uses `--no-fetch`; it cannot refresh the
database or infer exploitability.

Generate a default-feature public API baseline from the release being superseded:

~~~sh
uv run python scripts/snapshot_rust_semver.py   --rust-tools-prefix /new/external/rust-tools   --package my-package   --crate-name my_crate   --baseline-id v1.2.3   --release-type minor
~~~

Run this online only if the separate dependency-cache preparation requires network access. Baseline
generation itself uses pinned Cargo with `--locked --offline`, creates rustdoc JSON in external
scratch, and publishes the baseline before its canonical descriptor. Commit and review both files.
The descriptor binds the baseline identifier, digest, selected package and crate, default-feature
policy, release type, Rust version, and host target.

## Dependency preparation

The installers intentionally do not fetch project dependencies. A separate reviewed setup step may
populate `RUST_PREFIX/runtime-cargo` with exact `Cargo.lock` dependencies using pinned direct
Cargo and controlled network policy. Do not add `bin`, global Cargo configuration, or credentials
there. Public caches or repository-owned vendoring are the default; private registries need a
separate contract.

A missing cached package fails offline with content-minimized `adapter-failed` evidence. AWQ never
falls back to the network, updates `Cargo.lock`, installs a missing component, fetches an advisory,
queries a registry, or acquires a baseline during adapter execution.

## Evidence and limitations

Fixtures cover exact probes, toolchain and binary skew, missing and symlinked tools or policy,
hostile Cargo homes, lock drift, denied licenses, duplicate versions, unapproved Git sources,
known advisories, registry snapshot expiry and yank observations, advisory database expiry and tree
integrity, public API breakage, deadlines, external scratch, privacy normalization, bounded
acquisition, and atomic publication. Independent fixtures require native command and adapter status
to agree. Network-disabled smoke verifies all three supply modes after setup.

Formatting establishes layout only. Clippy is one pinned implementation's opinion. A build covers
default features, release profile, host, and target only. Documentation does not prove factual
quality or external links. Tests cover selected cases. License policy is not legal advice. A RustSec
match does not prove exploitability, and an absent match does not cover unpublished advisories.
Registry metadata records only one bounded observation. Semver comparison covers one library's
public default-feature rustdoc API for one target; it does not establish private, behavioral,
feature-complete, or cross-target compatibility. None of these gates proves runtime correctness,
unsafe-code soundness, provenance, performance, or complete behavior.
