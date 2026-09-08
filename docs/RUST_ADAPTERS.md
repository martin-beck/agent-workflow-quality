# Rust adapter family

The built-in `rust` family provides five reviewed, opt-in Linux x86-64 contracts using Rust 1.93.0.
Installing or upgrading AWQ never activates them, installs a toolchain, fetches a crate, or changes
a consumer lockfile.

| Contract | Evidence | Pinned native operation |
| --- | --- | --- |
| `ADAPTER-RUST-BUILD` | mechanical | `cargo build --locked --offline --workspace --release` |
| `ADAPTER-RUST-CLIPPY` | mechanical | `cargo clippy --locked --offline --workspace --all-targets -- -D warnings` |
| `ADAPTER-RUST-DOC` | mechanical | `RUSTDOCFLAGS="-D warnings" cargo doc --locked --offline --workspace --no-deps` |
| `ADAPTER-RUST-FMT` | mechanical | `cargo fmt --all -- --check` |
| `ADAPTER-RUST-TEST` | contract-test | `cargo test --locked --offline --workspace` |

Each catalog command is `awq-rust-check MODE`. Its exact version probe is:

~~~text
awq-rust-check 1.0.0 (Rust 1.93.0; Cargo 1.93.0; rustfmt 1.8.0-stable; Clippy 0.1.93)
~~~

Formatting, lint, compilation, documentation, and tests remain separate evidence.

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
project-owned Cargo configuration declares reviewed offline/source behavior. The wrapper passes
`--locked --offline` to every dependency-resolving operation. Formatting does not resolve
dependencies and uses its exact native arguments without those flags.

## Direct, proxy-free runtime

The installer retains this layout:

~~~text
PREFIX/
  bin/awq-rust-check
  lib/awq_rust_helper.py
  runtime-cargo/
  rustup/toolchains/1.93.0-x86_64-unknown-linux-gnu/bin/
~~~

Runtime never executes `PREFIX/cargo/bin` rustup proxies. It validates regular executable `cargo`,
`rustc`, `rustdoc`, `rustfmt`, `cargo-fmt`, `cargo-clippy`, and `clippy-driver` files in the exact
toolchain directory. Formatting and Clippy call direct plugin binaries using Cargo's native
subcommand argv shape; `CARGO`, `RUSTC`, and `RUSTDOC` are pinned absolute paths. Independent
fixtures run corresponding direct `cargo fmt`, `cargo clippy`, build, doc, and test commands and
require their results to match the adapter.

`PREFIX/runtime-cargo` is the only runtime Cargo home. It must be canonical and may not contain
`bin`, global configuration, or credential files, including dangling symlinks. This prevents plugin
lookup or global configuration from reaching rustup, user toolchains, or credentials. The child
environment contains only exact paths, Cargo offline controls, fixed locale/color controls, and a
per-invocation temporary directory.

Each command gets a fresh external `CARGO_TARGET_DIR` and `TMPDIR`, so build output does not enter
the repository. A caller-supplied `TMPDIR` must be an existing canonical absolute directory; CI and
development should place it on the intended build volume. Otherwise the operating-system temporary
root is used.

Standard input is closed and tool output is discarded. Helper errors emit only:

~~~text
awq-rust-check: validation failed
~~~

AWQ returns stable findings without diagnostics, source excerpts, crate names, environment values,
credentials, or machine paths. The helper's 14-minute internal deadline fits inside the catalog's
15-minute deadline.

## Reviewed acquisition

The online installer supports Linux x86-64 and stages beside a new destination:

~~~sh
uv run python scripts/install_rust_tools.py --prefix /new/external/rust-tools
export PATH="/new/external/rust-tools/bin:$PATH"
~~~

It downloads only from `static.rust-lang.org` with same-host redirect checks and bounded streams:

- rustup-init 1.29.0 for `x86_64-unknown-linux-gnu`, SHA-256
  `4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10`;
- Rust 1.93.0 channel manifest, SHA-256
  `beb6ba4e41c84e9c11c80e6804a007497d0c8ba0810cd403fabc8f4a9c45b1f8`.

The digest-verified initializer installs the minimal release plus rustfmt and Clippy. Rustup verifies
component archives against manifest hashes. Before publication, the installer requires rustup's
recorded update hash to match the reviewed manifest digest prefix, creates the proxy-free runtime
Cargo home, copies the reviewed helper, and requires exact probes. A same-filesystem rename
atomically publishes verified staging. Existing paths, including dangling symlinks, fail before
acquisition. The installer is online; it is not an adapter runtime command.

## Dependency preparation

The installer intentionally does not fetch project dependencies. A separate reviewed setup step may
populate `PREFIX/runtime-cargo` with exact `Cargo.lock` dependencies using pinned direct Cargo and
controlled network policy. Do not add `bin`, global Cargo config, or credentials there. Public
caches or repository-owned vendoring are the default; private registries need a separate contract.

A missing cached package fails offline with content-minimized `adapter-failed` evidence. AWQ never
falls back to the network, updates `Cargo.lock`, or installs a missing component.

## Evidence and limitations

Fixtures cover exact probes, toolchain skew, missing/symlinked tools and configuration, hostile
runtime Cargo homes, formatting drift, Clippy warnings, compile and rustdoc errors, lock skew,
failing tests, uncached dependencies, deadlines, external scratch, privacy normalization, checksum
and redirect failures, manifest consumption, dangling destinations, and atomic publication.

Formatting establishes layout only. Clippy is one pinned implementation's opinion. A build covers
default features, release profile, host, and target only. Documentation does not prove factual
quality or external links. Tests cover selected cases. None proves runtime correctness, unsafe-code
soundness, cross-target portability, supply-chain trust, API compatibility, performance, or
complete behavior; later Rust assurance ARs remain visible.
