# Reproducible releases

AWQ release recipe `awq-release-v1` produces a wheel, source archive, and canonical release
manifest. It is intentionally narrow:

- Linux x86-64
- CPython 3.13.15
- uv 0.12.8
- Hatchling 1.27.0 and the complete hash-pinned closure in
  `config/release-build-constraints.txt`

The builder rejects a dirty tracked source tree, records the exact commit, tree, commit epoch,
registry digests, build-input digest, and artifact identities, and creates two independent tracked
Git snapshots. Each snapshot has its own build and temporary directory. Untracked files are not
copied. Both outputs must be byte-identical; the builder does not rewrite an unexplained difference.

## Prepare and build

Dependency acquisition is a separate online setup step. Populate an external uv cache using the
reviewed constraints before entering the offline build:

```sh
export UV_CACHE_DIR=/new/external/uv-cache
uv python install 3.13.15
uv venv /new/external/release-inputs --python 3.13.15
uv pip install \
  --python /new/external/release-inputs/bin/python \
  --require-hashes \
  -r config/release-build-constraints.txt
```

From the clean signed candidate commit, use new directories outside the source tree:

```sh
release_python="$(uv python find 3.13.15)"
PYTHONPATH=src "$release_python" scripts/build_release.py \
  --source "$PWD" \
  --output /new/external/awq-release \
  --scratch /new/external/scratch \
  --uv-cache "$UV_CACHE_DIR" \
  --uv "$(command -v uv)"
```

The build subprocess receives a minimal environment, no credentials or proxy variables, exact
argument arrays, no uv configuration discovery, hash-required build constraints, offline/no-download
flags, and a finite process-tree deadline. The prepopulated cache is transport storage rather than an
unconstrained input: selected build distributions must match the committed hashes. For defense in
depth, release operators should additionally run the build in an OS network namespace or equivalent
sandbox; the Python process cannot itself remove host network capability.

## Verify

Verification has no runtime dependency and performs no network access:

```sh
uv run awq --root . release-verify \
  /new/external/awq-release/agent_workflow_quality-0.13.0.release.json \
  --source \
  --format json
```

Omit `--source` to verify a downloaded local bundle without a checkout. Verification rejects
unknown or noncanonical manifest fields, undeclared bundle files, digest/size/version skew, unsafe or
duplicate archive paths, links, development metadata, bounds violations, noncanonical timestamps,
permissions or ownership, and credential or machine-path signatures.

The manifest reserves unique artifact kinds for SPDX SBOMs, in-toto provenance, and signatures so
later releases can extend the same bundle without weakening reject-unknown semantics. AR-0024 and
AR-0025 supply those artifacts.

## Trust boundary

A matching SHA-256 proves local byte identity against the manifest; it does not authenticate who
published the manifest. Until signed provenance and trust-root verification land in AR-0025, obtain
the manifest from the public GitHub release associated with the signed tag and verify that tag using
the repository's reviewed SSH allowed-signers file. Never treat an unsigned manifest alone as
publisher authenticity, SLSA provenance, certification, or proof that the build host was uncompromised.
