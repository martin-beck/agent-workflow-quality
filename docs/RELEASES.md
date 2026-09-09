# Reproducible releases

AWQ release recipe `awq-release-v1` produces a wheel, source archive, SPDX 3.0.1 SBOM, and canonical
release manifest and non-circular in-toto provenance. An external operator signs the final manifest.
It is intentionally narrow:

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
  --uv "$(command -v uv)" \
  --trust-policy-sha256 REVIEWED_CANONICAL_POLICY_SHA256
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
  /new/external/awq-release/agent_workflow_quality-0.17.0.release.json \
  --source \
  --format json
```

Omit `--source` to verify a downloaded local bundle without a checkout. Verification rejects
unknown or noncanonical manifest fields, undeclared bundle files, digest/size/version skew, unsafe or
duplicate archive paths, links, development metadata, bounds violations, noncanonical timestamps,
permissions or ownership, and credential or machine-path signatures.

Schema-version-2 manifests bind the mandatory SPDX SBOM and its inventory/schema digests.
See [the SBOM profile](SBOM.md) for exact coverage, origins, license review and limitations.
Version 3 adds a separate provenance identity and a manifest-bound trust-policy digest.
See [signed provenance and updates](PROVENANCE.md) for the exact non-circular construction.

## Trust boundary

A matching SHA-256 proves byte identity, not publisher authenticity. Structural release-verify
reports authentication not-checked. Use release-authenticate or update with independently provisioned
external trust, the local signed manifest and bundle, exact source and independently reviewed
annotated tag-object pin. See [the trust and rotation procedure](PROVENANCE.md).
Clone-local allowed_signers is not a bootstrap authority. Optional GitHub attestations describe only
the exact hosted build outputs; offline verification does not claim to validate those online records.
