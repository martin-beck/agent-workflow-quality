# Contributing

Use the coordinated process in `docs/DEVELOPMENT.md`. Changes need focused tests, hostile-path
coverage, deterministic generated outputs, a signed commit and a matching `Signed-off-by` trailer.

Install the checksum-pinned shell, documentation, schema, and Rust tools into new prefixes
outside the repository and prepend their `bin` directories to `PATH`. Acquisition is online; the
gates themselves are offline. Rust contracts currently support Linux x86-64 and require any
third-party dependency cache to be populated by a separate reviewed step. Rust supply contracts also
require reviewed repository policy, time-bounded registry metadata, the release-bundled RustSec
snapshot, and a digest-bound semver baseline as documented in `docs/RUST_ADAPTERS.md`. Snapshot
generation is a separate setup operation and must never be moved into an adapter runtime.

```sh
uv run python scripts/install_shell_tools.py --prefix /new/external/shell-tools
uv run python scripts/install_documentation_tools.py --prefix /new/external/doc-tools
uv run python scripts/install_schema_tools.py --prefix /new/external/schema-tools
uv run python scripts/install_rust_tools.py --prefix /new/external/rust-tools
uv run python scripts/install_rust_supply_tools.py \
  --prefix /new/external/rust-supply-tools \
  --rust-tools-prefix /new/external/rust-tools
```

Run the complete local gate before publication:

```sh
uv sync --locked --group quality
uv run python scripts/check_source_headers.py
uv run ruff format --check src tests scripts
uv run ruff check src tests scripts
uv run mypy src tests scripts
uv run coverage run --branch -m unittest discover -s tests -p 'test_*.py'
uv run coverage report --fail-under=95
uv run python scripts/generate_catalog.py --check
uv run python scripts/generate_sbom_fixture.py --check
uv run python scripts/generate_provenance_fixture.py --check
uv run python scripts/check_assurance_models.py
uv run python scripts/validate_contracts.py
uv run python -m awq --root . doctor --format json
uv run python -m awq --root . check --tier pr --format json
release_python="$(uv python find 3.13.15)"
PYTHONPATH=src "$release_python" scripts/build_release.py \
  --source "$PWD" \
  --output /new/external/awq-release \
  --scratch /new/external/scratch \
  --uv-cache /new/external/uv-cache \
  --uv "$(command -v uv)"
uv run awq --root . release-verify \
  /new/external/awq-release/agent_workflow_quality-0.17.0.release.json \
  --source --format json
```

The source-header gate checks every tracked Python and shell source, including the extensionless
`tools/awq` launcher, except content below the explicit `fixtures/`, `generated/`, and `vendor/`
roots. Those roots contain hostile fixtures,
derived content, or externally owned source and must not be rewritten to satisfy first-party policy.
For every selected source, the exact
`Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.` line must immediately
precede `SPDX-License-Identifier: MIT`. The canonical adjacent pair must be unique, while standalone
SPDX text elsewhere in source content or test data is not treated as a second header. Only an
interpreter shebang may precede the header.

Never reduce a floor, broaden an exception, suppress a finding, or regenerate expected output solely
to make a check pass. Explain intentional policy changes in the pull request.
