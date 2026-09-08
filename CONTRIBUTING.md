# Contributing

Use the coordinated process in `docs/DEVELOPMENT.md`. Changes need focused tests, hostile-path
coverage, deterministic generated outputs, a signed commit and a matching `Signed-off-by` trailer.

Run the complete local gate before publication:

```sh
uv sync --locked --only-group quality
uv run python scripts/check_source_headers.py
uv run ruff format --check src tests scripts
uv run ruff check src tests scripts
uv run mypy src tests scripts
uv run coverage run --branch -m unittest discover -s tests -p 'test_*.py'
uv run coverage report --fail-under=95
uv run python scripts/generate_catalog.py --check
uv run python -m awq --root . doctor --format json
uv run python -m awq --root . check --tier pr --format json
uv build
uv run python scripts/verify_distribution.py dist/*
```

The source-header gate checks every tracked Python and shell source, including the extensionless
`tools/awq` launcher, except content below the explicit `fixtures/`, `generated/`, and `vendor/`
roots. Those roots contain hostile fixtures,
derived content, or externally owned source and must not be rewritten to satisfy first-party policy.
For every selected source, the exact
`Copyright (C) Huawei Technologies Co., Ltd. 2026. All rights reserved.` line must immediately
precede `SPDX-License-Identifier: MIT`; both lines must be unique. Only an interpreter shebang may
precede the header.

Never reduce a floor, broaden an exception, suppress a finding, or regenerate expected output solely
to make a check pass. Explain intentional policy changes in the pull request.
