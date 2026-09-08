# Contributing

Use the coordinated process in `docs/DEVELOPMENT.md`. Changes need focused tests, hostile-path
coverage, deterministic generated outputs, a signed commit and a matching `Signed-off-by` trailer.

Run the complete local gate before publication:

```sh
uv sync --locked --only-group quality
uv run ruff format --check src tests scripts
uv run ruff check src tests scripts
uv run mypy src tests scripts
uv run coverage run --branch -m unittest discover -s tests -p 'test_*.py'
uv run coverage report --fail-under=95
uv run python scripts/generate_catalog.py --check
uv run python -m awq --root . doctor --format json
uv run python -m awq --root . check --tier pr --format json
```

Never reduce a floor, broaden an exception, suppress a finding, or regenerate expected output solely
to make a check pass. Explain intentional policy changes in the pull request.
