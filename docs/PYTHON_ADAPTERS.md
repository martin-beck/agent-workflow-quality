# Python adapter family

The built-in `python` catalog family provides six reviewed, opt-in contracts. It does not install
tools, modify project configuration, or activate itself in a consumer policy.

| Contract | Exact tool pin | Native command |
| --- | --- | --- |
| `ADAPTER-PYTHON-RUFF-FORMAT` | Ruff 0.16.5 | `ruff format --check --config pyproject.toml .` |
| `ADAPTER-PYTHON-RUFF-LINT` | Ruff 0.16.5 | `ruff check --config pyproject.toml .` |
| `ADAPTER-PYTHON-MYPY` | mypy 2.3.1 | `mypy --config-file pyproject.toml` |
| `ADAPTER-PYTHON-UNITTEST` | Python 3.12 | `python -m unittest discover -s tests -p test_*.py` |
| `ADAPTER-PYTHON-COVERAGE-01-RUN` | coverage.py 7.16.0 | `coverage run --branch -m unittest discover -s tests -p test_*.py` |
| `ADAPTER-PYTHON-COVERAGE-02-REPORT` | coverage.py 7.16.0 | `coverage report` |

The two coverage identifiers deliberately sort execution before reporting. Python is pinned to its
supported major and minor because patch releases remain compatible; every third-party quality tool
uses an exact reviewed release and exact probe output.

## Agent adoption

Inspect the machine-readable catalog from the installed AWQ release:

```sh
awq --root . adapter-catalog --family python --format json
```

An agent must review the returned assumptions and commands against the target repository, then copy
only the accepted contract objects into the `adapters` array in `quality/awq.json`. Run
`awq policy-diff BASE HEAD --format json` during review. Merely installing or upgrading AWQ never
enables these commands.

Install the exact tools through the consumer's reviewed development lock before execution. For an
AWQ-style uv project this is:

```sh
uv add --dev ruff==0.16.5 mypy==2.3.1 coverage==7.16.0
uv sync --frozen
```

The installation step is intentionally separate and may require network access. The exact probes
assume official Ruff wheels, compiled mypy wheels, and coverage wheels with the C extension; a
source-only or otherwise different build fails closed even when its package version matches. Once
AWQ and the locked tools are installed, catalog inspection and adapter execution are offline.

## Project-owned configuration

Every contract requires `pyproject.toml`. The repository remains authoritative for selected Ruff
rules, mypy scope and strictness, and coverage sources and thresholds. A representative baseline is:

```toml
[tool.ruff]
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "I"]

[tool.mypy]
python_version = "3.12"
strict = true
files = ["src", "tests"]

[tool.coverage.run]
branch = true
source = ["src"]

[tool.coverage.report]
fail_under = 95
show_missing = true
```

The unittest contracts assume tests are discoverable below `tests` as `test_*.py`. Projects using
pytest, a different layout, generated sources, namespace packages, or multiple Python versions must
author and review repository-specific contracts rather than misrepresenting catalog applicability.

## Verification and limitations

Executable fixtures prove native-command equivalence for conforming and failing projects under the
pinned tools. Separate cases cover absent configuration, unavailable executables, exact-version
skew, failure classification, remediation, and catalog schema integrity. Contract argv is audited to
contain no installer, resolver, updater, download command, or URL.

These adapters are deterministic mechanical and contract-test evidence, not proof of correctness,
test completeness, security, or multi-platform compatibility. The runner discards command output
and source excerpts; remediation directs developers to rerun the native command when detail is
needed. Coverage report requires data produced by the matching coverage-run contract.
