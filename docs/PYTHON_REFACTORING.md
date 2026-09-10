# Bounded Python refactoring observations

AWQ 0.20 supports the first language-specific collector: python-integer-function-v1, using exact
CPython 3.12.14 on Linux x86-64. It executes reviewed finite cases, not arbitrary Python packages.
Other Python versions, languages and platforms fail closed. Native consumer gates remain retained.

## Offline setup and commands

Install AWQ from a verified local wheel without dependencies or network. Independently provision
CPython 3.12.14 and review its executable SHA-256, standard library and host provenance before setup.
The installer never downloads an interpreter, resolves packages or contacts a service.

~~~sh
python scripts/install_refactor_tools.py \
  --prefix /new/external/refactor-tools \
  --python /reviewed/cpython/bin/python3.12 \
  --python-sha256 REVIEWED_EXECUTABLE_SHA256
awq --root . refactor-collect quality/python-refactor.json \
  --tools /reviewed/refactor-tools --format json
awq-refactor-check --version
awq-refactor-check collect
~~~

Paths above are placeholders, not automatically discovered trust roots. The installer copies the
installed AWQ Python/data bundle into an absent external prefix, verifies every declared file,
the interpreter digest and exact native version, then publishes with Linux atomic no-replace rename.
Existing or dangling-symlink prefixes fail. Runtime repeats integrity and version checks; no runtime
dependency is added to AWQ. The externally provisioned interpreter and standard library remain a
reviewed trust assumption, not a complete independently verified Python distribution SBOM.

The installed adapter has exact version 1.0.0 and the catalog identifier
ADAPTER-PYTHON-REFACTORING-COLLECT. Its fixed configuration is quality/python-refactor.json.
The direct CLI accepts a confined repository-relative policy plus an explicit local tools prefix.
Use [the schema](../schemas/python-refactor.schema.json) and
[template](../templates/python-refactor.json); source paths are interpreted beneath the selected root.
The template's commitments and cases are synthetic. Copy the
[controlled fixture](../fixtures/conforming/refactoring/quality/python-refactor.json) with its
sibling Python files only as a learning/test example, not evidence about a consumer.

## Supported source and execution boundary

Each UTF-8 source is at most 4,096 bytes and contains exactly one function: transform(x), with one
return expression. No annotations, decorators, imports, calls, attributes, assignments, loops,
comprehensions, containers, exponentiation, extra names or statements are accepted. Expressions
permit bounded integer constants, x, addition/subtraction/multiplication, integer floor division/
modulo, unary operators, comparisons, Boolean operators and conditional expressions.
There are at most 128 AST nodes; constants have absolute value at most 10,000.
All returned values must be integers, not Booleans, with absolute value at most 1,000,000.

Exact source bytes are digest-checked and validated before subprocess execution. The standalone
worker validates the AST again and uses CPython compilation/evaluation with no builtins.
The fixed native argv is the verified absolute interpreter, -I, -S, -B and the verified worker path;
only canonical bounded source/case data enters stdin. Environment is limited to locale and a
nonexistent home; cwd is the filesystem root. No candidate source filename enters tracebacks.
Diagnostics are discarded. Captured numeric observations remain private and are never printed.

Every subprocess has a three-second wall deadline, two CPU seconds, 256 MiB address-space bound,
zero regular-file output allowance and 32 open descriptors. Timeout terminates its process group.
The interpreter probe plus two source runs and at most eight mutant runs are finite; the shared
adapter adds a 45-second outer deadline. The worker emits at most 41 bounded integers, with an
8,192-byte checked response ceiling. This is a restricted expression executor, not a general
hostile-code sandbox or proof about the host, provisioned standard library or filesystem races.

## Four evidence methods

The canonical policy requires three through 41 sorted unique inputs, each in -100 through 100.
The domain must contain zero and every input's negation. Expected outputs are reviewed integers.
Before and after source commitments must differ; formatting changes alone cannot establish success.
One through eight explicit, source-distinct mutants are required. Duplicate paths or mutant digests
fail. Runtime source errors, invalid outputs, timeouts and malformed tools fail the whole collection;
they never count as a successfully killed mutant.

| Method | Finite check |
| --- | --- |
| characterization | Before and after outputs equal every reviewed expected value |
| differential | Every before output equals its paired after output |
| property | Both outputs are nondecreasing, odd on mirrored inputs, and zero-preserving |
| mutation | Every explicit mutant differs from the reviewed expected vector |

Every record retains before/after mismatch counts. Characterization, differential and mutation
records count reviewed example failures; property records count the three fixed relations, the minimum case count makes counts compatible
with the shared evidence bound. No random generation, inferred test discovery, tolerance, automatic
mutation synthesis or equivalent-mutant exclusion is hidden in this profile.
The fixed properties intentionally limit which functions fit this first profile.

The result contains AR-0006-shaped method records, source/case/result/tool commitments and counts.
A normalized plan commitment binds cases, properties, ordered source/mutant identities and review;
tool commitments bind that plan and the verified installation, without including host paths.
The installed catalog adapter emits only a canonical refactor-evidence digest binding, never logs,
source excerpts, numeric outputs, prompts, credentials, names, owners or machine paths.

## Independent tests and limitations

Tests compare actual wrapper observations to a separate native CPython command that compiles the
complete trusted fixture function directly, without importing or invoking the worker.
Positive, behavior-mismatch, property-failure, surviving-mutant and arithmetic-error fixtures are
checked independently. Hostile tests cover AST escape attempts, malformed canonical JSON, unknown
fields, stale hashes, unsafe/symlink paths, unsupported tools/platforms, resource/protocol errors and
atomic installer failure.

Collection is bounded-native-observation, distinct from the
[declaration-only assurance evaluator](FORMAL_ASSURANCE.md). A separately copied AR-0006 record still
does not authenticate its producer or reviewer. Reviews, expected values, normalization choices and
mutation selection remain human-governed assumptions. Hashes do not establish truth or privacy.

Finite agreement is not universal behavior preservation, a refinement theorem, unbounded safety,
complete mutation coverage, package/API compatibility, concurrency or I/O correctness.
General Python suites and other languages need later reviewed profiles and independent native
equivalence. Existing native gates are never removed or weakened.
