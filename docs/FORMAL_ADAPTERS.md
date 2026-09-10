# Bounded formal-model adapter

The `formal-model` family provides one opt-in, offline TLC contract:
`ADAPTER-FORMAL-MODEL-TLC`. It is evidence collection for a reviewed TLA+ model. It does not prove
that production code implements or refines the model.

## Reviewed contract

Setup installs the `tlc` launcher separately with:

~~~sh
uv run python scripts/install_formal_tools.py --prefix /new/external/formal-tools
~~~

The installer downloads only the fixed TLA+ Tools `1.8.0` release asset, limits it to 10 MB,
requires SHA-256
`8836549e83db7f0b3f9fdde679ab56270d18e06198366d217d960738c02b9dbe`, stages the JAR and
digest-checking launcher, probes it, and atomically publishes a new prefix. Runtime never downloads
Java, the launcher, or TLA+ Tools. The launcher requires a separately provisioned `java` on
`PATH` and returns exactly `TLC 1.8.0` for `tlc --version`.

The catalog command is fixed:

~~~text
tlc -workers 1 -depth 1000 -config formal/Model.cfg formal/Model.tla
~~~

`schemas/formal-adapter-contract.schema.json` and zero-dependency runtime validation require:

- the stable adapter and tool identifiers;
- direct execution without a shell, response file, placeholder, or constructed argument;
- 1 through 16 workers and a depth from 1 through 1,000,000;
- exactly one confined `.cfg` path followed by one confined `.tla` path;
- a finite deadline and `bounded-model` evidence classification.

The checked-in configuration remains responsible for finite constants and named invariants. Review
those bounds together with the command bounds; the adapter cannot infer missing state-space limits
from model text.

## Normalized evidence

AWQ uses the shared minimal environment, closes standard input, discards standard error, kills the
model-checker process group at the deadline, and caps standard output at 4096 bytes. Output is held
only while classifying the terminal result and is never placed in evidence.

A successful TLC terminal marker with exit zero produces `pass`. A recognized invariant violation
produces `adapter-model-failed`. Missing tools, version skew, missing model/configuration, timeout,
oversized output, and malformed terminal output retain their distinct shared adapter codes.

The result repeats the reviewed evidence class and limitation. It contains no state trace, invariant
name, source excerpt, command output, host path, or environment value. Rerun the exact native command
outside AWQ when private diagnostic output is needed.

## Independent native equivalence

Contract fixtures invoke the catalog argv directly and classify its process result independently
from `run_adapter`. Both successful exhaustion and a failing invariant must agree. Additional
hostile fixtures cover unavailable tools, exact-version skew, unsupported model suffixes and dynamic
bounds, missing inputs, process-tree timeout, malformed output, and output redaction.
