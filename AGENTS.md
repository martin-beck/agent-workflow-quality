# Contributor instructions

Read `docs/DEVELOPMENT.md`, `docs/ARCHITECTURE.md`, `docs/QUALITY.md`, the active coordination
task and its plan before changing this project. Development is coordinated in
`martin-beck/agent-workflow-quality-state` with Agent Workflow Coordinator.

Preserve the zero-runtime-dependency and offline-after-install boundaries. Requirements and profiles
are public contracts: use stable identifiers, reject unknown fields, update generated documentation,
and add positive plus negative tests for every behavioral change. Commands execute argument arrays
without a shell, remain bounded, and never retain subprocess output in evidence.

Do not add telemetry, floating versions, runtime downloads, executable plugins, credentials, private
paths, host data, prompts, transcripts, or unbounded evidence. Commits must be SSH-signed and carry a
matching DCO Signed-off-by trailer. Publish changes through reviewed pull requests.
