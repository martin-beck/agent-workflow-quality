# Requirement catalogue

This file is generated from the registry consumed by AWQ. Do not edit it directly.

Registry SHA-256: `a8780bc8ee4f0c6e30bade722c3a75142e8971fe42b67eaa7f7f034d05e6cd11`

## Profiles

| Profile | Purpose | Requirements |
| --- | --- | --- |
| `android-jvm` | Gradle and Android dependency-integrity baseline. | 1 |
| `core` | Portable repository baseline. | 4 |
| `docs` | Documentation structure and local integrity. | 1 |
| `formal-evidence` | Truthful bounded formal-evidence claims. | 1 |
| `github-actions` | GitHub Actions integrity and permissions. | 3 |
| `privacy` | Content-minimized public repository baseline. | 1 |
| `python` | Python source baseline. | 1 |
| `rust` | Rust dependency-integrity baseline. | 1 |
| `schemas` | Machine-readable JSON baseline. | 1 |
| `shell` | Shell entry-point baseline. | 1 |
| `supply-chain` | Pinned AWQ policy supply chain. | 1 |

## Requirements

### AWQ-CORE-001: Portable text

Tracked text uses UTF-8, LF and a final newline.

- Profiles: `core`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Does not assess prose meaning.
- Remediation: Normalize encoding and line endings.
- Exception policy: No exceptions for first-party text.
- Standards: NIST-SSDF-PO.3

### AWQ-CORE-002: Repository path integrity

Tracked paths are case-unique and symlinks remain inside the repository.

- Profiles: `core`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Assumes the inspected Git index is authoritative.
- Remediation: Repair collisions, broken links or escaping links.
- Exception policy: No exceptions.
- Standards: NIST-SSDF-PS.1

### AWQ-CORE-003: Merge-marker rejection

Tracked text contains no unresolved merge markers.

- Profiles: `core`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Marker-like fixture files require an explicit fixture scope.
- Remediation: Resolve the merge and retain the intended content.
- Exception policy: Fixture paths may be narrowly excluded.
- Standards: NIST-SSDF-PS.1

### AWQ-CORE-004: Classified formats

Every tracked file format is classified or explicitly declared.

- Profiles: `core`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Classification does not validate domain semantics.
- Remediation: Enable a profile or declare the format with a local gate.
- Exception policy: Declarations require a remediation owner.
- Standards: NIST-SSDF-PO.1

### AWQ-DOC-001: Local documentation links

Relative Markdown links resolve inside the repository.

- Profiles: `docs`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: External availability is a scheduled network check.
- Remediation: Repair the path or anchor target.
- Exception policy: Generated external URLs may be scoped separately.
- Standards: NIST-SSDF-PO.3

### AWQ-FORMAL-001: Truthful formal evidence

Formal-method documentation classifies bounds, assumptions and non-claims.

- Profiles: `formal-evidence`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Text presence does not prove the model ran or refined implementation.
- Remediation: Document evidence class, finite bounds, assumptions and limitations.
- Exception policy: No unclassified proof claims.
- Standards: NIST-SSDF-PW.7

### AWQ-GHA-001: Immutable Actions

GitHub Actions references use complete commit SHAs.

- Profiles: `github-actions`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: A pinned action can still contain vulnerable code.
- Remediation: Pin the reviewed action revision to its full SHA.
- Exception policy: Local actions are exempt; remote mutable refs are not.
- Standards: SLSA-BUILD

### AWQ-GHA-002: Workflow permissions

Each workflow declares explicit least-privilege permissions and job deadlines.

- Profiles: `github-actions`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Static inspection cannot prove hosted repository settings.
- Remediation: Add explicit permissions and timeout-minutes.
- Exception policy: No silent omission.
- Standards: NIST-SSDF-PS.1

### AWQ-GHA-003: Valid workflow-local paths

Paths referenced by GitHub workflow commands exist inside the repository.

- Profiles: `github-actions`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Static token recognition does not interpret dynamically constructed paths.
- Remediation: Correct the reference or add the required tracked file.
- Exception policy: Dynamic references require a narrow project-local gate.
- Standards: NIST-SSDF-PW.7

### AWQ-JVM-001: Verified Gradle dependencies

Gradle projects commit dependency verification metadata.

- Profiles: `android-jvm`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Metadata does not prove dependency behavior is safe.
- Remediation: Review artifacts and regenerate strict SHA-256 verification metadata.
- Exception policy: No unverified release dependency.
- Standards: SLSA-BUILD

### AWQ-PRIV-001: Credential and private-path exclusion

Tracked text excludes credential signatures and machine-private absolute paths.

- Profiles: `privacy`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Pattern scanning cannot prove absence of all sensitive data.
- Remediation: Remove the value, rotate credentials when needed and use synthetic fixtures.
- Exception policy: Synthetic canaries must be isolated under declared fixture paths.
- Standards: NIST-SSDF-PS.3

### AWQ-PY-001: Python syntax

First-party Python files compile under the running supported interpreter.

- Profiles: `python`
- Tier: `pr`
- Evidence: `contract-test`
- Deterministic: `true`
- Network: `false`
- Limitation: Compilation is not typing, lint or runtime behavior evidence.
- Remediation: Repair syntax and rerun project-specific Python gates.
- Exception policy: No exceptions for first-party Python.
- Standards: NIST-SSDF-PW.7

### AWQ-RUST-001: Locked Rust workspace

A Rust project commits Cargo.lock.

- Profiles: `rust`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: A lockfile does not audit advisories or licenses.
- Remediation: Generate, review and commit Cargo.lock.
- Exception policy: Library-only exceptions require an explicit project decision.
- Standards: SLSA-BUILD

### AWQ-SCHEMA-001: Parseable JSON

Every tracked JSON document parses without duplicate structural ambiguity.

- Profiles: `schemas`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Parsing does not establish schema conformance.
- Remediation: Repair JSON and run its owning schema validator.
- Exception policy: No exceptions.
- Standards: NIST-SSDF-PW.7

### AWQ-SHELL-001: Shell entry points

Executable shell files have a shell shebang.

- Profiles: `shell`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: Does not replace ShellCheck, shfmt or Bats.
- Remediation: Add the correct shebang and executable mode or remove executable mode.
- Exception policy: No exceptions for first-party executable shell.
- Standards: NIST-SSDF-PW.7

### AWQ-SUPPLY-001: Pinned quality bundle

The project lock binds profiles and requirements to an immutable registry digest.

- Profiles: `supply-chain`
- Tier: `pr`
- Evidence: `mechanical`
- Deterministic: `true`
- Network: `false`
- Limitation: The digest does not establish upstream trust by itself.
- Remediation: Run an explicit reviewed AWQ update from the intended release.
- Exception policy: No floating bundle references.
- Standards: SLSA-PROVENANCE-V1
