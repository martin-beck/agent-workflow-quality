# Standards traceability

This file is generated from version-pinned control sources and reviewed mappings.
Mappings express alignment only. They do not assert certification, compliance, or a
framework maturity level.

Standards registry SHA-256: `5ce6475e6f2bda4b3c4d32745076976ca15defe823e63a331933c7781f7dff40`

## Pinned sources

| Source | Edition | Scope | Limitation |
| --- | --- | --- | --- |
| [COMMONMARK](https://spec.commonmark.org/0.31.2/) | `0.31.2` | Link destination syntax relevant to local documentation checks. | AWQ does not claim full CommonMark conformance. |
| [IETF-RFC8259](https://www.rfc-editor.org/info/rfc8259) | `RFC-8259-STD-90` | JSON parser acceptance requirements. | AWQ parsing does not validate an application-specific schema. |
| [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) | `SP-800-218-v1.1` | Selected practices and tasks used by AWQ mappings. | The catalogue is not a complete reproduction of SP 800-218. |
| [OPENSSF-OSPS](https://baseline.openssf.org/versions/2026-08-28) | `v2026.08.28` | Selected controls directly supported or related to AWQ requirements. | Mappings do not assert OSPS Baseline compliance or maturity. |
| [POSIX-SHELL](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html) | `POSIX.1-2024-Issue-8` | Shell input and command-language execution. | POSIX specifies hash-bang input as unspecified; AWQ shebang policy is a portability convention, not POSIX conformance. |
| [PYTHON-REFERENCE](https://docs.python.org/3.12/reference/) | `3.12.14` | Python 3.12 grammar used by the syntax requirement. | Compilation under one interpreter does not establish semantic conformance across implementations. |
| [SLSA](https://slsa.dev/spec/v1.2/) | `v1.2` | Selected Build track producer and provenance requirements. | AWQ mappings do not assert a SLSA level. |
| [SPDX](https://spdx.github.io/spdx-spec/v3.0.1/) | `3.0.1` | Core version-identification property relevant to machine-readable releases. | AWQ policy locks are not SPDX documents or software bills of materials. |

## Profile matrices

### `android-jvm`

| Requirement | Source control | Relationship | Evidence | Limitation |
| --- | --- | --- | --- | --- |
| [AWQ-JVM-001](REQUIREMENTS.md) | [OPENSSF-OSPS OSPS-QA-02.01](https://baseline.openssf.org/versions/2026-08-28#osps-qa-0201) | `supports` | `mechanical` | Verification metadata does not prove dependency behavior is safe or the list is complete. |

### `core`

| Requirement | Source control | Relationship | Evidence | Limitation |
| --- | --- | --- | --- | --- |
| [AWQ-CORE-001](REQUIREMENTS.md) | [NIST-SSDF PO.3.1](https://doi.org/10.6028/NIST.SP.800-218) | `related` | `mechanical` | Text normalization alone does not secure a development toolchain. |
| [AWQ-CORE-002](REQUIREMENTS.md) | [NIST-SSDF PS.1.1](https://doi.org/10.6028/NIST.SP.800-218) | `supports` | `mechanical` | It does not establish repository authorization or access controls. |
| [AWQ-CORE-003](REQUIREMENTS.md) | [NIST-SSDF PW.7.2](https://doi.org/10.6028/NIST.SP.800-218) | `related` | `mechanical` | It does not identify security vulnerabilities generally. |
| [AWQ-CORE-004](REQUIREMENTS.md) | [NIST-SSDF PO.1.1](https://doi.org/10.6028/NIST.SP.800-218) | `supports` | `mechanical` | Classification does not define all security requirements. |

### `docs`

| Requirement | Source control | Relationship | Evidence | Limitation |
| --- | --- | --- | --- | --- |
| [AWQ-DOC-001](REQUIREMENTS.md) | [COMMONMARK section-6.3](https://spec.commonmark.org/0.31.2/#links) | `supports` | `mechanical` | It does not establish complete CommonMark parsing or external URL availability. |

### `formal-evidence`

| Requirement | Source control | Relationship | Evidence | Limitation |
| --- | --- | --- | --- | --- |
| [AWQ-FORMAL-001](REQUIREMENTS.md) | [NIST-SSDF PW.7.2](https://doi.org/10.6028/NIST.SP.800-218) | `supports` | `mechanical` | Documentation checks do not execute a model or prove implementation refinement. |

### `github-actions`

| Requirement | Source control | Relationship | Evidence | Limitation |
| --- | --- | --- | --- | --- |
| [AWQ-GHA-001](REQUIREMENTS.md) | [SLSA build.producer.consistent-process](https://slsa.dev/spec/v1.2/build-requirements#follow-a-consistent-build-process) | `supports` | `mechanical` | Pinning actions does not establish a SLSA build level or trusted builder. |
| [AWQ-GHA-002](REQUIREMENTS.md) | [OPENSSF-OSPS OSPS-AC-04.02](https://baseline.openssf.org/versions/2026-08-28#osps-ac-0402) | `aligned` | `mechanical` | Static workflow inspection cannot verify repository-level defaults or runtime grants. |
| [AWQ-GHA-003](REQUIREMENTS.md) | [NIST-SSDF PW.7.2](https://doi.org/10.6028/NIST.SP.800-218) | `related` | `mechanical` | It does not review dynamically constructed paths or workflow behavior. |

### `privacy`

| Requirement | Source control | Relationship | Evidence | Limitation |
| --- | --- | --- | --- | --- |
| [AWQ-PRIV-001](REQUIREMENTS.md) | [OPENSSF-OSPS OSPS-BR-07.01](https://baseline.openssf.org/versions/2026-08-28#osps-br-0701) | `supports` | `mechanical` | Pattern matching cannot prove that all sensitive information is absent. |

### `python`

| Requirement | Source control | Relationship | Evidence | Limitation |
| --- | --- | --- | --- | --- |
| [AWQ-PY-001](REQUIREMENTS.md) | [PYTHON-REFERENCE full-grammar](https://docs.python.org/3.12/reference/grammar.html) | `aligned` | `contract-test` | Successful compilation does not prove runtime correctness or cross-implementation semantics. |

### `rust`

| Requirement | Source control | Relationship | Evidence | Limitation |
| --- | --- | --- | --- | --- |
| [AWQ-RUST-001](REQUIREMENTS.md) | [OPENSSF-OSPS OSPS-QA-02.01](https://baseline.openssf.org/versions/2026-08-28#osps-qa-0201) | `supports` | `mechanical` | A lockfile does not audit vulnerabilities, licenses, or malicious packages. |

### `schemas`

| Requirement | Source control | Relationship | Evidence | Limitation |
| --- | --- | --- | --- | --- |
| [AWQ-SCHEMA-001](REQUIREMENTS.md) | [IETF-RFC8259 section-9](https://www.rfc-editor.org/rfc/rfc8259#section-9) | `aligned` | `mechanical` | Parser acceptance does not prove schema conformance or semantic correctness. |

### `shell`

| Requirement | Source control | Relationship | Evidence | Limitation |
| --- | --- | --- | --- | --- |
| [AWQ-SHELL-001](REQUIREMENTS.md) | [POSIX-SHELL 2.1](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html#tag_19_01) | `related` | `mechanical` | POSIX leaves hash-bang handling unspecified, so this is a portability convention only. |

### `supply-chain`

| Requirement | Source control | Relationship | Evidence | Limitation |
| --- | --- | --- | --- | --- |
| [AWQ-SUPPLY-001](REQUIREMENTS.md) | [SLSA build.provenance.exists](https://slsa.dev/spec/v1.2/build-requirements#provenance-generation) | `related` | `mechanical` | The lock is not build provenance and does not establish any SLSA level. |
| [AWQ-SUPPLY-001](REQUIREMENTS.md) | [SPDX Core.CreationInfo.specVersion](https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Properties/specVersion/) | `related` | `mechanical` | An AWQ lock is not an SPDX document or software bill of materials. |

## Coverage gaps

### AWQ requirements without a mapping

- None.

### Catalogued source controls without an AWQ mapping

- [NIST-SSDF PO.3.2](https://doi.org/10.6028/NIST.SP.800-218): Follow recommended security practices to deploy and maintain tools and toolchains
- [NIST-SSDF PS.3.1](https://doi.org/10.6028/NIST.SP.800-218): Securely archive the necessary files and supporting data for each software release
- [OPENSSF-OSPS OSPS-QA-06.03](https://baseline.openssf.org/versions/2026-08-28#osps-qa-0603): Major changes should add or update automated tests

## Source-version drift

- None; every mapping names its source's pinned edition.
