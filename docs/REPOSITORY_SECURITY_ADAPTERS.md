# Repository-security adapters

The optional `repository-security` family provides bounded, offline checks for
workflow syntax (`actionlint`), pedantic workflow security (`zizmor`), and
secrets introduced by an exact Git history range (`gitleaks`). Tools are setup
inputs: installers accept only reviewed HTTPS artifacts, verify a complete
SHA-256 before atomic publication, and probe the exact version. Adapter
execution performs no acquisition or network access.

The gitleaks contract is intentionally range-bound. A caller must substitute
two exact 40-hex revisions for `{base}` and `{head}` and must reject shallow or
ambiguous history before invoking the pinned binary. Redaction is mandatory;
AWQ evidence contains classifications and digests only, never matched values,
diagnostics, or source excerpts.

Native downstream or device evidence is not an authorization gate for this
family. Hosted runners, or a pinned container/VM for another architecture or
distribution, provide the execution environment while retaining the same
contract and privacy boundaries.

Contracts are catalog templates and remain opt-in in `quality/awq.json`.
