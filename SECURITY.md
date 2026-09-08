# Security policy

Report vulnerabilities privately through GitHub's security-advisory interface. Do not open a public
issue containing an exploit, credential, private repository data or identifying evidence.

Supported releases are the latest minor release in the current major series. The project has no
runtime network access, telemetry or secret input. Its trust boundary is the checked-out policy and
the explicit project configuration chosen by the operator. AWQ is not a sandbox and does not make an
untrusted repository safe to execute; configured local gates run as the invoking user.

Security fixes require a regression fixture, bounded evidence, a signed release and an explicit
description of the affected versions and proof boundary.
