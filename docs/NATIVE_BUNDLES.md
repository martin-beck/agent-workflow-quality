# Native package and runtime-bundle assurance

The native-bundle-evaluate command validates a consumer-owned, canonical manifest for complete
native packages and offline runtime bundles. It performs bounded non-extracting archive inspection,
requires an exact sorted file inventory with permissions, sizes, SHA-256 digests, target and license
identity, and rejects links, irregular members, duplicates, unsafe paths, private-content patterns,
and member or aggregate size overruns.

An optional ELF policy constrains class, machine, architecture, dynamic dependencies, hardening,
executable stack, text relocations, features, strings, symbols, alignment and size. Executable
records bind content-minimized observations from checksum-pinned offline readelf and nm setup;
tool diagnostics and source or host paths are not evidence. Consumers choose the policy values and
retain their native build, test and package gates.

Every package binds exact source and toolchain identities, a normalized timestamp, complete license
or notice paths, a detached signature digest tied to an externally reviewed signer policy, and two
byte-identical rebuild digests with an inventory-manifest digest. Signature bytes are checked for
integrity, but cryptographic authority remains the external signer policy's responsibility.

Verification never extracts or executes package content, downloads tools, authorizes execution, or
claims sandboxing, feature completeness, malware absence, or portability beyond the declared target.
