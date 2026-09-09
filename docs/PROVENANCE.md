# Signed provenance and verified updates

AWQ v0.15.0 adds a strict offline profile of [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
and [SLSA provenance v1](https://slsa.dev/spec/v1.2/provenance).
It does not claim a SLSA level, certification, a trusted host, or that a local build ran on GitHub.

## Build type

The immutable source-commit URL of this section is the buildType identifier.
The recipe builds twice with exact Python, uv, Hatchling and hash-required build inputs in
[RELEASES.md](RELEASES.md). The external trust-policy SHA-256 is an explicit build input.
Source commit, tree and commit epoch are recorded. No current time, private path, credential,
random invocation identifier or invented hosted timestamp enters provenance.

Manifest v3 artifacts contains exactly wheel, sdist and SPDX SBOM. The separate provenance record
contains name, media_type, size and SHA-256. The trust_policy_sha256 binds the canonical candidate
policy. The detached signature is the one optional sidecar named MANIFEST.release.json.sig.
It is never hashed inside its own signed manifest.

The non-circular order is:

1. Build payload artifacts and their manifest records.
2. Construct the v3 manifest projection, omitting only its top-level provenance record.
3. Generate provenance subjects equal to every payload artifact; the predicate binds the projection
   digest, exact source, workflow path/commit/digest, and finite material set.
4. Add the provenance identity to the final canonical manifest.
5. An authorized operator signs the exact final manifest in SSH namespace awq-release.

The schemas are release-manifest.schema.json, release-provenance.schema.json and
release-trust-policy.schema.json under schemas/. Runtime verification additionally regenerates the
exact statement, rejects unknown fields and noncanonical JSON, and checks subject/material hashes.
Remote workflow actions require complete commit SHAs. Schema validity alone is insufficient.

## Builder identity

The immutable source-commit URL of this section identifies the reviewed local recipe, not GitHub.
runDetails.builder.version records exact recipe/tool versions and constraints digest.
No SLSA level or hosted timestamps are claimed. resolvedDependencies contains Git commit/tree and
the bounded source/lock/license/schema/registry/build/workflow material set in src/awq/provenance.py.
Verification compares source and sdist materials without executing them.

## Provision trust independently

Provision canonical JSON outside the bundle, candidate source and consumer tree.
Do not treat candidate config/allowed_signers as an independent trust anchor.
Location separation is enforced; authority must be established out of band.
Initial policy fields are schema_version 1, repository equal to the exact public AWQ URL,
generation 1, previous_policy_sha256 null, retired [], and nonempty roots. Each root has exactly:

- principal: bounded ASCII SSH identity.
- public_key: canonical bare ssh-ed25519 key, without options or comments.
- fingerprint: SHA256 of the SSH wire key, base64 without padding.
- valid_after and valid_until: exact UTC YYYY-MM-DDTHH:MM:SSZ timestamps.

Sort roots by fingerprint and retired fingerprints lexically. Use compact sorted JSON and final LF.
Expiry uses verification time, not a caller-selected timestamp. No key is a bundled default authority.
Rotating keys may share a principal. An operator signs and tags separately:

    ssh-keygen -Y sign -f /external/operator-key -n awq-release /external/bundle/MANIFEST.release.json
    git tag -s -a v0.15.0 EXACT_COMMIT -m "AWQ v0.15.0"

Obtain the full 40-hex annotated tag-object SHA independently. Verification requires exact
refs/tags/v0.15.0, that object pin, an annotated SSH-signed tag, and its exact manifest source commit.
Lightweight tags, channels, moved refs and clone-local signer configuration cannot authenticate.
The same authorized key signs manifest and tag.

## Standalone tag verification without persistent configuration

The distributed config/allowed_signers is review material, not an independent bootstrap root.
First compare the exact key fingerprint and principal to an independently authenticated channel.
Provision the reviewed public key and allowed-signers line outside the candidate tree. Then use:

    ssh-keygen -lf /external/trust/release-key.pub -E sha256
    git -C /external/source -c gpg.ssh.allowedSignersFile=/external/trust/allowed_signers \
      verify-tag REVIEWED_40_HEX_TAG_OBJECT

The allowed-signers line must authorize only the reviewed principal/key for this operation.
The command-scoped configuration is not saved in the clone. Also compare the exact tag ref/object
and target source commit; signature verification by itself does not establish those identities.
The AWQ authenticated path performs all these checks and additionally requires the external JSON
policy; the manual command does not replace the mandatory policy or verify bundle contents.

## Offline commands and rotation

Structural release-verify preserves historical v1/v2 verification but reports authentication
not-checked. Authentication and updates require v3:

    awq release-authenticate --manifest /external/bundle/MANIFEST.release.json \
      --trust-policy /external/trust/policy.json --source /external/source \
      --tag refs/tags/v0.15.0 --tag-object REVIEWED_40_HEX_TAG_OBJECT --format json

Dry-run and write both require all local evidence:

    awq --root /consumer update --to 0.15.0 \
      --manifest /external/bundle/MANIFEST.release.json \
      --trust-policy /external/trust/policy.json --source /external/source \
      --tag refs/tags/v0.15.0 --tag-object REVIEWED_40_HEX_TAG_OBJECT --dry-run --format json

Remove only --dry-run after reviewing the exact lock_diff. Candidate and installed verifier versions
may differ. Authenticated registry/catalog bytes are parsed without importing candidate Python or
running candidate commands. Unsupported schemas fail closed. Versions increase strictly; replays and
downgrades fail. Historical locks bootstrap only from independently provisioned generation-1 policy.

The v2 lock embeds authenticated policy/digest/generation, signer identity, signature/provenance/
manifest digests and exact tag ref/object. Later updates first authenticate under those stored old
roots. Candidate policy must be unchanged or generation old+1, chaining previous_policy_sha256 to
the old canonical digest. The signed manifest binds the candidate policy. Rotation requires an
unchanged active signing key in the overlap: add B alongside A in one release, then retire A in a
later release signed by B. Adding and removing in one transition, altered retained keys, missing
overlap, retired-key resurrection, duplicates, generation conflicts and last-root removal fail.
Same-principal A to A+B to B is supported. Never reset a lock to bypass its rollback/trust anchor.

## Atomicity and evidence boundary

Reviewed offline SSH/Git verification and directory-locking updates require a POSIX host with
/usr/bin/git and /usr/bin/ssh-keygen. Other CLI commands remain importable without POSIX resource
modules. Source cleanliness uses bounded Git tree/index plumbing and raw blob identities, never
checkout clean filters, hooks, or candidate code. Symlinks, submodules, unsupported modes and dirty
tracked bytes/index entries fail; untracked noise is ignored as in the builder.
Verification has zero runtime Python package dependencies and no network calls.
Subprocesses receive no inherited credentials or shell, bounded output and a process-tree deadline.
[Git transport controls](https://git-scm.com/docs/git) disable lazy promisor fetching and permit no
transport protocols, including checkout-configured remote helpers. Missing objects fail offline.

Verification and pre-commit failures leave consumer bytes unchanged. A cooperating directory lock
serializes updates. Dry-run creates no consumer files. Write stages/fsyncs only the new lock,
rechecks original policy/lock bytes, then atomically replaces the lock. Policy, source, manifests and
trust files are not modified. Replace is the commit point. A subsequent directory-fsync failure
returns committed true and durability unconfirmed, not a byte-identical failure claim.
Non-cooperating writers, kernel faults and power-loss persistence are outside this proof.
Keep verification inputs stable during inspection.

The tag-only release-attestation workflow rebuilds deterministic unsigned outputs and uses pinned
actions/attest with job-scoped contents:read, id-token:write and attestations:write. Set the reviewed
public AWQ_RELEASE_TRUST_POLICY_SHA256 repository variable first. GitHub/Sigstore evidence describes
those exact CI outputs, not independently rebuilt local assets. It is optional online environmental
evidence, never an offline trust root or SLSA-level claim. PR verification has no OIDC/write grant
and uses a synthetic zero policy digest solely for unsigned construction tests. CI has no signing key.
