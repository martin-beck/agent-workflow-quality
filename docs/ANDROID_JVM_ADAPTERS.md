# Android and JVM assurance adapters

The android-jvm family separates eleven conclusions that must not be conflated: Gradle input
integrity, formatting, static analysis, host tests, coverage, dependency analysis, ABI compatibility,
Android lint, Android build, configured device intent, and observed connected-test evidence.

All executable contracts use awq-android-jvm-check 1.0.0 with Temurin 17.0.20.1+1, Gradle 9.1.0,
Android Gradle Plugin 9.0.1, and Kotlin 2.3.20 on Linux x86-64. The installer verifies immutable
official JDK and Gradle archives by SHA-256, extracts them into a new external prefix, writes a
canonical manifest, probes the installed binaries, and publishes atomically:

~~~sh
uv run python scripts/install_android_jvm_tools.py \
  --prefix /new/external/android-jvm-tools
export PATH="/new/external/android-jvm-tools/bin:$PATH"
~~~

Acquisition may use the network. Adapter execution never does: the helper invokes the installed
Gradle binary directly with offline, no-daemon, and no-scan controls, a private project cache, a
credential-free environment, closed stdin, discarded output, resource limits, and a process-group
deadline. Project dependencies and the Android SDK are separate reviewed acquisition inputs. The
installer creates an empty isolated android-sdk; populate it before runtime using project-owned,
checksum-reviewed setup. Missing SDK packages or dependency cache entries fail offline.

## Canonical project policy

Commit quality/android-jvm.json conforming to schemas/android-jvm-policy.schema.json. The example
under fixtures/conforming/android-jvm is agent-readable. It declares exact toolchain pins; sorted
Gradle tasks for each conclusion; SHA-256 records for settings, version catalogue, verification
metadata, wrapper JAR and properties; every lockfile; the closed repository allowlist; finite
resource budgets; and the device plan.

The helper additionally enforces conditions beyond JSON Schema:

- the tracked Git tree is clean, bounded, UTF-8-addressable, and copied into external scratch;
- wrapper properties are exact and include the Gradle distribution digest;
- dependency verification accepts SHA-256 records only;
- project repositories are centrally denied and only google(), mavenCentral(), and
  gradlePluginPortal() may be selected;
- Gradle cannot consume global properties, init scripts, credentials, or inherited home state; and
- original and copied lockfiles retain their reviewed digests.

Tasks preserve each consumer's native Gradle semantics. Agent Relay mappings include spotlessCheck,
detekt, test, koverXmlReport, koverVerify, buildHealth, checkKotlinAbi, lintDebug, and assembleDebug;
the exact lists remain repository-owned.

## Device evidence boundary

device-plan validates intent only and never claims execution. connected-tests accepts environmental
evidence only when canonical observation data matches the configured API, ABI, form factor, locale,
and image digest; names the current Git revision; is no older than max_age_hours; asserts successful
UI and accessibility checks; and binds the complete sorted JUnit report set by SHA-256. Reports must
be bounded UTF-8 XML without DTDs or entities, cover all required modules, meet test/executed floors,
and contain no failures or errors.

This prevents stale reports, a different commit, or a boolean-only declaration from satisfying the
device contract. It does not prove behavior outside the selected device, test set, variant, locale,
or observation window.

## Adoption and equivalence

Start in shadow mode. Install and prefetch into external storage, copy the reviewed family contracts
from awq adapter-catalog --family android-jvm, and compare every AWQ status with the consumer's
native command on the same revision. Promote only conclusions with sustained equality; retain
consumer-only emulator orchestration, screenshots, accessibility artifact inspection, signing, and
release tests until separate equivalence evidence exists.

The wrapper emits only canonical bounded binding metadata. Gradle diagnostics, source excerpts,
environment contents, device logs, prompts, transcripts, and credentials are discarded.
