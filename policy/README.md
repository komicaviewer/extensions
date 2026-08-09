# Distribution admission policy

This directory is the destination-owned trust boundary for release pull requests.
The `pull_request_target` workflow runs the policy from the current base commit and
treats the candidate checkout only as untrusted data. Candidate scripts are never
executed.

Candidate changes are allowlisted to `index.json`, `index.min.json`, `apk/*`, and
`icon/*`. The gate compares complete base/candidate tree snapshots, including file
mode and symlink changes, so a release PR cannot smuggle workflow, policy, metadata,
or documentation changes into the destination branch.

The base `policy/admission_policy.json` and its referenced offline `tuf/root.json`
are the only admission trust anchors. The policy owns
the exact metadata for every Source and a separate `signerPins` allowlist for every
package. `repo.json.signingKeyFingerprint` is distribution metadata for legacy
clients; the gate deliberately does not use that global value to authorize any APK.

The production policy is intentionally **unprovisioned and fail-closed** while its
seven `signerPins` arrays are empty. A maintainer must obtain each package's approved
SHA-256 signing-certificate fingerprint through the controlled key-provisioning
process and pin it under that package before any release can pass. Unit tests inject
fixture-only pins into a temporary policy; fixture pins must never be copied into the
production policy.

Repository delivery is additionally threshold-signed with ECDSA P-256/SHA-256.
The gate verifies the embedded/offline root, unversioned timestamp, versioned
snapshot and targets metadata, expiry, rollback, exact hashes and lengths, then
binds every `apk/*.apk` target to package, version, stable signer-lineage root,
current package-specific signer pins, service class, protocol, policy hash, and
signed display metadata. Production has `trustedRepository.provisioned=false`
until the reviewed root and role keys exist, so missing trust material cannot
fall back to `repo.json` or a global signing certificate.

The policy verifies the exact seven APK / thirteen Source catalog, both indexes,
every APK and PNG, APK SHA-256, package, version, exact destination-owned Source
metadata, package-specific signing certificates, and the presence and bounded size
of DEX payloads. APKs containing the legacy
`assets/newshub-extension.json` registry are rejected: candidate-owned registry
metadata is not an authority and is not used by admission. The gate also rejects
version downgrades, same-version APK replacements, and package deletions not
pre-authorized by the base admission policy.

## Bootstrap and repository settings

The workflow cannot protect the pull request that first introduces it. Merge this
bootstrap change after review, then create a branch ruleset for `main`:

1. Require pull requests and disallow direct pushes.
2. Require the `Distribution admission / verify` status check.
3. Require branches to be up to date before merging.
4. Do not permit the publishing bot or its token to bypass the ruleset.
5. Enable auto-merge; the publishing identity needs permission to open and update
   pull requests, but must not have direct-push or ruleset-bypass access.

The upstream publisher should therefore create/update a release PR instead of
pushing `main`. A fine-grained token needs repository `Contents: read and write`
and `Pull requests: read and write` for this repository. The destination admission
workflow itself uses only `contents: read` and `pull-requests: read` and requires no
new secret.

After a merge, `Post-publish verification / verify` independently checks the
exact `GITHUB_SHA` checkout, confirms `refs/heads/main` still resolves to that SHA,
and performs six bounded cache-busted reads of raw `main`. It compares both remote
indexes and every referenced APK/icon with the local commit and always emits a
GitHub Step Summary. It is intentionally a push check, not the PR required check,
and there is no scheduled workflow.

Signer provisioning, key rotation, Source metadata changes, or an intentional
package removal are two-step policy operations.
The admission check deliberately rejects policy changes in release candidate PRs,
so a maintainer must first use a controlled maintenance window to update the base
policy (temporarily adjusting the ruleset if necessary), restore the ruleset, and
only then submit the distribution PR. The publishing identity must never receive
that maintenance bypass. A candidate distribution PR therefore cannot authorize
its own signer, Source identity/metadata, or deletion.
