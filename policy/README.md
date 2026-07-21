# Distribution admission policy

This directory is the destination-owned trust boundary for release pull requests.
The `pull_request_target` workflow runs the policy from the current base commit and
treats the candidate checkout only as untrusted data. Candidate scripts are never
executed.

Candidate changes are allowlisted to `index.json`, `index.min.json`, `apk/*`, and
`icon/*`. The gate compares complete base/candidate tree snapshots, including file
mode and symlink changes, so a release PR cannot smuggle workflow, policy, metadata,
or documentation changes into the destination branch.

The base `repo.json` `signingKeyFingerprint` is the APK signing trust anchor, so
the admission check needs no signing secret. The policy verifies the exact seven
APK / thirteen Source catalog, both indexes, every APK and PNG, APK SHA-256, package,
version, registry metadata, registry class presence in DEX, and signing certificate.
It also rejects version downgrades, same-version APK replacements, and package
deletions not pre-authorized by the base admission policy.

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

Key rotation or an intentional package removal is a two-step policy operation.
The admission check deliberately rejects policy changes in release candidate PRs,
so a maintainer must first use a controlled maintenance window to update the base
policy (temporarily adjusting the ruleset if necessary), restore the ruleset, and
only then submit the distribution PR. The publishing identity must never receive
that maintenance bypass. A candidate distribution PR therefore cannot authorize
its own signer or deletion.
