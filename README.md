# Host the official NewsHub extension repository

This repository contains the official signed extension distribution for NewsHub. The current app authenticates The Update Framework (TUF) style metadata before it lists or downloads an extension. It does not trust `repo.json`, `index.json`, or an APK hash from an unsigned index.

Third-party publishers should follow the [self-hosted repository guide](https://github.com/komicaviewer/NewsHub/blob/dev/docs/self-host-extension-repository.md). The official repository policy is fixed to the packages maintained by the NewsHub project and is not a reusable third-party template.

## Files consumed by NewsHub

NewsHub reads these files from one fixed HTTPS base URL:

```text
metadata/root.json
metadata/<next-version>.root.json
metadata/timestamp.json
metadata/<version>.snapshot.json
metadata/<version>.targets.json
targets/apk/<content-versioned-name>.apk
```

The app obtains `metadata/root.json` when a user adds a third-party repository. The official root is embedded in NewsHub. Root rotation still uses versioned root files.

Signed targets bind each APK to its package, version, byte length, SHA-256 digest, signing lineage, current signer pins, Source services, protocol version, and complete network policy. APK downloads stay under `targets/apk/` on the same HTTPS trust domain.

## Files retained for official publication

The official publisher also manages these files:

- `repo.json`: legacy repository description retained for tooling compatibility
- `index.json` and `index.min.json`: unsigned producer indexes used by the destination admission gate
- `apk/`: producer artifacts mirrored into authenticated targets
- `icon/`: extension icons used by the official distribution
- `policy/`: destination-owned admission policy and trust root

Current NewsHub releases do not read the legacy indexes or `apk/` directory. Do not use them as a third-party client contract.

## Add the official repository in NewsHub

The official repository is built into NewsHub. Its canonical base URL is:

```text
https://raw.githubusercontent.com/komicaviewer/extensions/main
```

NewsHub verifies the embedded root before it refreshes signed metadata. A GitHub web URL is accepted only as an alias for this built-in official repository.

## Publish an official release

The controlled GCP publisher in [`extensions-source`](https://github.com/komicaviewer/extensions-source) builds all official APKs, signs each package, generates threshold-signed repository metadata, and opens a distribution pull request. It never pushes `main` directly.

The destination admission gate runs code from the protected base branch. It verifies the complete package and Source set, exact indexes, APK identity, signer pins, Source services, protocol, network-policy hashes, and signed metadata before the publisher can merge the exact reviewed head.

Protocol 2 requires a coordinated release of NewsHub and all official extension APKs. Updating `policy/admission_policy.json` alone is not a publication: the release remains blocked until authorized production keys sign the matching targets, snapshot, and timestamp metadata.

Run the local policy tests with:

```bash
python3 -m unittest discover -s policy -p 'test_*.py' -v
```

Run a complete distribution admission check with the commands documented in [`policy/README.md`](policy/README.md).
