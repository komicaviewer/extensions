# NewsHub Extensions

This repository hosts packaged extension APKs for [NewsHub](https://github.com/twkevinzhang/NewsHub).

## Structure

- `repo.json` — Repository metadata (name, description, baseUrl)
- `index.json` — Index of all available extensions
- `apk/` — Extension APK files (named by package name)
- `icon/` — Extension icon PNG files (named by package name)

## File Formats

### repo.json
```json
{
  "name": "NewsHub Extensions",
  "description": "...",
  "baseUrl": "https://raw.githubusercontent.com/komicaviewer/extensions/main"
}
```

### index.json
```json
[
  {
    "pkg": "tw.kevinzhang.extension.gamer",
    "name": "Gamer",
    "versionCode": 1,
    "versionName": "1.0",
    "lang": "zh-TW",
    "apkName": "tw.kevinzhang.extension.gamer-v1.apk",
    "iconName": "tw.kevinzhang.extension.gamer.png",
    "sha256": "<sha256-hex>",
    "sources": [
      {
        "id": "tw.kevinzhang.gamer",
        "name": "Gamer",
        "lang": "zh-TW",
        "baseUrl": "https://forum.gamer.com.tw"
      }
    ]
  }
]
```

APK download URL: `{baseUrl}/apk/{apkName}`
Icon URL: `{baseUrl}/icon/{iconName}`

## Usage in NewsHub App

Add this repository URL in the NewsHub app settings:
```
https://github.com/komicaviewer/extensions
```

The app resolves raw content URLs automatically.

## Publishing

CI in [extensions-source](https://github.com/komicaviewer/extensions-source)
builds a complete release candidate and opens a pull request in this repository.
It never pushes `main` directly.

The destination-owned `Distribution admission / verify` check reads candidate
APKs as untrusted data and requires the exact three-APK/nine-Source contract,
matching indexes, files, hashes, versions, registries, signing certificate, and
Source classes. Branch protection admits the pull request only after that check
passes. A separate push check then verifies the published `main` ref and raw
download content. There is no scheduled daily audit.
