# Required GitHub Actions Secrets

Configure in **komicaviewer/extensions-source** → Settings → Secrets and variables → Actions:

| Secret | Description |
|--------|-------------|
| `SIGNING_KEY` | Base64-encoded keystore: `base64 -w 0 keystore.jks` |
| `KEY_STORE_PASSWORD` | Keystore password |
| `KEY_ALIAS` | Key alias |
| `KEY_PASSWORD` | Key password |
| `EXTENSIONS_REPO_TOKEN` | GitHub PAT with `repo` scope for `komicaviewer/extensions` |

## Generate a keystore (first time)

```bash
keytool -genkey -v -keystore keystore.jks -alias komicaviewer \
  -keyalg RSA -keysize 2048 -validity 10000
base64 -w 0 keystore.jks   # paste output as SIGNING_KEY secret
```
