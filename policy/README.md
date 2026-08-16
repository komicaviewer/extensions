# Distribution 發佈准入政策

本目錄是 `extensions` destination repository 擁有的信任邊界。候選發佈的
script、metadata 與 APK 都是不可信資料；驗證時只能執行當前受保護
`main` 上的 `policy/admission_gate.py` 與其依賴，不得執行候選 branch
中的程式。

## 目前的全 GCP 流程

Repository 沒有 GitHub Actions workflow。完整流程為：

1. `extensions-source` 的 GCP publication build 以七組獨立簽章憑證建置 APK。
2. Build 在本地生成 distribution tree，確認 catalog、indexes、files、hashes、
   versions、Source classes 與 signing certificates。
3. Distribution publisher GitHub App 只把 allowlist 內的 distribution artifacts push 到
   `automation/extensions-cloudbuild-*` branch，並建立 PR。
4. 所有 GCP admission 完成後，publisher 對該 PR 的 exact head SHA 寫入
   `GCP distribution admission / verify` success status。
5. `main` branch protection 要求該 exact context、`strict=true`/必須跟上最新
   `main`、PR、linear history、conversation resolution 與無 bypass。只有
   distribution publisher App 可合併 exact head。

該 status 由 distribution publisher 以 installation token 寫入，不是已刪除的
GitHub Actions check。Publisher 同時有 Contents write/merge 與 Commit statuses write，
因此它是對自己剛執行的 GCP admission 自證，不是第二個獨立
reviewer identity。Branch protection 主要防止其他 identity、未跟上 `main` 或
沒有 exact status 的 commit 進入。本殘餘風險必須保留在 deployment
preflight，不得宣稱為獨立 destination approval。

在 status context、branch protection 或 App 綁定尚未建立前，Scheduler 與
publication trigger 必須維持停用。

## 准入契約

Candidate 只允許修改 `index.json`、`index.min.json`、`apk/*`、`icon/*`、
受管理的 `metadata/*` 與 `targets/apk/*`。Gate 比對 base/candidate 完整 tree，
包含 file mode 與 symlink，拒絕把 workflow、policy、repository metadata 或文件
夾帶進 release PR。

`policy/admission_policy.json` 與其引用的 offline `tuf/root.json` 是官方發佈的信任
anchor。政策包含每個 Source 的 destination-owned metadata，並為每個 package
維護獨立 `signerPins`。`repo.json.signingKeyFingerprint` 只是舊版 client
metadata，不能授權 APK。

目前 NewsHub client 只使用 threshold-signed metadata 與 `targets/apk/*`。`repo.json`、
`index.json`、`index.min.json` 與 `apk/*` 只保留給官方 producer/admission 流程，
不是第三方 repository contract。

正式政策在七個 `signerPins` 尚未填入受核准 SHA-256 certificate fingerprint
時會 fail closed。Unit tests 只對暫存 fixture 注入測試 pin；絕不得複製到
production policy。

Repository delivery 另以 ECDSA P-256/SHA-256 threshold-signed metadata 保護。Gate
會驗證 root、timestamp、versioned snapshot/targets、expiry、rollback、hash、length，
並把每個 APK 綁定 package、version、signer lineage、service class、protocol、
policy hash 與 Source metadata。`trustedRepository.provisioned=false` 期間一律
fail closed。

Gate 必須驗證：

- 七個 APK／十三個 Sources 的完整 catalog。
- `index.json` 與 `index.min.json` 語意一致。
- 每個 APK、PNG、SHA-256、package、version 與 package-specific signer。
- Source metadata、service class、protocol 與 DEX payload 的上限/下限。
- 禁止 legacy `assets/newshub-extension.json`。
- 禁止 version downgrade、同版本 APK replacement，以及未預先授權的 package/
  Source 刪除。

每個 Source 的 `protocol` 必須是 `2`。Protocol 2 policy maintenance 與 signed
distribution 是兩個步驟：先合併 destination-owned policy，不代表可以發佈；必須再由
受控 production TUF keys 產生版本遞增且內容相符的 targets、snapshot 與 timestamp。
兩步之間 admission 預期維持 fail closed。

新版 targets 的 package `custom` 可用 `acceptedArtifacts` 明確授權最多兩個舊 APK；
每筆都必須精確綁定較小的 `versionCode`、1–64 MiB 的 `length` 與小寫 SHA-256。
NewsHub 不會沿用未出現在目前已驗簽 metadata 的本機歷史；刪除該筆就是立即撤銷。

## 本機驗證

```bash
python3 -m unittest discover -s policy -p 'test_*.py' -v

python3 policy/admission_gate.py \
  --candidate /absolute/candidate-tree \
  --base /absolute/base-main-tree \
  --policy-root /absolute/base-main-tree/policy \
  --aapt /absolute/android-sdk/build-tools/34.0.0/aapt \
  --apksigner /absolute/android-sdk/build-tools/34.0.0/apksigner
```

簽章 pin、TUF root/role keys、Source metadata 或 package removal 是兩階段 maintenance
操作。Release candidate PR 不得修改信任 anchor 來授權自己；必須由
受控 maintenance change 先進入 base policy，再建立 distribution PR。
