# GCP 發佈機密

本 repository 與 `extensions-source` 均不使用 GitHub Actions，也不使用 Actions secrets。
Extension 發佈由 GCP Cloud Build 執行；簽章材料與 GitHub App material 存放於 GCP
Secret Manager，Cloud Build 只在隔離的簽署／發佈步驟取得所需 secret。

Secret 名稱、IAM 分工、metadata-only readiness check 與 bootstrap 流程由 private
`extension-ops` repository 的 `config/required-secrets.json`、`docs/gcp/` 與
`infra/terraform/PREDEPLOY.md` 管理。不得把 secret value、keystore、密碼或長效 PAT
提交到任一 repository；distribution 發佈只使用短效 GitHub App token。
