#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <candidate-repository> <base-repository>" >&2
  exit 2
fi

policy_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
candidate_dir=$1
base_dir=$2

: "${AAPT:?AAPT must point to the Android aapt executable}"
: "${APKSIGNER:?APKSIGNER must point to the Android apksigner executable}"

exec python3 "${policy_dir}/admission_gate.py" \
  --candidate "${candidate_dir}" \
  --base "${base_dir}" \
  --policy-root "${policy_dir}" \
  --aapt "${AAPT}" \
  --apksigner "${APKSIGNER}"
