#!/bin/bash
set -euo pipefail

KERNEL_ROOT="${1:?kernel root}"
BASELINE="${2:?Samsung DLKM CRC baseline}"
REPORT_DIR="${3:?report output directory}"
KMI_MODE="${4:-runtime-compat}"
KMI_PROFILE="${5:-full}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BASE_COMMIT="9bf8da21bb7e5891bb9b4ef917893a5792874608"
BASE_HELPER="$(mktemp -t verify-samsung-dlkm-crcs.XXXXXX.sh)"
trap 'rm -f "$BASE_HELPER"' EXIT

# Preserve the exact 2485-symbol Samsung ZZI4 strict CRC gate byte-for-byte.
curl --fail --location --silent --show-error --retry 3 --retry-delay 2 \
  "https://raw.githubusercontent.com/kaos2310/Super-Builders/${BASE_COMMIT}/android14-6.1/build-helpers/verify-samsung-dlkm-crcs.sh" \
  -o "$BASE_HELPER"
grep -qF 'Samsung S928B DLKM CRC audit' "$BASE_HELPER"
grep -qF 'strict-rejection' "$BASE_HELPER"
bash "$BASE_HELPER" "$KERNEL_ROOT" "$BASELINE" "$REPORT_DIR" "$KMI_MODE" "$KMI_PROFILE"

# Then audit only the new CI/live-test gunyah_qcom module delta. This cannot
# weaken the baseline gate above and does not package any module into AnyKernel.
MODULE_AUDIT="$SCRIPT_DIR/audit-e3q-gunyah-qcom-module.sh"
test -s "$MODULE_AUDIT" || { echo "::error::Missing gunyah_qcom module audit: $MODULE_AUDIT"; exit 1; }
bash -n "$MODULE_AUDIT"
bash "$MODULE_AUDIT" "$KERNEL_ROOT" "$REPORT_DIR"
