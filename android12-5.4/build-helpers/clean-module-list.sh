#!/bin/bash
set -euo pipefail

KERNEL_ROOT="${1:?}"
cd "$KERNEL_ROOT"

sed -i '/zsmalloc\.ko/d; /zram\.ko/d' common/android/gki_aarch64_modules 2>/dev/null || true
sed -i '/zsmalloc\.ko/d; /zram\.ko/d' common/modules.bzl 2>/dev/null || true
