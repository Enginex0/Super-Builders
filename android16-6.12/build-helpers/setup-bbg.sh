#!/bin/bash
set -euo pipefail

KERNEL_ROOT="${1:?}"
DEFCONFIG="${2:?}"
FRAGMENT="${3:-}"

cd "$KERNEL_ROOT"
curl -LSs https://github.com/vc-teahouse/Baseband-guard/raw/main/setup.sh | bash
if [ -n "$FRAGMENT" ]; then
  echo "CONFIG_BBG=y" >> "$FRAGMENT"
else
  echo "CONFIG_BBG=y" >> "$DEFCONFIG"
fi
# lockdown is the LSM anchor on 5.10 kernels
sed -i '/^config LSM$/,/^help$/{ /^[[:space:]]*default/ { /baseband_guard/! s/lockdown/lockdown,baseband_guard/ } }' common/security/Kconfig
