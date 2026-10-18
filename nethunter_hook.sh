#!/bin/bash
# NUKI/NURFS Genevn (SM6450 parrot) - Native Unified Kernel Image
# GKI 1.0: stage-1 ramdisk is Google skeleton (DO NOT TOUCH), stage-2 is where we blend.
# 2 years WIP: fs/koto matrix (ANBU) + SUSFS/ZeroMount + KPM-EUD + NURFS Debian-blended rootfs
# This hook merges the verified config chain. ksu-nh.defconfig is already deduped final,
# but we re-merge with fragments to guarantee last-wins for local edits.
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== NUKI staged merge: base sacred, middle staged, ending final ==="
python3 scripts/kconfig/merge_nuki.py \
  --base arch/arm64/configs/ksu-nh.defconfig \
  --middle arch/arm64/configs/consolidate.fragment arch/arm64/configs/defconfig.fragment arch/arm64/configs/vendor/moto-parrot-sm6450.config arch/arm64/configs/vendor/ext_config/debug-parrot-genevn.config \
  --ending arch/arm64/configs/vendor/ext_config/debug_moto_parrot_genevn.config arch/arm64/configs/nurfs-linux.fragment \
  -o .config
mkdir -p out && cp .config out/.config
echo "NUKI merge done: $(grep -c "^CONFIG_" .config) CONFIGs, $(wc -l < .config) lines"

if [ -f "deploy_lz4.sh" ]; then
  chmod +x deploy_lz4.sh
  ./deploy_lz4.sh || true
fi

# Toolchains are in-tree (snapdragon-toolchain) - no download needed on 22.04
# clang-r416183b (clang 12.0.5), gcc-linaro-7.5.0, sdclang 8 - kept on purpose for jammy
echo "Toolchain: $(tools/toolchains/snapdragon-toolchain/clang-r416183b/bin/clang --version 2>&1 | head -1)"
