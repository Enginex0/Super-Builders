#!/bin/bash
# Localized ABI Bypass for Motorola Kernel
set -e

# Hardcode your kernel root
ROOT="/root/kernel-msm-1"

# 1. Disable TRIM_UNUSED_KSYMS (The most critical step)
# This finds your actual defconfig and turns off the feature that deletes your mods
DEFCONFIG="$ROOT/arch/arm64/configs/vendor/your_motorola_defconfig" 
# NOTE: Replace 'your_motorola_defconfig' with your actual filename!

if [ -f "$DEFCONFIG" ]; then
    sed -i 's/CONFIG_TRIM_UNUSED_KSYMS=y/# CONFIG_TRIM_UNUSED_KSYMS is not set/' "$DEFCONFIG"
    echo "bypass-abi: Disabled TRIM_UNUSED_KSYMS"
else
    echo "Warning: Could not find $DEFCONFIG"
fi

# 2. Disable ABI checks in your build config
BUILD_CONFIG="$ROOT/build.config"
if [ -f "$BUILD_CONFIG" ]; then
    sed -i 's/check_defconfig//g' "$BUILD_CONFIG"
    echo "bypass-abi: Disabled check_defconfig"
fi

echo "bypass-abi: Done."
