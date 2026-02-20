#!/bin/bash
# Validates overlayfs availability and ensures tmpfs xattr/ACL support.
# CONFIG_OVERLAY_FS is already set in GKI gki_defconfig — this gate confirms
# it wasn't stripped and adds any missing tmpfs xattr/ACL entries defensively.
# Usage: ./add-overlayfs-support.sh <KERNEL_COMMON_DIR>
set -e

KERNEL_DIR="$1"
[ -n "$KERNEL_DIR" ] || { echo "FATAL: KERNEL_COMMON_DIR required"; exit 1; }

DEFCONFIG="$KERNEL_DIR/arch/arm64/configs/gki_defconfig"
[ -f "$DEFCONFIG" ] || { echo "FATAL: gki_defconfig not found at $DEFCONFIG"; exit 1; }

echo "=== add-overlayfs-support ==="

grep -q 'CONFIG_OVERLAY_FS=y' "$DEFCONFIG" || {
    echo "FATAL: CONFIG_OVERLAY_FS not set — overlayfs unavailable in this kernel"
    exit 1
}

# Defensive: ensure xattr/ACL entries are present even if fragment application missed them
for sym in CONFIG_TMPFS_XATTR CONFIG_TMPFS_POSIX_ACL; do
    grep -q "^${sym}=" "$DEFCONFIG" || {
        echo "[+] Adding missing $sym=y to defconfig"
        echo "${sym}=y" >> "$DEFCONFIG"
    }
done

echo "[+] Overlayfs support validated (OVERLAY_FS=y, TMPFS_XATTR=y, TMPFS_POSIX_ACL=y)"
