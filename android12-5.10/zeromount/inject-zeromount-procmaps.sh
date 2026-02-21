#!/bin/bash
# inject-zeromount-procmaps.sh - Hook show_map_vma() for dev/ino spoofing (F1)
#
# Detection vector: /proc/PID/maps leaks real backing file dev/ino for
# mmap'd redirected files. Detectors compare stat() dev/ino (spoofed)
# against maps dev/ino (real) — mismatch = detection.
#
# Hook: After ino = inode->i_ino in show_map_vma(), call
# zeromount_spoof_mmap_metadata() to replace dev/ino with virtual values.
#
# Target: fs/proc/task_mmu.c
# Kernel: 5.10 (android12-5.10)
#
# Usage: ./inject-zeromount-procmaps.sh <kernel-source-dir>

set -e

KERNEL_DIR="${1:?Usage: $0 <kernel-source-dir>}"
TARGET="$KERNEL_DIR/fs/proc/task_mmu.c"

if [ ! -f "$TARGET" ]; then
    echo "[ERROR] File not found: $TARGET"
    exit 1
fi

echo "[INFO] ZeroMount /proc/PID/maps spoofing injection (F1)"
echo "[INFO] Target: $TARGET"

if grep -q "zeromount_spoof_mmap_metadata" "$TARGET"; then
    echo "[INFO] Hook already present — skipping"
    exit 0
fi

# Verify anchor exists
if ! grep -q 'ino = inode->i_ino;' "$TARGET"; then
    echo "[ERROR] Cannot find 'ino = inode->i_ino;' anchor in show_map_vma"
    exit 1
fi

cp "$TARGET" "${TARGET}.bak"

# [1/2] Inject #include <linux/zeromount.h>
echo "[INFO] [1/2] Injecting zeromount.h include..."

# Find a suitable include to anchor after
if grep -q '#include <linux/pkeys.h>' "$TARGET"; then
    sed -i '/#include <linux\/pkeys.h>/a\
#ifdef CONFIG_ZEROMOUNT\
#include <linux/zeromount.h>\
#endif' "$TARGET"
elif grep -q '#include <linux/uaccess.h>' "$TARGET"; then
    sed -i '/#include <linux\/uaccess.h>/a\
#ifdef CONFIG_ZEROMOUNT\
#include <linux/zeromount.h>\
#endif' "$TARGET"
elif grep -q '#include <linux/pagemap.h>' "$TARGET"; then
    sed -i '/#include <linux\/pagemap.h>/a\
#ifdef CONFIG_ZEROMOUNT\
#include <linux/zeromount.h>\
#endif' "$TARGET"
else
    echo "[ERROR] Cannot find suitable include anchor in task_mmu.c"
    mv "${TARGET}.bak" "$TARGET"
    exit 1
fi

if ! grep -q '#include <linux/zeromount.h>' "$TARGET"; then
    echo "[ERROR] Failed to inject include"
    mv "${TARGET}.bak" "$TARGET"
    exit 1
fi
echo "[OK] Include injected"

# [2/2] Inject spoofing hook after "ino = inode->i_ino;" in show_map_vma
echo "[INFO] [2/2] Injecting show_map_vma hook..."

# The pattern in show_map_vma (5.10):
#   if (file) {
#       struct inode *inode = file_inode(vma->vm_file);
#       dev = inode->i_sb->s_dev;
#       ino = inode->i_ino;
#       // <<< INJECT HERE >>>
#
# We use awk to inject only inside show_map_vma, after "ino = inode->i_ino;"

awk '
BEGIN { in_func = 0; injected = 0 }

# Handle split declaration: "static void\nshow_map_vma("
/^static void$/ { maybe_func = 1; print; next }
maybe_func && /^show_map_vma\(/ { in_func = 1; maybe_func = 0 }
maybe_func { maybe_func = 0 }

# Also handle single-line declaration
/^static void show_map_vma\(/ { in_func = 1 }

in_func && /ino = inode->i_ino;/ && !injected {
    print
    print "#ifdef CONFIG_ZEROMOUNT"
    print "\t\tzeromount_spoof_mmap_metadata(inode, &dev, &ino);"
    print "#endif"
    injected = 1
    next
}

in_func && /^}$/ { in_func = 0 }

{ print }

END {
    if (!injected) {
        print "INJECTION_FAILED" > "/dev/stderr"
        exit 1
    }
}
' "$TARGET" > "${TARGET}.tmp" || {
    echo "[ERROR] awk injection failed"
    mv "${TARGET}.bak" "$TARGET"
    rm -f "${TARGET}.tmp"
    exit 1
}

mv "${TARGET}.tmp" "$TARGET"

# Verify
echo "[INFO] Verifying injection..."
ERRORS=0

if ! grep -q '#include <linux/zeromount.h>' "$TARGET"; then
    echo "  [FAIL] zeromount.h include not found"
    ERRORS=$((ERRORS + 1))
else
    echo "  [OK] zeromount.h include"
fi

if ! grep -q 'zeromount_spoof_mmap_metadata' "$TARGET"; then
    echo "  [FAIL] zeromount_spoof_mmap_metadata call not found"
    ERRORS=$((ERRORS + 1))
else
    echo "  [OK] zeromount_spoof_mmap_metadata call"
fi

if [ "$ERRORS" -eq 0 ]; then
    echo "[SUCCESS] ZeroMount /proc/PID/maps spoofing hook injected"
    echo "  - Include: <linux/zeromount.h>"
    echo "  - Hook: show_map_vma() -> zeromount_spoof_mmap_metadata(inode, &dev, &ino)"
    rm -f "${TARGET}.bak"
else
    echo "[ERROR] Injection failed with $ERRORS errors. Restoring backup."
    mv "${TARGET}.bak" "$TARGET"
    exit 1
fi
