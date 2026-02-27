#!/bin/bash
# Fixes SUSFS GKI patch hunk failure on fs/proc/base.c for older 6.1 sublevels.
#
# The upstream SUSFS patch anchors the susfs_def.h include after dma-buf.h,
# which doesn't exist in sublevels before ~140. This script injects the
# include at a stable anchor when the patch hunk rejects.

set -e

KERNEL_DIR="$1"
PROC_BASE="$KERNEL_DIR/fs/proc/base.c"

if [ -z "$KERNEL_DIR" ] || [ ! -f "$PROC_BASE" ]; then
    echo "Usage: $0 <KERNEL_COMMON_DIR>"
    exit 1
fi

REJ="$PROC_BASE.rej"
if [ ! -f "$REJ" ]; then
    echo "[=] No proc/base.c reject found, GKI patch applied cleanly"
    exit 0
fi

echo "=== fix-proc-base-compat ==="
echo "    Reject found, applying cross-sublevel proc/base.c fix"

if grep -q 'linux/susfs_def.h' "$PROC_BASE"; then
    echo "[=] susfs_def.h already included in proc/base.c"
    rm -f "$REJ"
    exit 0
fi

# trace/events/oom.h is stable across all 6.1 sublevels
if grep -q '#include <trace/events/oom.h>' "$PROC_BASE"; then
    sed -i '/#include <trace\/events\/oom.h>/i\
#ifdef CONFIG_KSU_SUSFS_SUS_MAP\
#include <linux/susfs_def.h>\
#endif\
' "$PROC_BASE"
elif grep -q '#include "internal.h"' "$PROC_BASE"; then
    sed -i '/#include "internal.h"/i\
#ifdef CONFIG_KSU_SUSFS_SUS_MAP\
#include <linux/susfs_def.h>\
#endif\
' "$PROC_BASE"
else
    echo "[FAIL] Cannot find stable anchor in proc/base.c"
    exit 1
fi

if grep -q 'linux/susfs_def.h' "$PROC_BASE"; then
    echo "[OK] susfs_def.h include injected into proc/base.c"
    rm -f "$REJ"
else
    echo "[FAIL] Injection failed — susfs_def.h not found after sed"
    exit 1
fi
