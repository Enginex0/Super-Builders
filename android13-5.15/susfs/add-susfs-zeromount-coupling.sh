#!/bin/bash
# inject-susfs-zeromount-coupling.sh
# Injects zeromount_is_uid_blocked extern and susfs_is_uid_zeromount_excluded
# inline wrapper into susfs_def.h, and modifies is_i_uid_not_allowed in susfs.c
# to add zeromount exclusion.
#
# Usage: ./inject-susfs-zeromount-coupling.sh <SUSFS_KERNEL_PATCHES_DIR>

set -e

SUSFS_DIR="$1"

if [ -z "$SUSFS_DIR" ]; then
    echo "Usage: $0 <SUSFS_KERNEL_PATCHES_DIR>"
    exit 1
fi

SUSFS_DEF_H="$SUSFS_DIR/include/linux/susfs_def.h"
SUSFS_C="$SUSFS_DIR/fs/susfs.c"

for f in "$SUSFS_DEF_H" "$SUSFS_C"; do
    if [ ! -f "$f" ]; then
        echo "FATAL: missing $f"
        exit 1
    fi
done

echo "=== inject-susfs-zeromount-coupling ==="
inject_count=0

# --- 1. Extern + inline wrapper in susfs_def.h ---
if grep -q 'zeromount_is_uid_blocked' "$SUSFS_DEF_H"; then
    echo "[=] zeromount coupling already present in susfs_def.h"
else
    echo "[+] Injecting zeromount coupling into susfs_def.h"
    # Anchor: before the final #endif guard of the header
    # The last #endif closes #ifndef KSU_SUSFS_DEF_H
    sed -i '/^#endif.*KSU_SUSFS_DEF_H/ i\
\/\/ ZeroMount integration: extern when enabled, no-op helper when disabled\
#ifdef CONFIG_ZEROMOUNT\
extern bool zeromount_is_uid_blocked(uid_t uid);\
static inline bool susfs_is_uid_zeromount_excluded(uid_t uid) {\
\treturn zeromount_is_uid_blocked(uid);\
}\
#else\
static inline bool susfs_is_uid_zeromount_excluded(uid_t uid) { return false; }\
#endif' "$SUSFS_DEF_H"
    ((inject_count++)) || true
fi

# Validate
if ! grep -q 'zeromount_is_uid_blocked' "$SUSFS_DEF_H"; then
    echo "FATAL: zeromount coupling injection failed in susfs_def.h"
    exit 1
fi

# --- 2. Modify is_i_uid_not_allowed() in susfs.c ---
# Upstream dev consolidated the 3 uid-check functions into just is_i_uid_not_allowed.
if grep -q 'susfs_is_uid_zeromount_excluded' "$SUSFS_C"; then
    echo "[=] zeromount checks already present in susfs.c"
else
    echo "[+] Injecting zeromount check into is_i_uid_not_allowed in susfs.c"

    sed -i '/^static inline bool is_i_uid_not_allowed(uid_t i_uid) {$/a \\tif (susfs_is_uid_zeromount_excluded(current_uid().val))\n\t\treturn false;' "$SUSFS_C"

    ((inject_count++)) || true
fi

# Validate
count=$(grep -c 'susfs_is_uid_zeromount_excluded' "$SUSFS_C" || true)
if [ "$count" -lt 1 ]; then
    echo "FATAL: expected at least 1 zeromount check in susfs.c, found $count"
    exit 1
fi

echo "=== Done: $inject_count injections applied ==="
