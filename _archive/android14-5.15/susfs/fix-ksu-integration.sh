#!/bin/bash
# fix-ksu-integration.sh - Patches KSU source files after SUSFS KSU integration patch
# Must run AFTER 10_enable_susfs_for_ksu.patch is applied
#
# Targets:
#   $KSU_DIR/kernel/setuid_hook.c  (L3, L7)
#   $KSU_DIR/kernel/ksud.c         (L4, L9)
#   $KSU_DIR/kernel/sucompat.c     (L8)

set -euo pipefail

KSU_DIR="${1:?Usage: $0 <ksu_dir>}"

SETUID_HOOK="$KSU_DIR/kernel/setuid_hook.c"
KSUD="$KSU_DIR/kernel/ksud.c"
SUCOMPAT="$KSU_DIR/kernel/sucompat.c"

for f in "$SETUID_HOOK" "$KSUD" "$SUCOMPAT"; do
    if [ ! -f "$f" ]; then
        echo "FATAL: missing $f"
        exit 1
    fi
done

echo "=== fix-ksu-integration ==="
fix_count=0

# --- 1. L3: off-by-one in is_zygote_normal_app_uid (setuid_hook.c) ---
# Android UIDs 10000-19999 inclusive; upstream has < 19999 which excludes 19999
if grep -q 'uid >= 10000 && uid < 19999' "$SETUID_HOOK"; then
    echo "[+] Fixing off-by-one in is_zygote_normal_app_uid (uid < 19999 -> < 20000)"
    sed -i 's/uid >= 10000 && uid < 19999/uid >= 10000 \&\& uid < 20000/' "$SETUID_HOOK"
    ((fix_count++)) || true
else
    echo "[=] is_zygote_normal_app_uid range already correct"
fi

# --- 2. L7: susfs_zygote_sid == 0 early-boot guard (setuid_hook.c) ---
# Before SELinux policy loads, susfs_zygote_sid is 0. Without this guard,
# any process with SID 0 could match the zygote check during early boot.
if ! grep -q 'susfs_zygote_sid == 0' "$SETUID_HOOK"; then
    echo "[+] Adding susfs_zygote_sid == 0 early-boot guard"
    sed -i '/if (!susfs_is_sid_equal(current_cred(), susfs_zygote_sid))/i \
\tif (susfs_zygote_sid == 0) {\
\t\treturn 0;\
\t}\
' "$SETUID_HOOK"
    ((fix_count++)) || true
else
    echo "[=] susfs_zygote_sid == 0 guard already present"
fi

# --- 3. L4: remove redundant ksu_handle_execveat_init call (ksud.c) ---
# The SUSFS ifdef block in ksu_handle_execveat_ksud() calls
# (void)ksu_handle_execveat_init(filename) but the return value is discarded.
# The real call happens in ksu_handle_execveat_sucompat() where the return
# value is properly checked. Remove the redundant call to avoid double-work.
if grep -q '(void)ksu_handle_execveat_init(filename)' "$KSUD"; then
    echo "[+] Removing redundant ksu_handle_execveat_init call from ksud.c"
    sed -i '/#ifdef CONFIG_KSU_SUSFS/{
        N
        /We need to run ksu_handle_execveat_init/{
            N
            /(void)ksu_handle_execveat_init(filename);/{
                N
                /#endif/d
            }
        }
    }' "$KSUD"
    ((fix_count++)) || true
else
    echo "[=] Redundant ksu_handle_execveat_init already removed"
fi

# --- 3b. L4: remove orphaned extern ksu_handle_execveat_init declaration (ksud.c) ---
# After L4 removes the (void)ksu_handle_execveat_init(filename) call, the
# extern declaration above ksu_handle_execveat_ksud() becomes dead code.
if grep -q 'extern int ksu_handle_execveat_init' "$KSUD"; then
    echo "[+] Removing orphaned extern ksu_handle_execveat_init declaration from ksud.c"
    sed -i '/#ifdef CONFIG_KSU_SUSFS/{
        N
        /extern int ksu_handle_execveat_init/{
            N
            /#endif/d
        }
    }' "$KSUD"
    ((fix_count++)) || true
else
    echo "[=] Orphaned extern ksu_handle_execveat_init already removed"
fi

# --- 4. L8: dead return 0 in ksu_handle_faccessat (sucompat.c) ---
# The SUSFS variant of ksu_handle_faccessat has two consecutive return 0;
# statements separated by a blank line. The second is unreachable dead code.
# Pattern: "return 0;\n\n    return 0;" — remove the blank line + second return.
if awk '/ksu_handle_faccessat.*dfd.*filename_user.*mode/,/^}/ {
       if (/return 0;/) { count++ }
       if (/^}/ && count >= 2) { found=1; exit 0 }
   } END { exit !found }' "$SUCOMPAT"; then
    echo "[+] Removing dead return 0 in ksu_handle_faccessat"
    # Scope to the faccessat function, match return 0; + blank + return 0;
    sed -i '/ksu_handle_faccessat.*dfd.*filename_user.*mode/,/^}/ {
        /[[:space:]]*return 0;$/{
            N
            /\n$/{
                N
                /\n[[:space:]]*return 0;$/{ s/\n\n[[:space:]]*return 0;// }
            }
        }
    }' "$SUCOMPAT"
    ((fix_count++)) || true
else
    echo "[=] Dead return 0 already removed from ksu_handle_faccessat"
fi

# --- 5. L9: WRITE_ONCE/READ_ONCE for __read_mostly hook flags (ksud.c) ---
# These booleans are written from one context and read from another.
# Plain assignment on ARM64 can be reordered by compiler/CPU without
# WRITE_ONCE/READ_ONCE barriers.

# 5a. Writers: plain assignment -> WRITE_ONCE
if grep -q 'ksu_init_rc_hook = false;' "$KSUD"; then
    echo "[+] Wrapping hook flag writers with WRITE_ONCE"
    sed -i 's/ksu_init_rc_hook = false;/WRITE_ONCE(ksu_init_rc_hook, false);/' "$KSUD"
    sed -i 's/ksu_execveat_hook = false;/WRITE_ONCE(ksu_execveat_hook, false);/' "$KSUD"
    sed -i 's/ksu_input_hook = false;/WRITE_ONCE(ksu_input_hook, false);/' "$KSUD"
    ((fix_count++)) || true
else
    echo "[=] Hook flag writers already use WRITE_ONCE"
fi

# 5b. Reader: plain dereference -> READ_ONCE
if grep -q 'if (!ksu_input_hook)' "$KSUD"; then
    echo "[+] Wrapping hook flag reader with READ_ONCE"
    sed -i 's/if (!ksu_input_hook)/if (!READ_ONCE(ksu_input_hook))/' "$KSUD"
    ((fix_count++)) || true
else
    echo "[=] Hook flag reader already uses READ_ONCE"
fi

echo "=== Done: $fix_count fixes applied ==="
