#!/bin/bash
# Patches GKI .patch files and KSU source after SUSFS fork is in place.
# The fork already contains all SUSFS C-source fixes and features.
# This script handles ONLY: GKI patch modifications + KSU source fixes.
#
# Usage: ./patch-gki.sh <SUSFS_DIR> <KSU_DIR>

set -euo pipefail

SUSFS_DIR="${1:?Usage: $0 <SUSFS_DIR> <KSU_DIR>}"
KSU_DIR="${2:?Usage: $0 <SUSFS_DIR> <KSU_DIR>}"

patch_count=0

echo "=== patch-gki: GKI patch modifications ==="

# -- Remove EACCES permission leak from SUS_PATH in GKI patch --
for patch_file in "$SUSFS_DIR"/50_add_susfs_in_gki-*.patch; do
    [ -f "$patch_file" ] || continue
    if grep -q 'ERR_PTR(-EACCES)' "$patch_file"; then
        echo "[+] Removing EACCES permission leak from $(basename "$patch_file")"
        awk '
        /^\+[[:space:]]*if \(flags & \(LOOKUP_CREATE \| LOOKUP_EXCL\)\) \{/ {
            print "+"; getline; print "+"; getline; print "+"
            next
        }
        /^\+[[:space:]]*if \(create_flags\) \{/ {
            saved = $0
            if (getline > 0 && $0 ~ /ERR_PTR\(-EACCES\)/) {
                print "+"; print "+"
                getline; print "+"; getline; print "+"
                next
            }
            print saved
        }
        { print }
        ' "$patch_file" > "$patch_file.tmp" && mv "$patch_file.tmp" "$patch_file"
        ((patch_count++)) || true
    fi
done

# -- Extend kallsyms filter to hide zeromount symbols (M4) --
for patch_file in "$SUSFS_DIR"/50_add_susfs_in_gki-*.patch; do
    [ -f "$patch_file" ] || continue
    if grep -q 'susfs_starts_with(iter->name, "is_zygote")' "$patch_file" && \
       ! grep -q 'susfs_starts_with(iter->name, "zeromount")' "$patch_file"; then
        echo "[+] Extending kallsyms filter for zeromount symbols in $(basename "$patch_file")"
        sed -i 's/susfs_starts_with(iter->name, "is_zygote"))/susfs_starts_with(iter->name, "is_zygote") ||\n+\t\t\tsusfs_starts_with(iter->name, "zeromount"))/' "$patch_file"
        ((patch_count++)) || true
    fi
done

# -- Supercall dispatch for kstat_redirect and open_redirect_all (L5) --
ksu_patch="$SUSFS_DIR/KernelSU/10_enable_susfs_for_ksu.patch"
if [ -f "$ksu_patch" ]; then
    if ! grep -q 'CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT' "$ksu_patch"; then
        echo "[+] Adding CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT dispatch handler"
        sed -i '/CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY/,/+        }/ {
            /+        }/ a\
+        if (cmd == CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT) {\
+            susfs_add_sus_kstat_redirect(arg);\
+            return 0;\
+        }
        }' "$ksu_patch"
        ((patch_count++)) || true
    fi

    if ! grep -q 'CMD_SUSFS_ADD_OPEN_REDIRECT_ALL' "$ksu_patch"; then
        echo "[+] Adding CMD_SUSFS_ADD_OPEN_REDIRECT_ALL dispatch handler"
        sed -i '/CMD_SUSFS_ADD_OPEN_REDIRECT)/,/+        }/ {
            /+        }/ a\
+        if (cmd == CMD_SUSFS_ADD_OPEN_REDIRECT_ALL) {\
+            susfs_add_open_redirect_all(arg);\
+            return 0;\
+        }
        }' "$ksu_patch"
        ((patch_count++)) || true
    fi
fi

echo "=== patch-gki: KSU integration fixes ==="

SETUID_HOOK="$KSU_DIR/kernel/setuid_hook.c"
KSUD="$KSU_DIR/kernel/ksud.c"
SUCOMPAT="$KSU_DIR/kernel/sucompat.c"

for f in "$SETUID_HOOK" "$KSUD" "$SUCOMPAT"; do
    [ -f "$f" ] || { echo "FATAL: missing $f"; exit 1; }
done

# -- Off-by-one in is_zygote_normal_app_uid (L3) --
if grep -q 'uid >= 10000 && uid < 19999' "$SETUID_HOOK"; then
    echo "[+] Fixing off-by-one in is_zygote_normal_app_uid (uid < 19999 -> < 20000)"
    sed -i 's/uid >= 10000 && uid < 19999/uid >= 10000 \&\& uid < 20000/' "$SETUID_HOOK"
    ((patch_count++)) || true
fi

# -- susfs_zygote_sid == 0 early-boot guard (L7) --
if ! grep -q 'susfs_zygote_sid == 0' "$SETUID_HOOK"; then
    echo "[+] Adding susfs_zygote_sid == 0 early-boot guard"
    sed -i '/if (!susfs_is_sid_equal(current_cred(), susfs_zygote_sid))/i \
\tif (susfs_zygote_sid == 0) {\
\t\treturn 0;\
\t}\
' "$SETUID_HOOK"
    ((patch_count++)) || true
fi

# -- Remove redundant ksu_handle_execveat_init call (L4) --
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
    ((patch_count++)) || true
fi

# -- Remove orphaned extern ksu_handle_execveat_init declaration (L4) --
if grep -q 'extern int ksu_handle_execveat_init' "$KSUD"; then
    echo "[+] Removing orphaned extern ksu_handle_execveat_init declaration"
    sed -i '/#ifdef CONFIG_KSU_SUSFS/{
        N
        /extern int ksu_handle_execveat_init/{
            N
            /#endif/d
        }
    }' "$KSUD"
    ((patch_count++)) || true
fi

# -- Dead return 0 in ksu_handle_faccessat (L8) --
if awk '/ksu_handle_faccessat.*dfd.*filename_user.*mode/,/^}/ {
       if (/return 0;/) { count++ }
       if (/^}/ && count >= 2) { found=1; exit 0 }
   } END { exit !found }' "$SUCOMPAT"; then
    echo "[+] Removing dead return 0 in ksu_handle_faccessat"
    sed -i '/ksu_handle_faccessat.*dfd.*filename_user.*mode/,/^}/ {
        /[[:space:]]*return 0;$/{
            N
            /\n$/{
                N
                /\n[[:space:]]*return 0;$/{ s/\n\n[[:space:]]*return 0;// }
            }
        }
    }' "$SUCOMPAT"
    ((patch_count++)) || true
fi

# -- WRITE_ONCE/READ_ONCE for hook flags (L9) --
if grep -q 'ksu_init_rc_hook = false;' "$KSUD"; then
    echo "[+] Wrapping hook flag writers with WRITE_ONCE"
    sed -i 's/ksu_init_rc_hook = false;/WRITE_ONCE(ksu_init_rc_hook, false);/' "$KSUD"
    sed -i 's/ksu_execveat_hook = false;/WRITE_ONCE(ksu_execveat_hook, false);/' "$KSUD"
    sed -i 's/ksu_input_hook = false;/WRITE_ONCE(ksu_input_hook, false);/' "$KSUD"
    ((patch_count++)) || true
fi

if grep -q 'if (!ksu_input_hook)' "$KSUD"; then
    echo "[+] Wrapping hook flag reader with READ_ONCE"
    sed -i 's/if (!ksu_input_hook)/if (!READ_ONCE(ksu_input_hook))/' "$KSUD"
    ((patch_count++)) || true
fi

echo "=== patch-gki: done ($patch_count patches) ==="
