#!/bin/bash
# add-stock-overlay-hide.sh
# Injects CMD_SUSFS_HIDE_MOUNT (0x55563) with per-mount registration
# into SUSFS source files. Runs BEFORE the GKI patch copies these into
# the kernel tree.
#
# Usage: ./add-stock-overlay-hide.sh <SUSFS_KERNEL_PATCHES_DIR> [KSU_DIR]

set -e

SUSFS_DIR="${1:?Usage: $0 <SUSFS_KERNEL_PATCHES_DIR>}"

SUSFS_DEF_H="$SUSFS_DIR/include/linux/susfs_def.h"
SUSFS_H="$SUSFS_DIR/include/linux/susfs.h"
SUSFS_C="$SUSFS_DIR/fs/susfs.c"

for f in "$SUSFS_DEF_H" "$SUSFS_H" "$SUSFS_C"; do
    if [ ! -f "$f" ]; then
        echo "FATAL: missing $f"
        exit 1
    fi
done

echo "=== add-stock-overlay-hide ==="
inject_count=0

# --- 1. CMD code in susfs_def.h ---
if grep -q 'CMD_SUSFS_HIDE_MOUNT' "$SUSFS_DEF_H"; then
    echo "[=] CMD_SUSFS_HIDE_MOUNT already present in susfs_def.h"
else
    echo "[+] Injecting CMD_SUSFS_HIDE_MOUNT into susfs_def.h"
    sed -i '/CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE/a #define CMD_SUSFS_HIDE_MOUNT 0x55563' "$SUSFS_DEF_H"
    ((inject_count++)) || true
fi

if ! grep -q 'CMD_SUSFS_HIDE_MOUNT' "$SUSFS_DEF_H"; then
    echo "FATAL: CMD_SUSFS_HIDE_MOUNT injection failed"
    exit 1
fi

# --- 2. Structs in susfs.h ---
if grep -q 'st_susfs_hide_mount' "$SUSFS_H"; then
    echo "[=] st_susfs_hide_mount already present in susfs.h"
else
    echo "[+] Injecting st_susfs_hide_mount structs into susfs.h"
    # Anchor: after the closing }; of st_susfs_hide_sus_mnts_for_non_su_procs
    sed -i '/^struct st_susfs_hide_sus_mnts_for_non_su_procs {/,/^};/ {
        /^};/ a\
\
struct st_susfs_hide_mount {\
\tchar                                    mount_point[SUSFS_MAX_LEN_PATHNAME];\
\tunsigned int                            spoofed_dev;\
\tint                                     err;\
};\
\
struct st_susfs_hide_mount_hlist {\
\tdev_t                                   s_dev;\
\tdev_t                                   spoofed_dev;\
\tstruct hlist_node                       node;\
};
    }' "$SUSFS_H"
    ((inject_count++)) || true
fi

if ! grep -q 'st_susfs_hide_mount' "$SUSFS_H"; then
    echo "FATAL: st_susfs_hide_mount struct injection failed"
    exit 1
fi

# --- 3. Function declarations in susfs.h ---
if grep -q 'void susfs_hide_mount' "$SUSFS_H"; then
    echo "[=] susfs_hide_mount declarations already present in susfs.h"
else
    echo "[+] Injecting susfs_hide_mount declarations into susfs.h"
    sed -i '/void susfs_set_hide_sus_mnts_for_non_su_procs/a void susfs_hide_mount(void __user **user_info);\nbool susfs_is_mount_hidden(dev_t s_dev);\nvoid susfs_spoof_stat_dev(struct kstat *stat);' "$SUSFS_H"
    ((inject_count++)) || true
fi

if ! grep -q 'void susfs_hide_mount' "$SUSFS_H"; then
    echo "FATAL: susfs_hide_mount declaration injection failed"
    exit 1
fi

# --- 4. Hash table + functions in susfs.c ---
if grep -q 'HIDDEN_MOUNT_HLIST' "$SUSFS_C"; then
    echo "[=] HIDDEN_MOUNT_HLIST already present in susfs.c"
else
    echo "[+] Injecting hide_mount implementation into susfs.c"
    # Anchor: after susfs_set_hide_sus_mnts_for_non_su_procs log line and closing }
    sed -i '/CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS -> ret/,/^}/ {
        /^}/ a\
\
static DEFINE_HASHTABLE(HIDDEN_MOUNT_HLIST, 6);\
static DEFINE_SPINLOCK(susfs_spin_lock_hidden_mount);\
\
void susfs_hide_mount(void __user **user_info)\
{\
\tstruct st_susfs_hide_mount info = {0};\
\tstruct st_susfs_hide_mount_hlist *new_entry;\
\tstruct path p;\
\n\tif (copy_from_user(&info, (struct st_susfs_hide_mount __user *)*user_info, sizeof(info))) {\
\t\tinfo.err = -EFAULT;\
\t\tgoto out_copy_to_user;\
\t}\
\tinfo.mount_point[SUSFS_MAX_LEN_PATHNAME - 1] = '"'"'\\0'"'"';\
\n\tif (kern_path(info.mount_point, LOOKUP_FOLLOW, &p)) {\
\t\tSUSFS_LOGE("hide_mount: path '"'"'%s'"'"' not found\\n", info.mount_point);\
\t\tinfo.err = -ENOENT;\
\t\tgoto out_copy_to_user;\
\t}\
\n\tnew_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);\
\tif (!new_entry) {\
\t\tpath_put(&p);\
\t\tinfo.err = -ENOMEM;\
\t\tgoto out_copy_to_user;\
\t}\
\n\tnew_entry->s_dev = p.dentry->d_sb->s_dev;\
\tnew_entry->spoofed_dev = info.spoofed_dev;\
\tspin_lock(&susfs_spin_lock_hidden_mount);\
\thash_add(HIDDEN_MOUNT_HLIST, &new_entry->node, new_entry->s_dev);\
\tspin_unlock(&susfs_spin_lock_hidden_mount);\
\n\tSUSFS_LOGI("hide_mount: s_dev=%u spoofed=%u path='"'"'%s'"'"' added to hidden list\\n",\
\t           new_entry->s_dev, new_entry->spoofed_dev, info.mount_point);\
\tpath_put(&p);\
\tinfo.err = 0;\
\nout_copy_to_user:\
\tif (copy_to_user(&((struct st_susfs_hide_mount __user *)*user_info)->err,\
\t                 &info.err, sizeof(info.err))) {\
\t\tSUSFS_LOGE("hide_mount: copy_to_user failed\\n");\
\t}\
}\
\
bool susfs_is_mount_hidden(dev_t s_dev)\
{\
\tstruct st_susfs_hide_mount_hlist *entry;\
\n\thash_for_each_possible(HIDDEN_MOUNT_HLIST, entry, node, s_dev) {\
\t\tif (entry->s_dev == s_dev)\
\t\t\treturn true;\
\t}\
\treturn false;\
}\
\
void susfs_spoof_stat_dev(struct kstat *stat)\
{\
\tstruct st_susfs_hide_mount_hlist *entry;\
\n\tif (!susfs_is_current_proc_umounted())\
\t\treturn;\
\tif (susfs_is_current_ksu_domain())\
\t\treturn;\
\n\thash_for_each_possible(HIDDEN_MOUNT_HLIST, entry, node, stat->dev) {\
\t\tif (entry->s_dev == stat->dev) {\
\t\t\tstat->dev = entry->spoofed_dev;\
\t\t\treturn;\
\t\t}\
\t}\
}
    }' "$SUSFS_C"
    ((inject_count++)) || true
fi

if ! grep -q 'susfs_hide_mount' "$SUSFS_C"; then
    echo "FATAL: susfs_hide_mount function injection failed"
    exit 1
fi
if ! grep -q 'susfs_is_mount_hidden' "$SUSFS_C"; then
    echo "FATAL: susfs_is_mount_hidden function injection failed"
    exit 1
fi
if ! grep -q 'susfs_spoof_stat_dev' "$SUSFS_C"; then
    echo "FATAL: susfs_spoof_stat_dev function injection failed"
    exit 1
fi

echo "=== Done: $inject_count injections applied ==="
