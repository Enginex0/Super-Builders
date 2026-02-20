#!/bin/bash
# inject-susfs-features.sh - Inject custom SUSFS features
#
# Consolidated from add-kstat-redirect.sh, add-open-redirect-all.sh,
# add-unicode-filter-func.sh. Each feature is a self-contained function.
#
# Usage: ./inject-susfs-features.sh <SUSFS_KERNEL_PATCHES_DIR>

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

inject_count=0

inject_kstat_redirect() {
echo "=== inject-susfs-kstat-redirect ==="

# --- 1. CMD code in susfs_def.h ---
if grep -q 'CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT' "$SUSFS_DEF_H"; then
    echo "[=] CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT already present in susfs_def.h"
else
    echo "[+] Injecting CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT into susfs_def.h"
    sed -i '/CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY/a #define CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT 0x55573' "$SUSFS_DEF_H"
    ((inject_count++)) || true
fi

# Validate
if ! grep -q 'CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT' "$SUSFS_DEF_H"; then
    echo "FATAL: CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT injection failed"
    exit 1
fi

# --- 2. Struct in susfs.h ---
if grep -q 'st_susfs_sus_kstat_redirect' "$SUSFS_H"; then
    echo "[=] st_susfs_sus_kstat_redirect already present in susfs.h"
else
    echo "[+] Injecting st_susfs_sus_kstat_redirect struct into susfs.h"
    # Anchor: after the closing }; of st_susfs_sus_kstat_hlist struct
    sed -i '/^struct st_susfs_sus_kstat_hlist {/,/^};/ {
        /^};/ a\
\
struct st_susfs_sus_kstat_redirect {\
\tchar                                    virtual_pathname[SUSFS_MAX_LEN_PATHNAME];\
\tchar                                    real_pathname[SUSFS_MAX_LEN_PATHNAME];\
\tunsigned long                           spoofed_ino;\
\tunsigned long                           spoofed_dev;\
\tunsigned int                            spoofed_nlink;\
\tlong long                               spoofed_size;\
\tlong                                    spoofed_atime_tv_sec;\
\tlong                                    spoofed_mtime_tv_sec;\
\tlong                                    spoofed_ctime_tv_sec;\
\tlong                                    spoofed_atime_tv_nsec;\
\tlong                                    spoofed_mtime_tv_nsec;\
\tlong                                    spoofed_ctime_tv_nsec;\
\tunsigned long                           spoofed_blksize;\
\tunsigned long long                      spoofed_blocks;\
\tint                                     err;\
};
    }' "$SUSFS_H"
    ((inject_count++)) || true
fi

# Validate
if ! grep -q 'st_susfs_sus_kstat_redirect' "$SUSFS_H"; then
    echo "FATAL: st_susfs_sus_kstat_redirect struct injection failed"
    exit 1
fi

# --- 3. Function declaration in susfs.h ---
if grep -q 'susfs_add_sus_kstat_redirect' "$SUSFS_H"; then
    echo "[=] susfs_add_sus_kstat_redirect declaration already present in susfs.h"
else
    echo "[+] Injecting susfs_add_sus_kstat_redirect declaration into susfs.h"
    # Anchor: after susfs_add_sus_kstat declaration
    sed -i '/void susfs_add_sus_kstat(void __user \*\*user_info);/a void susfs_add_sus_kstat_redirect(void __user **user_info);' "$SUSFS_H"
    ((inject_count++)) || true
fi

# Validate
if ! grep -q 'susfs_add_sus_kstat_redirect' "$SUSFS_H"; then
    echo "FATAL: susfs_add_sus_kstat_redirect declaration injection failed"
    exit 1
fi

# --- 4. Function body in susfs.c ---
if grep -q 'susfs_add_sus_kstat_redirect' "$SUSFS_C"; then
    echo "[=] susfs_add_sus_kstat_redirect function already present in susfs.c"
else
    echo "[+] Injecting susfs_add_sus_kstat_redirect function into susfs.c"
    # Anchor: after the closing brace of susfs_add_sus_kstat() function.
    # We find the SUSFS_LOGI for CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY and inject after
    # the next closing brace (end of susfs_add_sus_kstat).
    # Strategy: find the unique log line at end of susfs_add_sus_kstat, then its closing }
    sed -i '/CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY -> ret/,/^}/ {
        /^}/ a\
\
void susfs_add_sus_kstat_redirect(void __user **user_info) {\
\tstruct st_susfs_sus_kstat_redirect info = {0};\
\tstruct st_susfs_sus_kstat_hlist *new_entry = NULL;\
\tstruct st_susfs_sus_kstat_hlist *virtual_entry = NULL;\
\tstruct path p_real;\
\tstruct path p_virtual;\
\tstruct inode *inode_real = NULL;\
\tstruct inode *inode_virtual = NULL;\
\tunsigned long virtual_ino = 0;\
\tbool virtual_path_resolved = false;\
\n\tif (copy_from_user(&info, (struct st_susfs_sus_kstat_redirect __user*)*user_info, sizeof(info))) {\
\t\tinfo.err = -EFAULT;\
\t\tgoto out_copy_to_user;\
\t}\
\n\tif (strlen(info.virtual_pathname) == 0 || strlen(info.real_pathname) == 0) {\
\t\tinfo.err = -EINVAL;\
\t\tgoto out_copy_to_user;\
\t}\
\n\tnew_entry = kzalloc(sizeof(struct st_susfs_sus_kstat_hlist), GFP_KERNEL);\
\tif (!new_entry) {\
\t\tinfo.err = -ENOMEM;\
\t\tgoto out_copy_to_user;\
\t}\
\n#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)\
#ifdef CONFIG_MIPS\
\tinfo.spoofed_dev = new_decode_dev(info.spoofed_dev);\
#else\
\tinfo.spoofed_dev = huge_decode_dev(info.spoofed_dev);\
#endif /* CONFIG_MIPS */\
#else\
\tinfo.spoofed_dev = old_decode_dev(info.spoofed_dev);\
#endif /* defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64) */\
\n\tSUSFS_LOGI("kstat_redirect: ENTRY vpath='"'"'%s'"'"' rpath='"'"'%s'"'"'\\n",\
\t           info.virtual_pathname, info.real_pathname);\
\tif (!kern_path(info.virtual_pathname, 0, &p_virtual)) {\
\t\tinode_virtual = d_inode(p_virtual.dentry);\
\t\tif (inode_virtual) {\
\t\t\tvirtual_ino = inode_virtual->i_ino;\
\t\t\tif (!test_bit(AS_FLAGS_SUS_KSTAT, &inode_virtual->i_mapping->flags)) {\
\t\t\t\tspin_lock(&inode_virtual->i_lock);\
\t\t\t\tset_bit(AS_FLAGS_SUS_KSTAT, &inode_virtual->i_mapping->flags);\
\t\t\t\tspin_unlock(&inode_virtual->i_lock);\
\t\t\t}\
\t\t\tvirtual_path_resolved = true;\
\t\t\tSUSFS_LOGI("kstat_redirect: VPATH_OK ino=%lu flagged='"'"'%s'"'"'\\n",\
\t\t\t           virtual_ino, info.virtual_pathname);\
\t\t}\
\t\tpath_put(&p_virtual);\
\t} else {\
\t\tSUSFS_LOGI("kstat_redirect: VPATH_MISSING '"'"'%s'"'"' (new file)\\n",\
\t\t           info.virtual_pathname);\
\t}\
\n\tinfo.err = kern_path(info.real_pathname, 0, &p_real);\
\tif (info.err) {\
\t\tSUSFS_LOGE("Failed opening real file '"'"'%s'"'"'\\n", info.real_pathname);\
\t\tkfree(new_entry);\
\t\tgoto out_copy_to_user;\
\t}\
\n\tinode_real = d_inode(p_real.dentry);\
\tif (!inode_real) {\
\t\tpath_put(&p_real);\
\t\tkfree(new_entry);\
\t\tSUSFS_LOGE("inode is NULL for real file '"'"'%s'"'"'\\n", info.real_pathname);\
\t\tinfo.err = -EINVAL;\
\t\tgoto out_copy_to_user;\
\t}\
\n\tif (!test_bit(AS_FLAGS_SUS_KSTAT, &inode_real->i_mapping->flags)) {\
\t\tspin_lock(&inode_real->i_lock);\
\t\tset_bit(AS_FLAGS_SUS_KSTAT, &inode_real->i_mapping->flags);\
\t\tspin_unlock(&inode_real->i_lock);\
\t}\
\n\tnew_entry->target_ino = inode_real->i_ino;\
\tnew_entry->info.is_statically = 0;\
\tnew_entry->info.target_ino = inode_real->i_ino;\
\tstrncpy(new_entry->info.target_pathname, info.virtual_pathname, SUSFS_MAX_LEN_PATHNAME - 1);\
\tnew_entry->info.target_pathname[SUSFS_MAX_LEN_PATHNAME-1] = 0;\
\tnew_entry->info.spoofed_ino = info.spoofed_ino;\
\tnew_entry->info.spoofed_dev = info.spoofed_dev;\
\tnew_entry->info.spoofed_nlink = info.spoofed_nlink;\
\tnew_entry->info.spoofed_size = info.spoofed_size;\
\tnew_entry->info.spoofed_atime_tv_sec = info.spoofed_atime_tv_sec;\
\tnew_entry->info.spoofed_mtime_tv_sec = info.spoofed_mtime_tv_sec;\
\tnew_entry->info.spoofed_ctime_tv_sec = info.spoofed_ctime_tv_sec;\
\tnew_entry->info.spoofed_atime_tv_nsec = info.spoofed_atime_tv_nsec;\
\tnew_entry->info.spoofed_mtime_tv_nsec = info.spoofed_mtime_tv_nsec;\
\tnew_entry->info.spoofed_ctime_tv_nsec = info.spoofed_ctime_tv_nsec;\
\tnew_entry->info.spoofed_blksize = info.spoofed_blksize;\
\tnew_entry->info.spoofed_blocks = info.spoofed_blocks;\
\n\tpath_put(&p_real);\
\n\tif (virtual_path_resolved && virtual_ino != 0 && virtual_ino != new_entry->target_ino) {\
\t\tvirtual_entry = kzalloc(sizeof(struct st_susfs_sus_kstat_hlist), GFP_KERNEL);\
\t\tif (!virtual_entry) {\
\t\t\tSUSFS_LOGE("kstat_redirect: ALLOC_FAIL virtual_entry, aborting\\n");\
\t\t\tkfree(new_entry);\
\t\t\tinfo.err = -ENOMEM;\
\t\t\tgoto out_copy_to_user;\
\t\t}\
\t\tmemcpy(&virtual_entry->info, &new_entry->info, sizeof(new_entry->info));\
\t\tvirtual_entry->target_ino = virtual_ino;\
\t\tvirtual_entry->info.target_ino = virtual_ino;\
\t}\
\n\tspin_lock(&susfs_spin_lock_sus_kstat);\
\thash_add(SUS_KSTAT_HLIST, &new_entry->node, new_entry->target_ino);\
\tif (virtual_entry) {\
\t\thash_add(SUS_KSTAT_HLIST, &virtual_entry->node, virtual_ino);\
\t}\
\tspin_unlock(&susfs_spin_lock_sus_kstat);\
\n\tSUSFS_LOGI("kstat_redirect: RPATH_OK ino=%lu dev=%lu '"'"'%s'"'"'\\n",\
\t           new_entry->target_ino, new_entry->info.spoofed_dev, info.real_pathname);\
\tif (virtual_entry) {\
\t\tSUSFS_LOGI("kstat_redirect: DUAL_INODE vino=%lu rino=%lu '"'"'%s'"'"'\\n",\
\t\t           virtual_ino, new_entry->target_ino, info.virtual_pathname);\
\t} else if (virtual_path_resolved && virtual_ino == new_entry->target_ino) {\
\t\tSUSFS_LOGI("kstat_redirect: SAME_INODE ino=%lu '"'"'%s'"'"'\\n",\
\t\t           virtual_ino, info.virtual_pathname);\
\t}\
\n#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)\
\tSUSFS_LOGI("redirect: virtual: '"'"'%s'"'"', real: '"'"'%s'"'"', target_ino: '"'"'%lu'"'"', spoofed_ino: '"'"'%lu'"'"', spoofed_dev: '"'"'%lu'"'"', spoofed_nlink: '"'"'%u'"'"', spoofed_size: '"'"'%llu'"'"', spoofed_atime_tv_sec: '"'"'%ld'"'"', spoofed_mtime_tv_sec: '"'"'%ld'"'"', spoofed_ctime_tv_sec: '"'"'%ld'"'"', spoofed_atime_tv_nsec: '"'"'%ld'"'"', spoofed_mtime_tv_nsec: '"'"'%ld'"'"', spoofed_ctime_tv_nsec: '"'"'%ld'"'"', spoofed_blksize: '"'"'%lu'"'"', spoofed_blocks: '"'"'%llu'"'"', added to SUS_KSTAT_HLIST\\n",\
\t\t\tinfo.virtual_pathname, info.real_pathname, new_entry->target_ino,\
\t\t\tnew_entry->info.spoofed_ino, new_entry->info.spoofed_dev,\
\t\t\tnew_entry->info.spoofed_nlink, new_entry->info.spoofed_size,\
\t\t\tnew_entry->info.spoofed_atime_tv_sec, new_entry->info.spoofed_mtime_tv_sec, new_entry->info.spoofed_ctime_tv_sec,\
\t\t\tnew_entry->info.spoofed_atime_tv_nsec, new_entry->info.spoofed_mtime_tv_nsec, new_entry->info.spoofed_ctime_tv_nsec,\
\t\t\tnew_entry->info.spoofed_blksize, new_entry->info.spoofed_blocks);\
#else\
\tSUSFS_LOGI("redirect: virtual: '"'"'%s'"'"', real: '"'"'%s'"'"', target_ino: '"'"'%lu'"'"', spoofed_ino: '"'"'%lu'"'"', spoofed_dev: '"'"'%lu'"'"', spoofed_nlink: '"'"'%u'"'"', spoofed_size: '"'"'%llu'"'"', spoofed_atime_tv_sec: '"'"'%ld'"'"', spoofed_mtime_tv_sec: '"'"'%ld'"'"', spoofed_ctime_tv_sec: '"'"'%ld'"'"', spoofed_atime_tv_nsec: '"'"'%ld'"'"', spoofed_mtime_tv_nsec: '"'"'%ld'"'"', spoofed_ctime_tv_nsec: '"'"'%ld'"'"', spoofed_blksize: '"'"'%lu'"'"', spoofed_blocks: '"'"'%llu'"'"', added to SUS_KSTAT_HLIST\\n",\
\t\t\tinfo.virtual_pathname, info.real_pathname, new_entry->target_ino,\
\t\t\tnew_entry->info.spoofed_ino, new_entry->info.spoofed_dev,\
\t\t\tnew_entry->info.spoofed_nlink, new_entry->info.spoofed_size,\
\t\t\tnew_entry->info.spoofed_atime_tv_sec, new_entry->info.spoofed_mtime_tv_sec, new_entry->info.spoofed_ctime_tv_sec,\
\t\t\tnew_entry->info.spoofed_atime_tv_nsec, new_entry->info.spoofed_mtime_tv_nsec, new_entry->info.spoofed_ctime_tv_nsec,\
\t\t\tnew_entry->info.spoofed_blksize, new_entry->info.spoofed_blocks);\
#endif\
\n\tinfo.err = 0;\
out_copy_to_user:\
\tif (copy_to_user(&((struct st_susfs_sus_kstat_redirect __user*)*user_info)->err, &info.err, sizeof(info.err))) {\
\t\tinfo.err = -EFAULT;\
\t}\
\tSUSFS_LOGI("kstat_redirect: EXIT ret=%d vpath='"'"'%s'"'"'\\n", info.err, info.virtual_pathname);\
}
    }' "$SUSFS_C"
    ((inject_count++)) || true
fi

# Validate
if ! grep -q 'susfs_add_sus_kstat_redirect' "$SUSFS_C"; then
    echo "FATAL: susfs_add_sus_kstat_redirect function injection failed"
    exit 1
fi
}

inject_open_redirect_all() {
echo "=== inject-susfs-open-redirect-all ==="

# --- 1. CMD code in susfs_def.h ---
if grep -q 'CMD_SUSFS_ADD_OPEN_REDIRECT_ALL' "$SUSFS_DEF_H"; then
    echo "[=] CMD_SUSFS_ADD_OPEN_REDIRECT_ALL already present in susfs_def.h"
else
    echo "[+] Injecting CMD_SUSFS_ADD_OPEN_REDIRECT_ALL into susfs_def.h"
    sed -i '/CMD_SUSFS_ADD_OPEN_REDIRECT 0x555c0/a #define CMD_SUSFS_ADD_OPEN_REDIRECT_ALL 0x555c1' "$SUSFS_DEF_H"
    ((inject_count++)) || true
fi

# --- 2. AS_FLAGS and BIT in susfs_def.h ---
if grep -q 'AS_FLAGS_OPEN_REDIRECT_ALL' "$SUSFS_DEF_H"; then
    echo "[=] AS_FLAGS_OPEN_REDIRECT_ALL already present in susfs_def.h"
else
    echo "[+] Injecting AS_FLAGS_OPEN_REDIRECT_ALL into susfs_def.h"
    sed -i '/^#define AS_FLAGS_SUS_MAP/a #define AS_FLAGS_OPEN_REDIRECT_ALL 40' "$SUSFS_DEF_H"
    ((inject_count++)) || true
fi

if grep -q 'BIT_OPEN_REDIRECT_ALL' "$SUSFS_DEF_H"; then
    echo "[=] BIT_OPEN_REDIRECT_ALL already present in susfs_def.h"
else
    echo "[+] Injecting BIT_OPEN_REDIRECT_ALL into susfs_def.h"
    sed -i '/^#define AS_FLAGS_OPEN_REDIRECT_ALL/a #define BIT_OPEN_REDIRECT_ALL BIT(40)' "$SUSFS_DEF_H"
    ((inject_count++)) || true
fi

# Validate
if ! grep -q 'CMD_SUSFS_ADD_OPEN_REDIRECT_ALL' "$SUSFS_DEF_H"; then
    echo "FATAL: CMD_SUSFS_ADD_OPEN_REDIRECT_ALL injection failed"
    exit 1
fi
if ! grep -q 'AS_FLAGS_OPEN_REDIRECT_ALL' "$SUSFS_DEF_H"; then
    echo "FATAL: AS_FLAGS_OPEN_REDIRECT_ALL injection failed"
    exit 1
fi
if ! grep -q 'BIT_OPEN_REDIRECT_ALL' "$SUSFS_DEF_H"; then
    echo "FATAL: BIT_OPEN_REDIRECT_ALL injection failed"
    exit 1
fi

# --- 3. Struct in susfs.h ---
if grep -q 'st_susfs_open_redirect_all_hlist' "$SUSFS_H"; then
    echo "[=] st_susfs_open_redirect_all_hlist already present in susfs.h"
else
    echo "[+] Injecting st_susfs_open_redirect_all_hlist struct into susfs.h"
    # Anchor: after the closing }; of st_susfs_open_redirect_hlist
    sed -i '/^struct st_susfs_open_redirect_hlist {/,/^};/ {
        /^};/ a\
\
struct st_susfs_open_redirect_all_hlist {\
\tunsigned long                           target_ino;\
\tchar                                    target_pathname[SUSFS_MAX_LEN_PATHNAME];\
\tchar                                    redirected_pathname[SUSFS_MAX_LEN_PATHNAME];\
\tstruct hlist_node                       node;\
};
    }' "$SUSFS_H"
    ((inject_count++)) || true
fi

# Validate
if ! grep -q 'st_susfs_open_redirect_all_hlist' "$SUSFS_H"; then
    echo "FATAL: st_susfs_open_redirect_all_hlist struct injection failed"
    exit 1
fi

# --- 4. Function declarations in susfs.h ---
if grep -q 'susfs_add_open_redirect_all' "$SUSFS_H"; then
    echo "[=] susfs_add_open_redirect_all declaration already present in susfs.h"
else
    echo "[+] Injecting open_redirect_all declarations into susfs.h"
    sed -i '/void susfs_add_open_redirect(void __user \*\*user_info);/a void susfs_add_open_redirect_all(void __user **user_info);\nstruct filename* susfs_get_redirected_path_all(unsigned long ino);' "$SUSFS_H"
    ((inject_count++)) || true
fi

# Validate
if ! grep -q 'susfs_add_open_redirect_all' "$SUSFS_H"; then
    echo "FATAL: susfs_add_open_redirect_all declaration injection failed"
    exit 1
fi

# --- 5. Hash table + spinlock in susfs.c ---
if grep -q 'OPEN_REDIRECT_ALL_HLIST' "$SUSFS_C"; then
    echo "[=] OPEN_REDIRECT_ALL_HLIST already present in susfs.c"
else
    echo "[+] Injecting OPEN_REDIRECT_ALL hash table into susfs.c"
    sed -i '/DEFINE_HASHTABLE(OPEN_REDIRECT_HLIST, 10);/a static DEFINE_SPINLOCK(susfs_spin_lock_open_redirect_all);\nstatic DEFINE_HASHTABLE(OPEN_REDIRECT_ALL_HLIST, 10);' "$SUSFS_C"
    ((inject_count++)) || true
fi

# Validate
if ! grep -q 'OPEN_REDIRECT_ALL_HLIST' "$SUSFS_C"; then
    echo "FATAL: OPEN_REDIRECT_ALL_HLIST injection failed"
    exit 1
fi

# --- 6. Three functions in susfs.c ---
if grep -q 'susfs_update_open_redirect_all_inode' "$SUSFS_C"; then
    echo "[=] open_redirect_all functions already present in susfs.c"
else
    echo "[+] Injecting open_redirect_all functions into susfs.c"
    # Anchor: after susfs_add_open_redirect() function
    # Find CMD_SUSFS_ADD_OPEN_REDIRECT -> ret log line and its closing brace
    sed -i '/CMD_SUSFS_ADD_OPEN_REDIRECT -> ret/,/^}/ {
        /^}/ a\
\
static int susfs_update_open_redirect_all_inode(struct st_susfs_open_redirect_all_hlist *new_entry) {\
\tstruct path path_target;\
\tstruct inode *inode_target;\
\tint err = 0;\
\n\terr = kern_path(new_entry->target_pathname, LOOKUP_FOLLOW, &path_target);\
\tif (err) {\
\t\tSUSFS_LOGE("Failed opening file '"'"'%s'"'"'\\n", new_entry->target_pathname);\
\t\treturn err;\
\t}\
\n\tinode_target = d_inode(path_target.dentry);\
\tif (!inode_target) {\
\t\tSUSFS_LOGE("inode_target is NULL\\n");\
\t\terr = -EINVAL;\
\t\tgoto out_path_put_target;\
\t}\
\n\tspin_lock(&inode_target->i_lock);\
\tset_bit(AS_FLAGS_OPEN_REDIRECT_ALL, &inode_target->i_mapping->flags);\
\tspin_unlock(&inode_target->i_lock);\
\nout_path_put_target:\
\tpath_put(&path_target);\
\treturn err;\
}\
\
void susfs_add_open_redirect_all(void __user **user_info) {\
\tstruct st_susfs_open_redirect info = {0};\
\tstruct st_susfs_open_redirect_all_hlist *new_entry;\
\n\tif (copy_from_user(&info, (struct st_susfs_open_redirect __user*)*user_info, sizeof(info))) {\
\t\tinfo.err = -EFAULT;\
\t\tgoto out_copy_to_user;\
\t}\
\n\tnew_entry = kmalloc(sizeof(struct st_susfs_open_redirect_all_hlist), GFP_KERNEL);\
\tif (!new_entry) {\
\t\tinfo.err = -ENOMEM;\
\t\tgoto out_copy_to_user;\
\t}\
\n\tnew_entry->target_ino = info.target_ino;\
\tstrncpy(new_entry->target_pathname, info.target_pathname, SUSFS_MAX_LEN_PATHNAME-1);\
\tnew_entry->target_pathname[SUSFS_MAX_LEN_PATHNAME-1] = 0;\
\tstrncpy(new_entry->redirected_pathname, info.redirected_pathname, SUSFS_MAX_LEN_PATHNAME-1);\
\tnew_entry->redirected_pathname[SUSFS_MAX_LEN_PATHNAME-1] = 0;\
\tif (susfs_update_open_redirect_all_inode(new_entry)) {\
\t\tSUSFS_LOGE("failed adding path '"'"'%s'"'"' to OPEN_REDIRECT_ALL_HLIST\\n", new_entry->target_pathname);\
\t\tkfree(new_entry);\
\t\tinfo.err = -EINVAL;\
\t\tgoto out_copy_to_user;\
\t}\
\n\tspin_lock(&susfs_spin_lock_open_redirect_all);\
\thash_add_rcu(OPEN_REDIRECT_ALL_HLIST, &new_entry->node, info.target_ino);\
\tspin_unlock(&susfs_spin_lock_open_redirect_all);\
\tSUSFS_LOGI("target_ino: '"'"'%lu'"'"', target_pathname: '"'"'%s'"'"' redirected_pathname: '"'"'%s'"'"', is successfully added to OPEN_REDIRECT_ALL_HLIST\\n",\
\t\t\tnew_entry->target_ino, new_entry->target_pathname, new_entry->redirected_pathname);\
\tinfo.err = 0;\
out_copy_to_user:\
\tif (copy_to_user(&((struct st_susfs_open_redirect __user*)*user_info)->err, &info.err, sizeof(info.err))) {\
\t\tinfo.err = -EFAULT;\
\t}\
\tSUSFS_LOGI("CMD_SUSFS_ADD_OPEN_REDIRECT_ALL -> ret: %d\\n", info.err);\
}\
\
struct filename* susfs_get_redirected_path_all(unsigned long ino) {\
\tstruct st_susfs_open_redirect_all_hlist *entry;\
\tchar tmp_path[SUSFS_MAX_LEN_PATHNAME];\
\tbool found = false;\
\n\trcu_read_lock();\
\thash_for_each_possible_rcu(OPEN_REDIRECT_ALL_HLIST, entry, node, ino) {\
\t\tif (entry->target_ino == ino) {\
\t\t\tSUSFS_LOGI("Redirect_all for ino: %lu\\n", ino);\
\t\t\tstrncpy(tmp_path, entry->redirected_pathname, SUSFS_MAX_LEN_PATHNAME - 1);\
\t\t\ttmp_path[SUSFS_MAX_LEN_PATHNAME - 1] = 0;\
\t\t\tfound = true;\
\t\t\tbreak;\
\t\t}\
\t}\
\trcu_read_unlock();\
\treturn found ? getname_kernel(tmp_path) : ERR_PTR(-ENOENT);\
}
    }' "$SUSFS_C"
    ((inject_count++)) || true
fi

# Validate
if ! grep -q 'susfs_add_open_redirect_all' "$SUSFS_C"; then
    echo "FATAL: susfs_add_open_redirect_all function injection failed"
    exit 1
fi
if ! grep -q 'susfs_get_redirected_path_all' "$SUSFS_C"; then
    echo "FATAL: susfs_get_redirected_path_all function injection failed"
    exit 1
fi
if ! grep -q 'susfs_update_open_redirect_all_inode' "$SUSFS_C"; then
    echo "FATAL: susfs_update_open_redirect_all_inode function injection failed"
    exit 1
fi
}

inject_unicode_filter_func() {
echo "=== inject-susfs-unicode-filter-func ==="

# --- 1. #include <linux/limits.h> in susfs.c ---
if grep -q '#include <linux/limits.h>' "$SUSFS_C"; then
    echo "[=] #include <linux/limits.h> already present in susfs.c"
else
    echo "[+] Injecting #include <linux/limits.h> into susfs.c"
    sed -i '/#include <linux\/susfs.h>/a #include <linux/limits.h>' "$SUSFS_C"
    ((inject_count++)) || true
fi

if ! grep -q '#include <linux/limits.h>' "$SUSFS_C"; then
    echo "FATAL: #include <linux/limits.h> injection failed"
    exit 1
fi

# --- 2. Unicode filter function body in susfs.c ---
# Anchor: after the SUSFS_LOGE macro line, before susfs_starts_with.
# The block goes between the #endif of the log macros and the next function.
if grep -q 'susfs_check_unicode_bypass' "$SUSFS_C"; then
    echo "[=] susfs_check_unicode_bypass already present in susfs.c"
else
    echo "[+] Injecting susfs_check_unicode_bypass function into susfs.c"
    # Anchor on the SUSFS_LOGE macro (last line of the log config block)
    sed -i '/^#define SUSFS_LOGE/,/^#endif/ {
        /^#endif/ a\
\
#ifdef CONFIG_KSU_SUSFS_UNICODE_FILTER\
\
static const unsigned char PAT_RTL_OVERRIDE[]   = {0xE2, 0x80, 0xAE};\
static const unsigned char PAT_LTR_OVERRIDE[]   = {0xE2, 0x80, 0xAD};\
static const unsigned char PAT_RTL_EMBED[]      = {0xE2, 0x80, 0xAB};\
static const unsigned char PAT_LTR_EMBED[]      = {0xE2, 0x80, 0xAA};\
static const unsigned char PAT_ZWSP[]           = {0xE2, 0x80, 0x8B};\
static const unsigned char PAT_ZWNJ[]           = {0xE2, 0x80, 0x8C};\
static const unsigned char PAT_ZWJ[]            = {0xE2, 0x80, 0x8D};\
static const unsigned char PAT_BOM[]            = {0xEF, 0xBB, 0xBF};\
\
bool susfs_check_unicode_bypass(const char __user *filename)\
{\
\tchar *buf;\
\tunsigned int uid;\
\tbool blocked = false;\
\tlong len;\
\tint i;\
\
\tif (!filename)\
\t\treturn false;\
\
\tuid = current_uid().val;\
\tif (uid == 0 || uid == 1000)\
\t\treturn false;\
\
\tbuf = __getname();\
\tif (!buf)\
\t\treturn false;\
\
\tlen = strncpy_from_user(buf, filename, PATH_MAX - 1);\
\tif (len <= 0) {\
\t\t__putname(buf);\
\t\treturn false;\
\t}\
\tbuf[len] = 0;\
\
\tfor (i = 0; i < len; i++) {\
\t\tunsigned char c = (unsigned char)buf[i];\
\
\t\tif (c <= 127)\
\t\t\tcontinue;\
\
\t\tif (i + 2 < len) {\
\t\t\tif (memcmp(&buf[i], PAT_RTL_OVERRIDE, 3) == 0 ||\
\t\t\t    memcmp(&buf[i], PAT_LTR_OVERRIDE, 3) == 0 ||\
\t\t\t    memcmp(&buf[i], PAT_RTL_EMBED, 3) == 0 ||\
\t\t\t    memcmp(&buf[i], PAT_LTR_EMBED, 3) == 0 ||\
\t\t\t    memcmp(&buf[i], PAT_ZWSP, 3) == 0 ||\
\t\t\t    memcmp(&buf[i], PAT_ZWNJ, 3) == 0 ||\
\t\t\t    memcmp(&buf[i], PAT_ZWJ, 3) == 0 ||\
\t\t\t    memcmp(&buf[i], PAT_BOM, 3) == 0) {\
\t\t\t\tSUSFS_LOGI("unicode: blocked pattern uid=%u\\n", uid);\
\t\t\t\tblocked = true;\
\t\t\t\tbreak;\
\t\t\t}\
\t\t}\
\
\t\tif (c == 0xD0 || c == 0xD1) {\
\t\t\tSUSFS_LOGI("unicode: blocked cyrillic uid=%u\\n", uid);\
\t\t\tblocked = true;\
\t\t\tbreak;\
\t\t}\
\
\t\tif (c == 0xCC || (c == 0xCD && i + 1 < len && (unsigned char)buf[i+1] <= 0xAF)) {\
\t\t\tSUSFS_LOGI("unicode: blocked diacritical uid=%u\\n", uid);\
\t\t\tblocked = true;\
\t\t\tbreak;\
\t\t}\
\
\t\tSUSFS_LOGI("unicode: blocked byte 0x%02x uid=%u\\n", c, uid);\
\t\tblocked = true;\
\t\tbreak;\
\t}\
\t__putname(buf);\
\treturn blocked;\
}\
#endif
    }' "$SUSFS_C"
    ((inject_count++)) || true
fi

if ! grep -q 'susfs_check_unicode_bypass' "$SUSFS_C"; then
    echo "FATAL: susfs_check_unicode_bypass function injection failed"
    exit 1
fi

# --- 3. Declaration in susfs.h ---
# Anchor: before the final #endif that closes the header guard
if grep -q 'susfs_check_unicode_bypass' "$SUSFS_H"; then
    echo "[=] susfs_check_unicode_bypass declaration already present in susfs.h"
else
    echo "[+] Injecting susfs_check_unicode_bypass declaration into susfs.h"
    # Insert before susfs_init declaration as a reliable anchor near the end
    sed -i '/^void susfs_init(void);/a \
\
#ifdef CONFIG_KSU_SUSFS_UNICODE_FILTER\
bool susfs_check_unicode_bypass(const char __user *filename);\
#endif' "$SUSFS_H"
    ((inject_count++)) || true
fi

if ! grep -q 'susfs_check_unicode_bypass' "$SUSFS_H"; then
    echo "FATAL: susfs_check_unicode_bypass declaration injection failed"
    exit 1
fi
}

# Execution order matches gki-build.yml
inject_kstat_redirect
inject_open_redirect_all
inject_unicode_filter_func

echo "=== Done: $inject_count injections applied ==="
