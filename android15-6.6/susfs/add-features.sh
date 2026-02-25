#!/bin/bash
# Injects custom SUSFS features, zeromount coupling, and supercall dispatch.
#
# Features:
#   - kstat_redirect (CMD + struct + function body)
#   - open_redirect_all (CMD + AS_FLAGS + struct + 3 functions)
#   - unicode_filter (byte pattern filter for bidi/ZW/cyrillic attacks)
#   - BUILD_BUG_ON guards for address_space flag bit collisions
#   - zeromount coupling (extern + inline wrapper + uid exclusion)
#   - supercall dispatch handlers for kstat_redirect + open_redirect_all
#
# Usage: ./add-features.sh <SUSFS_DIR>

set -euo pipefail

SUSFS_DIR="${1:?Usage: $0 <SUSFS_DIR>}"

SUSFS_DEF_H="$SUSFS_DIR/include/linux/susfs_def.h"
SUSFS_H="$SUSFS_DIR/include/linux/susfs.h"
SUSFS_C="$SUSFS_DIR/fs/susfs.c"

for f in "$SUSFS_DEF_H" "$SUSFS_H" "$SUSFS_C"; do
    [ -f "$f" ] || { echo "FATAL: missing $f"; exit 1; }
done

inject_count=0

inject_kstat_redirect() {
    echo "=== kstat_redirect ==="

    # CMD code
    if ! grep -q 'CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT' "$SUSFS_DEF_H"; then
        echo "[+] CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT"
        sed -i '/CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY/a #define CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT 0x55573' "$SUSFS_DEF_H"
        ((inject_count++)) || true
    fi
    grep -q 'CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT' "$SUSFS_DEF_H" || { echo "FATAL: CMD injection failed"; exit 1; }

    # Struct
    if ! grep -q 'st_susfs_sus_kstat_redirect' "$SUSFS_H"; then
        echo "[+] st_susfs_sus_kstat_redirect struct"
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
    grep -q 'st_susfs_sus_kstat_redirect' "$SUSFS_H" || { echo "FATAL: struct injection failed"; exit 1; }

    # Declaration
    if ! grep -q 'susfs_add_sus_kstat_redirect' "$SUSFS_H"; then
        echo "[+] susfs_add_sus_kstat_redirect declaration"
        sed -i '/void susfs_add_sus_kstat(void __user \*\*user_info);/a void susfs_add_sus_kstat_redirect(void __user **user_info);' "$SUSFS_H"
        ((inject_count++)) || true
    fi
    grep -q 'susfs_add_sus_kstat_redirect' "$SUSFS_H" || { echo "FATAL: declaration injection failed"; exit 1; }

    # Function body
    if ! grep -q 'susfs_add_sus_kstat_redirect' "$SUSFS_C"; then
        echo "[+] susfs_add_sus_kstat_redirect function body"
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
\thash_add_rcu(SUS_KSTAT_HLIST, &new_entry->node, new_entry->target_ino);\
\tif (virtual_entry) {\
\t\thash_add_rcu(SUS_KSTAT_HLIST, &virtual_entry->node, virtual_ino);\
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
    grep -q 'susfs_add_sus_kstat_redirect' "$SUSFS_C" || { echo "FATAL: function injection failed"; exit 1; }
}

inject_open_redirect_all() {
    echo "=== open_redirect_all ==="

    # CMD code
    if ! grep -q 'CMD_SUSFS_ADD_OPEN_REDIRECT_ALL' "$SUSFS_DEF_H"; then
        echo "[+] CMD_SUSFS_ADD_OPEN_REDIRECT_ALL"
        sed -i '/CMD_SUSFS_ADD_OPEN_REDIRECT 0x555c0/a #define CMD_SUSFS_ADD_OPEN_REDIRECT_ALL 0x555c1' "$SUSFS_DEF_H"
        ((inject_count++)) || true
    fi

    # AS_FLAGS + BIT
    if ! grep -q 'AS_FLAGS_OPEN_REDIRECT_ALL' "$SUSFS_DEF_H"; then
        echo "[+] AS_FLAGS_OPEN_REDIRECT_ALL"
        sed -i '/^#define AS_FLAGS_SUS_MAP/a #define AS_FLAGS_OPEN_REDIRECT_ALL 40' "$SUSFS_DEF_H"
        ((inject_count++)) || true
    fi

    if ! grep -q 'BIT_OPEN_REDIRECT_ALL' "$SUSFS_DEF_H"; then
        echo "[+] BIT_OPEN_REDIRECT_ALL"
        sed -i '/^#define AS_FLAGS_OPEN_REDIRECT_ALL/a #define BIT_OPEN_REDIRECT_ALL BIT(40)' "$SUSFS_DEF_H"
        ((inject_count++)) || true
    fi

    for sym in CMD_SUSFS_ADD_OPEN_REDIRECT_ALL AS_FLAGS_OPEN_REDIRECT_ALL BIT_OPEN_REDIRECT_ALL; do
        grep -q "$sym" "$SUSFS_DEF_H" || { echo "FATAL: $sym injection failed"; exit 1; }
    done

    # Struct
    if ! grep -q 'st_susfs_open_redirect_all_hlist' "$SUSFS_H"; then
        echo "[+] st_susfs_open_redirect_all_hlist struct"
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
    grep -q 'st_susfs_open_redirect_all_hlist' "$SUSFS_H" || { echo "FATAL: struct injection failed"; exit 1; }

    # Declarations
    if ! grep -q 'susfs_add_open_redirect_all' "$SUSFS_H"; then
        echo "[+] open_redirect_all declarations"
        sed -i '/void susfs_add_open_redirect(void __user \*\*user_info);/a void susfs_add_open_redirect_all(void __user **user_info);\nstruct filename* susfs_get_redirected_path_all(unsigned long ino);' "$SUSFS_H"
        ((inject_count++)) || true
    fi
    grep -q 'susfs_add_open_redirect_all' "$SUSFS_H" || { echo "FATAL: declaration injection failed"; exit 1; }

    # Hash table + spinlock
    if ! grep -q 'OPEN_REDIRECT_ALL_HLIST' "$SUSFS_C"; then
        echo "[+] OPEN_REDIRECT_ALL_HLIST hash table"
        sed -i '/DEFINE_HASHTABLE(OPEN_REDIRECT_HLIST, 10);/a static DEFINE_SPINLOCK(susfs_spin_lock_open_redirect_all);\nstatic DEFINE_HASHTABLE(OPEN_REDIRECT_ALL_HLIST, 10);' "$SUSFS_C"
        ((inject_count++)) || true
    fi
    grep -q 'OPEN_REDIRECT_ALL_HLIST' "$SUSFS_C" || { echo "FATAL: hash table injection failed"; exit 1; }

    # Functions
    if ! grep -q 'susfs_update_open_redirect_all_inode' "$SUSFS_C"; then
        echo "[+] open_redirect_all functions"
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

    for sym in susfs_add_open_redirect_all susfs_get_redirected_path_all susfs_update_open_redirect_all_inode; do
        grep -q "$sym" "$SUSFS_C" || { echo "FATAL: $sym injection failed"; exit 1; }
    done

    # hash_add -> hash_add_rcu in writer
    if grep -q 'hash_add(OPEN_REDIRECT_ALL_HLIST' "$SUSFS_C"; then
        echo "[+] Converting hash_add to hash_add_rcu in open_redirect_all writer"
        sed -i 's/hash_add(OPEN_REDIRECT_ALL_HLIST,/hash_add_rcu(OPEN_REDIRECT_ALL_HLIST,/g' "$SUSFS_C"
        ((inject_count++)) || true
    fi
}

inject_unicode_filter() {
    echo "=== unicode_filter ==="

    # #include <linux/limits.h>
    if ! grep -q '#include <linux/limits.h>' "$SUSFS_C"; then
        echo "[+] limits.h include"
        sed -i '/#include <linux\/susfs.h>/a #include <linux/limits.h>' "$SUSFS_C"
        ((inject_count++)) || true
    fi
    grep -q '#include <linux/limits.h>' "$SUSFS_C" || { echo "FATAL: limits.h injection failed"; exit 1; }

    # Function body
    if ! grep -q 'susfs_check_unicode_bypass' "$SUSFS_C"; then
        echo "[+] susfs_check_unicode_bypass function"
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
\tchar buf[NAME_MAX + 1];\
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
\tlen = strncpy_from_user(buf, filename, NAME_MAX);\
\tif (len <= 0)\
\t\treturn false;\
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
\treturn blocked;\
}\
#endif
        }' "$SUSFS_C"
        ((inject_count++)) || true
    fi
    grep -q 'susfs_check_unicode_bypass' "$SUSFS_C" || { echo "FATAL: unicode function injection failed"; exit 1; }

    # Declaration in susfs.h
    if ! grep -q 'susfs_check_unicode_bypass' "$SUSFS_H"; then
        echo "[+] susfs_check_unicode_bypass declaration"
        sed -i '/^void susfs_init(void);/a \
\
#ifdef CONFIG_KSU_SUSFS_UNICODE_FILTER\
bool susfs_check_unicode_bypass(const char __user *filename);\
#endif' "$SUSFS_H"
        ((inject_count++)) || true
    fi
    grep -q 'susfs_check_unicode_bypass' "$SUSFS_H" || { echo "FATAL: declaration injection failed"; exit 1; }
}

inject_build_bug_on_guards() {
    echo "=== BUILD_BUG_ON guards (L5) ==="

    # pagemap.h include
    if ! grep -q '#include <linux/pagemap.h>' "$SUSFS_C"; then
        echo "[+] pagemap.h include"
        sed -i '/#include <linux\/susfs.h>/a #include <linux/pagemap.h>' "$SUSFS_C"
        ((inject_count++)) || true
    fi

    # Guards in susfs_init()
    if ! grep -q 'BUILD_BUG_ON.*AS_FLAGS_SUS_PATH' "$SUSFS_C"; then
        echo "[+] BUILD_BUG_ON guards"
        local bug_on_lines='\tBUILD_BUG_ON(AS_FLAGS_SUS_PATH <= AS_LARGE_FOLIO_SUPPORT);\
\tBUILD_BUG_ON(AS_FLAGS_SUS_MAP >= BITS_PER_LONG);\
\tBUILD_BUG_ON(AS_FLAGS_OPEN_REDIRECT_ALL >= BITS_PER_LONG);'
        if grep -q 'AS_FLAGS_SUS_PATH_PARENT' "$SUSFS_DEF_H"; then
            bug_on_lines="${bug_on_lines}"'\
\tBUILD_BUG_ON(AS_FLAGS_SUS_PATH_PARENT >= BITS_PER_LONG);'
        fi
        sed -i "/^void susfs_init(void) {/a \\
${bug_on_lines}" "$SUSFS_C"
        ((inject_count++)) || true
    fi
    grep -q 'BUILD_BUG_ON.*AS_FLAGS_SUS_PATH' "$SUSFS_C" || { echo "FATAL: BUILD_BUG_ON injection failed"; exit 1; }
}

inject_zeromount_coupling() {
    echo "=== zeromount coupling (M3) ==="

    # Extern + inline wrapper in susfs_def.h
    if ! grep -q 'zeromount_is_uid_blocked' "$SUSFS_DEF_H"; then
        echo "[+] zeromount coupling in susfs_def.h"
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
    grep -q 'zeromount_is_uid_blocked' "$SUSFS_DEF_H" || { echo "FATAL: zeromount coupling failed"; exit 1; }

    # uid exclusion check in is_i_uid_not_allowed()
    if ! grep -q 'susfs_is_uid_zeromount_excluded' "$SUSFS_C"; then
        echo "[+] zeromount check in is_i_uid_not_allowed"
        sed -i '/^static inline bool is_i_uid_not_allowed(uid_t i_uid) {$/a \\tif (susfs_is_uid_zeromount_excluded(current_uid().val))\n\t\treturn false;' "$SUSFS_C"
        ((inject_count++)) || true
    fi

    count=$(grep -c 'susfs_is_uid_zeromount_excluded' "$SUSFS_C" || true)
    [ "$count" -ge 1 ] || { echo "FATAL: zeromount check injection failed"; exit 1; }
}

inject_supercall_dispatch() {
    echo "=== supercall dispatch (C4) ==="

    local ksu_patch="$SUSFS_DIR/KernelSU/10_enable_susfs_for_ksu.patch"
    [ -f "$ksu_patch" ] || { echo "FATAL: missing $ksu_patch"; exit 1; }

    # kstat_redirect handler
    if ! grep -q 'CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT' "$ksu_patch"; then
        echo "[+] CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT handler"
        sed -i '/CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY/,/+        }/ {
            /+        }/ a\
+        if (cmd == CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT) {\
+            susfs_add_sus_kstat_redirect(arg);\
+            return 0;\
+        }
        }' "$ksu_patch"
        ((inject_count++)) || true
    fi
    grep -q 'CMD_SUSFS_ADD_SUS_KSTAT_REDIRECT' "$ksu_patch" || { echo "FATAL: kstat_redirect dispatch failed"; exit 1; }

    # open_redirect_all handler
    if ! grep -q 'CMD_SUSFS_ADD_OPEN_REDIRECT_ALL' "$ksu_patch"; then
        echo "[+] CMD_SUSFS_ADD_OPEN_REDIRECT_ALL handler"
        sed -i '/CMD_SUSFS_ADD_OPEN_REDIRECT)/,/+        }/ {
            /+        }/ a\
+        if (cmd == CMD_SUSFS_ADD_OPEN_REDIRECT_ALL) {\
+            susfs_add_open_redirect_all(arg);\
+            return 0;\
+        }
        }' "$ksu_patch"
        ((inject_count++)) || true
    fi
    grep -q 'CMD_SUSFS_ADD_OPEN_REDIRECT_ALL' "$ksu_patch" || { echo "FATAL: open_redirect_all dispatch failed"; exit 1; }
}

inject_kstat_redirect
inject_open_redirect_all
inject_unicode_filter
inject_build_bug_on_guards
inject_zeromount_coupling
inject_supercall_dispatch

echo "=== add-features done ($inject_count injections) ==="
