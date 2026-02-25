#!/bin/bash
# Cross-sublevel fdinfo.c compat fix for SUSFS GKI patch rejects.
# Older sublevels use IN_ALL_EVENTS + ignored_mask:%x; newer use
# inotify_mark_user_mask + ignored_mask:0. This detects which is
# present and injects the SUS_MOUNT block accordingly.
#
# Also resolves GKI patch rejects on namespace.c and task_mmu.c
# for older 6.6 sublevels (<=58) where include layout differs.
#
# Usage: ./patch-fdinfo-compat.sh KERNEL_DIR
set -e

KERNEL_DIR="${1:?KERNEL_COMMON_DIR required}"
FDINFO="$KERNEL_DIR/fs/notify/fdinfo.c"
REJ="$FDINFO.rej"

[ -f "$FDINFO" ] || { echo "FATAL: $FDINFO not found"; exit 1; }

# --- Part 1: fdinfo.c SUS_MOUNT compat ---

fix_fdinfo() {
    if [ ! -f "$REJ" ]; then
        echo "[=] No fdinfo.c reject found, GKI patch applied cleanly"
        return 0
    fi

    if grep -q 'out_seq_printf' "$FDINFO"; then
        echo "[=] SUSFS SUS_MOUNT block already present in fdinfo.c"
        rm -f "$REJ"
        return 0
    fi

    if grep -q 'IN_ALL_EVENTS' "$FDINFO"; then
        FORMAT="old"
        echo "[+] Detected OLD format (IN_ALL_EVENTS + ignored_mask:%x)"
    else
        FORMAT="new"
        echo "[+] Detected NEW format (inotify_mark_user_mask + ignored_mask:0)"
    fi

    if [ "$FORMAT" = "old" ]; then
        awk '
        /u32 mask = mark->mask & IN_ALL_EVENTS;/ && !injected {
            print
            print "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
            print "\t\tmnt = real_mount(file->f_path.mnt);"
            print "\t\tif (likely(susfs_is_current_proc_umounted()) &&"
            print "\t\t\t\t\tmnt->mnt_id >= DEFAULT_KSU_MNT_ID)"
            print "\t\t{"
            print "\t\t\tstruct path path;"
            print "\t\t\tchar *pathname = kmalloc(PAGE_SIZE, GFP_KERNEL);"
            print "\t\t\tchar *dpath;"
            print "\t\t\tif (!pathname) {"
            print "\t\t\t\tgoto out_seq_printf;"
            print "\t\t\t}"
            print "\t\t\tdpath = d_path(&file->f_path, pathname, PAGE_SIZE);"
            print "\t\t\tif (!dpath) {"
            print "\t\t\t\tgoto out_free_pathname;"
            print "\t\t\t}"
            print "\t\t\tif (kern_path(dpath, 0, &path)) {"
            print "\t\t\t\tgoto out_free_pathname;"
            print "\t\t\t}"
            print "\t\t\tseq_printf(m, \"inotify wd:%x ino:%lx sdev:%x mask:%x ignored_mask:%x \","
            print "\t\t\t\t\tinode_mark->wd, path.dentry->d_inode->i_ino, path.dentry->d_inode->i_sb->s_dev,"
            print "\t\t\t\t\tmask, mark->ignored_mask);"
            print "\t\t\tshow_mark_fhandle(m, path.dentry->d_inode);"
            print "\t\t\tseq_putc(m, \047\\n\047);"
            print "\t\t\tiput(inode);"
            print "\t\t\tpath_put(&path);"
            print "\t\t\tkfree(pathname);"
            print "\t\t\treturn;"
            print "out_free_pathname:"
            print "\t\t\tkfree(pathname);"
            print "\t\t}"
            print "out_seq_printf:"
            print "\t\t;"
            print "#endif"
            injected = 1
            next
        }
        { print }
        ' "$FDINFO" > "$FDINFO.tmp" && mv "$FDINFO.tmp" "$FDINFO"
    else
        awk '
        /if \(inode\) \{/ && !injected {
            print
            print "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT"
            print "\t\tmnt = real_mount(file->f_path.mnt);"
            print "\t\tif (likely(susfs_is_current_proc_umounted()) &&"
            print "\t\t\t\t\tmnt->mnt_id >= DEFAULT_KSU_MNT_ID)"
            print "\t\t{"
            print "\t\t\tstruct path path;"
            print "\t\t\tchar *pathname = kmalloc(PAGE_SIZE, GFP_KERNEL);"
            print "\t\t\tchar *dpath;"
            print "\t\t\tif (!pathname) {"
            print "\t\t\t\tgoto out_seq_printf;"
            print "\t\t\t}"
            print "\t\t\tdpath = d_path(&file->f_path, pathname, PAGE_SIZE);"
            print "\t\t\tif (!dpath) {"
            print "\t\t\t\tgoto out_free_pathname;"
            print "\t\t\t}"
            print "\t\t\tif (kern_path(dpath, 0, &path)) {"
            print "\t\t\t\tgoto out_free_pathname;"
            print "\t\t\t}"
            print "\t\t\tseq_printf(m, \"inotify wd:%x ino:%lx sdev:%x mask:%x ignored_mask:0 \","
            print "\t\t\t\t\tinode_mark->wd, path.dentry->d_inode->i_ino, path.dentry->d_inode->i_sb->s_dev,"
            print "\t\t\t\t\tinotify_mark_user_mask(mark));"
            print "\t\t\tshow_mark_fhandle(m, path.dentry->d_inode);"
            print "\t\t\tseq_putc(m, \047\\n\047);"
            print "\t\t\tiput(inode);"
            print "\t\t\tpath_put(&path);"
            print "\t\t\tkfree(pathname);"
            print "\t\t\treturn;"
            print "out_free_pathname:"
            print "\t\t\tkfree(pathname);"
            print "\t\t}"
            print "out_seq_printf:"
            print "\t\t;"
            print "#endif"
            injected = 1
            next
        }
        { print }
        ' "$FDINFO" > "$FDINFO.tmp" && mv "$FDINFO.tmp" "$FDINFO"
    fi

    grep -q 'out_seq_printf' "$FDINFO" || { echo "FATAL: SUSFS SUS_MOUNT injection failed in fdinfo.c"; exit 1; }

    rm -f "$REJ"
    echo "[+] fdinfo.c cross-sublevel fix applied"
}

# --- Part 2: GKI patch reject compat for older 6.6 sublevels ---

fix_namespace_rej() {
    local rej="$KERNEL_DIR/fs/namespace.c.rej"
    local f="$KERNEL_DIR/fs/namespace.c"
    [ -f "$rej" ] || return 0

    echo "[+] Resolving namespace.c reject"

    if ! grep -q '#include <linux/susfs_def.h>' "$f"; then
        sed -i '/#include "pnode.h"/i\
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\
#include <linux/susfs_def.h>\
#endif' "$f"
    fi

    if ! grep -q 'extern bool susfs_is_current_ksu_domain' "$f"; then
        sed -i '/#include "internal.h"/a\
\
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\
extern bool susfs_is_current_ksu_domain(void);\
extern bool susfs_is_sdcard_android_data_decrypted __read_mostly;\
\
static atomic64_t susfs_ksu_mounts = ATOMIC64_INIT(0);\
\
#define CL_COPY_MNT_NS BIT(25)\
#endif' "$f"
    fi

    rm -f "$rej"
    echo "[+] namespace.c fixed"
}

fix_task_mmu_rej() {
    local rej="$KERNEL_DIR/fs/proc/task_mmu.c.rej"
    local f="$KERNEL_DIR/fs/proc/task_mmu.c"
    [ -f "$rej" ] || return 0

    echo "[+] Resolving task_mmu.c reject"

    awk '
    /^static ssize_t pagemap_read/ { in_func=1 }
    in_func && /int ret = 0, copied = 0;/ {
        print
        print "#ifdef CONFIG_KSU_SUSFS_SUS_MAP"
        print "\tstruct vm_area_struct *vma;"
        print "#endif"
        in_func=0
        next
    }
    { print }
    ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"

    rm -f "$rej"
    echo "[+] task_mmu.c fixed"
}

fix_fdinfo
fix_namespace_rej
fix_task_mmu_rej
