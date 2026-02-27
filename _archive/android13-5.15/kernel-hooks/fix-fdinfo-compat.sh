#!/bin/bash
# Fixes SUSFS GKI patch hunk failure on fs/notify/fdinfo.c for older sublevels.
#
# The upstream SUSFS GKI patch targets the newest sublevel where fdinfo.c uses
# inotify_mark_user_mask() and "ignored_mask:0". Older sublevels (≤~148) use
# "u32 mask = mark->mask & IN_ALL_EVENTS" and "ignored_mask:%x" instead.
#
# This script detects which format is present and injects the SUS_MOUNT block
# with the correct seq_printf format for the sublevel.
#
# Usage: ./fix-susfs-fdinfo-compat.sh <KERNEL_COMMON_DIR>

set -e

KERNEL_DIR="$1"
FDINFO="$KERNEL_DIR/fs/notify/fdinfo.c"

if [ -z "$KERNEL_DIR" ] || [ ! -f "$FDINFO" ]; then
    echo "Usage: $0 <KERNEL_COMMON_DIR>"
    exit 1
fi

# Only run if the GKI patch left a reject on fdinfo.c
REJ="$FDINFO.rej"
if [ ! -f "$REJ" ]; then
    echo "[=] No fdinfo.c reject found, GKI patch applied cleanly"
    exit 0
fi

echo "=== fix-susfs-fdinfo-compat ==="
echo "    Reject found, applying cross-sublevel fdinfo.c fix"

# Already injected?
if grep -q 'out_seq_printf' "$FDINFO"; then
    echo "[=] SUSFS SUS_MOUNT block already present in fdinfo.c"
    rm -f "$REJ"
    exit 0
fi

# Detect old vs new format
if grep -q 'IN_ALL_EVENTS' "$FDINFO"; then
    FORMAT="old"
    echo "    Detected OLD format (IN_ALL_EVENTS + ignored_mask:%x)"
else
    FORMAT="new"
    echo "    Detected NEW format (inotify_mark_user_mask + ignored_mask:0)"
fi

if [ "$FORMAT" = "old" ]; then
    # Old format: anchor on the u32 mask declaration to avoid C89 mixed-declaration error
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
    # New format: inject SUSFS block before seq_printf (same as upstream patch)
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

# Verify
if ! grep -q 'out_seq_printf' "$FDINFO"; then
    echo "FATAL: SUSFS SUS_MOUNT injection failed in fdinfo.c"
    exit 1
fi

rm -f "$REJ"
echo "    fdinfo.c cross-sublevel fix applied"
echo "=== Done ==="
