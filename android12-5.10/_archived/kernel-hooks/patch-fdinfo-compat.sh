#!/bin/bash
# Cross-sublevel fdinfo.c compat fix for SUSFS GKI patch rejects.
# Older sublevels use IN_ALL_EVENTS + ignored_mask:%x; newer use
# inotify_mark_user_mask + ignored_mask:0. This detects which is
# present and injects the SUS_MOUNT block accordingly.
# Usage: ./patch-fdinfo-compat.sh KERNEL_DIR
set -e

KERNEL_DIR="${1:?KERNEL_COMMON_DIR required}"
FDINFO="$KERNEL_DIR/fs/notify/fdinfo.c"
REJ="$FDINFO.rej"

[ -f "$FDINFO" ] || { echo "FATAL: $FDINFO not found"; exit 1; }

if [ ! -f "$REJ" ]; then
    echo "[=] No fdinfo.c reject found, GKI patch applied cleanly"
    exit 0
fi

if grep -q 'out_seq_printf' "$FDINFO"; then
    echo "[=] SUSFS SUS_MOUNT block already present in fdinfo.c"
    rm -f "$REJ"
    exit 0
fi

if grep -q 'IN_ALL_EVENTS' "$FDINFO"; then
    FORMAT="old"
    echo "[+] Detected OLD format (IN_ALL_EVENTS + ignored_mask:%x)"
else
    FORMAT="new"
    echo "[+] Detected NEW format (inotify_mark_user_mask + ignored_mask:0)"
fi

# Both formats share the same structure, differing only in mask/seq_printf args
generate_awk_program() {
    local mask_decl="$1" seq_printf_args="$2"

    cat <<'PREAMBLE'
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
PREAMBLE

    # Format-specific lines
    [ -n "$mask_decl" ] && printf '    print "%s"\n' "$mask_decl"

    cat <<'MIDDLE'
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
MIDDLE

    printf '    print "%s"\n' "$seq_printf_args"

    cat <<'TAIL'
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
TAIL
}

if [ "$FORMAT" = "old" ]; then
    AWK_PROG=$(generate_awk_program \
        '\t\t\tu32 fmask = mark->mask & IN_ALL_EVENTS;' \
        '\t\t\tseq_printf(m, "inotify wd:%x ino:%lx sdev:%x mask:%x ignored_mask:%x ",\n\t\t\t\t\tinode_mark->wd, path.dentry->d_inode->i_ino, path.dentry->d_inode->i_sb->s_dev,\n\t\t\t\t\tfmask, mark->ignored_mask);')
else
    AWK_PROG=$(generate_awk_program \
        "" \
        '\t\t\tseq_printf(m, "inotify wd:%x ino:%lx sdev:%x mask:%x ignored_mask:0 ",\n\t\t\t\t\tinode_mark->wd, path.dentry->d_inode->i_ino, path.dentry->d_inode->i_sb->s_dev,\n\t\t\t\t\tinotify_mark_user_mask(mark));')
fi

awk "$AWK_PROG" "$FDINFO" > "$FDINFO.tmp" && mv "$FDINFO.tmp" "$FDINFO"

grep -q 'out_seq_printf' "$FDINFO" || { echo "FATAL: SUSFS SUS_MOUNT injection failed in fdinfo.c"; exit 1; }

rm -f "$REJ"
echo "[+] fdinfo.c cross-sublevel fix applied"
