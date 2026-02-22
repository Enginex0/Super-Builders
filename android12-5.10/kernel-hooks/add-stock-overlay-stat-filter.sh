#!/bin/bash
# add-stock-overlay-stat-filter.sh
# Hooks vfs_getattr() and vfs_statx() in fs/stat.c to spoof overlay
# s_dev values, making overlay mounts invisible to stat()-based detection.
#
# Runs AFTER the GKI patch (kernel tree already patched with SUSFS).
#
# Usage: ./add-stock-overlay-stat-filter.sh <KERNEL_COMMON_DIR>

set -e

KERNEL_DIR="${1:?Usage: $0 <KERNEL_COMMON_DIR>}"
STAT_C="$KERNEL_DIR/fs/stat.c"

if [ ! -f "$STAT_C" ]; then
    echo "FATAL: $STAT_C not found"
    exit 1
fi

echo "=== add-stock-overlay-stat-filter ==="
echo "    Target: $STAT_C"

if grep -q 'susfs_spoof_stat_dev' "$STAT_C"; then
    echo "[=] susfs_spoof_stat_dev hook already present"
    exit 0
fi

# Add extern declaration near top of file (after existing includes)
if ! grep -q 'extern.*susfs_spoof_stat_dev' "$STAT_C"; then
    # Anchor: after the EXPORT_SYMBOL(vfs_getattr_nosec) line
    sed -i '/EXPORT_SYMBOL(vfs_getattr_nosec)/a \
\nextern void susfs_spoof_stat_dev(struct kstat *stat);\nextern bool susfs_is_mount_hidden(dev_t s_dev);\nextern bool susfs_is_current_proc_umounted(void);\nextern bool susfs_is_current_ksu_domain(void);' "$STAT_C"
    echo "[+] Added extern declarations"
fi

# Hook vfs_getattr(): change the return to capture retval and call spoof
# Original:
#   return vfs_getattr_nosec(path, stat, request_mask, query_flags);
# }
# EXPORT_SYMBOL(vfs_getattr);
#
# New:
#   retval = vfs_getattr_nosec(path, stat, request_mask, query_flags);
#   if (!retval)
#       susfs_spoof_stat_dev(stat);
#   return retval;

awk '
/^int vfs_getattr\(/ { in_vfs_getattr = 1 }
in_vfs_getattr && /return vfs_getattr_nosec\(/ {
    # Replace the return statement with capture + spoof + return
    sub(/return vfs_getattr_nosec/, "retval = vfs_getattr_nosec")
    # Remove trailing semicolon to add our block
    sub(/;[[:space:]]*$/, ";")
    print
    print "\tif (!retval)"
    print "\t\tsusfs_spoof_stat_dev(stat);"
    print "\treturn retval;"
    in_vfs_getattr = 0
    next
}
{ print }
' "$STAT_C" > "$STAT_C.tmp" && mv "$STAT_C.tmp" "$STAT_C"

echo "[+] Hooked vfs_getattr() with susfs_spoof_stat_dev()"

# Hook vfs_statx(): clear STATX_ATTR_MOUNT_ROOT for spoofed mounts
# After the existing line:
#   if (path.mnt->mnt_root == path.dentry)
#       stat->attributes |= STATX_ATTR_MOUNT_ROOT;
#   stat->attributes_mask |= STATX_ATTR_MOUNT_ROOT;
# Add:
#   if (susfs_is_current_proc_umounted() && !susfs_is_current_ksu_domain() &&
#       susfs_is_mount_hidden(real_mount(path.mnt)->mnt.mnt_sb->s_dev)) {
#       stat->attributes &= ~STATX_ATTR_MOUNT_ROOT;
#   }

# Simpler approach: clear MOUNT_ROOT if the stat->dev was spoofed
# We can check if stat->dev doesn't match the vfsmount's s_dev (meaning it was spoofed)
awk '
/stat->attributes_mask \|= STATX_ATTR_MOUNT_ROOT/ {
    print
    print "\tif (susfs_is_current_proc_umounted() &&"
    print "\t    !susfs_is_current_ksu_domain() &&"
    print "\t    susfs_is_mount_hidden(path.mnt->mnt_sb->s_dev))"
    print "\t{"
    print "\t\tstat->attributes &= ~STATX_ATTR_MOUNT_ROOT;"
    print "\t}"
    next
}
{ print }
' "$STAT_C" > "$STAT_C.tmp" && mv "$STAT_C.tmp" "$STAT_C"

echo "[+] Hooked vfs_statx() to clear STATX_ATTR_MOUNT_ROOT"

# Validate
if ! grep -q 'susfs_spoof_stat_dev' "$STAT_C"; then
    echo "FATAL: vfs_getattr hook injection failed"
    exit 1
fi
if grep -c 'STATX_ATTR_MOUNT_ROOT' "$STAT_C" | grep -q '^[4-9]'; then
    echo "[+] STATX_ATTR_MOUNT_ROOT filter validated"
else
    echo "WARN: STATX_ATTR_MOUNT_ROOT filter may not have injected correctly"
fi

echo "=== Done: stat filter hooks injected ==="
