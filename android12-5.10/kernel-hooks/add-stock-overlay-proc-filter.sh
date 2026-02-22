#!/bin/bash
# add-stock-overlay-proc-filter.sh
# Injects susfs_is_mount_hidden() filter into show_vfsmnt, show_mountinfo,
# show_vfsstat in fs/proc_namespace.c. Runs AFTER the GKI patch.
#
# The existing GKI patch adds a CONFIG_KSU_SUSFS_SUS_MOUNT block per function
# that hides KSU mounts (mnt_id >= 500000). We inject an additional block
# inside the same #ifdef that hides per-mount registered stock OEM overlays.
#
# Safety: only filters app processes post-setuid (TIF_PROC_UMOUNTED flag).
# System daemons, init, and KSU root shell always see all mounts.
#
# Usage: ./add-stock-overlay-proc-filter.sh <KERNEL_COMMON_DIR>

set -e

KERNEL_DIR="${1:?Usage: $0 <KERNEL_COMMON_DIR>}"
PROC_NS="$KERNEL_DIR/fs/proc_namespace.c"

if [ ! -f "$PROC_NS" ]; then
    echo "FATAL: $PROC_NS not found"
    exit 1
fi

echo "=== add-stock-overlay-proc-filter ==="
echo "    Target: $PROC_NS"

if grep -q 'susfs_is_mount_hidden' "$PROC_NS"; then
    echo "[=] susfs_is_mount_hidden filter already present"
    exit 0
fi

# Verify the SUS_MOUNT blocks exist (from GKI patch)
mount_block_count=$(grep -c 'susfs_hide_sus_mnts_for_non_su_procs' "$PROC_NS" || true)
if [ "$mount_block_count" -lt 3 ]; then
    echo "FATAL: expected 3 susfs_hide_sus_mnts_for_non_su_procs blocks, found $mount_block_count"
    echo "       GKI patch may not have been applied correctly"
    exit 1
fi

echo "[+] Injecting susfs_is_mount_hidden into $mount_block_count show_* functions"

# For each CONFIG_KSU_SUSFS_SUS_MOUNT block (one per show_ function),
# insert a new filter block before the #endif that closes it.
# The awk script finds 'susfs_hide_sus_mnts_for_non_su_procs', then
# at the next '#endif' inserts our block above it.
awk '
/susfs_hide_sus_mnts_for_non_su_procs/ {
    in_sus_mount_block = 1
}
in_sus_mount_block && /^#endif/ {
    print "\t{"
    print "\t\tstruct mount *r_hm = real_mount(mnt);"
    print "\t\tif (susfs_is_mount_hidden(r_hm->mnt_id) &&"
    print "\t\t    susfs_is_current_proc_umounted() &&"
    print "\t\t    !susfs_is_current_ksu_domain())"
    print "\t\t{"
    print "\t\t\treturn 0;"
    print "\t\t}"
    print "\t}"
    in_sus_mount_block = 0
}
{ print }
' "$PROC_NS" > "$PROC_NS.tmp" && mv "$PROC_NS.tmp" "$PROC_NS"

# Validate
count=$(grep -c 'susfs_is_mount_hidden' "$PROC_NS" || true)
if [ "$count" -lt 3 ]; then
    echo "FATAL: expected 3 susfs_is_mount_hidden checks, found $count"
    exit 1
fi

echo "=== Done: $count filter blocks injected ==="
