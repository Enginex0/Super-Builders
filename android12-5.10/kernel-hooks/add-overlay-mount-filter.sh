#!/bin/bash
# Hides overlay mounts from umounted processes in proc_namespace.c.
# Runs AFTER SUSFS GKI patch. MUST run BEFORE add-mount-display.sh.
# Usage: ./add-overlay-mount-filter.sh <KERNEL_COMMON_DIR>
set -e
KERNEL_DIR="$1"
PROC_NS="$KERNEL_DIR/fs/proc_namespace.c"
[ -f "$PROC_NS" ] || { echo "FATAL: $PROC_NS not found"; exit 1; }
echo "=== add-overlay-mount-filter ==="

grep -q '0x794c7630' "$PROC_NS" && { echo "[=] Already present"; exit 0; }

grep -q 'susfs_hide_sus_mnts_for_non_su_procs' "$PROC_NS" || {
    echo "FATAL: SUSFS SUS_MOUNT block not found — apply SUSFS GKI patch first"; exit 1; }

cp "$PROC_NS" "${PROC_NS}.bak"

# Add extern zeromount_hide_overlays after the SUSFS extern declarations
awk '
/extern bool susfs_is_current_ksu_domain\(void\);/ {
    print
    print "#ifdef CONFIG_ZEROMOUNT"
    print "extern bool zeromount_hide_overlays;"
    print "#endif"
    next
}
{ print }
' "$PROC_NS" > "${PROC_NS}.tmp" && mv "${PROC_NS}.tmp" "$PROC_NS"

# Inject overlay filter after each SUS_MOUNT #endif (3 occurrences — one per show_* function)
awk '
/r->mnt_id >= DEFAULT_KSU_MNT_ID/ { in_sus = 1 }
in_sus && /^#endif/ {
    print
    print ""
    print "#if defined(CONFIG_KSU_SUSFS_SUS_MOUNT) && defined(CONFIG_ZEROMOUNT)"
    print "\tif (zeromount_hide_overlays &&"
    print "\t    sb->s_magic == 0x794c7630 &&"
    print "\t    susfs_is_current_proc_umounted())"
    print "\t{"
    print "\t\treturn 0;"
    print "\t}"
    print "#endif"
    in_sus = 0
    next
}
{ print }
' "$PROC_NS" > "${PROC_NS}.tmp" && mv "${PROC_NS}.tmp" "$PROC_NS"

count=$(grep -c '0x794c7630' "$PROC_NS" || true)
[ "$count" -eq 3 ] || { echo "FATAL: expected 3 overlay blocks, got $count"; mv "${PROC_NS}.bak" "$PROC_NS"; exit 1; }
rm -f "${PROC_NS}.bak"
echo "[+] Overlay mount filter injected (3 show_* functions)"
