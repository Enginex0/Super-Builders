#!/bin/bash
# Validates overlayfs config and injects SUSFS Kconfig/defconfig entries.
# Usage: ./patch-config.sh KERNEL_DIR SUSFS_SOURCE [KCONFIG] [DEFCONFIG]
set -e

KERNEL_DIR="${1:?KERNEL_COMMON_DIR required}"
SUSFS_SOURCE="${2:?SUSFS_SOURCE required}"
KCONFIG="$3"
DEFCONFIG="${4:-$KERNEL_DIR/arch/arm64/configs/gki_defconfig}"

[ -f "$DEFCONFIG" ] || { echo "FATAL: gki_defconfig not found at $DEFCONFIG"; exit 1; }

validate_overlayfs() {
    grep -q 'CONFIG_OVERLAY_FS=y' "$DEFCONFIG" || {
        echo "FATAL: CONFIG_OVERLAY_FS not set in defconfig"
        exit 1
    }

    for sym in CONFIG_TMPFS_XATTR CONFIG_TMPFS_POSIX_ACL; do
        grep -q "^${sym}=" "$DEFCONFIG" || {
            echo "[+] Adding missing $sym=y"
            echo "${sym}=y" >> "$DEFCONFIG"
        }
    done

    echo "[+] Overlayfs validated"
}

KCONFIG_ENTRIES=(
    "susfs_add_sus_kstat_redirect|KSU_SUSFS_SUS_KSTAT_REDIRECT|SUSFS kstat redirect|Redirects kstat lookups to real file metadata for spoofed paths.|KSU_SUSFS_SUS_KSTAT"
    "susfs_add_open_redirect_all|KSU_SUSFS_OPEN_REDIRECT_ALL|SUSFS open redirect for all UIDs|Extends open redirect to all UIDs instead of only root/system.|KSU_SUSFS_OPEN_REDIRECT"
    "susfs_check_unicode_bypass|KSU_SUSFS_UNICODE_FILTER|Unicode Filter (blocks scoped storage bypass)|Blocks filesystem path attacks using unicode characters.|KSU_SUSFS"
)

inject_kconfig_entries() {
    [ -n "$KCONFIG" ] && [ -f "$KCONFIG" ] || return 0

    local count=0
    for entry in "${KCONFIG_ENTRIES[@]}"; do
        IFS='|' read -r func config desc help_text depends_on <<< "$entry"
        [ -z "$depends_on" ] && depends_on="KSU_SUSFS"

        grep -q "$func" "$SUSFS_SOURCE" 2>/dev/null || {
            echo "[-] $func not in source, skipping Kconfig"
            continue
        }

        grep -q "$config" "$KCONFIG" && {
            echo "[=] $config already in Kconfig"
            continue
        }

        echo "[+] Adding $config to Kconfig (depends on $depends_on)"
        printf '\nconfig %s\n    bool "%s"\n    depends on %s\n    default y\n    help\n      %s\n' \
            "$config" "$desc" "$depends_on" "$help_text" >> "$KCONFIG"
        ((count++)) || true

        if [ -f "$DEFCONFIG" ] && ! grep -q "CONFIG_$config" "$DEFCONFIG"; then
            echo "CONFIG_$config=y" >> "$DEFCONFIG"
            echo "[+] Added CONFIG_$config to defconfig"
        fi
    done

    echo "[+] $count Kconfig entries added"
}

validate_overlayfs
inject_kconfig_entries
