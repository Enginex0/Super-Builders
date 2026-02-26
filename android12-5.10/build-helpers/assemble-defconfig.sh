#!/bin/bash
set -euo pipefail

FRAGMENT_SRC="${1:?}"
FRAGMENT_DST="${2:?}"
DEFCONFIG="${3:?}"
shift 3

ADD_SUSFS=false
ADD_OVERLAYFS=false
ADD_ZRAM=false
ADD_KPM=false

for arg in "$@"; do
  case "$arg" in
    --susfs) ADD_SUSFS=true ;;
    --overlayfs) ADD_OVERLAYFS=true ;;
    --zram) ADD_ZRAM=true ;;
    --kpm) ADD_KPM=true ;;
  esac
done

extract_section() {
  awk "/^# \\[$1\\]/{found=1; next} /^# \\[/{found=0} found && NF" "$FRAGMENT_SRC"
}

extract_section "base" >> "$FRAGMENT_DST"
$ADD_SUSFS && extract_section "susfs" >> "$FRAGMENT_DST"
$ADD_OVERLAYFS && extract_section "overlayfs" >> "$FRAGMENT_DST"
$ADD_ZRAM && extract_section "zram" >> "$FRAGMENT_DST"
$ADD_KPM && extract_section "kpm" >> "$FRAGMENT_DST"

# dedup: last-wins per CONFIG_ key
tac "$FRAGMENT_DST" | awk -F= '/^CONFIG_/{if(seen[$1]++)next} {print}' | tac > "${FRAGMENT_DST}.tmp"
mv "${FRAGMENT_DST}.tmp" "$FRAGMENT_DST"

# GKI build.sh sources the fragment as bash but never merges it into .config.
# Int/string Kconfig values AND their parent tristate must be in gki_defconfig
# directly, otherwise make gki_defconfig can't resolve the dependency chain.
grep -q '^CONFIG_IP_SET=' "$DEFCONFIG" || echo 'CONFIG_IP_SET=y' >> "$DEFCONFIG"
grep -q '^CONFIG_IP_SET_MAX=' "$DEFCONFIG" || echo 'CONFIG_IP_SET_MAX=65534' >> "$DEFCONFIG"

if $ADD_ZRAM; then
  sed -i 's/CONFIG_ZRAM=m/CONFIG_ZRAM=y/g' "$DEFCONFIG" 2>/dev/null || true
  sed -i 's/CONFIG_ZSMALLOC=m/CONFIG_ZSMALLOC=y/g' "$DEFCONFIG" 2>/dev/null || true
  grep -q '^CONFIG_ZRAM=' "$DEFCONFIG" || echo 'CONFIG_ZRAM=y' >> "$DEFCONFIG"
  grep -q '^CONFIG_ZSMALLOC=' "$DEFCONFIG" || echo 'CONFIG_ZSMALLOC=y' >> "$DEFCONFIG"
  grep -q '^CONFIG_ZRAM_DEF_COMP=' "$DEFCONFIG" || echo 'CONFIG_ZRAM_DEF_COMP="lz4kd"' >> "$DEFCONFIG"
fi
