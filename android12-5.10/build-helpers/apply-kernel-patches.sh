#!/bin/bash
set -euo pipefail

KERNEL_DIR="${1:?Usage: apply-kernel-patches.sh <kernel_dir> <kernel_ver> <patches_dir>}"
KERNEL_VER="${2:?}"
PATCHES_DIR="${3:?}"

ADD_PTRACE="${ADD_PTRACE:-true}"
ADD_PERF="${ADD_PERF:-true}"

MAJOR="${KERNEL_VER%%.*}"
MINOR="${KERNEL_VER#*.}"
COMMON="$PATCHES_DIR/common"

TARGET="${ANDROID_VER:-unknown}-${KERNEL_VER}"

apply() { patch -p1 -F3 --forward < "$1" || true; }
apply_required() {
  local patch_file="$1"
  test -s "$patch_file" || {
    echo "::error::Required kernel patch is missing: $patch_file"
    exit 1
  }
  patch -p1 --no-backup-if-mismatch < "$patch_file"
}

cd "$KERNEL_DIR"

if [ "$ADD_PTRACE" = "true" ] && [ -f "$PATCHES_DIR/gki_ptrace.patch" ]; then
  if [ "$MAJOR" -lt 5 ] || { [ "$MAJOR" -eq 5 ] && [ "$MINOR" -lt 16 ]; }; then
    apply "$PATCHES_DIR/gki_ptrace.patch"
    echo "apply-kernel-patches: ptrace fix applied (kernel $KERNEL_VER < 5.16)"
  fi
fi

[ ! -d "$COMMON" ] && { echo "apply-kernel-patches: $COMMON not found"; exit 0; }

if [ "$TARGET" = "android14-6.1" ]; then
  apply_required "$COMMON/ntsync/ntsync_base.patch"
  apply_required "$COMMON/ntsync/ntsync_compat_android14-6.1.patch"
  apply_required "$COMMON/bbrv3/0001-net-tcp-backport-BBRv3-to-android14-6.1.patch"

  test -f drivers/misc/ntsync.c
  grep -qx 'config NTSYNC' drivers/misc/Kconfig
  test -f net/ipv4/tcp_bbr3.c
  grep -qx 'config TCP_CONG_BBR3' net/ipv4/Kconfig
  echo "apply-kernel-patches: r6 NTSYNC and BBRv3 sources applied"
fi

[ "$ADD_PERF" != "true" ] && exit 0

apply "$COMMON/optimized_mem_operations.patch"
apply "$COMMON/file_struct_8bytes_align.patch"
apply "$COMMON/reduce_cache_pressure.patch"
apply "$COMMON/mem_opt_prefetch.patch"

if [ "$MAJOR" -ge 6 ]; then
  apply "$COMMON/optimise_memcmp.patch"
else
  sed -e 's/SYM_FUNC_START(__pi_memcmp)/SYM_FUNC_START_WEAK_PI(memcmp)/' \
      -e 's/SYM_FUNC_END(__pi_memcmp)/SYM_FUNC_END_PI(memcmp)/' \
      -e 's/SYM_FUNC_ALIAS_WEAK(memcmp, __pi_memcmp)/EXPORT_SYMBOL_NOKASAN(memcmp)/' \
      "$COMMON/optimise_memcmp.patch" | patch -p1 -F3 --forward || true
fi

apply "$COMMON/minimise_wakeup_time.patch"
apply "$COMMON/int_sqrt.patch"
apply "$COMMON/force_tcp_nodelay.patch"
apply "$COMMON/reduce_gc_thread_sleep_time.patch"
apply "$COMMON/add_timeout_wakelocks_globally.patch"
if [[ "$TARGET" = "android14-6.1" && "${SAMSUNG_SOURCE_BASE_APPLIED:-false}" = "true" ]]; then
  F2FS_HEADER=fs/f2fs/f2fs.h
  [[ "$(grep -cF 'DEFAULT_IO_TIMEOUT' "$F2FS_HEADER")" -eq 1 ]]
  [[ "$(grep -cF 'msecs_to_jiffies(20)' "$F2FS_HEADER")" -eq 1 ]]
  [[ "$(grep -cF 'default: 20ms' "$F2FS_HEADER")" -eq 1 ]]
  sed -i \
    -e 's/default: 20ms/default: 6ms/' \
    -e 's/msecs_to_jiffies(20)/msecs_to_jiffies(6)/' \
    "$F2FS_HEADER"
  [[ "$(grep -cF 'msecs_to_jiffies(6)' "$F2FS_HEADER")" -eq 1 ]]
  [[ "$(grep -cF 'default: 6ms' "$F2FS_HEADER")" -eq 1 ]]
  [[ ! -f "$F2FS_HEADER.rej" ]]
  echo "apply-kernel-patches: Samsung F2FS congestion patch port applied"
else
  apply "$COMMON/f2fs_reduce_congestion.patch"
fi
apply "$COMMON/reduce_freeze_timeout.patch"

if [ "$MAJOR" -ge 6 ]; then
  apply "$COMMON/clear_page_16bytes_align.patch"
else
  sed 's/SYM_FUNC_START_PI(clear_page)/SYM_FUNC_START_PI(__pi_clear_page)/' \
    "$COMMON/clear_page_16bytes_align.patch" | patch -p1 -F3 --forward || true
fi

# upstream declares val as unsigned long but uses %u (expects unsigned int *)
sed 's/unsigned long val;/unsigned int val;/' \
  "$COMMON/add_limitation_scaling_min_freq.patch" | patch -p1 -F3 --forward || true
apply "$COMMON/re_write_limitation_scaling_min_freq.patch"
apply "$COMMON/adjust_cpu_scan_order.patch"
if [[ "$TARGET" = "android14-6.1" && "${SAMSUNG_SOURCE_BASE_APPLIED:-false}" = "true" ]]; then
  SAMSUNG_WAKE_PATCH="$COMMON/Samsung/avoid_extra_s2idle_wake_attempts_oneui8.5.patch"
  test -s "$SAMSUNG_WAKE_PATCH" || {
    echo "::error::Required Samsung OneUI 8.5 wakeup patch is missing: $SAMSUNG_WAKE_PATCH"
    exit 1
  }
  patch -p1 -F3 --no-backup-if-mismatch < "$SAMSUNG_WAKE_PATCH"
  WAKE_BLOCK=$(sed -n '/^void pm_system_wakeup(void)$/,/^}/p' drivers/base/power/wakeup.c)
  [[ "$(grep -cF 'if (atomic_inc_return_relaxed(&pm_abort_suspend) == 1) {' <<< "$WAKE_BLOCK")" -eq 1 ]]
  [[ "$(grep -cF 'suspend_abort_fs_sync();' <<< "$WAKE_BLOCK")" -eq 1 ]]
  [[ "$(grep -cF 's2idle_wake();' <<< "$WAKE_BLOCK")" -eq 1 ]]
  [[ ! -f drivers/base/power/wakeup.c.rej ]]
  echo "apply-kernel-patches: Samsung OneUI 8.5 s2idle wake patch applied"
else
  apply "$COMMON/avoid_extra_s2idle_wake_attempts.patch"
fi
apply "$COMMON/disable_cache_hot_buddy.patch"
apply "$COMMON/f2fs_enlarge_min_fsync_blocks.patch"
apply "$COMMON/increase_ext4_default_commit_age.patch"
apply "$COMMON/increase_sk_mem_packets.patch"
apply "$COMMON/reduce_pci_pme_wakeups.patch"
apply "$COMMON/silence_irq_cpu_logspam.patch"
apply "$COMMON/silence_system_logspam.patch"
apply "$COMMON/use_unlikely_wrap_cpufreq.patch"

if [ -f "$COMMON/unicode_bypass_fix_6.1+.patch" ]; then
  if [ "$TARGET" = "android14-6.1" ]; then
    apply_required "$COMMON/unicode_bypass_fix_6.1+.patch"
    grep -Fq "*LEAF_STR(leaf) == '\\0'" fs/unicode/utf8-norm.c
  elif [ "$MAJOR" -gt 6 ] || { [ "$MAJOR" -eq 6 ] && [ "$MINOR" -ge 1 ]; }; then
    apply "$COMMON/unicode_bypass_fix_6.1+.patch"
  else
    apply "$COMMON/unicode_bypass_fix_6.1-.patch"
  fi
fi

if [ -f "$COMMON/IPv6_NAT_FIX.patch" ]; then
  if [ "$TARGET" = "android14-6.1" ]; then
    apply_required "$COMMON/IPv6_NAT_FIX.patch"
    grep -q 'define config_fix' kernel/Makefile
  else
    apply "$COMMON/IPv6_NAT_FIX.patch"
  fi
fi

echo "apply-kernel-patches: done"
