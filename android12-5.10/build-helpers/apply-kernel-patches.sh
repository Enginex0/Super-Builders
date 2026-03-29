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

apply() { patch -p1 -F3 --forward < "$1" || true; }

cd "$KERNEL_DIR"

if [ "$ADD_PTRACE" = "true" ] && [ -f "$PATCHES_DIR/gki_ptrace.patch" ]; then
  if [ "$MAJOR" -lt 5 ] || { [ "$MAJOR" -eq 5 ] && [ "$MINOR" -lt 16 ]; }; then
    apply "$PATCHES_DIR/gki_ptrace.patch"
    echo "apply-kernel-patches: ptrace fix applied (kernel $KERNEL_VER < 5.16)"
  fi
fi

[ "$ADD_PERF" != "true" ] && exit 0
[ ! -d "$COMMON" ] && { echo "apply-kernel-patches: $COMMON not found"; exit 0; }

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
apply "$COMMON/f2fs_reduce_congestion.patch"
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
apply "$COMMON/avoid_extra_s2idle_wake_attempts.patch"
apply "$COMMON/disable_cache_hot_buddy.patch"
apply "$COMMON/f2fs_enlarge_min_fsync_blocks.patch"
apply "$COMMON/increase_ext4_default_commit_age.patch"
apply "$COMMON/increase_sk_mem_packets.patch"
apply "$COMMON/reduce_pci_pme_wakeups.patch"
apply "$COMMON/silence_irq_cpu_logspam.patch"
apply "$COMMON/silence_system_logspam.patch"
apply "$COMMON/use_unlikely_wrap_cpufreq.patch"

if [ -f "$COMMON/unicode_bypass_fix_6.1+.patch" ]; then
  if [ "$MAJOR" -gt 6 ] || { [ "$MAJOR" -eq 6 ] && [ "$MINOR" -ge 1 ]; }; then
    apply "$COMMON/unicode_bypass_fix_6.1+.patch"
  else
    apply "$COMMON/unicode_bypass_fix_6.1-.patch"
  fi
fi

[ -f "$COMMON/IPv6_NAT_FIX.patch" ] && apply "$COMMON/IPv6_NAT_FIX.patch"

echo "apply-kernel-patches: done"
