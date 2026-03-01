#!/bin/bash
# Runs AFTER KSU setup — fixes kernel and KSU compat for 5.4
set -euo pipefail

KERNEL_COMMON="$1"
SUBLEVEL="$2"

cd "$KERNEL_COMMON" || exit 1

# KSU-Next and WKSU lack the pre-5.7 compat that SukiSU has in kernel_compat.h
# SukiSU already includes sched/task.h and defines TWA_RESUME — skip it
PARENT="$(dirname "$KERNEL_COMMON")"
for al in "$PARENT"/*/kernel/allowlist.c; do
  [ -f "$al" ] || continue
  grep -q 'TWA_RESUME' "$al" || continue
  grep -q 'sched/task\.h' "$al" && continue

  sed -i '/#include <linux\/task_work.h>/a\
#include <linux/version.h>\
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)\
#include <linux/sched/task.h>\
#else\
#include <linux/sched.h>\
#endif\
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)\
#ifndef TWA_RESUME\
#define TWA_RESUME true\
#endif\
#endif' "$al"

  echo "Patched $(basename "$(dirname "$(dirname "$al")")")/kernel/allowlist.c with pre-5.7 compat"
done

# linux/pgtable.h was split from asm/pgtable.h in 5.8
for src in "$PARENT"/*/kernel/*.c; do
  [ -f "$src" ] || continue
  grep -q '#include <linux/pgtable.h>' "$src" || continue
  sed -i 's|#include <linux/pgtable.h>|#include <asm/pgtable.h>|' "$src"
  echo "Fixed pgtable.h in $(basename "$(dirname "$(dirname "$src")")")/kernel/$(basename "$src")"
done
