#!/bin/bash
set -euo pipefail

KERNEL_COMMON="$1"
SUBLEVEL="$2"

cd "$KERNEL_COMMON" || exit 1

if [[ "$SUBLEVEL" -lt 218 ]]; then
  TASK_MMU="fs/proc/task_mmu.c"
  if [[ -f "$TASK_MMU" ]] && grep -q 'goto show_pad;' "$TASK_MMU" && ! grep -q '^show_pad:' "$TASK_MMU"; then
    sed -i '/show_smap_vma_flags(m, vma);/{n;/^$/a\show_pad:
}' "$TASK_MMU"
    echo "Added show_pad: label for sublevel $SUBLEVEL (<218)"
  fi
fi
